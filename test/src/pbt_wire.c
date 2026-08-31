// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// The wire picobootx's core talks to.
//
// On a device this is src/picobootx_vendor.c driving tinyusb's endpoint
// streams.  Here it is a pair of packet queues, implementing the same
// picoboot_vendor_* API, plus the two tinyusb control entry points the core
// answers through.
//
// The model keeps packet boundaries rather than presenting a byte stream.  It
// has to: the protocol's acknowledgement is a packet, the absence of a trailing
// packet after a transfer that fills the endpoint exactly is the reason
// picobootx does not use tinyusb's stock vendor driver, and a byte-stream model
// would lose both.

#include <stdlib.h>
#include <string.h>

#include "pbt.h"
#include "picobootx_vendor.h"

// The bulk FIFOs are one endpoint's worth each, as CFG_TUD_PICOBOOT_RX_BUFSIZE
// and CFG_TUD_PICOBOOT_TX_BUFSIZE set them.
#define PBT_RX_FIFO PBT_PACKET_MAX
#define PBT_TX_FIFO PBT_PACKET_MAX

// How many packets one scenario may collect before the harness gives up.  Far
// more than any scenario needs, so hitting it means a transfer is not
// terminating.
#define PBT_PACKET_LOG_MAX 256u

// Task calls pbt_pump will make before deciding the device is not going to
// settle.  A transfer of the largest size any scenario asks for completes in
// far fewer.
#define PBT_PUMP_MAX 512u

// ---------------------------------------------------------------------------
// Receive side
// ---------------------------------------------------------------------------

static uint8_t  s_rx[PBT_RX_FIFO];
static uint32_t s_rx_len;
static uint32_t s_rx_pos;

static uint32_t pbt_rx_available(void) { return s_rx_len - s_rx_pos; }

// ---------------------------------------------------------------------------
// Transmit side
// ---------------------------------------------------------------------------

static uint8_t  s_tx[PBT_TX_FIFO];
static uint32_t s_tx_len;

// How much of the transmit FIFO the wire admits to having.  An integrator sets
// this with CFG_TUD_PICOBOOT_TX_BUFSIZE, so it is a configuration and not a
// fault: a device with a small one hands the fill functions less room than one
// item, and they have to decline the call rather than truncate the item.
static uint32_t s_tx_fifo;

// ---------------------------------------------------------------------------
// Armed transport faults
//
// Each is consumed by the call it applies to, so a scenario shows the failure
// and then that the very next call is served normally.  PBT_NO_FAULT is the
// disarmed value, chosen so that a fault of zero bytes — the case that matters
// for a read — is still expressible.
// ---------------------------------------------------------------------------

#define PBT_NO_FAULT 0xFFFFFFFFu

static bool     s_refuse_zlp;
static uint32_t s_short_read;
static uint32_t s_short_write;

static pbt_packet_t s_packets[PBT_PACKET_LOG_MAX];
static uint32_t     s_packet_count;

// Packets emitted but whose transmit-completion callback has not yet been
// delivered.  On a device the callback arrives when the USB transfer finishes,
// which is always after the call that queued it returned.
static uint32_t s_packets_completed;

// Every emitted payload byte in order, for asserting a transfer's content
// without caring how it was split into packets.
static uint8_t  s_payload[PBT_PACKET_LOG_MAX * PBT_PACKET_MAX];
static uint32_t s_payload_len;

// ---------------------------------------------------------------------------
// Endpoint state
// ---------------------------------------------------------------------------

static bool s_stalled_out;
// Whether the device is taking anything from the host.  A pause is not a halt,
// so nothing about it reaches the host except that its packets go nowhere.
static bool s_rx_paused;
static bool s_stalled_in;

static bool *pbt_stall_flag(uint8_t ep_addr) {
    if (ep_addr == PBT_EP_OUT) {
        return &s_stalled_out;
    }
    if (ep_addr == PBT_EP_IN) {
        return &s_stalled_in;
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// Control state
// ---------------------------------------------------------------------------

static uint8_t  s_ctrl_reply[64];
static uint32_t s_ctrl_reply_len;

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

void pbt_wire_reset(void) {
    s_rx_len            = 0;
    s_rx_pos            = 0;
    s_tx_len            = 0;
    s_packet_count      = 0;
    s_packets_completed = 0;
    s_payload_len       = 0;
    s_stalled_out       = false;
    s_rx_paused         = false;
    s_stalled_in        = false;
    s_ctrl_reply_len    = 0;
    s_tx_fifo           = PBT_TX_FIFO;
    s_refuse_zlp        = false;
    s_short_read        = PBT_NO_FAULT;
    s_short_write       = PBT_NO_FAULT;
}

void pbt_wire_tx_fifo(uint32_t bytes) {
    if (bytes == 0u || bytes > PBT_TX_FIFO) {
        pbt_fail(__FILE__, __LINE__,
                 "a transmit FIFO of %u bytes is outside the 1..%u the wire "
                 "models", bytes, PBT_TX_FIFO);
        return;
    }
    s_tx_fifo = bytes;
}

void pbt_wire_refuse_zlp(void) { s_refuse_zlp = true; }

void pbt_wire_short_read(uint32_t bytes) { s_short_read = bytes; }

void pbt_wire_short_write(uint32_t bytes) { s_short_write = bytes; }

// ---------------------------------------------------------------------------
// picoboot_vendor_* — receive
// ---------------------------------------------------------------------------

uint32_t picoboot_vendor_available(void) {
    return pbt_rx_available();
}

bool picoboot_vendor_peek(uint8_t *u8) {
    if (pbt_rx_available() == 0u) {
        return false;
    }
    *u8 = s_rx[s_rx_pos];
    return true;
}

uint32_t picoboot_vendor_read(void *buffer, uint32_t bufsize) {
    uint32_t avail = pbt_rx_available();
    uint32_t n     = bufsize < avail ? bufsize : avail;

    if (s_short_read != PBT_NO_FAULT) {
        uint32_t limit = s_short_read;
        s_short_read = PBT_NO_FAULT;
        if (limit < n) {
            pbt_log("short_read", n, limit, 0, 0);
            n = limit;
        }
    }

    memcpy(buffer, s_rx + s_rx_pos, n);
    s_rx_pos += n;
    return n;
}

void picoboot_vendor_read_clear(void) {
    pbt_log("rx_clear", pbt_rx_available(), 0, 0, 0);
    s_rx_len = 0;
    s_rx_pos = 0;
}

bool picoboot_vendor_read_xfer(void) {
    return true;
}

bool picoboot_vendor_write_pending(void) {
    return s_tx_len > 0u;
}

void picoboot_vendor_read_pause(void) {
    pbt_log("rx_pause", 0, 0, 0, 0);
    s_rx_paused = true;
}

void picoboot_vendor_read_resume(void) {
    pbt_log("rx_resume", 0, 0, 0, 0);
    s_rx_paused = false;
}

// ---------------------------------------------------------------------------
// picoboot_vendor_* — transmit
// ---------------------------------------------------------------------------

uint32_t picoboot_vendor_write_available(void) {
    return s_tx_fifo - s_tx_len;
}

uint32_t picoboot_vendor_write(const void *buffer, uint32_t bufsize) {
    uint32_t space = picoboot_vendor_write_available();
    uint32_t n     = bufsize < space ? bufsize : space;

    if (s_short_write != PBT_NO_FAULT) {
        uint32_t limit = s_short_write;
        s_short_write = PBT_NO_FAULT;
        if (limit < n) {
            pbt_log("short_write", n, limit, 0, 0);
            n = limit;
        }
    }

    memcpy(s_tx + s_tx_len, buffer, n);
    s_tx_len += n;
    return n;
}

uint32_t picoboot_vendor_write_flush(void) {
    if (s_tx_len == 0u) {
        return 0u;
    }
    if (s_packet_count >= PBT_PACKET_LOG_MAX) {
        pbt_fail(__FILE__, __LINE__,
                 "device emitted more than %u packets — transfer is not "
                 "terminating", PBT_PACKET_LOG_MAX);
        s_tx_len = 0;
        return 0u;
    }

    pbt_packet_t *pkt = &s_packets[s_packet_count++];
    pkt->len = s_tx_len;
    memcpy(pkt->data, s_tx, s_tx_len);

    memcpy(s_payload + s_payload_len, s_tx, s_tx_len);
    s_payload_len += s_tx_len;

    // The first byte is carried in the log so a one-byte acknowledgement can be
    // told apart from a one-byte data packet without going to the packet array.
    pbt_log("packet_in", s_tx_len, s_tx[0], 0, 0);

    uint32_t sent = s_tx_len;
    s_tx_len = 0;
    return sent;
}

bool picoboot_vendor_write_clear(void) {
    pbt_log("tx_clear", s_tx_len, 0, 0, 0);
    s_tx_len = 0;
    return true;
}

bool picoboot_vendor_send_zlp(void) {
    if (s_refuse_zlp) {
        // The device's refuses when the write is not accepted or the flush
        // cannot claim the endpoint, and reports the refusal the same way.
        s_refuse_zlp = false;
        pbt_log("zlp_refused", 0, 0, 0, 0);
        return false;
    }

    // This mirrors the body in src/picobootx_vendor.c, which does not send a
    // zero-length packet at all: it sends a single zero byte.  The two must
    // agree, or the suite pins behaviour the device does not have.
    //
    // picoboot_rx_cb accepts both a zero-length and a one-byte packet as the
    // host's acknowledgement, for the same reason in the other direction.
    uint8_t buf[1] = { 0 };
    if (picoboot_vendor_write(buf, 1) != 1u) {
        return false;
    }
    return picoboot_vendor_write_flush() == 1u;
}

// ---------------------------------------------------------------------------
// picoboot_vendor_* — endpoint management
// ---------------------------------------------------------------------------

bool picoboot_vendor_is_endpoint_stalled(uint8_t ep_addr) {
    const bool *flag = pbt_stall_flag(ep_addr);
    return flag != NULL && *flag;
}

void picoboot_vendor_stall_endpoint(uint8_t ep_addr) {
    bool *flag = pbt_stall_flag(ep_addr);
    if (flag == NULL) {
        pbt_fail(__FILE__, __LINE__, "stall of unknown endpoint 0x%02x",
                 ep_addr);
        return;
    }
    if (*flag) {
        // Already halted.  The device driver returns without touching the
        // endpoint, and so does this.
        pbt_log("stall_redundant", ep_addr, 0, 0, 0);
        return;
    }
    pbt_log("stall", ep_addr, 0, 0, 0);
    *flag = true;
}

void picoboot_vendor_unstall_endpoint(uint8_t ep_addr) {
    bool *flag = pbt_stall_flag(ep_addr);
    if (flag == NULL) {
        pbt_fail(__FILE__, __LINE__, "unstall of unknown endpoint 0x%02x",
                 ep_addr);
        return;
    }

    bool was_stalled = *flag;
    if (was_stalled) {
        pbt_log("unstall", ep_addr, 0, 0, 0);
        *flag = false;
    }

    // Clearing a halt leaves the endpoint unarmed, so the driver re-arms it.
    // Both directions end up empty either way.  Which branch was taken is
    // recorded because the two are different code paths on a device.
    if (ep_addr == PBT_EP_OUT) {
        if (was_stalled) {
            picoboot_vendor_read_clear();
        } else {
            pbt_log("rx_clear_soft", pbt_rx_available(), 0, 0, 0);
            s_rx_len = 0;
            s_rx_pos = 0;
        }
    } else {
        picoboot_vendor_write_clear();
    }
}

// ---------------------------------------------------------------------------
// tinyusb control entry points
// ---------------------------------------------------------------------------

bool tud_control_xfer(uint8_t rhport, const tusb_control_request_t *request,
                      void *buffer, uint16_t len) {
    (void)rhport;
    (void)request;

    uint32_t n = len;
    if (n > sizeof(s_ctrl_reply)) {
        n = sizeof(s_ctrl_reply);
    }
    if (n > 0u && buffer != NULL) {
        memcpy(s_ctrl_reply, buffer, n);
    } else {
        n = 0;
    }
    s_ctrl_reply_len = n;

    pbt_log("control_xfer", request->bRequest, len, 0, 0);
    return true;
}

bool tud_control_status(uint8_t rhport, const tusb_control_request_t *request) {
    (void)rhport;
    pbt_log("control_status", request->bRequest, 0, 0, 0);
    s_ctrl_reply_len = 0;
    return true;
}

// ---------------------------------------------------------------------------
// The harness side of the wire
// ---------------------------------------------------------------------------

void pbt_host_send(const void *data, uint32_t len) {
    if (len > PBT_PACKET_MAX) {
        pbt_fail(__FILE__, __LINE__,
                 "host packet of %u bytes exceeds the endpoint size", len);
        return;
    }

    // A packet arriving on a halted endpoint is not accepted by the device.
    // Recording it rather than delivering it is what lets a scenario show that
    // a stall really did stop the host being heard.
    if (s_stalled_out) {
        pbt_log("packet_out_stalled", len, 0, 0, 0);
        return;
    }

    // A device owing the host packets takes nothing from it.  Dropping it here
    // is what lets a scenario show the host was not heard.
    if (s_rx_paused) {
        pbt_log("packet_out_paused", len, 0, 0, 0);
        return;
    }

    // The receive FIFO is compacted first, exactly as a stream is when the
    // driver hands it the next transfer.
    if (s_rx_pos > 0u) {
        memmove(s_rx, s_rx + s_rx_pos, s_rx_len - s_rx_pos);
        s_rx_len -= s_rx_pos;
        s_rx_pos = 0;
    }
    if (s_rx_len + len > PBT_RX_FIFO) {
        pbt_fail(__FILE__, __LINE__,
                 "host packet of %u bytes overruns the receive FIFO, which "
                 "already holds %u", len, s_rx_len);
        return;
    }

    // A zero-length packet carries no buffer, and copying from one is undefined
    // even for no bytes.
    if (len > 0u) {
        memcpy(s_rx + s_rx_len, data, len);
        s_rx_len += len;
    }

    pbt_log("packet_out", len, 0, 0, 0);

    // The vendor driver notifies the protocol handler with what is now
    // available, not with what this packet carried.
    picoboot_rx_cb(pbt_state(), picoboot_vendor_available());
}

void pbt_host_send_cmd(const picoboot_cmd_t *cmd) {
    pbt_host_send(cmd, (uint32_t)sizeof(*cmd));
}

void pbt_host_ack(void) {
    pbt_host_send(NULL, 0);
}

void pbt_host_ack_byte(void) {
    uint8_t byte = 0;
    pbt_host_send(&byte, 1);
}

void pbt_complete_tx(void) {
    while (s_packets_completed < s_packet_count) {
        const pbt_packet_t *pkt = &s_packets[s_packets_completed++];
        pbt_log("tx_complete", pkt->len, 0, 0, 0);
        picoboot_tx_cb(pbt_state(), pkt->len);
    }
}

void pbt_task(void) {
    picoboot_task(pbt_state());
}

void pbt_pump(void) {
    for (unsigned i = 0; i < PBT_PUMP_MAX; i++) {
        uint32_t   events  = pbt_event_count();
        uint32_t   packets = s_packet_count;
        pb_state_t state   = pbt_cur_state();

        picoboot_task(pbt_state());
        pbt_complete_tx();

        if (pbt_event_count() == events && s_packet_count == packets &&
            pbt_cur_state() == state) {
            return;
        }
    }

    pbt_fail(__FILE__, __LINE__,
             "device had not settled after %u task calls — state %s",
             PBT_PUMP_MAX, pbt_state_name(pbt_cur_state()));
}

uint32_t pbt_packet_count(void) { return s_packet_count; }

const pbt_packet_t *pbt_packet(uint32_t index) {
    return index < s_packet_count ? &s_packets[index] : NULL;
}

uint32_t       pbt_payload_len(void) { return s_payload_len; }
const uint8_t *pbt_payload(void)     { return s_payload; }

bool pbt_ep_stalled(uint8_t ep_addr) {
    return picoboot_vendor_is_endpoint_stalled(ep_addr);
}

void pbt_force_stall(uint8_t ep_addr) {
    bool *flag = pbt_stall_flag(ep_addr);
    if (flag == NULL) {
        pbt_fail(__FILE__, __LINE__, "forced stall of unknown endpoint 0x%02x",
                 ep_addr);
        return;
    }
    pbt_log("force_stall", ep_addr, 0, 0, 0);
    *flag = true;
}

// ---------------------------------------------------------------------------
// Control transfers, from the harness side
// ---------------------------------------------------------------------------

bool pbt_ctrl_at_stage(uint8_t stage, uint8_t type, uint8_t recipient,
                       uint8_t b_request, uint16_t w_value, uint16_t w_index,
                       uint16_t w_length) {
    tusb_control_request_t req;
    memset(&req, 0, sizeof(req));
    req.bmRequestType_bit.recipient = recipient & 0x1Fu;
    req.bmRequestType_bit.type      = type & 0x03u;
    req.bmRequestType_bit.direction = 1u;  // device to host
    req.bRequest                    = b_request;
    req.wValue                      = w_value;
    req.wIndex                      = w_index;
    req.wLength                     = w_length;

    s_ctrl_reply_len = 0;
    return picoboot_control_xfer_cb(pbt_state(), PBT_RHPORT, stage, &req);
}

bool pbt_ctrl(uint8_t type, uint8_t recipient, uint8_t b_request,
              uint16_t w_value, uint16_t w_index, uint16_t w_length) {
    return pbt_ctrl_at_stage(CONTROL_STAGE_SETUP, type, recipient, b_request,
                             w_value, w_index, w_length);
}

bool pbt_ctrl_get_status(picoboot_status_t *out) {
    bool handled = pbt_ctrl(TUSB_REQ_TYPE_VENDOR, TUSB_REQ_RCPT_INTERFACE,
                            0x42u, 0u, 0u, (uint16_t)sizeof(*out));
    if (handled && out != NULL) {
        memset(out, 0, sizeof(*out));
        uint32_t n = s_ctrl_reply_len < sizeof(*out) ? s_ctrl_reply_len
                                                     : (uint32_t)sizeof(*out);
        memcpy(out, s_ctrl_reply, n);
    }
    return handled;
}

bool pbt_ctrl_interface_reset(void) {
    return pbt_ctrl(TUSB_REQ_TYPE_VENDOR, TUSB_REQ_RCPT_INTERFACE, 0x41u, 0u,
                    0u, 0u);
}

bool pbt_ctrl_clear_ep_halt(uint8_t ep_addr) {
    // The host stack clears the halt before the class driver is given the
    // request, which is the condition the library's re-arm is responding to.
    bool *flag = pbt_stall_flag(ep_addr);
    if (flag != NULL && *flag) {
        pbt_log("host_cleared_halt", ep_addr, 0, 0, 0);
        *flag = false;
    }

    return pbt_ctrl(TUSB_REQ_TYPE_STANDARD, TUSB_REQ_RCPT_ENDPOINT,
                    TUSB_REQ_CLEAR_FEATURE, TUSB_REQ_FEATURE_EDPT_HALT,
                    ep_addr, 0u);
}

uint32_t       pbt_ctrl_reply_len(void) { return s_ctrl_reply_len; }
const uint8_t *pbt_ctrl_reply(void)     { return s_ctrl_reply; }
