// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// A device controller driver for a machine with no USB hardware.
//
// tinyusb reaches its silicon through the dcd_* interface, and supplies no
// implementation when CFG_TUSB_MCU is OPT_MCU_NONE.  This is that
// implementation, written against a model of the bus instead of a controller.
// It is why real tinyusb and picobootx's real vendor driver can run in a
// process: everything above this file is the shipped code.
//
// The model is thin, but not thinner than the part.  An endpoint holds one
// queued transfer, a stall flag, and the packets it has latched out of the
// driver's buffer with the data toggle each carries — because a packet is
// latched and numbered as a transfer is armed, and a model that did either
// later cannot see a device that loses track of one.  The host in usbt_host.c
// satisfies a transfer and the completion goes back through
// dcd_event_xfer_complete, as a controller's interrupt would.  Nothing here
// decides anything about the protocol.

#include <string.h>

#include "device/dcd.h"
#include "tusb.h"
#include "usbt.h"
#include "usbt_dcd.h"

// Endpoint 0 plus the two bulk endpoints, in both directions.  Sized from
// tinyusb's own maximum so an out-of-range address is caught here rather than
// running off the array.
#define USBT_EP_SLOTS (TUP_DCD_ENDPOINT_MAX * 2u)

typedef struct {
    bool     open;
    bool     stalled;
    uint16_t packet_max;

    // The transfer tinyusb has queued, if any.
    //
    // A transfer is backed either by a linear buffer or by a FIFO, and both
    // reach the controller: usbd offers dcd_edpt_xfer for one and
    // dcd_edpt_xfer_fifo for the other, and picobootx's vendor driver uses the
    // FIFO form, since it opens its streams with no endpoint buffer.  Only one
    // of the two is ever set.
    bool       pending;
    uint8_t   *buf;
    tu_fifo_t *ff;
    uint16_t   total;
    uint16_t   moved;

    // The packets the controller has latched, for a device to host transfer.
    //
    // The part copies a packet into one of the endpoint's own buffers as the
    // transfer is armed, so the bytes a host reads left the driver's FIFO
    // before it asked.  A model that read them at collection would show a
    // packet that should have been withdrawn as delivering whatever the FIFO
    // holds by then, rather than the stale bytes a host really receives.
    //
    // Two, because the part arms both when more than a packet is left.  The
    // host then takes two before the device hears one completion, and arming
    // has taken two data toggles rather than one.
    //
    // picobootx reaches only the first: tu_edpt_stream_write_xfer arms what its
    // FIFO holds, and CFG_TUD_PICOBOOT_TX_BUFSIZE is one packet.  The pair is
    // here because the part has it and another consumer would meet it.
    uint8_t    pkt[2][USBT_PACKET_MAX];
    uint16_t   pkt_len[2];

    // The toggle each latched packet carries, and the one the next will.  A bus
    // numbers packets alternately so either end can spot a repeat.  The number
    // is stamped as a buffer is filled, so arming takes one whether or not the
    // packet is ever collected, and withdrawing has to give it back.
    uint8_t    pkt_pid[2];
    uint8_t    next_pid;

    // How many of the two the host has yet to take, and which is next.  On the
    // part these are the AVAILABLE bits and the buffer selector.
    uint8_t    armed;
    uint8_t    next_buf;

    // Bytes taken out of the driver's buffer and not yet delivered.  With two
    // armed the read offset and the delivered count stop agreeing, and moved is
    // the delivered one.
    uint16_t   latched;

    // Whether this endpoint arms one buffer at a time, which the part decides
    // rather than the driver.  Endpoint zero has no endpoint control register,
    // so it cannot arm a second, and a device's OUT endpoints are single
    // buffered because a short packet from the host would strand it.
    bool       single;
} usbt_ep_t;

static usbt_ep_t s_ep[USBT_EP_SLOTS];
static uint8_t   s_address;
static bool      s_connected;
static bool      s_sof_enabled;
static bool      s_remote_wakeup;

// Index an endpoint address.  Number in the low four bits, direction in bit 7,
// which is how a USB endpoint address is laid out.
static unsigned ep_slot(uint8_t ep_addr) {
    unsigned num = ep_addr & 0x0Fu;
    unsigned dir = (ep_addr & 0x80u) ? 1u : 0u;
    return (num * 2u) + dir;
}

// ---------------------------------------------------------------------------
// What the host side uses
// ---------------------------------------------------------------------------

void usbt_dcd_reset(void) {
    memset(s_ep, 0, sizeof(s_ep));
    s_address       = USBT_ADDR_DEFAULT;
    s_connected     = false;
    s_sof_enabled   = false;
    s_remote_wakeup = false;
}

bool usbt_dcd_ep_open(uint8_t ep_addr) {
    return s_ep[ep_slot(ep_addr)].open;
}

bool usbt_dcd_ep_stalled(uint8_t ep_addr) {
    return s_ep[ep_slot(ep_addr)].stalled;
}

bool usbt_dcd_ep_pending(uint8_t ep_addr) {
    return s_ep[ep_slot(ep_addr)].pending;
}

uint8_t usbt_dcd_in_pid(uint8_t ep_addr) {
    const usbt_ep_t *ep = &s_ep[ep_slot(ep_addr)];
    return ep->pkt_pid[ep->next_buf];
}

uint8_t usbt_dcd_address(void) {
    return s_address;
}

bool usbt_dcd_connected(void) {
    return s_connected;
}

// Fill one of the endpoint's buffers out of the driver's, and say how much went
// in.  The part's prepare_ep_buffer.
static uint16_t ep_prepare(usbt_ep_t *ep, unsigned buf_id) {
    uint32_t left = (uint32_t)(ep->total - ep->moved - ep->latched);
    uint32_t want = left < ep->packet_max ? left : ep->packet_max;

    if (ep->ff != NULL) {
        want = tu_fifo_read_n(ep->ff, ep->pkt[buf_id], (uint16_t)want);
    } else if (ep->buf != NULL) {
        memcpy(ep->pkt[buf_id], ep->buf + ep->moved + ep->latched, want);
    } else {
        want = 0;
    }
    ep->pkt_len[buf_id] = (uint16_t)want;
    ep->pkt_pid[buf_id] = ep->next_pid;
    ep->next_pid ^= 1u;
    return (uint16_t)want;
}

// Arm the endpoint, which is what starting a device to host transfer does and
// what finishing a pair does again.  The part's hw_endpoint_start_next_buffer:
// the first buffer always, the second where a packet is still owed after it.
static void ep_latch(usbt_ep_t *ep) {
    ep->next_buf = 0;
    ep->armed    = 0;
    ep->latched  = 0;

    ep->latched = (uint16_t)(ep->latched + ep_prepare(ep, 0));
    ep->armed++;

    if (!ep->single && (uint32_t)(ep->total - ep->moved - ep->latched) > 0) {
        ep->latched = (uint16_t)(ep->latched + ep_prepare(ep, 1));
        ep->armed++;
    }
}

uint32_t usbt_dcd_take_in(uint8_t ep_addr, uint8_t *out, uint32_t max) {
    usbt_ep_t *ep = &s_ep[ep_slot(ep_addr)];
    if (!ep->pending) {
        return 0;
    }

    // One packet at a time, as a bus moves them, and it is a packet the
    // endpoint latched when the transfer was armed.  A transfer longer than a
    // packet therefore takes several calls, which is what makes the device's
    // refill path run rather than being handed the whole thing at once.
    if (ep->armed == 0) {
        return 0;
    }
    uint32_t take = ep->pkt_len[ep->next_buf];
    if (take > max) {
        take = max;
    }
    memcpy(out, ep->pkt[ep->next_buf], take);
    ep->moved   = (uint16_t)(ep->moved + take);
    ep->latched = (uint16_t)(ep->latched - ep->pkt_len[ep->next_buf]);
    ep->next_buf++;
    ep->armed--;

    // A short packet ends the transfer wherever it falls, a zero length one
    // included.  It cannot fall on the first of a pair: the second is armed
    // only where a whole packet went into the first.
    const bool short_packet = take < ep->packet_max;

    // The other half of a pair is taken before the device hears anything.  The
    // part raises one completion for the two, which is what it is told to do by
    // EP_CTRL_INTERRUPT_PER_DOUBLE_BUFFER as the pair is armed.
    if (ep->armed > 0 && !short_packet) {
        return take;
    }

    if (ep->moved >= ep->total || short_packet) {
        uint16_t moved = ep->moved;
        ep->pending = false;
        ep->buf     = NULL;
        ep->ff      = NULL;
        ep->armed   = 0;
        ep->latched = 0;
        dcd_event_xfer_complete(USBT_RHPORT, ep_addr, moved, XFER_RESULT_SUCCESS,
                                false);
    } else {
        ep_latch(ep);
    }

    return take;
}

uint32_t usbt_dcd_give_out(uint8_t ep_addr, const uint8_t *in, uint32_t len) {
    usbt_ep_t *ep = &s_ep[ep_slot(ep_addr)];
    if (!ep->pending) {
        return 0;
    }

    uint32_t room = (uint32_t)(ep->total - ep->moved);
    uint32_t give = len < room ? len : room;

    if (give > 0) {
        if (ep->ff != NULL) {
            give = tu_fifo_write_n(ep->ff, in, (uint16_t)give);
        } else if (ep->buf != NULL) {
            memcpy(ep->buf + ep->moved, in, give);
        }
    }
    ep->moved = (uint16_t)(ep->moved + give);

    if (ep->moved >= ep->total || len < ep->packet_max) {
        uint16_t moved = ep->moved;
        ep->pending = false;
        ep->buf     = NULL;
        ep->ff      = NULL;
        dcd_event_xfer_complete(USBT_RHPORT, ep_addr, moved, XFER_RESULT_SUCCESS,
                                false);
    }

    return give;
}

void usbt_dcd_setup(const uint8_t setup[8]) {
    // A SETUP packet clears a stall on the control endpoint, as the hardware
    // does, so a device that stalled one request can answer the next.
    s_ep[ep_slot(0x00u)].stalled = false;
    s_ep[ep_slot(0x80u)].stalled = false;
    dcd_event_setup_received(USBT_RHPORT, setup, false);
}

void usbt_dcd_bus_reset(void) {
    usbt_dcd_reset();
    dcd_event_bus_reset(USBT_RHPORT, TUSB_SPEED_FULL, false);
}

// ---------------------------------------------------------------------------
// tinyusb's device controller interface
// ---------------------------------------------------------------------------

bool dcd_init(uint8_t rhport, const tusb_rhport_init_t *rh_init) {
    (void)rhport;
    (void)rh_init;
    usbt_dcd_reset();
    return true;
}

// usbd calls this first when the stack is torn down, and abandons the teardown
// if it fails — which is what its weak stub does.  Without a real one here
// tud_deinit returns before it deinitialises the class drivers or clears the
// device's own state, so tusb_init afterwards finds the stack still initialised
// and skips it, and a scenario runs against the previous scenario's device.
bool dcd_deinit(uint8_t rhport) {
    (void)rhport;
    usbt_dcd_reset();
    return true;
}

void dcd_int_enable(uint8_t rhport) {
    (void)rhport;  // nothing interrupts here — the host advances the model
}

void dcd_int_disable(uint8_t rhport) {
    (void)rhport;
}

void dcd_set_address(uint8_t rhport, uint8_t dev_addr) {
    s_address = dev_addr;

    // The device answers the status stage of SET_ADDRESS at its old address,
    // which tinyusb expects to complete before it moves on.
    dcd_edpt_xfer(rhport, 0x80u, NULL, 0, false);
}

void dcd_remote_wakeup(uint8_t rhport) {
    (void)rhport;
    s_remote_wakeup = true;
}

void dcd_connect(uint8_t rhport) {
    (void)rhport;
    s_connected = true;
}

void dcd_disconnect(uint8_t rhport) {
    (void)rhport;
    s_connected = false;
}

void dcd_sof_enable(uint8_t rhport, bool en) {
    (void)rhport;
    s_sof_enabled = en;
}

void dcd_edpt0_status_complete(uint8_t rhport,
                               tusb_control_request_t const *request) {
    (void)rhport;
    (void)request;
}

bool dcd_edpt_open(uint8_t rhport, tusb_desc_endpoint_t const *desc_ep) {
    (void)rhport;
    usbt_ep_t *ep = &s_ep[ep_slot(desc_ep->bEndpointAddress)];
    ep->open       = true;
    ep->stalled    = false;
    ep->pending    = false;
    ep->packet_max = (uint16_t)tu_edpt_packet_size(desc_ep);

    // An endpoint the host has just configured is at DATA0 in both directions.
    ep->next_pid = 0;
    return true;
}

void dcd_edpt_close_all(uint8_t rhport) {
    (void)rhport;
    for (unsigned i = 0; i < USBT_EP_SLOTS; i++) {
        s_ep[i].open    = false;
        s_ep[i].pending = false;
    }
}

bool dcd_edpt_xfer(uint8_t rhport, uint8_t ep_addr, uint8_t *buffer,
                   uint16_t total_bytes, bool is_isr) {
    (void)rhport;
    (void)is_isr;
    usbt_ep_t *ep = &s_ep[ep_slot(ep_addr)];

    ep->pending = true;
    ep->buf     = buffer;
    ep->ff      = NULL;
    ep->total   = total_bytes;
    ep->moved   = 0;

    // Endpoint 0 is never opened by a descriptor, so it has no packet size of
    // its own until one is given here.
    if (ep->packet_max == 0) {
        ep->packet_max = CFG_TUD_ENDPOINT0_SIZE;
    }

    ep->single = (tu_edpt_number(ep_addr) == 0u);
    if (ep_addr & 0x80u) {
        ep_latch(ep);
    }

    return true;
}

// The FIFO form of the above.  usbd falls back to a weak stub that always
// fails when a port does not define this, which is not a failure any caller
// expects: picobootx's vendor driver opens its streams with no endpoint buffer,
// so every one of its transfers arrives here, and vendord_open refuses the
// configuration outright if the first one does not start.
bool dcd_edpt_xfer_fifo(uint8_t rhport, uint8_t ep_addr, tu_fifo_t *ff,
                        uint16_t total_bytes, bool is_isr) {
    (void)rhport;
    (void)is_isr;
    usbt_ep_t *ep = &s_ep[ep_slot(ep_addr)];

    ep->pending = true;
    ep->buf     = NULL;
    ep->ff      = ff;
    ep->total   = total_bytes;
    ep->moved   = 0;

    if (ep->packet_max == 0) {
        ep->packet_max = CFG_TUD_ENDPOINT0_SIZE;
    }

    ep->single = (tu_edpt_number(ep_addr) == 0u);
    if (ep_addr & 0x80u) {
        ep_latch(ep);
    }

    return true;
}

void dcd_edpt_stall(uint8_t rhport, uint8_t ep_addr) {
    (void)rhport;
    usbt_ep_t *ep = &s_ep[ep_slot(ep_addr)];
    ep->stalled = true;

    // A stalled endpoint drops whatever was queued on it, the latched packets
    // included.  Leaving either in place would let a later host read take bytes
    // the device abandoned.  The toggle is left where it stands, which is what
    // the part does - writing STALL over the buffer control word touches no
    // shadow - and it is why a stall alone cannot stand in for a withdrawal.
    ep->pending = false;
    ep->buf     = NULL;
    ep->ff      = NULL;
    ep->armed   = 0;
    ep->latched = 0;
}

bool dcd_edpt_abort_xfer(uint8_t rhport, uint8_t ep_addr) {
    (void)rhport;
    usbt_ep_t *ep = &s_ep[ep_slot(ep_addr)];
    if (!ep->pending) {
        return false;
    }

    // The fields a stall drops, and for the same reason: a packet the device
    // took back must not be there for a later host read to take.
    //
    // And the toggle each withdrawn packet took as it was filled goes back.  By
    // the parity of what is still armed, not by one - the host may have taken
    // the first of a pair already, and a packet it has had is not one to
    // renumber.
    ep->next_pid ^= (uint8_t)(ep->armed & 1u);

    ep->pending = false;
    ep->buf     = NULL;
    ep->ff      = NULL;
    ep->armed   = 0;
    ep->latched = 0;
    return true;
}

void dcd_edpt_clear_stall(uint8_t rhport, uint8_t ep_addr) {
    (void)rhport;
    usbt_ep_t *ep = &s_ep[ep_slot(ep_addr)];
    ep->stalled = false;

    // CLEAR_FEATURE(ENDPOINT_HALT) leaves the endpoint at DATA0, which the host
    // has done to itself as it sent the request.  USB 2.0 9.4.5.
    ep->next_pid = 0;
}

// The fork's own clear, and the whole of what makes it different: the halt goes
// and the data toggle stays.  picobootx unhalts an endpoint from INTERFACE
// RESET, where the host has cleared nothing and its own toggle has not moved,
// so a clear that reset the device's would lose the next packet.
void dcd_edpt_clear_stall_soft(uint8_t rhport, uint8_t ep_addr) {
    (void)rhport;
    s_ep[ep_slot(ep_addr)].stalled = false;
}

// ---------------------------------------------------------------------------
// Interfaces tinyusb requires a port to define, which this model has no use for
//
// usbd references all of these unconditionally, so a port has to supply them
// whether or not its hardware has anything to do.  There is no isochronous
// endpoint in a picoboot device and nothing interrupts this model.
// ---------------------------------------------------------------------------

bool dcd_edpt_iso_alloc(uint8_t rhport, uint8_t ep_addr,
                        uint16_t largest_packet_size) {
    (void)rhport;
    (void)ep_addr;
    (void)largest_packet_size;
    return false;
}

bool dcd_edpt_iso_activate(uint8_t rhport, tusb_desc_endpoint_t const *desc_ep) {
    (void)rhport;
    (void)desc_ep;
    return false;
}

void dcd_int_handler(uint8_t rhport) {
    (void)rhport;
}
