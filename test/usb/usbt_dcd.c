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
// The model is deliberately thin.  An endpoint holds at most one queued
// transfer — the buffer tinyusb handed over and how much of it has moved — and
// a stall flag.  The host in usbt_host.c satisfies a queued transfer and the
// completion is reported back through dcd_event_xfer_complete, which is what a
// controller's interrupt would do.  Nothing here decides anything about the
// protocol.  It moves bytes and records state a host could observe.

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

    // The transfer tinyusb has queued, if any.  buf is tinyusb's own memory —
    // the model never copies it aside, because a controller would not.
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

uint8_t usbt_dcd_address(void) {
    return s_address;
}

bool usbt_dcd_connected(void) {
    return s_connected;
}

uint32_t usbt_dcd_take_in(uint8_t ep_addr, uint8_t *out, uint32_t max) {
    usbt_ep_t *ep = &s_ep[ep_slot(ep_addr)];
    if (!ep->pending) {
        return 0;
    }

    // One packet at a time, as a bus moves them.  A transfer longer than a
    // packet therefore takes several calls, which is what makes the device's
    // refill path run rather than being handed the whole thing at once.
    uint32_t left = (uint32_t)(ep->total - ep->moved);
    uint32_t take = left < ep->packet_max ? left : ep->packet_max;
    if (take > max) {
        take = max;
    }

    if (take > 0) {
        if (ep->ff != NULL) {
            take = tu_fifo_read_n(ep->ff, out, (uint16_t)take);
        } else if (ep->buf != NULL) {
            memcpy(out, ep->buf + ep->moved, take);
        }
    }
    ep->moved = (uint16_t)(ep->moved + take);

    // A transfer finishes when it has all moved, or when the device offered
    // less than a full packet — which is how a short packet, a zero length one
    // included, terminates one.
    if (ep->moved >= ep->total || take < ep->packet_max) {
        uint16_t moved = ep->moved;
        ep->pending = false;
        ep->buf     = NULL;
        ep->ff      = NULL;
        dcd_event_xfer_complete(USBT_RHPORT, ep_addr, moved, XFER_RESULT_SUCCESS,
                                false);
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

    return true;
}

void dcd_edpt_stall(uint8_t rhport, uint8_t ep_addr) {
    (void)rhport;
    usbt_ep_t *ep = &s_ep[ep_slot(ep_addr)];
    ep->stalled = true;

    // A stalled endpoint drops whatever was queued on it.  Leaving the transfer
    // in place would let a later host read take bytes the device abandoned.
    ep->pending = false;
    ep->buf     = NULL;
    ep->ff      = NULL;
}

void dcd_edpt_clear_stall(uint8_t rhport, uint8_t ep_addr) {
    (void)rhport;
    s_ep[ep_slot(ep_addr)].stalled = false;
}

// ---------------------------------------------------------------------------
// Interfaces tinyusb requires a port to define, which this model has no use for
//
// usbd references all of these unconditionally, so a port has to supply them
// whether or not its hardware has anything to do.  There is no isochronous
// endpoint in a picoboot device, nothing interrupts this model, and a soft
// clear differs from a real one only in leaving the data toggle alone, which
// nothing here tracks.
// ---------------------------------------------------------------------------

void dcd_edpt_clear_stall_soft(uint8_t rhport, uint8_t ep_addr) {
    dcd_edpt_clear_stall(rhport, ep_addr);
}

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
