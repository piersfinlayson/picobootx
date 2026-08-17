// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// A model of a USB host, driving the device controller in usbt_dcd.c.
//
// It does what a host controller does and no more: put a SETUP packet on the
// wire, move data packets in whichever direction the request asked for, and
// finish with a status stage.  It makes no decisions about picoboot — a
// scenario says what the host did, and the assertions are about what the device
// did in reply.
//
// Everything here runs tud_task() between steps.  On a device that work happens
// because an interrupt queued an event and the main loop drained it.  Here the
// host is the only thing that moves time, so a step that does not pump leaves
// the device with an event it has not seen.

#include <string.h>

#include "tusb.h"
#include "usbt.h"
#include "usbt_dcd.h"

// Most passes of tud_task() one step may take.  Generous: it only bites when
// the device would never settle, which is a defect rather than a slow machine.
#define USBT_PUMP_MAX 64u

#define USBT_EP0_OUT 0x00u
#define USBT_EP0_IN  0x80u

static bool s_last_in_was_zlp;

// The clock tinyusb reads.  It moves only when a scenario moves it, so a
// scenario that cares about elapsed time says so rather than depending on how
// long the machine took.
static uint32_t s_millis;

uint32_t tusb_time_millis_api(void) {
    return s_millis;
}

void usbt_advance_ms(uint32_t ms) {
    s_millis += ms;
    usbt_settle();
}

// Let the device run until it stops producing work.  tud_task() drains one
// event at a time, and handling one can queue another — a transfer completing
// makes the class driver start the next — so it is called until a pass changes
// nothing that matters.
void usbt_settle(void) {
    for (unsigned i = 0; i < USBT_PUMP_MAX; i++) {
        tud_task();
        usbt_app_task();
    }
}

void usbt_begin(void) {
    // Every scenario gets a device that has just been plugged in.  tinyusb
    // holds its state in file statics, so without tearing the stack down first
    // a second scenario would run against whatever the previous one left —
    // including the vendor driver's stream buffers and endpoint bookkeeping.
    if (tusb_inited()) {
        tusb_deinit(USBT_RHPORT);
    }

    pbt_device_reset();
    usbt_app_reset();
    usbt_two_interfaces(false);
    usbt_dcd_reset();
    s_last_in_was_zlp = false;
    s_millis          = 0;

    tusb_rhport_init_t init = {
        .role  = TUSB_ROLE_DEVICE,
        .speed = TUSB_SPEED_FULL,
    };
    tusb_init(USBT_RHPORT, &init);
    usbt_settle();
}

void usbt_bus_reset(void) {
    usbt_dcd_bus_reset();
    usbt_settle();
}

// ---------------------------------------------------------------------------
// Control transfers
// ---------------------------------------------------------------------------

// Whether the device has refused the control endpoint in either direction.  A
// stall on either is the device refusing the request as a whole, which is what
// a host sees.
static bool ctrl_stalled(void) {
    return usbt_dcd_ep_stalled(USBT_EP0_IN) || usbt_dcd_ep_stalled(USBT_EP0_OUT);
}

usbt_ctrl_result_t usbt_control(uint8_t bmRequestType, uint8_t bRequest,
                                uint16_t wValue, uint16_t wIndex,
                                const uint8_t *buf, uint16_t buf_len,
                                uint16_t wLength) {
    usbt_ctrl_result_t result = { .ok = false, .len = 0 };

    const uint8_t setup[8] = {
        bmRequestType,
        bRequest,
        (uint8_t)(wValue & 0xFFu),  (uint8_t)(wValue >> 8),
        (uint8_t)(wIndex & 0xFFu),  (uint8_t)(wIndex >> 8),
        (uint8_t)(wLength & 0xFFu), (uint8_t)(wLength >> 8),
    };

    usbt_dcd_setup(setup);
    usbt_settle();

    if (ctrl_stalled()) {
        return result;
    }

    const bool device_to_host = (bmRequestType & 0x80u) != 0u;

    if (wLength > 0 && device_to_host) {
        // Read packets until the device finishes the transfer, which it does
        // either by producing everything asked for or by offering a short
        // packet.  usbt_dcd_take_in reports the completion for us.
        for (unsigned i = 0; i < USBT_PUMP_MAX; i++) {
            if (!usbt_dcd_ep_pending(USBT_EP0_IN)) {
                break;
            }

            uint8_t   packet[USBT_PACKET_MAX];
            uint32_t  room = (uint32_t)(sizeof(result.data) - result.len);
            uint32_t  took = usbt_dcd_take_in(USBT_EP0_IN, packet,
                                              room < sizeof(packet)
                                                  ? room : sizeof(packet));
            if (took > 0) {
                memcpy(result.data + result.len, packet, took);
                result.len += took;
            }
            usbt_settle();

            if (ctrl_stalled()) {
                return result;
            }
            if (took == 0) {
                break;
            }
        }

        // The host acknowledges by sending a zero length OUT.
        usbt_dcd_give_out(USBT_EP0_OUT, NULL, 0);
        usbt_settle();
    } else if (wLength > 0) {
        uint32_t sent = 0;
        while (sent < buf_len) {
            uint32_t chunk = buf_len - sent;
            if (chunk > USBT_PACKET_MAX) {
                chunk = USBT_PACKET_MAX;
            }
            if (usbt_dcd_give_out(USBT_EP0_OUT, buf + sent, chunk) == 0) {
                break;
            }
            sent += chunk;
            usbt_settle();

            if (ctrl_stalled()) {
                return result;
            }
        }

        // The device acknowledges with a zero length IN.
        uint8_t discard[USBT_PACKET_MAX];
        usbt_dcd_take_in(USBT_EP0_IN, discard, sizeof(discard));
        usbt_settle();
    } else {
        // No data stage, so the status stage is the whole of the reply.
        uint8_t discard[USBT_PACKET_MAX];
        usbt_dcd_take_in(USBT_EP0_IN, discard, sizeof(discard));
        usbt_settle();
    }

    result.ok = !ctrl_stalled();
    return result;
}

usbt_ctrl_result_t usbt_get_descriptor(uint8_t type, uint8_t index,
                                       uint16_t wLength) {
    return usbt_control(TUSB_DIR_IN_MASK | TUSB_REQ_RCPT_DEVICE |
                            (TUSB_REQ_TYPE_STANDARD << 5),
                        TUSB_REQ_GET_DESCRIPTOR,
                        (uint16_t)((type << 8) | index), 0,
                        NULL, 0, wLength);
}

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

bool usbt_enumerate(void) {
    usbt_bus_reset();

    // Each step says which one it was.  A host that cannot enumerate a device
    // is told nothing by "enumeration failed", and neither is a reader of this
    // suite's output.
    usbt_ctrl_result_t r = usbt_get_descriptor(TUSB_DESC_DEVICE, 0,
                                               sizeof(tusb_desc_device_t));
    if (!r.ok || r.len != sizeof(tusb_desc_device_t)) {
        pbt_fail(__FILE__, __LINE__,
                 "GET_DESCRIPTOR(device): ok %d, %u bytes of %zu",
                 (int)r.ok, r.len, sizeof(tusb_desc_device_t));
        return false;
    }

    r = usbt_control(TUSB_REQ_RCPT_DEVICE | (TUSB_REQ_TYPE_STANDARD << 5),
                     TUSB_REQ_SET_ADDRESS, USBT_ADDR_ASSIGNED, 0, NULL, 0, 0);
    if (!r.ok) {
        pbt_fail(__FILE__, __LINE__, "SET_ADDRESS was refused");
        return false;
    }

    // A real host reads the configuration descriptor twice — once for its
    // length, then in full.  Both are done here because a device that answers
    // the short read wrongly is a device picotool cannot enumerate.
    r = usbt_get_descriptor(TUSB_DESC_CONFIGURATION, 0,
                            sizeof(tusb_desc_configuration_t));
    if (!r.ok || r.len != sizeof(tusb_desc_configuration_t)) {
        pbt_fail(__FILE__, __LINE__,
                 "GET_DESCRIPTOR(configuration, header): ok %d, %u bytes",
                 (int)r.ok, r.len);
        return false;
    }

    const tusb_desc_configuration_t *cfg =
        (const tusb_desc_configuration_t *)r.data;
    uint16_t total = cfg->wTotalLength;

    r = usbt_get_descriptor(TUSB_DESC_CONFIGURATION, 0, total);
    if (!r.ok || r.len != total) {
        pbt_fail(__FILE__, __LINE__,
                 "GET_DESCRIPTOR(configuration, %u bytes): ok %d, got %u",
                 total, (int)r.ok, r.len);
        return false;
    }

    r = usbt_control(TUSB_REQ_RCPT_DEVICE | (TUSB_REQ_TYPE_STANDARD << 5),
                     TUSB_REQ_SET_CONFIGURATION, USBT_CONFIG_VALUE, 0,
                     NULL, 0, 0);
    if (!r.ok) {
        pbt_fail(__FILE__, __LINE__, "SET_CONFIGURATION was refused");
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Bulk transfers
// ---------------------------------------------------------------------------

bool usbt_bulk_out(const uint8_t *buf, uint32_t len) {
    if (usbt_dcd_ep_stalled(USBT_EP_OUT)) {
        return false;
    }

    uint32_t sent = 0;
    do {
        uint32_t chunk = len - sent;
        if (chunk > USBT_PACKET_MAX) {
            chunk = USBT_PACKET_MAX;
        }

        if (!usbt_dcd_ep_pending(USBT_EP_OUT)) {
            // The device has nothing queued to receive into, so the packet
            // would be NAKed on a bus.  Let it catch up, then give up rather
            // than spinning.
            usbt_settle();
            if (!usbt_dcd_ep_pending(USBT_EP_OUT)) {
                return false;
            }
        }

        usbt_dcd_give_out(USBT_EP_OUT, buf + sent, chunk);
        sent += chunk;
        usbt_settle();

        // A device that refuses what it has just been given halts the endpoint
        // afterwards.  The bytes it took stay taken — on a bus the host learns
        // of the halt from the next transaction, not the one that was accepted
        // — so a halt ends the send rather than unsaying it.  Only bytes still
        // unsent are lost, and that is what the return value reports.
        if (usbt_dcd_ep_stalled(USBT_EP_OUT)) {
            break;
        }
    } while (sent < len);

    return sent == len;
}

uint32_t usbt_bulk_in(uint8_t *buf, uint32_t len) {
    s_last_in_was_zlp = false;

    if (usbt_dcd_ep_stalled(USBT_EP_IN)) {
        return 0;
    }

    usbt_settle();
    if (!usbt_dcd_ep_pending(USBT_EP_IN)) {
        return 0;
    }

    uint32_t got = 0;
    for (unsigned i = 0; i < USBT_PUMP_MAX; i++) {
        uint8_t  packet[USBT_PACKET_MAX];
        uint32_t room = len - got;
        if (room > sizeof(packet)) {
            room = sizeof(packet);
        }

        uint32_t took = usbt_dcd_take_in(USBT_EP_IN, packet, room);
        if (took > 0) {
            memcpy(buf + got, packet, took);
            got += took;
        }
        usbt_settle();

        // A packet shorter than the maximum ends the transfer, and a zero
        // length one is the shortest of those.  The protocol gives it meaning,
        // so it is recorded rather than lost among "no bytes arrived".
        if (took < USBT_PACKET_MAX) {
            s_last_in_was_zlp = (got == 0);
            break;
        }
        if (got >= len || !usbt_dcd_ep_pending(USBT_EP_IN)) {
            break;
        }
    }

    return got;
}

bool usbt_bulk_in_zlp(void) {
    return s_last_in_was_zlp;
}

// ---------------------------------------------------------------------------
// Endpoint state
// ---------------------------------------------------------------------------

bool usbt_ep_halted(uint8_t ep_addr) {
    return usbt_dcd_ep_stalled(ep_addr);
}

bool usbt_clear_halt(uint8_t ep_addr) {
    usbt_ctrl_result_t r =
        usbt_control(TUSB_REQ_RCPT_ENDPOINT | (TUSB_REQ_TYPE_STANDARD << 5),
                     TUSB_REQ_CLEAR_FEATURE, TUSB_REQ_FEATURE_EDPT_HALT,
                     ep_addr, NULL, 0, 0);
    return r.ok;
}

