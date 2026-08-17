// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// The usb suite's harness: a model of a USB host, and the device controller it
// talks to.
//
// The core suite reaches picobootx through picoboot_vendor_*, standing in for
// the transport.  This suite goes in one level lower, at tinyusb's own device
// controller interface, so real tinyusb and picobootx's real vendor driver sit
// between a scenario and the library.  A scenario therefore says what a host
// does — enumerate, issue a control request, send a bulk packet — rather than
// what the transport was asked for.

#ifndef PICOBOOTX_TEST_USBT_H
#define PICOBOOTX_TEST_USBT_H

#include <stdbool.h>
#include <stdint.h>

#include "tusb.h"
#include "pbt.h"

// Endpoints the test's descriptors declare.  The addresses are the example's,
// so what the suite enumerates is shaped like a device that ships.
#define USBT_EP_OUT   0x01u
#define USBT_EP_IN    0x81u

// The device's addresses, before and after SET_ADDRESS.
#define USBT_ADDR_DEFAULT 0u
#define USBT_ADDR_ASSIGNED 5u

#define USBT_CONFIG_VALUE 1u

// A full-speed bulk packet, and the control endpoint's size.
#define USBT_PACKET_MAX 64u

// Longest transfer a scenario may ask for in one call.
#define USBT_XFER_MAX 512u

// ---------------------------------------------------------------------------
// The host
// ---------------------------------------------------------------------------

// Put the bus and the device back to how they are before a host touches them,
// then bring tinyusb up.  Call first in every scenario.
void usbt_begin(void);

// Let the device make progress.  Runs tud_task() and lets the controller
// deliver whatever the device queued, repeatedly, until nothing more moves.
// Every host call below does this for itself, so a scenario needs it only to
// let time-free background work settle.
void usbt_settle(void);

// Initialise picobootx behind the vendor driver, with the shared default ops.
// usbt_begin does this, so a scenario calls it only to start over.
void usbt_start_picoboot(void);

// Whether usbt_settle() turns picobootx's own task.  A device runs that task
// from its application loop, so a packet reaching the vendor driver's FIFO and
// the task reading it are two separate moments, and this is how a scenario
// stands between them.  usbt_begin leaves the task running.
void usbt_run_picoboot_task(bool run);

// The library's state block, for a scenario asserting what state it is in.
pb_state_block_t *usbt_state(void);

// Move the clock tinyusb reads.  It stands still otherwise, so a scenario that
// depends on time says by how much.
void usbt_advance_ms(uint32_t ms);

// Signal a bus reset, as a host does before it addresses a device.
void usbt_bus_reset(void);

// The whole of enumeration: reset, read the device descriptor, assign an
// address, read the configuration descriptor, select the configuration.
// Returns false if any step was refused, leaving the failure recorded.
bool usbt_enumerate(void);

// ---------------------------------------------------------------------------
// Control transfers
// ---------------------------------------------------------------------------

// Result of a control transfer.
typedef struct {
    // Whether the device answered rather than stalling the request.
    bool     ok;
    // Bytes the device returned, for a device-to-host request.
    uint8_t  data[USBT_XFER_MAX];
    uint32_t len;
} usbt_ctrl_result_t;

// Issue a control transfer and run it to completion.  buf and buf_len carry the
// host-to-device payload, and are ignored for a device-to-host request, whose
// answer lands in the result.
usbt_ctrl_result_t usbt_control(uint8_t bmRequestType, uint8_t bRequest,
                                uint16_t wValue, uint16_t wIndex,
                                const uint8_t *buf, uint16_t buf_len,
                                uint16_t wLength);

// GET_DESCRIPTOR, the common case of the above.
usbt_ctrl_result_t usbt_get_descriptor(uint8_t type, uint8_t index,
                                       uint16_t wLength);

// ---------------------------------------------------------------------------
// Bulk transfers
// ---------------------------------------------------------------------------

// Send a packet to the OUT endpoint.  Returns whether every byte was delivered,
// so a device that halts the endpoint after accepting the packet — which is how
// it refuses a command — still reports true, and a host that finds the endpoint
// already halted, or that has it halted part way through, reports false.
bool usbt_bulk_out(const uint8_t *buf, uint32_t len);

// Read from the IN endpoint, up to len bytes.  Returns the number of bytes the
// device produced, which may be zero — a zero length packet is a message in
// this protocol, so it is reported through usbt_bulk_in_zlp() rather than being
// indistinguishable from nothing having arrived.
uint32_t usbt_bulk_in(uint8_t *buf, uint32_t len);

// Whether the last usbt_bulk_in() took a zero length packet off the wire.
bool usbt_bulk_in_zlp(void);

// ---------------------------------------------------------------------------
// Endpoint state, as a host can observe it
// ---------------------------------------------------------------------------

// Whether the device is refusing this endpoint.  A host discovers this from a
// transfer failing, and this is that same state read directly.
bool usbt_ep_halted(uint8_t ep_addr);

// CLEAR_FEATURE(ENDPOINT_HALT), which is how a host clears one.
bool usbt_clear_halt(uint8_t ep_addr);

// ---------------------------------------------------------------------------
// Descriptors the test presents
// ---------------------------------------------------------------------------

// The test owns these rather than borrowing the example's, because the claims
// this suite pins — the interface numbering picotool relies on, and interface 0
// carrying class 0xFF, subclass 0 and protocol 0 — are claims about descriptor
// content.  A suite asserting them should own what it asserts against.
extern const uint8_t *usbt_desc_device;
extern uint32_t       usbt_desc_device_len;
extern const uint8_t *usbt_desc_configuration;
extern uint32_t       usbt_desc_configuration_len;

// The same device with an interface behind picoboot's, which is what a device
// exposing something else alongside picoboot presents.
extern const uint8_t *usbt_desc_configuration_two;
extern uint32_t       usbt_desc_configuration_two_len;

// Which of the two configurations the device presents.  usbt_begin selects the
// one-interface one, so a scenario wanting the other says so after it.
void usbt_two_interfaces(bool two);

// The interface number the second configuration's spare driver was given, or
// -1 if it was never offered one.
int usbt_spare_interface(void);

// ---------------------------------------------------------------------------
// The suites
// ---------------------------------------------------------------------------

extern const pbt_suite_t usbt_suite_enumeration;
extern const pbt_suite_t usbt_suite_vendor;

#endif // PICOBOOTX_TEST_USBT_H
