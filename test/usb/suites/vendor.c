// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// picobootx's vendor driver, on a wire.
//
// The core suite reaches the protocol through a stand-in for the transport, so
// picobootx_vendor.c never runs there at all.  Here it does: a command crosses
// a real bulk endpoint, tinyusb's stream layer moves it, and the driver's own
// stall, unstall and zero length packet handling is what answers.  Those three
// are the reason tinyusb was forked, and this is the only place they are
// exercised.

#include <string.h>

#include "pbt.h"
#include "picobootx_vendor.h"
#include "usbt.h"
#include "usbt_dcd.h"

#include "device/usbd_pvt.h"

// The vendor interface's control requests, from picobootx_private.h.  A host
// issues these on the interface rather than on an endpoint.
#define VENDOR_IN  (uint8_t)(TUSB_DIR_IN_MASK | (TUSB_REQ_TYPE_VENDOR << 5) | \
                             TUSB_REQ_RCPT_INTERFACE)
#define VENDOR_OUT (uint8_t)((TUSB_REQ_TYPE_VENDOR << 5) | TUSB_REQ_RCPT_INTERFACE)

#define REQ_INTERFACE_RESET 0x41u
#define REQ_GET_CMD_STATUS  0x42u

// Bring a device up to the point a host would start talking picoboot to it.
static bool ready(void) {
    usbt_begin();
    usbt_start_picoboot();
    return usbt_enumerate();
}

// Send a command packet over the OUT endpoint, exactly as a host does.
static bool send_cmd(const picoboot_cmd_t *cmd) {
    return usbt_bulk_out((const uint8_t *)cmd, sizeof(*cmd));
}

// Ask the device to read len bytes of its own SRAM from addr and leave the
// answer on the IN endpoint.  The caller decides whether to take it off the
// wire, which is how a scenario arms a busy IN endpoint or a full transmit
// FIFO.
static bool start_read_at(uint32_t addr, uint32_t len) {
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_READ | PICOBOOT_DIR_IN,
                                 sizeof(pb_addr_size_args_t), len);
    pbt_args_addr_size(&cmd, addr, len);
    if (!send_cmd(&cmd)) {
        return false;
    }
    usbt_settle();
    return true;
}

// The same, from the bottom of SRAM.
static bool start_read(uint32_t len) {
    return start_read_at(RP2350_SRAM_BASE, len);
}

// Take everything the device has queued on the IN endpoint, until nothing is
// left in flight.  A scenario that armed a busy endpoint uses this to put it
// back to idle, so that what it asserts next is about an endpoint that is free.
static void drain_in(void) {
    uint8_t buf[USBT_XFER_MAX];
    for (unsigned i = 0; i < 16u && usbt_dcd_ep_pending(USBT_EP_IN); i++) {
        (void)usbt_bulk_in(buf, sizeof(buf));
        usbt_settle();
    }
}

// A command the device cannot serve, so it refuses it and halts both endpoints.
static picoboot_cmd_t unservable_read(void) {
    // An address no range owns, so the device refuses rather than reading.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_READ | PICOBOOT_DIR_IN,
                                 sizeof(pb_addr_size_args_t), 4u);
    pbt_args_addr_size(&cmd, 0xDEAD0000u, 4u);
    return cmd;
}

// Ask the device what became of the last command.
static pb_status_t cmd_status(void) {
    picoboot_status_t status;
    memset(&status, 0, sizeof(status));

    usbt_ctrl_result_t r = usbt_control(VENDOR_IN, REQ_GET_CMD_STATUS, 0, 0,
                                        NULL, 0, sizeof(status));
    if (!r.ok || r.len != sizeof(status)) {
        pbt_fail(__FILE__, __LINE__,
                 "GET_COMMAND_STATUS: ok %d, %u bytes of %zu",
                 (int)r.ok, r.len, sizeof(status));
        return PB_STATUS_UNKNOWN_ERROR;
    }

    memcpy(&status, r.data, sizeof(status));
    return (pb_status_t)status.status_code;
}

// A command with no data phase is acknowledged on the IN endpoint, with a
// packet shorter than the maximum — which is what ends a transfer.  The
// acknowledgement carries a single zero byte: tinyusb's stream layer will not
// start a transfer from an empty FIFO, so picoboot_vendor_send_zlp writes one
// byte to have something to send.  That is the shipped behaviour, and this
// pins it, so a change to how the acknowledgement is produced is visible here.
static void scenario_command_acknowledged(void) {
    PBT_REQUIRE(ready());

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_EXIT_XIP, 0, 0);
    PBT_REQUIRE(send_cmd(&cmd));

    uint8_t  buf[USBT_PACKET_MAX];
    uint32_t got = usbt_bulk_in(buf, sizeof(buf));

    PBT_CHECK_EQ(got, 1);
    PBT_CHECK_EQ(buf[0], 0);
    PBT_CHECK_STATUS(cmd_status(), PB_STATUS_OK);

    // Neither endpoint was refused, which is what tells a command that
    // succeeded apart from one the device rejected.
    PBT_CHECK(!usbt_ep_halted(USBT_EP_OUT));
    PBT_CHECK(!usbt_ep_halted(USBT_EP_IN));
}

// A device-to-host command puts its payload on the IN endpoint.
static void scenario_read_returns_data(void) {
    PBT_REQUIRE(ready());

    const uint32_t len = 32u;
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_READ | PICOBOOT_DIR_IN,
                                 sizeof(pb_addr_size_args_t), len);
    pbt_args_addr_size(&cmd, RP2350_SRAM_BASE, len);
    PBT_REQUIRE(send_cmd(&cmd));

    uint8_t  buf[USBT_XFER_MAX];
    uint32_t got = usbt_bulk_in(buf, len);

    PBT_CHECK_EQ(got, len);
    PBT_CHECK_STATUS(cmd_status(), PB_STATUS_OK);

    // What arrived is what the device model holds, so a driver that moved the
    // wrong bytes, or the right count of the wrong bytes, fails here.
    PBT_CHECK(memcmp(buf, pbt_sram(), len) == 0);
}

// A refused command halts both endpoints.  A host cannot then send anything
// until it clears them, which is the state INTERFACE RESET exists to leave.
static void scenario_refusal_halts_both_endpoints(void) {
    PBT_REQUIRE(ready());

    picoboot_cmd_t cmd = unservable_read();
    PBT_REQUIRE(send_cmd(&cmd));

    usbt_settle();

    PBT_CHECK(usbt_ep_halted(USBT_EP_OUT));
    PBT_CHECK(usbt_ep_halted(USBT_EP_IN));

    // The halted endpoint refuses the next command outright, which is what
    // makes the halt matter to a host.  The refused command was itself taken in
    // full before the device halted, so without this a halt that stopped
    // nothing would look the same.
    picoboot_cmd_t next = pbt_cmd(PB_CMD_EXIT_XIP, 0, 0);
    PBT_CHECK(!send_cmd(&next));

    // The status survives the halt, which is how a host finds out why.  An
    // address inside no region is refused as INVALID_ARG, the same answer the
    // core suite pins for a read the range check rejects.
    PBT_CHECK_STATUS(cmd_status(), PB_STATUS_INVALID_ARG);
}

// INTERFACE RESET clears both halts and returns the device to idle, so the next
// command is accepted.  This is the recovery a host performs, and it runs
// through picobootx's own control transfer handler.
static void scenario_interface_reset_recovers(void) {
    PBT_REQUIRE(ready());

    picoboot_cmd_t bad = unservable_read();
    PBT_REQUIRE(send_cmd(&bad));
    usbt_settle();
    PBT_REQUIRE(usbt_ep_halted(USBT_EP_OUT));

    usbt_ctrl_result_t r =
        usbt_control(VENDOR_OUT, REQ_INTERFACE_RESET, 0, 0, NULL, 0, 0);
    PBT_REQUIRE(r.ok);
    usbt_settle();

    PBT_CHECK(!usbt_ep_halted(USBT_EP_OUT));
    PBT_CHECK(!usbt_ep_halted(USBT_EP_IN));
    PBT_CHECK_EQ(usbt_cur_state(), PB_STATE_IDLE);

    // Discriminate against a reset that merely cleared the flags: a command
    // sent afterwards has to be accepted and answered.
    picoboot_cmd_t good = pbt_cmd(PB_CMD_EXIT_XIP, 0, 0);
    PBT_CHECK(send_cmd(&good));

    uint8_t buf[USBT_PACKET_MAX];
    PBT_CHECK_EQ(usbt_bulk_in(buf, sizeof(buf)), 1);
    PBT_CHECK_STATUS(cmd_status(), PB_STATUS_OK);
}

// CLEAR_FEATURE(ENDPOINT_HALT) is the other way a host clears a halt, and
// picobootx re-arms the endpoint when it sees one — tinyusb has already
// unstalled by the time the driver is told.
static void scenario_clear_feature_rearms_the_endpoint(void) {
    PBT_REQUIRE(ready());

    picoboot_cmd_t bad = unservable_read();
    PBT_REQUIRE(send_cmd(&bad));
    usbt_settle();
    PBT_REQUIRE(usbt_ep_halted(USBT_EP_OUT));

    PBT_CHECK(usbt_clear_halt(USBT_EP_OUT));
    PBT_CHECK(!usbt_ep_halted(USBT_EP_OUT));

    // Re-armed means a transfer is queued on it again.  Without that the
    // endpoint would be clear but deaf, and the next command would vanish.
    PBT_CHECK(usbt_dcd_ep_pending(USBT_EP_OUT));
}


// The transport's read API, on a FIFO holding a packet the protocol has not
// taken yet.  picobootx's core never calls peek or read_xfer — they are there
// for the application wrapping the driver — so this scenario is that
// application, and stands between the packet landing and the task reading it by
// holding the task off.
static void scenario_transport_reads_what_the_fifo_holds(void) {
    PBT_REQUIRE(ready());
    usbt_run_picoboot_task(false);

    // Fewer bytes than a command, so the task would discard them the moment it
    // ran.  Held off, they sit in the FIFO where the read API can see them.
    const uint8_t partial[4] = { 'p', 'i', 'c', 'o' };
    PBT_REQUIRE(usbt_bulk_out(partial, sizeof(partial)));

    PBT_CHECK_EQ(picoboot_vendor_available(), sizeof(partial));

    // Peeking does not consume: twice over, the same byte, and the count is
    // unchanged.  Reading does, which is what tells the two apart.
    uint8_t byte = 0;
    PBT_CHECK(picoboot_vendor_peek(&byte));
    PBT_CHECK_EQ(byte, partial[0]);
    byte = 0;
    PBT_CHECK(picoboot_vendor_peek(&byte));
    PBT_CHECK_EQ(byte, partial[0]);
    PBT_CHECK_EQ(picoboot_vendor_available(), sizeof(partial));

    uint8_t taken = 0;
    PBT_CHECK_EQ(picoboot_vendor_read(&taken, 1), 1);
    PBT_CHECK_EQ(taken, partial[0]);
    PBT_CHECK_EQ(picoboot_vendor_available(), sizeof(partial) - 1u);
    PBT_CHECK(picoboot_vendor_peek(&byte));
    PBT_CHECK_EQ(byte, partial[1]);

    // A transfer needs a whole packet of room in the FIFO, and the leftovers
    // deny it that, so the driver has none running and starting one is refused.
    PBT_CHECK(!usbt_dcd_ep_pending(USBT_EP_OUT));
    PBT_CHECK(!picoboot_vendor_read_xfer());
    PBT_CHECK(!usbt_dcd_ep_pending(USBT_EP_OUT));

    // Emptying the FIFO makes the room, and a transfer runs again.  Without
    // this the refusal above would look the same as an endpoint that never
    // takes anything.
    uint8_t rest[4];
    PBT_CHECK_EQ(picoboot_vendor_read(rest, sizeof(rest)), sizeof(partial) - 1u);
    PBT_CHECK_EQ(picoboot_vendor_available(), 0);
    PBT_CHECK(usbt_dcd_ep_pending(USBT_EP_OUT));

    // And the device takes a whole command again.
    usbt_run_picoboot_task(true);
    picoboot_cmd_t good = pbt_cmd(PB_CMD_EXIT_XIP, 0, 0);
    PBT_CHECK(send_cmd(&good));

    uint8_t buf[USBT_PACKET_MAX];
    PBT_CHECK_EQ(usbt_bulk_in(buf, sizeof(buf)), 1);
    PBT_CHECK_STATUS(cmd_status(), PB_STATUS_OK);
}

static void scenario_stalling_a_halted_endpoint_changes_nothing(void) {
    PBT_REQUIRE(ready());

    // Enumeration leaves the OUT endpoint armed and clear, which is the state
    // the first stall has to change.
    PBT_REQUIRE(!picoboot_vendor_is_endpoint_stalled(USBT_EP_OUT));
    PBT_REQUIRE(usbt_dcd_ep_pending(USBT_EP_OUT));

    picoboot_vendor_stall_endpoint(USBT_EP_OUT);
    PBT_CHECK(picoboot_vendor_is_endpoint_stalled(USBT_EP_OUT));
    PBT_CHECK(usbt_ep_halted(USBT_EP_OUT));
    PBT_CHECK(!usbt_dcd_ep_pending(USBT_EP_OUT));

    picoboot_vendor_stall_endpoint(USBT_EP_OUT);
    PBT_CHECK(picoboot_vendor_is_endpoint_stalled(USBT_EP_OUT));
    PBT_CHECK(usbt_ep_halted(USBT_EP_OUT));
    PBT_CHECK(!usbt_dcd_ep_pending(USBT_EP_OUT));

    // The halt is not a flag that sticks: the host clears it and picobootx puts
    // the endpoint back in service, so what the two stalls left was a halt and
    // not a broken endpoint.
    PBT_CHECK(usbt_clear_halt(USBT_EP_OUT));
    PBT_CHECK(!picoboot_vendor_is_endpoint_stalled(USBT_EP_OUT));
    PBT_CHECK(usbt_dcd_ep_pending(USBT_EP_OUT));
}

// The acknowledgement is a one-byte write followed by a flush, and the flush is
// what fails when the IN endpoint is still carrying the previous answer.
static void scenario_acknowledgement_waits_for_a_busy_endpoint(void) {
    PBT_REQUIRE(ready());

    // Half a packet of payload, left on the wire.  The endpoint is carrying a
    // transfer, and the FIFO is empty because arming took its bytes.
    PBT_REQUIRE(start_read(32u));
    PBT_REQUIRE(usbt_dcd_ep_pending(USBT_EP_IN));
    PBT_REQUIRE(picoboot_vendor_write_available() == 64u);

    PBT_CHECK(!picoboot_vendor_send_zlp());

    // One byte less room than before, so the write was taken and it was the
    // flush that refused.  A busy endpoint is what refuses it, not a want of
    // room.
    PBT_CHECK_EQ(picoboot_vendor_write_available(), 63u);

    // Once the host has taken the answer the same call is accepted, and a
    // transfer is queued for the host to read.
    drain_in();
    PBT_REQUIRE(!usbt_dcd_ep_pending(USBT_EP_IN));
    PBT_CHECK(picoboot_vendor_send_zlp());
    PBT_CHECK(usbt_dcd_ep_pending(USBT_EP_IN));
}

// The acknowledgement refused because the transmit FIFO has no room at all, so
// the write fails before any flush is attempted.
//
// Filling it takes a busy endpoint.  A write of a whole packet asks the stream
// layer to flush, the flush is refused because the endpoint is still carrying
// the last one, and the bytes stay where they are - which is the only way the
// FIFO reaches its depth, since arming a transfer empties it.
static void scenario_acknowledgement_needs_room_in_the_fifo(void) {
    PBT_REQUIRE(ready());

    // Something on the wire, so the endpoint is busy and the flush below has
    // nowhere to go.
    PBT_REQUIRE(start_read(4u));
    PBT_REQUIRE(usbt_dcd_ep_pending(USBT_EP_IN));
    PBT_REQUIRE(picoboot_vendor_write_available() == 64u);

    uint8_t filler[64];
    memset(filler, 0xA5, sizeof(filler));
    PBT_REQUIRE(picoboot_vendor_write(filler, sizeof(filler)) == sizeof(filler));
    PBT_REQUIRE(picoboot_vendor_write_available() == 0);

    PBT_CHECK(!picoboot_vendor_send_zlp());

    // Still no room, so nothing was buffered - this refusal is the write's and
    // not the flush's, which is what tells it from the other one.
    PBT_CHECK_EQ(picoboot_vendor_write_available(), 0);
}

// A reply the host never took, and what INTERFACE RESET does with it.
//
// Left armed, the controller hands it to whoever reads next, and every answer
// after that belongs to the question before it.  RP2350 datasheet 5.6.5.1 has
// INTERFACE RESET abort any in-process transfer, and this is one.  The core
// suite cannot ask it: a byte queue has no armed packet in it.
static void scenario_interface_reset_takes_back_an_uncollected_reply(void) {
    PBT_REQUIRE(ready());

    // The model fills SRAM with a repeating ramp, so two addresses four bytes
    // apart answer differently.
    PBT_REQUIRE(start_read_at(RP2350_SRAM_BASE, 4u));
    PBT_REQUIRE(usbt_dcd_ep_pending(USBT_EP_IN));

    // The host that walked away, replaced by one asking for a clean start.
    usbt_ctrl_result_t r =
        usbt_control(VENDOR_OUT, REQ_INTERFACE_RESET, 0, 0, NULL, 0, 0);
    PBT_REQUIRE(r.ok);
    usbt_settle();

    PBT_CHECK(!usbt_dcd_ep_pending(USBT_EP_IN));

    // The next question has to get its own answer.  A kept packet shows up as
    // the first answer's bytes, and a toggle not put back with it as no answer
    // at all - the endpoint latched the packet and its number together.
    PBT_REQUIRE(start_read_at(RP2350_SRAM_BASE + 4u, 4u));
    uint8_t buf[USBT_XFER_MAX];
    PBT_CHECK_EQ(usbt_bulk_in(buf, 4u), 4u);
    PBT_CHECK(memcmp(buf, pbt_sram() + 4u, 4u) == 0);
}

// A host that stops part way through collecting a reply.
//
// The scenario above walks away before taking anything, and its reply is one
// packet.  Stopping inside a longer one leaves the device mid data phase with
// the OUT endpoint closed and neither endpoint halted, so the host has no halt
// to clear and INTERFACE RESET is its only remedy.
static void scenario_interface_reset_rearms_after_a_partial_reply(void) {
    PBT_REQUIRE(ready());

    // Four packets of reply, and one of them taken.
    PBT_REQUIRE(start_read_at(RP2350_SRAM_BASE, 4u * USBT_PACKET_MAX));
    uint8_t buf[USBT_XFER_MAX];
    PBT_CHECK_EQ(usbt_bulk_in(buf, USBT_PACKET_MAX), (uint32_t)USBT_PACKET_MAX);

    // Nothing for a host to clear, which is what leaves the reset carrying it.
    PBT_CHECK(!usbt_ep_halted(USBT_EP_IN));
    PBT_CHECK(!usbt_ep_halted(USBT_EP_OUT));

    usbt_ctrl_result_t r =
        usbt_control(VENDOR_OUT, REQ_INTERFACE_RESET, 0, 0, NULL, 0, 0);
    PBT_REQUIRE(r.ok);
    usbt_settle();

    // The next command going out at all is the claim.  The endpoint was closed
    // while the phase was unfinished, so the reset has to be what opens it.
    PBT_REQUIRE(start_read_at(RP2350_SRAM_BASE + 8u, 4u));
    PBT_CHECK_EQ(usbt_bulk_in(buf, 4u), 4u);
    PBT_CHECK(memcmp(buf, pbt_sram() + 8u, 4u) == 0);
}

// A command sent inside a reply the host has not finished is not taken.
//
// The device still has packets queued for the host.  The RP2350 boot ROM leaves
// its OUT endpoint closed until that phase ends, so a host that walks away and
// asks something else is refused rather than served the tail of what it left.
static void scenario_a_command_inside_an_unfinished_reply_is_not_taken(void) {
    PBT_REQUIRE(ready());

    // Four packets of reply, one taken, three still owed.
    PBT_REQUIRE(start_read_at(RP2350_SRAM_BASE, 4u * USBT_PACKET_MAX));
    uint8_t buf[USBT_XFER_MAX];
    PBT_CHECK_EQ(usbt_bulk_in(buf, USBT_PACKET_MAX), (uint32_t)USBT_PACKET_MAX);

    // The host asks something else, having put nothing right.
    PBT_CHECK(!start_read_at(RP2350_SRAM_BASE + 8u, 4u));
}

// What the device says about its own endpoints while it owes the host packets.
//
// The hardware test reads this over a control request to say why a wire behaved
// as it did, so it is asked here of a state whose shape is known.
static void scenario_the_device_reports_its_endpoints_mid_reply(void) {
    PBT_REQUIRE(ready());

    PBT_REQUIRE(start_read_at(RP2350_SRAM_BASE, 4u * USBT_PACKET_MAX));

    // A packet is armed for the host and has not been taken.
    PBT_CHECK(usbd_edpt_busy(USBT_RHPORT, USBT_EP_IN));

    // And the receive endpoint refuses to be armed, which is what the transfer
    // callback asks after every packet.
    PBT_CHECK(!picoboot_vendor_read_xfer());

    // Once the host has taken the lot and acknowledged, both go the other way.
    uint8_t buf[USBT_XFER_MAX];
    PBT_CHECK_EQ(usbt_bulk_in(buf, 4u * USBT_PACKET_MAX),
                 (uint32_t)(4u * USBT_PACKET_MAX));
    PBT_REQUIRE(usbt_bulk_out(NULL, 0));
    usbt_settle();
    PBT_CHECK(!usbd_edpt_busy(USBT_RHPORT, USBT_EP_IN));
}

static const pbt_scenario_t k_scenarios[] = {
    { "a command with no data phase is acknowledged",
      scenario_command_acknowledged },
    { "a device to host command returns its payload",
      scenario_read_returns_data },
    { "a refused command halts both endpoints",
      scenario_refusal_halts_both_endpoints },
    { "INTERFACE RESET clears the halt and the next command is served",
      scenario_interface_reset_recovers },
    { "CLEAR_FEATURE re-arms the endpoint it cleared",
      scenario_clear_feature_rearms_the_endpoint },
    { "the transport reads what the OUT FIFO is holding",
      scenario_transport_reads_what_the_fifo_holds },
    { "stalling an endpoint that is already halted changes nothing",
      scenario_stalling_a_halted_endpoint_changes_nothing },
    { "the acknowledgement waits for a busy IN endpoint",
      scenario_acknowledgement_waits_for_a_busy_endpoint },
    { "the acknowledgement needs room in the transmit FIFO",
      scenario_acknowledgement_needs_room_in_the_fifo },
    { "INTERFACE RESET takes back a reply the host never collected",
      scenario_interface_reset_takes_back_an_uncollected_reply },
    { "INTERFACE RESET re-arms after a reply the host stopped part way through",
      scenario_interface_reset_rearms_after_a_partial_reply },
    { "a command sent inside a reply the host has not finished is not taken",
      scenario_a_command_inside_an_unfinished_reply_is_not_taken },
    { "the device reports its endpoints while it owes the host packets",
      scenario_the_device_reports_its_endpoints_mid_reply },
};

PBT_SUITE(usbt_suite_vendor, "vendor", k_scenarios);
