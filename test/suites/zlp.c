// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// Packet boundaries.
//
// picobootx does not use tinyusb's stock vendor driver because that driver
// appends a zero-length packet after any transfer that fills the endpoint
// exactly, and offers no way to send one on demand.  Under the picoboot
// protocol a packet boundary carries meaning, so both of those are wrong.  What
// follows pins the boundaries the protocol depends on.

#include "pbt.h"

static picoboot_cmd_t action_command(void) {
    picoboot_cmd_t cmd = pbt_cmd(0x01u, 0x01u, 0u);
    pbt_args_exclusive_access(&cmd, PB_EA_EXCL);
    return cmd;
}

static picoboot_cmd_t sram_read(uint32_t len) {
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_READ, 0x08u, len);
    pbt_args_addr_size(&cmd, RP2350_SRAM_BASE, len);
    return cmd;
}

static void scenario_acknowledgement_is_one_zero_byte(void) {
    pbt_begin();
    pbt_start();

    picoboot_cmd_t cmd = action_command();
    pbt_host_send_cmd(&cmd);
    pbt_pump();

    // The API calls this a zero-length packet and it is not one: what goes on
    // the wire is a single zero byte.  picoboot_rx_cb accepts both forms in the
    // other direction for the same reason.  This is what ships, so this is what
    // is pinned.
    PBT_REQUIRE(pbt_packet_count() == 1u);
    PBT_CHECK_EQ(pbt_packet(0)->len, 1u);
    PBT_CHECK_EQ(pbt_packet(0)->data[0], 0u);

    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_IDLE);
}

static void scenario_acknowledgement_precedes_the_return_to_idle(void) {
    pbt_begin();
    pbt_start();

    picoboot_cmd_t cmd = action_command();
    pbt_host_send_cmd(&cmd);

    // One task call queues the acknowledgement.  Until the hardware reports it
    // gone, the device is still waiting on it.
    pbt_task();
    PBT_CHECK_EQ(pbt_packet_count(), 1u);
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_AWAIT_ZLP);

    pbt_complete_tx();
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_IDLE);
}

static void scenario_a_full_endpoint_gets_no_trailing_packet(void) {
    pbt_begin();
    pbt_start();

    // Exactly one endpoint's worth of data.  A stock vendor driver would follow
    // this with a zero-length packet, which the protocol would read as the end
    // of a different thing entirely.
    picoboot_cmd_t cmd = sram_read(64u);
    pbt_host_send_cmd(&cmd);
    pbt_pump();

    PBT_CHECK_EQ(pbt_packet_count(), 1u);
    PBT_REQUIRE(pbt_packet(0) != NULL);
    PBT_CHECK_EQ(pbt_packet(0)->len, 64u);
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_AWAIT_ACK);
}

static void scenario_two_full_endpoints_get_no_trailing_packet(void) {
    pbt_begin();
    pbt_start();

    picoboot_cmd_t cmd = sram_read(128u);
    pbt_host_send_cmd(&cmd);
    pbt_pump();

    PBT_REQUIRE(pbt_packet_count() == 2u);
    PBT_CHECK_EQ(pbt_packet(0)->len, 64u);
    PBT_CHECK_EQ(pbt_packet(1)->len, 64u);
}

static void scenario_a_partial_final_packet_carries_data(void) {
    pbt_begin();
    pbt_start();

    // One byte past a full endpoint, so the transfer really does end in a
    // one-byte packet — and that packet is data, not an acknowledgement.
    picoboot_cmd_t cmd = sram_read(65u);
    pbt_host_send_cmd(&cmd);
    pbt_pump();

    PBT_REQUIRE(pbt_packet_count() == 2u);
    PBT_CHECK_EQ(pbt_packet(0)->len, 64u);
    PBT_CHECK_EQ(pbt_packet(1)->len, 1u);
    PBT_CHECK_EQ(pbt_packet(1)->data[0], pbt_sram()[64]);
    PBT_CHECK(pbt_packet(1)->data[0] != 0u);
}

static void scenario_zero_length_acknowledgement_ends_a_transfer(void) {
    pbt_begin();
    pbt_start();

    picoboot_cmd_t cmd = sram_read(32u);
    pbt_host_send_cmd(&cmd);
    pbt_pump();
    PBT_REQUIRE(pbt_cur_state() == PB_STATE_AWAIT_ACK);

    pbt_host_ack();
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_IDLE);

    picoboot_status_t status;
    PBT_REQUIRE(pbt_ctrl_get_status(&status));
    PBT_CHECK_STATUS(status.status_code, PB_STATUS_OK);
    PBT_CHECK_EQ(status.token, cmd.token);
}

static void scenario_single_byte_acknowledgement_ends_a_transfer(void) {
    pbt_begin();
    pbt_start();

    picoboot_cmd_t cmd = sram_read(32u);
    pbt_host_send_cmd(&cmd);
    pbt_pump();
    PBT_REQUIRE(pbt_cur_state() == PB_STATE_AWAIT_ACK);

    // A host stack that cannot send a true zero-length packet sends one byte,
    // and that is accepted as the same thing.
    pbt_host_ack_byte();
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_IDLE);

    // And the byte is swallowed rather than left in front of the next command.
    PBT_CHECK_EQ(picoboot_vendor_available(), 0u);
}

static void scenario_the_next_command_also_ends_a_transfer(void) {
    pbt_begin();
    pbt_start();

    picoboot_cmd_t read = sram_read(32u);
    pbt_host_send_cmd(&read);
    pbt_pump();
    PBT_REQUIRE(pbt_cur_state() == PB_STATE_AWAIT_ACK);

    // A host that goes straight on to its next command rather than
    // acknowledging is taken to have acknowledged, and the command it sent is
    // acted on rather than discarded.
    picoboot_cmd_t next = action_command();
    pbt_host_send_cmd(&next);
    pbt_pump();

    PBT_CHECK_EQ(pbt_count("op_exclusive_access"), 1);

    picoboot_status_t status;
    PBT_REQUIRE(pbt_ctrl_get_status(&status));
    PBT_CHECK_STATUS(status.status_code, PB_STATUS_OK);
    PBT_CHECK_EQ(status.token, next.token);
}

static void scenario_reboot_starts_before_its_acknowledgement(void) {
    pbt_begin();
    pbt_start();

    // Like the RP2350 boot ROM, the reboot is set going before the
    // acknowledgement is sent.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_REBOOT2, 0x10u, 0u);
    pbt_args_reboot2(&cmd, 0x0002u, 100u, 0x11u, 0x22u);

    pbt_host_send_cmd(&cmd);

    pbt_task();
    PBT_CHECK_EQ(pbt_count("rom_reboot"), 1);
    PBT_CHECK_EQ(pbt_packet_count(), 1u);
    PBT_CHECK(pbt_before("rom_reboot", "packet_in"));
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_AWAIT_ZLP);

    // The bootrom gets the command's arguments unchanged.
    PBT_REQUIRE(pbt_nth("rom_reboot", 0) != NULL);
    PBT_CHECK_EQ(pbt_nth("rom_reboot", 0)->a0, 0x0002u);
    PBT_CHECK_EQ(pbt_nth("rom_reboot", 0)->a1, 100u);
    PBT_CHECK_EQ(pbt_nth("rom_reboot", 0)->a2, 0x11u);
    PBT_CHECK_EQ(pbt_nth("rom_reboot", 0)->a3, 0x22u);

    // Collecting the acknowledgement ends the command and doesn't reboot again.
    pbt_complete_tx();
    PBT_CHECK_EQ(pbt_count("rom_reboot"), 1);
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_IDLE);
}

static void scenario_reboot_refused_when_the_bootrom_has_no_reboot(void) {
    pbt_begin();
    pbt_bootrom_withhold('R', 'B');
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_REBOOT2, 0x10u, 0u);
    pbt_args_reboot2(&cmd, 0x0002u, 100u, 0u, 0u);

    // No acknowledgement is sent, and nothing reboots.
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_NOT_FOUND);
    PBT_CHECK_EQ(pbt_count("op_reboot2"), 1);
    PBT_CHECK_EQ(pbt_count("rom_reboot"), 0);
    PBT_CHECK_EQ(pbt_packet_count(), 0u);
}

static const pbt_scenario_t k_scenarios[] = {
    { "an acknowledgement is a single zero byte",
      scenario_acknowledgement_is_one_zero_byte },
    { "the acknowledgement is sent before the device returns to idle",
      scenario_acknowledgement_precedes_the_return_to_idle },
    { "a transfer filling the endpoint exactly gets no trailing packet",
      scenario_a_full_endpoint_gets_no_trailing_packet },
    { "two full endpoints get no trailing packet",
      scenario_two_full_endpoints_get_no_trailing_packet },
    { "a partial final packet carries data, not an acknowledgement",
      scenario_a_partial_final_packet_carries_data },
    { "a zero-length packet ends a device-to-host transfer",
      scenario_zero_length_acknowledgement_ends_a_transfer },
    { "a single byte ends a device-to-host transfer",
      scenario_single_byte_acknowledgement_ends_a_transfer },
    { "the next command ends a device-to-host transfer, and still runs",
      scenario_the_next_command_also_ends_a_transfer },
    { "a reboot starts before its acknowledgement is sent",
      scenario_reboot_starts_before_its_acknowledgement },
    { "a reboot is refused when the bootrom does not publish one",
      scenario_reboot_refused_when_the_bootrom_has_no_reboot },
};

PBT_SUITE(pbt_suite_zlp, "zlp", k_scenarios);
