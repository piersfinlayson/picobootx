// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// What picobootx does when the transport underneath it does not do what it was
// asked.
//
// picoboot_vendor_* is an interface picobootx offers and an integrator
// implements.  The library therefore cannot assume the transport accepts
// everything it is handed, or hands back everything it said it had, and every
// place it checks is a place a host would otherwise see as a pipe that had gone
// quiet.  These scenarios arm each refusal for one call and then show the next
// call served normally, so what is being pinned is the handling and not some
// permanent damage to the state machine.
//
// The transmit FIFO size is in here too.  It is a configuration rather than a
// fault — CFG_TUD_PICOBOOT_TX_BUFSIZE is the integrator's to choose — but it is
// the condition the fill contract's third case exists for: room for less than
// one whole item, where the fill function must write nothing, leave done clear,
// and be asked again.

#include <string.h>

#include "pbt.h"

// The GET_INFO SYS flag carrying the most words, so a transmit FIFO can be
// chosen that has room for the leading count and not for the flag's data.
#define FLAG_BOOT_INFO 0x0040u
#define FLAG_BOOT_INFO_WORDS 4u

// Reads a 32-bit word out of the payload the device sent.
static uint32_t payload_word(uint32_t index) {
    uint32_t word = 0;
    if ((index + 1u) * 4u <= pbt_payload_len()) {
        memcpy(&word, pbt_payload() + (index * 4u), sizeof(word));
    }
    return word;
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

static void scenario_a_refused_acknowledgement_stalls(void) {
    pbt_begin();
    pbt_wire_refuse_zlp();
    pbt_start();

    // EXIT_XIP has no data phase, so the acknowledgement is the whole of the
    // device's answer and refusing it is the only thing that can go wrong.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_EXIT_XIP, 0x00u, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_UNKNOWN_ERROR);

    // The command ran — what failed was telling the host it had.  A device that
    // sat in AWAIT_ZLP waiting for a completion that will never come would look
    // to the host like a pipe that had stopped answering, so it halts instead.
    PBT_CHECK_EQ(pbt_count("op_exit_xip"), 1);
    PBT_CHECK_EQ(pbt_count("zlp_refused"), 1);
    PBT_CHECK_EQ(pbt_state()->state, PB_STATE_STALLED);
    PBT_CHECK(pbt_ep_stalled(PBT_EP_OUT));
    PBT_CHECK(pbt_ep_stalled(PBT_EP_IN));
    PBT_CHECK_EQ(pbt_packet_count(), 0u);

    picoboot_status_t status;
    PBT_REQUIRE(pbt_ctrl_get_status(&status));
    PBT_CHECK_EQ(status.token, cmd.token);
    PBT_CHECK_EQ(status.cmd_id, PB_CMD_EXIT_XIP);
    PBT_CHECK_EQ(status.in_progress, 0u);

    // The refusal was armed for one call, so the same command now succeeds and
    // the acknowledgement goes out.  What stalled was the transport's answer
    // and nothing about the command.
    pbt_recover();
    picoboot_cmd_t again = pbt_cmd(PB_CMD_EXIT_XIP, 0x00u, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&again), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_packet_count(), 1u);
    PBT_REQUIRE(pbt_packet(0) != NULL);
    PBT_CHECK_EQ(pbt_packet(0)->len, 1u);
}

static void scenario_a_short_read_of_a_command_stalls(void) {
    pbt_begin();
    pbt_start();

    // A command that finishes, so the status block names something specific
    // before the short read happens.
    picoboot_cmd_t first = pbt_cmd(PB_CMD_ENTER_XIP, 0x00u, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&first), PB_STATUS_OK);

    // A full command packet arrives, and the transport then hands over half of
    // it.  Half a command cannot be dispatched and the remaining bytes are no
    // longer at a command boundary, so the library halts rather than carry on
    // reading a stream it has lost its place in.
    pbt_wire_short_read(16u);
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_READ, 0x08u, 16u);
    pbt_args_addr_size(&cmd, RP2350_SRAM_BASE, 16u);
    pbt_host_send_cmd(&cmd);
    pbt_pump();

    PBT_CHECK_EQ(pbt_count("short_read"), 1);
    PBT_CHECK_EQ(pbt_state()->state, PB_STATE_STALLED);
    PBT_CHECK_EQ(pbt_count("op_read_prepare"), 0);

    picoboot_status_t status;
    PBT_REQUIRE(pbt_ctrl_get_status(&status));
    PBT_CHECK_STATUS(status.status_code, PB_STATUS_UNKNOWN_ERROR);

    // The halt happens before the command is adopted, so the identity reported
    // is still the previous command's.  A host that matched the failure to the
    // request it had just sent would match it to the wrong one — recorded here
    // as what the library does, since it is what a host will see.
    PBT_CHECK_EQ(status.token, first.token);
    PBT_CHECK_EQ(status.cmd_id, PB_CMD_ENTER_XIP);
    PBT_CHECK(status.token != cmd.token);
    PBT_CHECK_EQ(status.in_progress, 0u);

    // Clearing the halt discards the half-command with it, and the same command
    // then runs, so what stalled was the short read.
    pbt_recover();
    PBT_CHECK_EQ(picoboot_vendor_available(), 0u);
    picoboot_cmd_t again = pbt_cmd(PB_CMD_READ, 0x08u, 16u);
    pbt_args_addr_size(&again, RP2350_SRAM_BASE, 16u);
    PBT_CHECK_STATUS(pbt_run_cmd(&again), PB_STATUS_OK);
    PBT_REQUIRE(pbt_packet_count() == 2u);
    PBT_CHECK_EQ(pbt_packet(1)->len, 16u);
    PBT_CHECK_EQ(memcmp(pbt_packet(1)->data, pbt_sram(), 16u), 0);
}

static void scenario_a_read_that_returns_nothing_is_retried(void) {
    pbt_begin();
    pbt_start();

    uint8_t data[8];
    for (unsigned i = 0; i < sizeof(data); i++) {
        data[i] = (uint8_t)(0x60u + i);
    }

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_WRITE, 0x08u, sizeof(data));
    pbt_args_addr_size(&cmd, RP2350_SRAM_BASE + 0x40u, sizeof(data));
    pbt_host_send_cmd(&cmd);
    pbt_pump();
    PBT_REQUIRE(pbt_state()->state == PB_STATE_DATA_OUT);

    // The data arrives, and the transport then says it has none of it.  Inside
    // a data phase there is nothing wrong with that — the bytes are still
    // there — so the library leaves them alone rather than treating a call that
    // produced nothing as the end of the transfer.
    pbt_wire_short_read(0u);
    pbt_host_send(data, sizeof(data));
    pbt_task();

    PBT_CHECK_EQ(pbt_count("short_read"), 1);
    PBT_CHECK_EQ(pbt_count("op_write"), 0);
    PBT_CHECK_EQ(pbt_state()->state, PB_STATE_DATA_OUT);
    PBT_CHECK_EQ(picoboot_vendor_available(), sizeof(data));
    PBT_CHECK(!pbt_ep_stalled(PBT_EP_OUT));

    // Asked again, the transport answers and the transfer finishes with all of
    // the data, in order — nothing was dropped and nothing was doubled.
    pbt_pump();
    PBT_CHECK_EQ(pbt_state()->state, PB_STATE_IDLE);
    PBT_CHECK_EQ(pbt_count("op_write"), 1);
    PBT_CHECK_EQ(memcmp(pbt_sram() + 0x40u, data, sizeof(data)), 0);
}

static void scenario_a_short_write_stalls_the_transfer(void) {
    pbt_begin();
    pbt_start();

    // The transport reported room for the whole chunk and then took half of it.
    // Sending the half would leave the host reading a transfer whose remaining
    // length no longer matches what it was promised, so the transfer halts and
    // the half is never flushed.
    pbt_wire_short_write(16u);

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_READ, 0x08u, 32u);
    pbt_args_addr_size(&cmd, RP2350_SRAM_BASE, 32u);
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_UNKNOWN_ERROR);

    PBT_CHECK_EQ(pbt_count("short_write"), 1);
    PBT_CHECK_EQ(pbt_state()->state, PB_STATE_STALLED);
    PBT_CHECK_EQ(pbt_packet_count(), 0u);

    picoboot_status_t status;
    PBT_REQUIRE(pbt_ctrl_get_status(&status));
    PBT_CHECK_EQ(status.token, cmd.token);
    PBT_CHECK_EQ(status.cmd_id, PB_CMD_READ);

    // With the transport accepting what it said it would, the same read
    // delivers all thirty-two bytes in one packet.
    pbt_recover();
    picoboot_cmd_t again = pbt_cmd(PB_CMD_READ, 0x08u, 32u);
    pbt_args_addr_size(&again, RP2350_SRAM_BASE, 32u);
    PBT_CHECK_STATUS(pbt_run_cmd(&again), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_packet_count(), 1u);
    PBT_CHECK_EQ(pbt_payload_len(), 32u);
    PBT_CHECK_EQ(memcmp(pbt_payload(), pbt_sram(), 32u), 0);
}

// ---------------------------------------------------------------------------
// Room for less than one item
// ---------------------------------------------------------------------------

static void scenario_get_info_declines_room_for_less_than_a_word(void) {
    pbt_begin();
    // Ten bytes holds two words and leaves two, which is less than the four a
    // word needs.  Two bytes of a word cannot be sent, so the fill function has
    // to decline the call and wait for the endpoint to drain.
    pbt_wire_tx_fifo(10u);
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&cmd, PB_INFO_PARTITION, 0u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);

    // All five words, in order, with the split falling where the FIFO ran out
    // rather than in the middle of a word.
    PBT_REQUIRE(pbt_payload_len() == 20u);
    const uint32_t expected[] = {
        0x00000004u, 0x00000031u, 0x00000000u, 0xffffe000u, 0xfc078000u,
    };
    for (uint32_t i = 0; i < 5u; i++) {
        PBT_CHECK_EQ(payload_word(i), expected[i]);
    }

    PBT_REQUIRE(pbt_packet_count() == 3u);
    PBT_CHECK_EQ(pbt_packet(0)->len, 8u);
    PBT_CHECK_EQ(pbt_packet(1)->len, 8u);
    PBT_CHECK_EQ(pbt_packet(2)->len, 4u);

    // With room for the whole transfer it is one packet, so the three above are
    // the FIFO's doing and not the command's.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t roomy = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&roomy, PB_INFO_PARTITION, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&roomy), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_packet_count(), 1u);
    PBT_CHECK_EQ(pbt_payload_len(), 20u);
}

static void scenario_get_info_declines_room_for_less_than_a_flag(void) {
    pbt_begin();
    // Sixteen bytes is exactly one flag's data and no more, so once the leading
    // count is in the FIFO there is not room for the flag that follows it.  A
    // flag's data cannot be split across calls — the callback produces it in
    // one piece — so the fill function declines and asks to be called again.
    pbt_wire_tx_fifo(16u);
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u,
                                 4u + (FLAG_BOOT_INFO_WORDS * 4u));
    pbt_args_get_info(&cmd, PB_INFO_SYS, FLAG_BOOT_INFO);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);

    PBT_REQUIRE(pbt_payload_len() == 20u);
    PBT_CHECK_EQ(payload_word(0), FLAG_BOOT_INFO_WORDS);
    for (uint32_t i = 0; i < FLAG_BOOT_INFO_WORDS; i++) {
        PBT_CHECK_EQ(payload_word(1u + i), pbt_sys_info_word(FLAG_BOOT_INFO) + i);
    }

    // The count went out on its own, and the flag's data followed whole.
    PBT_REQUIRE(pbt_packet_count() == 2u);
    PBT_CHECK_EQ(pbt_packet(0)->len, 4u);
    PBT_CHECK_EQ(pbt_packet(1)->len, 16u);

    // The declined call did not reach the callback and did not move the cursor
    // on, so the flag was asked for once and answered once.  A decline that
    // consulted the callback and threw the answer away would show up here as
    // two calls, and one that advanced the cursor would show up as a missing
    // flag rather than a second packet.
    PBT_CHECK_EQ(pbt_count("op_get_info_sys"), 1);
    PBT_REQUIRE(pbt_nth("op_get_info_sys", 0) != NULL);
    PBT_CHECK_EQ(pbt_nth("op_get_info_sys", 0)->a0, FLAG_BOOT_INFO);
    PBT_CHECK_EQ(pbt_nth("op_get_info_sys", 0)->a1, FLAG_BOOT_INFO_WORDS * 4u);
}

static void scenario_otp_read_declines_room_for_less_than_a_row(void) {
    pbt_begin();
    for (unsigned i = 0; i < 4u; i++) {
        pbt_otp()[i] = 0xD0D00000u | i;
    }
    // Ten bytes holds two raw rows and leaves two, which is less than a row.
    pbt_wire_tx_fifo(10u);
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_OTP_READ, 0x05u, 16u);
    pbt_args_otp(&cmd, 0u, 4u, 0u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);

    PBT_REQUIRE(pbt_payload_len() == 16u);
    for (uint32_t i = 0; i < 4u; i++) {
        PBT_CHECK_EQ(payload_word(i), 0xD0D00000u | i);
    }

    // Two packets of two whole rows each, never a row split across them.
    PBT_REQUIRE(pbt_packet_count() == 2u);
    PBT_CHECK_EQ(pbt_packet(0)->len, 8u);
    PBT_CHECK_EQ(pbt_packet(1)->len, 8u);

    // And the row cursor moved by what was actually read, so the second access
    // starts where the first left off rather than repeating it.
    PBT_CHECK_EQ(pbt_count("op_otp_read"), 2);
    PBT_REQUIRE(pbt_nth("op_otp_read", 1) != NULL);
    PBT_CHECK_EQ(pbt_nth("op_otp_read", 0)->a0, 0u);
    PBT_CHECK_EQ(pbt_nth("op_otp_read", 0)->a2, 8u);
    PBT_CHECK_EQ(pbt_nth("op_otp_read", 1)->a0, 2u);
    PBT_CHECK_EQ(pbt_nth("op_otp_read", 1)->a2, 8u);
}

static const pbt_scenario_t k_scenarios[] = {
    { "an acknowledgement the transport refuses halts the command",
      scenario_a_refused_acknowledgement_stalls },
    { "a short read of a command halts before the command is adopted",
      scenario_a_short_read_of_a_command_stalls },
    { "a read that returns nothing mid-transfer is retried, not dropped",
      scenario_a_read_that_returns_nothing_is_retried },
    { "a write the transport truncates halts the transfer",
      scenario_a_short_write_stalls_the_transfer },
    { "GET_INFO declines a call with room for less than a word",
      scenario_get_info_declines_room_for_less_than_a_word },
    { "GET_INFO declines a call with room for less than a flag",
      scenario_get_info_declines_room_for_less_than_a_flag },
    { "OTP_READ declines a call with room for less than a row",
      scenario_otp_read_declines_room_for_less_than_a_row },
};

PBT_SUITE(pbt_suite_transport, "transport", k_scenarios);
