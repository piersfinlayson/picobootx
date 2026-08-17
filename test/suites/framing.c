// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// Command framing: what makes a 32-byte packet a command picobootx will act on,
// and what it does with one that is not.

#include <string.h>

#include "pbt.h"

// A command that is valid in every respect, used as the thing each malformed
// variant is compared against.  EXCLUSIVE_ACCESS is chosen because it has no
// data phase and its default implementation accepts every defined argument, so
// nothing but the framing can decide the outcome.
static picoboot_cmd_t valid_command(void) {
    picoboot_cmd_t cmd = pbt_cmd(0x01u, 0x01u, 0u);
    pbt_args_exclusive_access(&cmd, PB_EA_EXCL);
    return cmd;
}

static void scenario_valid_command_dispatches(void) {
    pbt_begin();
    pbt_start();

    picoboot_cmd_t cmd = valid_command();
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);

    PBT_CHECK_EQ(pbt_count("op_exclusive_access"), 1);
    PBT_CHECK_EQ(pbt_nth("op_exclusive_access", 0)->a0, PB_EA_EXCL);
    PBT_CHECK_EQ(pbt_state()->state, PB_STATE_IDLE);
    PBT_CHECK(!pbt_ep_stalled(PBT_EP_OUT));
    PBT_CHECK(!pbt_ep_stalled(PBT_EP_IN));
}

static void scenario_cmd_size_mismatch_stalls(void) {
    pbt_begin();
    pbt_start();

    // The only difference from the command above is the declared size.
    picoboot_cmd_t cmd = valid_command();
    cmd.cmd_size = 0x02u;

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_INVALID_CMD_LENGTH);

    // The rejection has to happen before the command is acted on, not after.
    PBT_CHECK_EQ(pbt_count("op_exclusive_access"), 0);
    PBT_CHECK_EQ(pbt_state()->state, PB_STATE_STALLED);
}

static void scenario_action_rejects_non_zero_transfer_len(void) {
    pbt_begin();
    pbt_start();

    picoboot_cmd_t cmd = valid_command();
    cmd.transfer_len = 4u;

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_INVALID_TRANSFER_LEN);
    PBT_CHECK_EQ(pbt_count("op_exclusive_access"), 0);
}

static void scenario_read_transfer_len_must_match_size(void) {
    pbt_begin();
    pbt_start();

    // READ derives its expected transfer length from the size in its arguments.
    // A transfer length that disagrees is rejected.
    picoboot_cmd_t bad = pbt_cmd(PB_CMD_READ, 0x08u, 32u);
    pbt_args_addr_size(&bad, RP2350_SRAM_BASE, 64u);

    PBT_CHECK_STATUS(pbt_run_cmd(&bad), PB_STATUS_INVALID_TRANSFER_LEN);
    PBT_CHECK_EQ(pbt_count("op_read_prepare"), 0);

    pbt_recover();

    // The same command with the two agreeing is accepted, so the rejection
    // above was about the disagreement and not about the command.
    picoboot_cmd_t good = pbt_cmd(PB_CMD_READ, 0x08u, 64u);
    pbt_args_addr_size(&good, RP2350_SRAM_BASE, 64u);

    PBT_CHECK_STATUS(pbt_run_cmd(&good), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_count("op_read_prepare"), 1);
}

static void scenario_otp_transfer_len_follows_ecc(void) {
    pbt_begin();
    pbt_start();

    // Four rows is sixteen bytes raw and eight bytes through ECC, so the same
    // row count accepts different transfer lengths depending on the flag.
    const uint16_t rows = 4u;

    picoboot_cmd_t raw = pbt_cmd(PB_CMD_OTP_READ, 0x05u, rows * 4u);
    pbt_args_otp(&raw, 0u, rows, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&raw), PB_STATUS_OK);

    pbt_recover();

    picoboot_cmd_t ecc = pbt_cmd(PB_CMD_OTP_READ, 0x05u, rows * 2u);
    pbt_args_otp(&ecc, 0u, rows, 1u);
    PBT_CHECK_STATUS(pbt_run_cmd(&ecc), PB_STATUS_OK);

    pbt_recover();

    // Each length is wrong for the other flag.
    picoboot_cmd_t raw_len_ecc_flag = pbt_cmd(PB_CMD_OTP_READ, 0x05u, rows * 4u);
    pbt_args_otp(&raw_len_ecc_flag, 0u, rows, 1u);
    PBT_CHECK_STATUS(pbt_run_cmd(&raw_len_ecc_flag),
                     PB_STATUS_INVALID_TRANSFER_LEN);

    pbt_recover();

    picoboot_cmd_t ecc_len_raw_flag = pbt_cmd(PB_CMD_OTP_READ, 0x05u, rows * 2u);
    pbt_args_otp(&ecc_len_raw_flag, 0u, rows, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&ecc_len_raw_flag),
                     PB_STATUS_INVALID_TRANSFER_LEN);
}

static void scenario_unknown_command_id_stalls(void) {
    pbt_begin();
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(0x7Fu, 0x00u, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_UNKNOWN_CMD);

    // The status still names the command that caused it, which is how a host
    // matches a failure to the request it sent.
    picoboot_status_t status;
    PBT_REQUIRE(pbt_ctrl_get_status(&status));
    PBT_CHECK_EQ(status.cmd_id, 0x7Fu);
    PBT_CHECK_EQ(status.token, cmd.token);
    PBT_CHECK_EQ(status.in_progress, 0u);
}

static void scenario_unsupported_commands_stall(void) {
    pbt_begin();
    pbt_start();

    // These three are in the command table and are refused there, rather than
    // being unknown.  A host sees the same status either way.
    const struct {
        const char *name;
        uint8_t     cmd_id;
    } refused[] = {
        { "REBOOT",          PB_CMD_REBOOT },
        { "EXEC",            PB_CMD_EXEC },
        { "VECTORIZE_FLASH", PB_CMD_VECTORIZE_FLASH },
    };

    for (unsigned i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
        picoboot_cmd_t cmd = pbt_cmd(refused[i].cmd_id, 0x00u, 0u);
        PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_UNKNOWN_CMD);
        pbt_recover();
    }
}

static void scenario_unknown_magic_stalls_but_keeps_identity(void) {
    pbt_begin();
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_READ, 0x08u, 0u);
    cmd.magic = 0xDEADBEEFu;

    pbt_host_send_cmd(&cmd);
    pbt_pump();

    picoboot_status_t status;
    PBT_REQUIRE(pbt_ctrl_get_status(&status));
    PBT_CHECK_STATUS(status.status_code, PB_STATUS_UNKNOWN_CMD);

    // A command with the wrong magic is not a command, but the identity fields
    // are still reported so a host can tell which of its requests died.
    PBT_CHECK_EQ(status.cmd_id, PB_CMD_READ);
    PBT_CHECK_EQ(status.token, cmd.token);

    // Nothing was dispatched.
    PBT_CHECK_EQ(pbt_count("op_read_prepare"), 0);
}

static void scenario_custom_magic_without_custom_ops_stalls(void) {
    pbt_begin();
    // Custom ops deliberately not registered.
    pbt_start();

    picoboot_cmd_t cmd = pbt_custom_cmd(PBT_CUSTOM_CMD_PING, 0x00u, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_UNKNOWN_CMD);
    PBT_CHECK_EQ(pbt_count("custom_dispatch"), 0);
}

static void scenario_a_third_magic_stalls_even_with_custom_ops(void) {
    pbt_begin();
    pbt_use_custom = true;
    pbt_start();

    // Registering a custom magic widens what the device answers to by exactly
    // one value.  A packet carrying neither the standard magic nor the
    // integrator's is still not a command.
    picoboot_cmd_t cmd = pbt_custom_cmd(PBT_CUSTOM_CMD_PING, 0x00u, 0u);
    cmd.magic = 0x0BADF00Du;

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_UNKNOWN_CMD);
    PBT_CHECK_EQ(pbt_count("custom_dispatch"), 0);

    // The identity is still reported, as it is for any unrecognised magic.
    picoboot_status_t status;
    PBT_REQUIRE(pbt_ctrl_get_status(&status));
    PBT_CHECK_EQ(status.token, cmd.token);
    PBT_CHECK_EQ(status.cmd_id, PBT_CUSTOM_CMD_PING);

    // The integrator's own magic, on the same command, reaches them — so what
    // was refused was the magic and not the command.
    pbt_recover();
    picoboot_cmd_t theirs = pbt_custom_cmd(PBT_CUSTOM_CMD_PING, 0x00u, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&theirs), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_count("custom_dispatch"), 1);
}

static void scenario_short_packet_is_discarded(void) {
    pbt_begin();
    pbt_start();

    uint8_t partial[16];
    memset(partial, 0x5Au, sizeof(partial));
    pbt_host_send(partial, sizeof(partial));
    pbt_pump();

    // A partial command is dropped rather than stalled, and the endpoints stay
    // running.
    PBT_CHECK_EQ(pbt_state()->state, PB_STATE_IDLE);
    PBT_CHECK(!pbt_ep_stalled(PBT_EP_OUT));
    PBT_CHECK_EQ(pbt_count("rx_clear"), 1);
    PBT_CHECK_EQ(picoboot_vendor_available(), 0u);

    // And the connection is still usable, so the discard cleared the way for
    // the next command rather than leaving stale bytes in front of it.
    picoboot_cmd_t cmd = valid_command();
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_count("op_exclusive_access"), 1);
}

static void scenario_single_byte_in_idle_is_consumed(void) {
    pbt_begin();
    pbt_start();

    uint8_t byte = 0x00u;
    pbt_host_send(&byte, 1);
    pbt_pump();

    // A lone byte is the acknowledgement form the protocol also accepts, and in
    // idle it is swallowed rather than treated as the start of a command.
    PBT_CHECK_EQ(picoboot_vendor_available(), 0u);
    PBT_CHECK_EQ(pbt_state()->state, PB_STATE_IDLE);
    PBT_CHECK_EQ(pbt_count("rx_clear"), 0);

    picoboot_cmd_t cmd = valid_command();
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);
}

static void scenario_declared_command_sizes(void) {
    // Every command's declared size, pinned in one place.  For each, the size
    // the table holds is accepted and one byte more is not — so the assertion
    // is about the size and not about whether the command happens to work.
    const struct {
        uint8_t cmd_id;
        uint8_t cmd_size;
    } table[] = {
        { PB_CMD_EXCLUSIVE_ACCESS, 0x01u },
        { PB_CMD_EXIT_XIP,         0x00u },
        { PB_CMD_ENTER_XIP,        0x00u },
        { PB_CMD_FLASH_ERASE,      0x08u },
        { PB_CMD_REBOOT2,          0x10u },
        { PB_CMD_READ,             0x08u },
        { PB_CMD_GET_INFO,         0x10u },
        { PB_CMD_OTP_READ,         0x05u },
        { PB_CMD_WRITE,            0x08u },
        { PB_CMD_OTP_WRITE,        0x05u },
    };

    for (unsigned i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        pbt_begin();
        pbt_start();

        picoboot_cmd_t wrong = pbt_cmd(table[i].cmd_id,
                                       (uint8_t)(table[i].cmd_size + 1u), 0u);
        pb_status_t got = pbt_run_cmd(&wrong);
        if (got != PB_STATUS_INVALID_CMD_LENGTH) {
            pbt_fail(__FILE__, __LINE__,
                     "cmd 0x%02x with size %u: expected INVALID_CMD_LENGTH, "
                     "got %s", table[i].cmd_id, table[i].cmd_size + 1u,
                     pbt_status_name((int)got));
        }

        pbt_recover();

        // With the declared size the command gets past the length check.  It
        // may still be refused for its arguments, which is a different status
        // and a different concern.
        picoboot_cmd_t right = pbt_cmd(table[i].cmd_id, table[i].cmd_size, 0u);
        pb_status_t accepted = pbt_run_cmd(&right);
        if (accepted == PB_STATUS_INVALID_CMD_LENGTH) {
            pbt_fail(__FILE__, __LINE__,
                     "cmd 0x%02x with its declared size %u was rejected for "
                     "length", table[i].cmd_id, table[i].cmd_size);
        }
    }
}

static const pbt_scenario_t k_scenarios[] = {
    { "a well-formed command is dispatched",
      scenario_valid_command_dispatches },
    { "a wrong cmd_size stalls before the command runs",
      scenario_cmd_size_mismatch_stalls },
    { "an action command rejects a non-zero transfer_len",
      scenario_action_rejects_non_zero_transfer_len },
    { "READ requires transfer_len to match its size argument",
      scenario_read_transfer_len_must_match_size },
    { "OTP transfer_len follows the ECC flag",
      scenario_otp_transfer_len_follows_ecc },
    { "an unknown command id stalls and is reported by id",
      scenario_unknown_command_id_stalls },
    { "commands the table refuses stall",
      scenario_unsupported_commands_stall },
    { "an unknown magic stalls but still reports token and id",
      scenario_unknown_magic_stalls_but_keeps_identity },
    { "a custom magic with no custom ops registered stalls",
      scenario_custom_magic_without_custom_ops_stalls },
    { "a third magic stalls even with custom ops registered",
      scenario_a_third_magic_stalls_even_with_custom_ops },
    { "a short packet is discarded, not stalled",
      scenario_short_packet_is_discarded },
    { "a lone byte in idle is consumed",
      scenario_single_byte_in_idle_is_consumed },
    { "every command's declared size",
      scenario_declared_command_sizes },
};

PBT_SUITE(pbt_suite_framing, "framing", k_scenarios);
