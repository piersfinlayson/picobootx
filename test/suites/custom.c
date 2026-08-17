// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// Custom commands: the contract picobootx offers an integrator through
// picoboot_custom_ops_t, exercised against the sample implementation in
// pbt_ops.c.

#include <string.h>

#include "pbt.h"

static void scenario_a_command_with_no_data_phase(void) {
    pbt_begin();
    pbt_use_custom = true;
    pbt_start();

    picoboot_cmd_t cmd = pbt_custom_cmd(PBT_CUSTOM_CMD_PING, 0x00u, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);

    // Dispatch runs once, and is told which command it is answering.
    PBT_CHECK_EQ(pbt_count("custom_dispatch"), 1);
    PBT_REQUIRE(pbt_nth("custom_dispatch", 0) != NULL);
    PBT_CHECK_EQ(pbt_nth("custom_dispatch", 0)->a0, PBT_CUSTOM_CMD_PING);

    // The interface says the buffer arguments are unused here, and they are.
    PBT_CHECK_EQ(pbt_nth("custom_dispatch", 0)->a2, 0u);
    PBT_CHECK_EQ(pbt_nth("custom_dispatch", 0)->a3, 0u);

    // Acknowledged the same way a built-in action command is.
    PBT_REQUIRE(pbt_packet_count() == 1u);
    PBT_CHECK_EQ(pbt_packet(0)->len, 1u);
    PBT_CHECK_EQ(pbt_packet(0)->data[0], 0u);

    // No fill for a command with nothing to send.
    PBT_CHECK_EQ(pbt_custom_fill_calls(), 0u);

    // The status names the custom command, not a built-in one.
    picoboot_status_t status;
    PBT_REQUIRE(pbt_ctrl_get_status(&status));
    PBT_CHECK_EQ(status.cmd_id, PBT_CUSTOM_CMD_PING);
    PBT_CHECK_EQ(status.token, cmd.token);
}

static void scenario_dispatch_refusal_carries_its_own_status(void) {
    pbt_begin();
    pbt_use_custom = true;
    pbt_start();

    // A status no built-in path produces, so the host is being told what the
    // integrator's code decided and not what the library fell back to.
    picoboot_cmd_t cmd = pbt_custom_cmd(PBT_CUSTOM_CMD_REFUSE, 0x00u, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PBT_CUSTOM_REFUSE_STATUS);

    PBT_CHECK_EQ(pbt_count("custom_dispatch"), 1);
    PBT_CHECK_EQ(pbt_packet_count(), 0u);
    PBT_CHECK(pbt_ep_stalled(PBT_EP_OUT));
    PBT_CHECK(pbt_ep_stalled(PBT_EP_IN));
}

static void scenario_an_unknown_custom_id_is_the_integrators_to_refuse(void) {
    pbt_begin();
    pbt_use_custom = true;
    pbt_start();

    // The library knows nothing about a custom command's identifiers, so an
    // identifier the integrator does not recognise reaches dispatch and is
    // refused there.
    picoboot_cmd_t cmd = pbt_custom_cmd(0x33u, 0x00u, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_UNKNOWN_CMD);
    PBT_CHECK_EQ(pbt_count("custom_dispatch"), 1);
}

static void scenario_data_in_dispatches_then_fills(void) {
    pbt_begin();
    pbt_use_custom = true;
    pbt_start();

    const uint32_t length = 100u;
    picoboot_cmd_t cmd = pbt_custom_cmd(PBT_CUSTOM_CMD_COUNT, 0x00u, length);
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);

    // Dispatch takes the preparing role, and only then is fill called.
    PBT_CHECK_EQ(pbt_count("custom_dispatch"), 1);
    PBT_CHECK(pbt_before("custom_dispatch", "custom_fill"));

    PBT_REQUIRE(pbt_payload_len() == length);
    for (uint32_t i = 0; i < length; i++) {
        if (pbt_payload()[i] != (uint8_t)i) {
            pbt_fail(__FILE__, __LINE__, "payload byte %u is 0x%02x", i,
                     pbt_payload()[i]);
            break;
        }
    }

    // More than one packet, so the transfer really was carried across calls.
    PBT_CHECK_EQ(pbt_packet_count(), 2u);
    PBT_CHECK_EQ(pbt_packet(0)->len, 64u);
    PBT_CHECK_EQ(pbt_packet(1)->len, 36u);
}

static void scenario_fill_is_handed_the_original_command(void) {
    pbt_begin();
    pbt_use_custom = true;
    pbt_start();

    // Arguments the integrator's fill would need, carried in the command rather
    // than anywhere the library owns.
    picoboot_cmd_t cmd = pbt_custom_cmd(PBT_CUSTOM_CMD_COUNT, 0x07u, 100u);
    for (unsigned i = 0; i < PICOBOOT_ARGS_LEN; i++) {
        cmd.args[i] = (uint8_t)(0xE0u + i);
    }

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);
    PBT_CHECK(pbt_custom_fill_calls() > 1u);

    // The command the last fill call saw is the one the host sent, in every
    // field.  The library keeps its own copy for the duration precisely because
    // the caller's has long since gone out of scope.
    const picoboot_cmd_t *seen = pbt_custom_last_cmd();
    PBT_CHECK_EQ(seen->magic, PBT_CUSTOM_MAGIC);
    PBT_CHECK_EQ(seen->token, cmd.token);
    PBT_CHECK_EQ(seen->cmd_id, cmd.cmd_id);
    PBT_CHECK_EQ(seen->cmd_size, cmd.cmd_size);
    PBT_CHECK_EQ(seen->transfer_len, cmd.transfer_len);
    PBT_CHECK_EQ(memcmp(seen->args, cmd.args, PICOBOOT_ARGS_LEN), 0);
}

static void scenario_fill_may_decline_a_call(void) {
    pbt_begin();
    pbt_use_custom = true;
    pbt_start();

    // Items that cannot be split, so a call arrives with room for some but not
    // all of one.  Writing nothing without reporting the transfer complete
    // means "call me again", and the library has to honour that rather than
    // treat it as the end.
    const uint32_t items  = 8u;
    const uint32_t length = items * PBT_CUSTOM_ITEM_SIZE;

    picoboot_cmd_t cmd = pbt_custom_cmd(PBT_CUSTOM_CMD_ITEMS, 0x00u, length);
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);

    PBT_REQUIRE(pbt_payload_len() == length);
    for (uint32_t i = 0; i < length; i++) {
        if (pbt_payload()[i] != (uint8_t)i) {
            pbt_fail(__FILE__, __LINE__, "payload byte %u is 0x%02x", i,
                     pbt_payload()[i]);
            break;
        }
    }

    // Two items fit in a packet and the third does not, so each packet is
    // forty-eight bytes and one call per packet produces nothing.
    PBT_CHECK_EQ(pbt_packet_count(), 4u);
    PBT_CHECK_EQ(pbt_packet(0)->len, 2u * PBT_CUSTOM_ITEM_SIZE);
    PBT_CHECK_EQ(pbt_packet(3)->len, 2u * PBT_CUSTOM_ITEM_SIZE);

    // Eight calls produced an item, and three produced nothing and asked to be
    // called again.  A library that ended the transfer on an empty call would
    // have stopped after the first forty-eight bytes.
    PBT_CHECK_EQ(pbt_custom_fill_calls(), items + 3u);
}

static void scenario_fill_refusal_carries_its_own_status(void) {
    pbt_begin();
    pbt_use_custom = true;
    pbt_start();

    picoboot_cmd_t cmd = pbt_custom_cmd(PBT_CUSTOM_CMD_STALL, 0x00u, 64u);
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PBT_CUSTOM_FILL_STATUS);

    // The refusal happened partway through, and nothing reached the host — a
    // partial answer would leave a host unable to tell how much of it to trust.
    PBT_CHECK(pbt_custom_fill_calls() >= 2u);
    PBT_CHECK_EQ(pbt_packet_count(), 0u);
    PBT_CHECK(pbt_ep_stalled(PBT_EP_IN));
}

static void scenario_data_in_without_fill_is_refused(void) {
    pbt_begin();
    pbt_use_custom = true;
    pbt_custom_ops.fill = NULL;
    pbt_start();

    picoboot_cmd_t cmd = pbt_custom_cmd(PBT_CUSTOM_CMD_COUNT, 0x00u, 32u);
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_UNKNOWN_CMD);

    // Refused before dispatch, so an integrator's preparation never runs for a
    // transfer that could not have been completed.
    PBT_CHECK_EQ(pbt_count("custom_dispatch"), 0);

    // Without a data phase the same ops still work, so what was refused was the
    // transfer and not the registration.
    pbt_recover();
    picoboot_cmd_t ping = pbt_custom_cmd(PBT_CUSTOM_CMD_PING, 0x00u, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&ping), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_count("custom_dispatch"), 1);
}

static void scenario_a_host_to_device_data_phase_is_refused(void) {
    pbt_begin();
    pbt_use_custom = true;
    pbt_start();

    // The direction bit is clear and the transfer length is not zero, which is
    // the one shape custom commands do not support.
    picoboot_cmd_t cmd = pbt_custom_cmd(PBT_CUSTOM_CMD_PING, 0x00u, 32u);
    PBT_CHECK(!(cmd.cmd_id & PICOBOOT_DIR_IN));

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_UNKNOWN_CMD);
    PBT_CHECK_EQ(pbt_count("custom_dispatch"), 0);

    // The same identifier with no data phase is accepted, so the refusal is
    // about the direction and length and not about the command.
    pbt_recover();
    picoboot_cmd_t no_data = pbt_custom_cmd(PBT_CUSTOM_CMD_PING, 0x00u, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&no_data), PB_STATUS_OK);
}

static void scenario_custom_ops_without_dispatch_is_refused(void) {
    pbt_begin();
    pbt_use_custom = true;
    pbt_custom_ops.dispatch = NULL;
    pbt_start();

    // A magic registered with nothing behind it cannot serve anything, and is
    // refused rather than called through.
    picoboot_cmd_t cmd = pbt_custom_cmd(PBT_CUSTOM_CMD_PING, 0x00u, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_UNKNOWN_CMD);
}

static void scenario_the_standard_magic_still_reaches_the_built_ins(void) {
    pbt_begin();
    pbt_use_custom = true;
    pbt_start();

    // The custom identifier space is the integrator's, so it overlaps the
    // standard one.  A command carrying the standard magic goes to the built-in
    // of that identifier.
    PBT_CHECK_EQ(PBT_CUSTOM_CMD_PING, PB_CMD_EXCLUSIVE_ACCESS);

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_EXCLUSIVE_ACCESS, 0x01u, 0u);
    pbt_args_exclusive_access(&cmd, PB_EA_EXCL);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_count("op_exclusive_access"), 1);
    PBT_CHECK_EQ(pbt_count("custom_dispatch"), 0);
}

static void scenario_the_custom_magic_reaches_the_integrator(void) {
    pbt_begin();
    pbt_use_custom = true;
    pbt_start();

    // The same identifier under the custom magic goes the other way, so the
    // routing really is by magic and not by identifier.
    picoboot_cmd_t cmd = pbt_custom_cmd(PBT_CUSTOM_CMD_PING, 0x00u, 0u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_count("custom_dispatch"), 1);
    PBT_CHECK_EQ(pbt_count("op_exclusive_access"), 0);

    // And the command size the built-in would have insisted on is not applied.
    PBT_CHECK_EQ(cmd.cmd_size, 0x00u);
}

static void scenario_the_standard_magic_wins_a_collision(void) {
    pbt_begin();
    pbt_use_custom = true;
    // An integrator that picks the standard magic for their own commands has
    // made a mistake, and the mistake must not cost them the standard command
    // set: the standard magic is matched first, so their dispatch never sees a
    // command and the built-ins keep working.
    pbt_custom_ops.magic = PICOBOOT_MAGIC;
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_EXCLUSIVE_ACCESS, 0x01u, 0u);
    pbt_args_exclusive_access(&cmd, PB_EA_EXCL);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_count("op_exclusive_access"), 1);
    PBT_CHECK_EQ(pbt_count("custom_dispatch"), 0);
}

static const pbt_scenario_t k_scenarios[] = {
    { "a custom command with no data phase is dispatched and acknowledged",
      scenario_a_command_with_no_data_phase },
    { "a refusal from dispatch reaches the host as the integrator's status",
      scenario_dispatch_refusal_carries_its_own_status },
    { "an identifier the integrator does not know is theirs to refuse",
      scenario_an_unknown_custom_id_is_the_integrators_to_refuse },
    { "a device-to-host custom command dispatches then fills",
      scenario_data_in_dispatches_then_fills },
    { "fill is handed the originating command on every call",
      scenario_fill_is_handed_the_original_command },
    { "fill may decline a call and be asked again",
      scenario_fill_may_decline_a_call },
    { "a refusal from fill reaches the host as the integrator's status",
      scenario_fill_refusal_carries_its_own_status },
    { "a device-to-host custom command without fill is refused",
      scenario_data_in_without_fill_is_refused },
    { "a host-to-device custom data phase is refused",
      scenario_a_host_to_device_data_phase_is_refused },
    { "custom ops registered without dispatch are refused",
      scenario_custom_ops_without_dispatch_is_refused },
    { "the standard magic still reaches the built-in commands",
      scenario_the_standard_magic_still_reaches_the_built_ins },
    { "the custom magic reaches the integrator for the same identifier",
      scenario_the_custom_magic_reaches_the_integrator },
    { "the standard magic wins if an integrator claims it too",
      scenario_the_standard_magic_wins_a_collision },
};

PBT_SUITE(pbt_suite_custom, "custom", k_scenarios);
