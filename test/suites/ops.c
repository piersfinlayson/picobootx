// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// What an integrator's partial ops table does.
//
// picoboot_ops_t is a table of callbacks, and an integrator fills in the ones
// their device supports.  A hole in it is not a mistake — it is how a device
// says it does not do that — so every hole has a defined answer, and the answers
// are not all the same.  A command whose work is entirely the callback's is
// refused as unknown.  An action whose callback is advisory succeeds without it.
// Each scenario here also shows the same command working once the callback is
// put back, so what is being pinned is the hole and not the command.

#include <string.h>

#include "pbt.h"

// ---------------------------------------------------------------------------
// Actions whose callbacks are optional
// ---------------------------------------------------------------------------

static void scenario_optional_action_callbacks_may_be_absent(void) {
    // These three commands are acknowledged whether or not the integrator has
    // anything to do for them.  A device with no exclusive-access notion and
    // nothing to do on entering or leaving execute-in-place is a device that
    // simply agrees, which is what a host expects of a no-op command.
    const struct {
        const char *name;
        uint8_t     cmd_id;
        uint8_t     cmd_size;
        const char *op;
    } cases[] = {
        { "EXCLUSIVE_ACCESS", PB_CMD_EXCLUSIVE_ACCESS, 0x01u,
          "op_exclusive_access" },
        { "EXIT_XIP",  PB_CMD_EXIT_XIP,  0x00u, "op_exit_xip" },
        { "ENTER_XIP", PB_CMD_ENTER_XIP, 0x00u, "op_enter_xip" },
    };

    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        pbt_begin();
        pbt_ops.exclusive_access = NULL;
        pbt_ops.exit_xip         = NULL;
        pbt_ops.enter_xip        = NULL;
        pbt_start();

        picoboot_cmd_t cmd = pbt_cmd(cases[i].cmd_id, cases[i].cmd_size, 0u);
        pb_status_t got = pbt_run_cmd(&cmd);
        if (got != PB_STATUS_OK) {
            pbt_fail(__FILE__, __LINE__, "%s without its callback: %s",
                     cases[i].name, pbt_status_name((int)got));
            continue;
        }
        if (pbt_count(cases[i].op) != 0) {
            pbt_fail(__FILE__, __LINE__, "%s called a callback that is not there",
                     cases[i].name);
        }
        // Acknowledged, so the host is not left waiting on a command that was
        // quietly dropped.
        if (pbt_packet_count() != 1u || pbt_packet(0)->len != 1u) {
            pbt_fail(__FILE__, __LINE__, "%s was not acknowledged",
                     cases[i].name);
        }

        // With the table complete the same command reaches the callback, so the
        // silence above was the hole and not the command.
        pbt_begin();
        pbt_start();
        picoboot_cmd_t again = pbt_cmd(cases[i].cmd_id, cases[i].cmd_size, 0u);
        if (pbt_run_cmd(&again) != PB_STATUS_OK ||
            pbt_count(cases[i].op) != 1) {
            pbt_fail(__FILE__, __LINE__,
                     "%s did not reach its callback with the table complete",
                     cases[i].name);
        }
    }
}

static void scenario_an_action_callback_that_refuses_stalls(void) {
    pbt_begin();
    pbt_start();

    // The default implementation accepts the three defined exclusive-access
    // types and refuses anything else, and a refusal from an action's callback
    // halts the command with the callback's own status rather than a generic
    // one.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_EXCLUSIVE_ACCESS, 0x01u, 0u);
    pbt_args_exclusive_access(&cmd, 0x7Fu);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_INVALID_ARG);
    PBT_CHECK_EQ(pbt_count("op_exclusive_access"), 1);
    PBT_CHECK_EQ(pbt_state()->state, PB_STATE_STALLED);
    PBT_CHECK_EQ(pbt_packet_count(), 0u);

    // Each defined type is accepted, so what was refused was the value and not
    // the command.
    const uint8_t accepted[] = {
        PB_EA_NOT_EXCL, PB_EA_EXCL, PB_EA_EXCL_AND_EJECT,
    };
    for (unsigned i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++) {
        pbt_recover();
        picoboot_cmd_t ok = pbt_cmd(PB_CMD_EXCLUSIVE_ACCESS, 0x01u, 0u);
        pbt_args_exclusive_access(&ok, accepted[i]);
        pb_status_t got = pbt_run_cmd(&ok);
        if (got != PB_STATUS_OK) {
            pbt_fail(__FILE__, __LINE__, "exclusive access type %u: %s",
                     accepted[i], pbt_status_name((int)got));
        }
    }
}

// ---------------------------------------------------------------------------
// REBOOT2
// ---------------------------------------------------------------------------

static void scenario_reboot2_without_prepare_is_refused(void) {
    pbt_begin();
    pbt_ops.reboot2_prepare = NULL;
    pbt_start();

    // Preparing is where the device decides whether it can reboot at all.  With
    // no way to ask, the command is refused rather than acknowledged and then
    // silently not carried out.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_REBOOT2, 0x10u, 0u);
    pbt_args_reboot2(&cmd, 0x0002u, 10u, 0u, 0u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_UNKNOWN_CMD);
    PBT_CHECK_EQ(pbt_count("op_reboot2_execute"), 0);
    PBT_CHECK_EQ(pbt_count("rom_reboot"), 0);
    PBT_CHECK_EQ(pbt_packet_count(), 0u);

    pbt_begin();
    pbt_start();
    picoboot_cmd_t again = pbt_cmd(PB_CMD_REBOOT2, 0x10u, 0u);
    pbt_args_reboot2(&again, 0x0002u, 10u, 0u, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&again), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_count("rom_reboot"), 1);
}

static void scenario_reboot2_without_execute_still_acknowledges(void) {
    pbt_begin();
    pbt_ops.reboot2_execute = NULL;
    pbt_start();

    // Rebooting is deferred until the acknowledgement has gone, and an
    // integrator with nothing to defer still gets the acknowledgement.  A
    // device that stopped short of it here would leave every host waiting.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_REBOOT2, 0x10u, 0u);
    pbt_args_reboot2(&cmd, 0x0002u, 10u, 0u, 0u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_count("op_reboot2_prepare"), 1);
    PBT_CHECK_EQ(pbt_count("rom_reboot"), 0);
    PBT_CHECK_EQ(pbt_packet_count(), 1u);
    PBT_REQUIRE(pbt_packet(0) != NULL);
    PBT_CHECK_EQ(pbt_packet(0)->len, 1u);
    PBT_CHECK_EQ(pbt_state()->state, PB_STATE_IDLE);

    // With the callback in place the same command reboots after the same
    // acknowledgement, so what was missing was the reboot and not the reply.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t again = pbt_cmd(PB_CMD_REBOOT2, 0x10u, 0u);
    pbt_args_reboot2(&again, 0x0002u, 10u, 0u, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&again), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_count("rom_reboot"), 1);
    PBT_CHECK(pbt_before("packet_in", "rom_reboot"));
}

// ---------------------------------------------------------------------------
// WRITE
// ---------------------------------------------------------------------------

static void scenario_write_without_prepare_is_refused(void) {
    pbt_begin();
    pbt_ops.write_prepare = NULL;
    pbt_start();

    // Preparing is what decides whether the destination is writable at all, and
    // whether it is flash or memory.  Without it the library cannot tell which
    // of the two paths a write belongs to, so it refuses instead of guessing.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_WRITE, 0x08u, 16u);
    pbt_args_addr_size(&cmd, RP2350_SRAM_BASE, 16u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_UNKNOWN_CMD);
    PBT_CHECK_EQ(pbt_count("op_write"), 0);
    PBT_CHECK_EQ(pbt_state()->state, PB_STATE_STALLED);

    // The same write with the callback present is accepted and reaches memory.
    pbt_begin();
    pbt_start();
    uint8_t data[16];
    memset(data, 0x3Cu, sizeof(data));
    picoboot_cmd_t again = pbt_cmd(PB_CMD_WRITE, 0x08u, sizeof(data));
    pbt_args_addr_size(&again, RP2350_SRAM_BASE, sizeof(data));
    pbt_host_send_cmd(&again);
    pbt_pump();
    pbt_host_send(data, sizeof(data));
    pbt_pump();
    PBT_CHECK_EQ(memcmp(pbt_sram(), data, sizeof(data)), 0);
}

static const pbt_scenario_t k_scenarios[] = {
    { "an action's optional callback may be absent",
      scenario_optional_action_callbacks_may_be_absent },
    { "an action callback that refuses halts with its own status",
      scenario_an_action_callback_that_refuses_stalls },
    { "REBOOT2 without its prepare callback is refused",
      scenario_reboot2_without_prepare_is_refused },
    { "REBOOT2 without its execute callback still acknowledges",
      scenario_reboot2_without_execute_still_acknowledges },
    { "WRITE without its prepare callback is refused",
      scenario_write_without_prepare_is_refused },
};

PBT_SUITE(pbt_suite_ops, "ops", k_scenarios);
