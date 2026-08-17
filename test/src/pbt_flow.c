// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// Setting a core-suite scenario up, and the two helpers that drive one.
//
// Split from pbt_core.c so the runner and the assertions there can be shared
// with the usb suite, which reaches the library through real tinyusb and has no
// use for the transport fake these depend on.

#include <stdio.h>
#include <string.h>

#include "pbt.h"

static union {
    uint32_t         words[PICOBOOT_STATE_SIZE / 4];
    pb_state_block_t block;
} s_state_buf;

// The 256-byte page buffer WRITE accumulates into.
static uint8_t s_flash_write_buf[256] __attribute__((aligned(4)));

pb_state_block_t *pbt_state(void) {
    return &s_state_buf.block;
}

// Defined in their own translation units.
void pbt_device_reset(void);
void pbt_wire_reset(void);
void pbt_ops_reset(void);
void pbt_custom_ops_reset(void);
void pbt_token_reset(void);

void pbt_begin(void) {
    pbt_log_reset();

    pbt_device_reset();
    pbt_wire_reset();
    pbt_ops_reset();
    pbt_custom_ops_reset();
    pbt_token_reset();

    memset(s_flash_write_buf, 0, sizeof(s_flash_write_buf));

    pbt_use_custom    = false;
    pbt_use_flash_buf = true;
}

void pbt_start(void) {
    picoboot_init(
        pbt_state(),
        &pbt_ops,
        pbt_use_custom ? &pbt_custom_ops : NULL,
        pbt_use_flash_buf ? s_flash_write_buf : NULL,
        PBT_RHPORT,
        PBT_EP_OUT,
        PBT_EP_IN,
        NULL
    );
}

void pbt_recover(void) {
    if (!pbt_ctrl_interface_reset()) {
        pbt_fail(__FILE__, __LINE__,
                 "the library declined INTERFACE RESET");
        return;
    }
    pbt_pump();

    if (pbt_ep_stalled(PBT_EP_OUT) || pbt_ep_stalled(PBT_EP_IN) ||
        pbt_state()->state != PB_STATE_IDLE) {
        pbt_fail(__FILE__, __LINE__,
                 "INTERFACE RESET left the device in %s with OUT %s and IN %s",
                 pbt_state_name(pbt_state()->state),
                 pbt_ep_stalled(PBT_EP_OUT) ? "halted" : "running",
                 pbt_ep_stalled(PBT_EP_IN) ? "halted" : "running");
    }
}

pb_status_t pbt_run_cmd(const picoboot_cmd_t *cmd) {
    pbt_host_send_cmd(cmd);
    pbt_pump();

    // A device-to-host command leaves the device waiting for the host's
    // completion packet, and the status block is not updated for the command
    // until that arrives.  A host sends it, so the harness does too.
    if (pbt_state()->state == PB_STATE_AWAIT_ACK) {
        pbt_host_ack();
        pbt_pump();
    }

    picoboot_status_t status;
    if (!pbt_ctrl_get_status(&status)) {
        pbt_fail(__FILE__, __LINE__,
                 "the library declined GET_COMMAND_STATUS");
        return PB_STATUS_UNKNOWN_ERROR;
    }
    return (pb_status_t)status.status_code;
}
