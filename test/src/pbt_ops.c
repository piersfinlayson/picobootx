// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// The callbacks picobootx is initialised with, and the helpers scenarios use to
// build commands.
//
// Every standard callback is picobootx's own default implementation with a
// recording wrapper around it, so the logic under test is the shipped logic and
// the log still says which callback the library reached and with what.  A
// scenario that wants to exercise a missing-callback path clears the member in
// pbt_ops before pbt_start.
//
// The custom command implementation is the harness's own — that is the point of
// it.  picoboot_custom_ops_t is an interface picobootx offers and never
// implements, so the only way to test the contract is to write an integrator's
// side of it, and this is a small one written to exercise each branch the
// contract describes.

#include <string.h>

#include "pbt.h"

// ---------------------------------------------------------------------------
// Recording wrappers around the default implementations
// ---------------------------------------------------------------------------

static pb_status_t op_exclusive_access(const pb_exclusive_access_args_t *args,
                                       void *ctx) {
    pbt_log("op_exclusive_access", args->ea_type, 0, 0, 0);
    return picoboot_default_exclusive_access(args, ctx);
}

static pb_status_t op_exit_xip(void *ctx) {
    pbt_log("op_exit_xip", 0, 0, 0, 0);
    return picoboot_default_exit_xip(ctx);
}

static pb_status_t op_enter_xip(void *ctx) {
    pbt_log("op_enter_xip", 0, 0, 0, 0);
    return picoboot_default_enter_xip(ctx);
}

static pb_status_t op_reboot2_prepare(const pb_reboot2_args_t *args, void *ctx) {
    pbt_log("op_reboot2_prepare", args->flags, args->delay_ms, args->p0,
            args->p1);
    return picoboot_default_reboot2_prepare(args, ctx);
}

static void op_reboot2_execute(const pb_reboot2_args_t *args, void *ctx) {
    pbt_log("op_reboot2_execute", args->flags, args->delay_ms, args->p0,
            args->p1);
    picoboot_default_reboot2_execute(args, ctx);
}

static pb_status_t op_get_info_sys(uint32_t flags, uint8_t *buf,
                                   uint32_t buf_len, uint32_t *bytes_written,
                                   void *ctx) {
    pbt_log("op_get_info_sys", flags, buf_len, 0, 0);
    return picoboot_default_get_info_sys(flags, buf, buf_len, bytes_written,
                                         ctx);
}

static pb_status_t op_read_prepare(uint32_t addr, uint32_t size, void *ctx) {
    pbt_log("op_read_prepare", addr, size, 0, 0);
    return picoboot_default_read_prepare(addr, size, ctx);
}

static pb_status_t op_read(uint32_t addr, uint8_t *buf, uint32_t len,
                           void *ctx) {
    pbt_log("op_read", addr, len, 0, 0);
    return picoboot_default_read(addr, buf, len, ctx);
}

static pb_status_t op_otp_read(uint16_t row, uint8_t ecc, uint8_t *buf,
                               uint32_t len, void *ctx) {
    pbt_log("op_otp_read", row, ecc, len, 0);
    return picoboot_default_otp_read(row, ecc, buf, len, ctx);
}

static pb_status_t op_write_prepare(uint32_t addr, uint32_t size,
                                    bool *is_flash, void *ctx) {
    pbt_log("op_write_prepare", addr, size, 0, 0);
    return picoboot_default_write_prepare(addr, size, is_flash, ctx);
}

static pb_status_t op_flash_page_write(uint32_t addr, const uint8_t *buf,
                                       void *ctx) {
    pbt_log("op_flash_page_write", addr, buf[0], 0, 0);
    return picoboot_default_flash_page_write(addr, buf, ctx);
}

static pb_status_t op_flash_erase_prepare(const pb_addr_size_args_t *args,
                                          void *ctx) {
    pbt_log("op_flash_erase_prepare", args->addr, args->size, 0, 0);
    return picoboot_default_flash_erase_prepare(args, ctx);
}

static pb_status_t op_flash_erase(const pb_addr_size_args_t *args, void *ctx) {
    pbt_log("op_flash_erase", args->addr, args->size, 0, 0);
    return picoboot_default_flash_erase(args, ctx);
}

static pb_status_t op_write(uint32_t addr, const uint8_t *buf, uint32_t len,
                            void *ctx) {
    pbt_log("op_write", addr, len, 0, 0);
    return picoboot_default_write(addr, buf, len, ctx);
}

static pb_status_t op_otp_write(uint16_t row, uint8_t ecc, const uint8_t *buf,
                                uint32_t len, void *ctx) {
    pbt_log("op_otp_write", row, ecc, len, 0);
    return picoboot_default_otp_write(row, ecc, buf, len, ctx);
}

void pbt_ops_reset(void) {
    pbt_ops = (picoboot_ops_t){
        .exclusive_access    = op_exclusive_access,
        .exit_xip            = op_exit_xip,
        .enter_xip           = op_enter_xip,
        .reboot2_prepare     = op_reboot2_prepare,
        .reboot2_execute     = op_reboot2_execute,
        .get_info_sys        = op_get_info_sys,
        .read_prepare        = op_read_prepare,
        .read                = op_read,
        .otp_read            = op_otp_read,
        .write_prepare       = op_write_prepare,
        .flash_page_write    = op_flash_page_write,
        .flash_erase_prepare = op_flash_erase_prepare,
        .flash_erase         = op_flash_erase,
        .write               = op_write,
        .otp_write           = op_otp_write,
    };
}

// ---------------------------------------------------------------------------
// The sample custom command implementation
// ---------------------------------------------------------------------------

// picoboot_custom_ops_t states that the callee tracks its own position between
// fill calls, in its own context, because the library keeps no cursor on its
// behalf.  This is that position.
static uint32_t       s_custom_produced;
static uint32_t       s_custom_fill_calls;
static picoboot_cmd_t s_custom_last_cmd;

void pbt_custom_reset(void) {
    s_custom_produced   = 0;
    s_custom_fill_calls = 0;
    memset(&s_custom_last_cmd, 0, sizeof(s_custom_last_cmd));
}

const picoboot_cmd_t *pbt_custom_last_cmd(void) { return &s_custom_last_cmd; }

uint32_t pbt_custom_fill_calls(void) { return s_custom_fill_calls; }

static pb_status_t custom_dispatch(const picoboot_cmd_t *cmd, uint8_t *buf,
                                   uint32_t buf_len, uint32_t *bytes_written,
                                   void *ctx) {
    (void)ctx;

    // The interface documents that buf is NULL and buf_len zero here, and that
    // bytes_written is ignored.  Recording them is how a change to that would
    // be noticed.
    pbt_log("custom_dispatch", cmd->cmd_id, cmd->transfer_len,
            buf == NULL ? 0u : 1u, buf_len);
    (void)bytes_written;

    s_custom_produced = 0;

    switch (cmd->cmd_id) {
        case PBT_CUSTOM_CMD_PING:
        case PBT_CUSTOM_CMD_COUNT:
        case PBT_CUSTOM_CMD_STALL:
        case PBT_CUSTOM_CMD_ITEMS:
            return PB_STATUS_OK;
        case PBT_CUSTOM_CMD_REFUSE:
            return PBT_CUSTOM_REFUSE_STATUS;
        default:
            return PB_STATUS_UNKNOWN_CMD;
    }
}

static pb_status_t custom_fill(const picoboot_cmd_t *cmd, uint8_t *buf,
                               uint32_t max_len, uint32_t *bytes_written,
                               bool *done, void *ctx) {
    (void)ctx;

    s_custom_fill_calls++;
    s_custom_last_cmd = *cmd;
    pbt_log("custom_fill", cmd->cmd_id, max_len, s_custom_produced, 0);

    *bytes_written = 0;
    *done          = false;

    uint32_t remaining = cmd->transfer_len - s_custom_produced;
    if (remaining == 0u) {
        *done = true;
        return PB_STATUS_OK;
    }

    switch (cmd->cmd_id) {
        case PBT_CUSTOM_CMD_STALL:
            if (s_custom_produced >= PBT_CUSTOM_STALL_AFTER) {
                // Refusing partway through a transfer, which the interface says
                // stalls the command with this status.
                return PBT_CUSTOM_FILL_STATUS;
            }
            break;

        case PBT_CUSTOM_CMD_ITEMS: {
            // Fixed-size items that cannot be split.  When there is not enough
            // room for the next one, the contract is to write nothing and leave
            // done clear, meaning "call me again".
            if (max_len < PBT_CUSTOM_ITEM_SIZE) {
                return PB_STATUS_OK;
            }
            for (uint32_t i = 0; i < PBT_CUSTOM_ITEM_SIZE; i++) {
                buf[i] = (uint8_t)(s_custom_produced + i);
            }
            s_custom_produced += PBT_CUSTOM_ITEM_SIZE;
            *bytes_written = PBT_CUSTOM_ITEM_SIZE;
            *done = (s_custom_produced >= cmd->transfer_len);
            return PB_STATUS_OK;
        }

        default:
            break;
    }

    uint32_t chunk = remaining < max_len ? remaining : max_len;
    if (cmd->cmd_id == PBT_CUSTOM_CMD_STALL) {
        uint32_t before_refusal = PBT_CUSTOM_STALL_AFTER - s_custom_produced;
        if (chunk > before_refusal) {
            chunk = before_refusal;
        }
    }

    for (uint32_t i = 0; i < chunk; i++) {
        buf[i] = (uint8_t)(s_custom_produced + i);
    }
    s_custom_produced += chunk;
    *bytes_written = chunk;
    *done = (s_custom_produced >= cmd->transfer_len);
    return PB_STATUS_OK;
}

void pbt_custom_ops_reset(void) {
    pbt_custom_ops = (picoboot_custom_ops_t){
        .magic    = PBT_CUSTOM_MAGIC,
        .dispatch = custom_dispatch,
        .fill     = custom_fill,
    };
    pbt_custom_reset();
}

// ---------------------------------------------------------------------------
// Building commands
// ---------------------------------------------------------------------------

// Sequential across a scenario, so several commands produce distinguishable
// tokens without a scenario having to invent them.  Starts well clear of the
// small integers a length, a status or a zeroed field would produce, so a
// token that turns up somewhere is unmistakably a token.
#define PBT_FIRST_TOKEN 0x7A000001u

static uint32_t s_next_token;

void pbt_token_reset(void) { s_next_token = PBT_FIRST_TOKEN; }

static picoboot_cmd_t pbt_cmd_with_magic(uint32_t magic, uint8_t cmd_id,
                                         uint8_t cmd_size,
                                         uint32_t transfer_len) {
    picoboot_cmd_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.magic        = magic;
    cmd.token        = s_next_token++;
    cmd.cmd_id       = cmd_id;
    cmd.cmd_size     = cmd_size;
    cmd.transfer_len = transfer_len;
    return cmd;
}

picoboot_cmd_t pbt_cmd(uint8_t cmd_id, uint8_t cmd_size,
                       uint32_t transfer_len) {
    return pbt_cmd_with_magic(PICOBOOT_MAGIC, cmd_id, cmd_size, transfer_len);
}

picoboot_cmd_t pbt_custom_cmd(uint8_t cmd_id, uint8_t cmd_size,
                              uint32_t transfer_len) {
    return pbt_cmd_with_magic(PBT_CUSTOM_MAGIC, cmd_id, cmd_size,
                              transfer_len);
}

void pbt_args_addr_size(picoboot_cmd_t *cmd, uint32_t addr, uint32_t size) {
    pb_addr_size_args_t args = { .addr = addr, .size = size };
    memcpy(cmd->args, &args, sizeof(args));
}

void pbt_args_otp(picoboot_cmd_t *cmd, uint16_t row, uint16_t row_count,
                  uint8_t ecc) {
    pb_otp_args_t args = { .row = row, .row_count = row_count, .ecc = ecc };
    memcpy(cmd->args, &args, sizeof(args));
}

void pbt_args_get_info(picoboot_cmd_t *cmd, uint8_t info_type,
                       uint32_t param0) {
    pb_get_info_args_t args;
    memset(&args, 0, sizeof(args));
    args.info_type = info_type;
    args.param0    = param0;
    memcpy(cmd->args, &args, sizeof(args));
}

void pbt_args_reboot2(picoboot_cmd_t *cmd, uint32_t flags, uint32_t delay_ms,
                      uint32_t p0, uint32_t p1) {
    pb_reboot2_args_t args = {
        .flags = flags, .delay_ms = delay_ms, .p0 = p0, .p1 = p1
    };
    memcpy(cmd->args, &args, sizeof(args));
}

void pbt_args_exclusive_access(picoboot_cmd_t *cmd, uint8_t ea_type) {
    cmd->args[0] = ea_type;
}

// ---------------------------------------------------------------------------
// Composite helpers
// ---------------------------------------------------------------------------

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
