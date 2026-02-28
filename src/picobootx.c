// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

#include <string.h>
#include "tusb.h"
#include "picobootx_private.h"
#include "usb_plugin.h"
#include "picobootx_vendor.h"

// ---------------------------------------------------------------------------
// GET_INFO: static flag -> word count table
// ---------------------------------------------------------------------------

typedef struct {
    uint32_t flag;
    uint8_t  word_count;
} pb_info_flag_entry_t;

// Construct a table of flag -> word count from the PB_INFO_FLAG_TABLE macro,
// and static assert that no flag exceeds PB_INFO_MAX_WORDS.  This allows the
// pb_info_count_words and pb_info_words_for_flag functions to be implemented
// as simple table lookups, without needing to hardcode any flag values or
// counts in the code itself.
#define X(flag, wc, name) { flag, wc },
static const pb_info_flag_entry_t k_info_flag_table[] = { PB_INFO_FLAG_TABLE };
#undef X

#define X(flag, wc, name) _Static_assert(wc <= PB_INFO_MAX_WORDS, #name " exceeds PB_INFO_MAX_WORDS");
PB_INFO_FLAG_TABLE
#undef X

#define INFO_FLAG_TABLE_COUNT \
    (sizeof(k_info_flag_table) / sizeof(k_info_flag_table[0]))

// picobootx's states as strings for logging
const char *pb_state_to_str[] = {
    "IDLE",
    "DATA_OUT",
    "DATA_IN",
    "AWAIT_ZLP",
    "AWAIT_ACK",
    "STALLED"
};

static uint32_t pb_info_count_words(uint32_t requested) {
    uint32_t total = 0u;
    for (uint32_t i = 0u; i < INFO_FLAG_TABLE_COUNT; i++) {
        if (requested & k_info_flag_table[i].flag) {
            total += k_info_flag_table[i].word_count;
        }
    }
    return total;
}

static uint8_t pb_info_words_for_flag(uint32_t flag) {
    for (uint32_t i = 0u; i < INFO_FLAG_TABLE_COUNT; i++) {
        if (k_info_flag_table[i].flag == flag) {
            return k_info_flag_table[i].word_count;
        }
    }
    return 0u;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

static void pb_set_state(pb_state_block_t *s, pb_state_t new_state) {
    //DEBUG("STATE: %s -> %s", pb_state_to_str[s->state], pb_state_to_str[new_state]);
    s->state = new_state;
}

void pb_set_status(pb_state_block_t *s, pb_status_t code, bool in_progress) {
    s->status.token       = s->token;
    s->status.status_code = (uint32_t)code;
    s->status.cmd_id      = s->cmd_id;
    s->status.in_progress = in_progress ? 1u : 0u;
    memset(s->status.reserved, 0, sizeof(s->status.reserved));
}

void pb_stall(pb_state_block_t *s, pb_status_t code) {
    ERR("STALL: cmd_id=0x%02x status=%u", s->cmd_id, code);
    pb_set_status(s, code, false);
    picoboot_vendor_stall_endpoint(s->ep_out);
    picoboot_vendor_stall_endpoint(s->ep_in);
    pb_set_state(s, PB_STATE_STALLED);
}

void pb_send_zlp(pb_state_block_t *s) {
    pb_set_status(s, PB_STATUS_OK, false);
    pb_set_state(s, PB_STATE_AWAIT_ZLP);
    if (!picoboot_vendor_send_zlp()) {
        ERR("pb_send_zlp: picoboot_vendor_send_zlp failed");
        pb_stall(s, PB_STATUS_UNKNOWN_ERROR);
        return;
    }
}

// ---------------------------------------------------------------------------
// Command validation
// ---------------------------------------------------------------------------

static pb_status_t pb_validate_cmd(const picoboot_cmd_t *cmd,
                                   uint8_t expected_cmd_size,
                                   uint32_t expected_transfer_len) {
    if (cmd->cmd_size != expected_cmd_size) {
        LOG("Invalid cmd_size: expected %u, got %u", expected_cmd_size, cmd->cmd_size);
        return PB_STATUS_INVALID_CMD_LENGTH;
    }
    if (cmd->transfer_len != expected_transfer_len) {
        LOG("Invalid transfer_len: expected %u, got %u", expected_transfer_len, cmd->transfer_len);
        return PB_STATUS_INVALID_TRANSFER_LEN;
    }
    return PB_STATUS_OK;
}

// ---------------------------------------------------------------------------
// Command dispatch
// ---------------------------------------------------------------------------

static void pb_dispatch_read(pb_state_block_t *s, const picoboot_cmd_t *cmd) {
    const pb_addr_size_args_t *args = (const pb_addr_size_args_t *)cmd->args;

    pb_status_t st = pb_validate_cmd(cmd, 8, args->size);
    if (st != PB_STATUS_OK) {
        pb_stall(s, st);
        return;
    }

    // Check the read arguments
    if (!s->ops->validate_read) {
        pb_stall(s, PB_STATUS_UNKNOWN_CMD);
        return;
    }
    st = s->ops->validate_read(args->addr, args->size, s->ctx);
    if (st != PB_STATUS_OK) {
        pb_stall(s, st);
        return;
    }

    // Perform the read
    if (!s->ops->read) {
        pb_stall(s, PB_STATUS_UNKNOWN_CMD);
        return;
    }

    s->xfer.read.addr = args->addr;
    s->xfer.read.remaining = args->size;
    pb_set_state(s, PB_STATE_DATA_IN);
}

static void pb_dispatch_get_info(pb_state_block_t *s, const picoboot_cmd_t *cmd) {
    const pb_get_info_args_t *args = (const pb_get_info_args_t *)cmd->args;

    DEBUG("GI: info_type=0x%08x param0=0x%08x transfer_len=%u", args->info_type, args->param0, cmd->transfer_len);

    // Note that the RP2350 datasheet says that bTransferLength mst be < 255,
    // but picotool uses 256.
    if (cmd->transfer_len == 0u ||
        (cmd->transfer_len & 0x3u) != 0u ||
        cmd->transfer_len > 256u) {
        pb_stall(s, PB_STATUS_INVALID_TRANSFER_LEN);
        return;
    }

    if ((args->info_type != (uint8_t)PB_INFO_SYS) &&
        (args->info_type != (uint8_t)PB_INFO_PARTITION)) {
        pb_stall(s, PB_STATUS_UNKNOWN_CMD);
        return;
    }

    switch (args->info_type) {
        case PB_INFO_SYS:
            if (!s->ops->get_info_sys) {
                pb_stall(s, PB_STATUS_UNKNOWN_CMD);
                return;
            }

            s->xfer.get_info.remaining_flags    = args->param0;
            s->xfer.get_info.transfer_remaining = cmd->transfer_len;
            s->xfer.get_info.header_sent        = false;
            break;

        case PB_INFO_PARTITION:
            // Hack - we will just return static data instead of the real
            // partition table
            s->xfer.get_info.remaining_flags    = 0u;  // used as word index
            s->xfer.get_info.transfer_remaining = cmd->transfer_len;
            s->xfer.get_info.header_sent        = true; // signals raw partition mode
            pb_set_state(s, PB_STATE_DATA_IN);
            break;

        default:
            LOG("Unsupported info_type: 0x%02x", args->info_type);
            pb_stall(s, PB_STATUS_UNKNOWN_CMD);
            return;
    }

    pb_set_state(s, PB_STATE_DATA_IN);
}

static void pb_dispatch_reboot2(pb_state_block_t *s, const picoboot_cmd_t *cmd) {
    pb_status_t st = pb_validate_cmd(cmd, 0x10u, 0x00000000u);
    if (st != PB_STATUS_OK) {
        pb_stall(s, st);
        return;
    }

    if (!s->ops->reboot2_prepare) {
        pb_stall(s, PB_STATUS_UNKNOWN_CMD);
        return;
    }

    const pb_reboot2_args_t *args = (const pb_reboot2_args_t *)cmd->args;
    s->reboot2_args = *args;

    st = s->ops->reboot2_prepare(&s->reboot2_args, s->ctx);
    if (st != PB_STATUS_OK) {
        pb_stall(s, st);
        return;
    }

    pb_send_zlp(s);

    // reboot2_execute call is deferred until ZLP completion callback
}

static void pb_dispatch_exclusive_access(pb_state_block_t *s, const picoboot_cmd_t *cmd) {
    pb_status_t st = pb_validate_cmd(cmd, 0x01u, 0x00000000u);
    if (st != PB_STATUS_OK) {
        pb_stall(s, st);
        return;
    }

    if (s->ops->exclusive_access) {
        const pb_exclusive_access_args_t *args = (const pb_exclusive_access_args_t *)cmd->args;
        st = s->ops->exclusive_access(args, s->ctx);
        if (st != PB_STATUS_OK) {
            pb_stall(s, st);
            return;
        }
    }

    pb_send_zlp(s);
}

static void pb_dispatch_exit_xip(pb_state_block_t *s, const picoboot_cmd_t *cmd) {
    pb_status_t st = pb_validate_cmd(cmd, 0x00u, 0x00000000u);
    if (st != PB_STATUS_OK) {
        pb_stall(s, st);
        return;
    }

    if (s->ops->exit_xip) {
        st = s->ops->exit_xip(s->ctx);
        if (st != PB_STATUS_OK) {
            pb_stall(s, st);
            return;
        }
    }

    pb_send_zlp(s);
}

static void pb_dispatch_enter_xip(pb_state_block_t *s, const picoboot_cmd_t *cmd) {
    pb_status_t st = pb_validate_cmd(cmd, 0x00u, 0x00000000u);
    if (st != PB_STATUS_OK) {
        pb_stall(s, st);
        return;
    }

    if (s->ops->enter_xip) {
        st = s->ops->enter_xip(s->ctx);
        if (st != PB_STATUS_OK) {
            pb_stall(s, st);
            return;
        }
    }

    pb_send_zlp(s);
}

static void pb_dispatch_flash_erase(pb_state_block_t *s, const picoboot_cmd_t *cmd) {
    pb_status_t st = pb_validate_cmd(cmd, 0x08u, 0x00000000u);
    if (st != PB_STATUS_OK) {
        pb_stall(s, st);
        return;
    }

    if (!s->ops->flash_erase) {
        pb_stall(s, PB_STATUS_UNKNOWN_CMD);
        return;
    }

    const pb_addr_size_args_t *args = (const pb_addr_size_args_t *)cmd->args;

    DEBUG("f erase: addr=0x%08x size=%u", args->addr, args->size);

    st = s->ops->flash_erase(args, s->ctx);
    if (st != PB_STATUS_OK) {
        pb_stall(s, st);
        return;
    }

    pb_send_zlp(s);
}

static void pb_dispatch_write(pb_state_block_t *s, const picoboot_cmd_t *cmd) {
    const pb_addr_size_args_t *args = (const pb_addr_size_args_t *)cmd->args;

    pb_status_t st = pb_validate_cmd(cmd, 0x08u, args->size);
    if (st != PB_STATUS_OK) {
        pb_stall(s, st);
        return;
    }

    if (!s->ops->write || !s->flash_write_buf) {
        pb_stall(s, PB_STATUS_UNKNOWN_CMD);
        return;
    }

    DEBUG("write: addr=0x%08x size=%u", args->addr, args->size);

    // Not yet implemented
    pb_stall(s, PB_STATUS_UNKNOWN_CMD);
}

static void pb_dispatch_otp_read(pb_state_block_t *s, const picoboot_cmd_t *cmd) {
    const pb_otp_args_t *args = (const pb_otp_args_t *)cmd->args;

    uint32_t expected_transfer_len;
    if (args->ecc) {
        expected_transfer_len = args->row_count * 2u;
    } else {
        expected_transfer_len = args->row_count * 4u;
    }
    pb_status_t st = pb_validate_cmd(cmd, 0x05u, expected_transfer_len);
    if (st != PB_STATUS_OK) {
        pb_stall(s, st);
        return;
    }

    if (!s->ops->otp_read) {
        pb_stall(s, PB_STATUS_UNKNOWN_CMD);
        return;
    }

    DEBUG("otp read: row=%u row_count=%u ecc=%d", args->row, args->row_count, args->ecc);

    s->xfer.otp_read.current_row = args->row;
    s->xfer.otp_read.rows_remaining = args->row_count;
    s->xfer.otp_read.ecc = args->ecc;
    s->xfer.otp_read.transfer_remaining = expected_transfer_len;
    pb_set_state(s, PB_STATE_DATA_IN);
}

static void pb_dispatch_otp_write(pb_state_block_t *s, const picoboot_cmd_t *cmd) {
    const pb_otp_args_t *args = (const pb_otp_args_t *)cmd->args;

    uint32_t expected_transfer_len;
    if (args->ecc) {
        expected_transfer_len = args->row_count * 2u;
    } else {
        expected_transfer_len = args->row_count * 4u;
    }
    pb_status_t st = pb_validate_cmd(cmd, 0x05, expected_transfer_len);
    if (st != PB_STATUS_OK) {
        pb_stall(s, st);
        return;
    }

    if (!s->ops->otp_write) {
        pb_stall(s, PB_STATUS_UNKNOWN_CMD);
        return;
    }

    DEBUG("otp write: row=%u row_count=%u ecc=%d", args->row, args->row_count, args->ecc);

    // Not yet implemented
    pb_stall(s, PB_STATUS_UNKNOWN_CMD);
}

const char *command_to_str(pb_cmd_id_t cmd) {
    switch (cmd) {
        case PB_CMD_EXCLUSIVE_ACCESS: return "EXCLUSIVE_ACCESS";
        case PB_CMD_REBOOT:           return "REBOOT";
        case PB_CMD_FLASH_ERASE:      return "FLASH_ERASE";
        case PB_CMD_WRITE:            return "WRITE";
        case PB_CMD_EXIT_XIP:         return "EXIT_XIP";
        case PB_CMD_ENTER_XIP:        return "ENTER_XIP";
        case PB_CMD_EXEC:             return "EXEC";
        case PB_CMD_VECTORIZE_FLASH:  return "VECTORIZE_FLASH";
        case PB_CMD_REBOOT2:          return "REBOOT2";
        case PB_CMD_OTP_WRITE:        return "OTP_WRITE";
        case PB_CMD_READ:             return "READ";
        case PB_CMD_GET_INFO:         return "GET_INFO";
        case PB_CMD_OTP_READ:         return "OTP_READ";
        default:                     return "UNKNOWN";
    }
}

static void pb_dispatch_cmd(pb_state_block_t *s, const picoboot_cmd_t *cmd) {
    s->token  = cmd->token;
    s->cmd_id = cmd->cmd_id;

    DEBUG("%s id=0x%02x token=0x%08x tlen=%u",
          command_to_str((pb_cmd_id_t)cmd->cmd_id), cmd->cmd_id, cmd->token, cmd->transfer_len);

    switch ((pb_cmd_id_t)cmd->cmd_id) {
        case PB_CMD_EXCLUSIVE_ACCESS:
            pb_dispatch_exclusive_access(s, cmd);
            break;

        case PB_CMD_EXIT_XIP:
            pb_dispatch_exit_xip(s, cmd);
            break;

        case PB_CMD_ENTER_XIP:
            pb_dispatch_enter_xip(s, cmd);
            break;

        case PB_CMD_READ:
            pb_dispatch_read(s, cmd);
            break;

        case PB_CMD_GET_INFO:
            pb_dispatch_get_info(s, cmd);
            break;

        case PB_CMD_REBOOT2:
            pb_dispatch_reboot2(s, cmd);
            break;

        // Not supported on RP2350.  Reject
        case PB_CMD_REBOOT:
        case PB_CMD_EXEC:
        case PB_CMD_VECTORIZE_FLASH:
            pb_stall(s, PB_STATUS_UNKNOWN_CMD);
            break;

        case PB_CMD_FLASH_ERASE:
            pb_dispatch_flash_erase(s, cmd);
            break;

        case PB_CMD_WRITE:
            pb_dispatch_write(s, cmd);
            break;

        case PB_CMD_OTP_READ:
            pb_dispatch_otp_read(s, cmd);
            break;

        case PB_CMD_OTP_WRITE:
            pb_dispatch_otp_write(s, cmd);
            break;

        default:
            ERR("Unknown command ID 0x%02x received", cmd->cmd_id);
            pb_stall(s, PB_STATUS_UNKNOWN_CMD);
            break;
    }
}

// ---------------------------------------------------------------------------
// State machine handlers
// ---------------------------------------------------------------------------

static void pb_task_idle(pb_state_block_t *s) {
    if (picoboot_vendor_available() < (uint32_t)PICOBOOT_CMD_LEN) {
        return;
    }

    picoboot_cmd_t cmd;
    uint32_t n = picoboot_vendor_read(&cmd, sizeof(cmd));
    if (n != PICOBOOT_CMD_LEN) {
        ERR("pb_task_idle: short read %u", n);
        pb_stall(s, PB_STATUS_UNKNOWN_ERROR);
        return;
    }

    if (cmd.magic == PICOBOOT_MAGIC) {
        pb_dispatch_cmd(s, &cmd);
    } else if (s->custom && cmd.magic == s->custom->magic) {
        s->token  = cmd.token;
        s->cmd_id = cmd.cmd_id;
        uint32_t bytes_written = 0u;
        pb_status_t st = s->custom->dispatch(&cmd, NULL, 0u, &bytes_written, s->ctx);
        if (st != PB_STATUS_OK) {
            pb_stall(s, st);
        } else {
            pb_send_zlp(s);
        }
    } else {
        s->token  = cmd.token;
        s->cmd_id = cmd.cmd_id;
        ERR("pb_task_idle: unknown magic 0x%08x", cmd.magic);
        pb_stall(s, PB_STATUS_UNKNOWN_CMD);
    }
}

static void pb_read_data_in(pb_state_block_t *s) {
    pb_in_read_t *r = &s->xfer.read;

    while (r->remaining > 0u) {
        uint32_t space = picoboot_vendor_write_available();
        if (space == 0u) {
            picoboot_vendor_write_flush();
            return;
        }

        uint8_t  buf[64];
        uint32_t chunk = r->remaining < sizeof(buf) ? r->remaining : sizeof(buf);
        if (chunk > space) chunk = space;

        pb_status_t st = s->ops->read(r->addr, buf, chunk, s->ctx);
        if (st != PB_STATUS_OK) {
            pb_stall(s, st);
            return;
        }

        uint32_t written = picoboot_vendor_write(buf, chunk);
        if (written != chunk) {
            ERR("pb_read_data_in: write short %u/%u", written, chunk);
            pb_stall(s, PB_STATUS_UNKNOWN_ERROR);
            return;
        }
        r->addr      += chunk;
        r->remaining -= chunk;
    }

    picoboot_vendor_write_flush();

    pb_set_state(s, PB_STATE_AWAIT_ACK);
}

static void pb_info_data_in(pb_state_block_t *s) {
    pb_in_get_info_t *gi = &s->xfer.get_info;

    #define K_PARTITION_DATA_COUNT 5
    static const uint32_t k_partition_data[K_PARTITION_DATA_COUNT] = {
        0x00000004u, 0x00000031u, 0x00000000u, 0xffffe000u, 0xfc078000u,
    };

    // For PB_INFO_PARTITION, header_sent is repurposed as a "raw mode" flag
    // and remaining_flags is repurposed as a word index into k_partition_data.
    if (s->cmd_id == (uint8_t)PB_CMD_GET_INFO && gi->header_sent) {
        while (gi->transfer_remaining > 0u) {
            uint32_t space = picoboot_vendor_write_available();
            if (space < sizeof(uint32_t)) {
                picoboot_vendor_write_flush();
                return;
            }

            uint32_t word = (gi->remaining_flags < K_PARTITION_DATA_COUNT)
                            ? k_partition_data[gi->remaining_flags]
                            : 0u;
            uint32_t written = picoboot_vendor_write((const uint8_t *)&word, sizeof(uint32_t));
            if (written != sizeof(uint32_t)) {
                pb_stall(s, PB_STATUS_UNKNOWN_ERROR);
                return;
            }
            gi->remaining_flags++;
            gi->transfer_remaining -= sizeof(uint32_t);
        }
        picoboot_vendor_write_flush();
        pb_set_state(s, PB_STATE_AWAIT_ACK);
        return;
    }

    if (!gi->header_sent) {
        if (picoboot_vendor_write_available() < sizeof(uint32_t)) {
            picoboot_vendor_write_flush();
            return;
        }
        uint32_t word_count = pb_info_count_words(gi->remaining_flags);
        uint32_t written = picoboot_vendor_write((const uint8_t *)&word_count, sizeof(word_count));
        if (written != sizeof(word_count)) {
            ERR("pb_task_data_in: header write short %u", written);
            pb_stall(s, PB_STATUS_UNKNOWN_ERROR);
            return;
        }
        gi->transfer_remaining -= sizeof(uint32_t);
        gi->header_sent = true;

        if (gi->transfer_remaining == 0u || gi->remaining_flags == 0u) {
            pb_set_state(s, PB_STATE_AWAIT_ACK);
            return;
        }
    }

    while (gi->remaining_flags != 0u && gi->transfer_remaining > 0u) {
        uint32_t flag = gi->remaining_flags & (~gi->remaining_flags + 1u);
        uint8_t  wc   = pb_info_words_for_flag(flag);

        if (wc == 0u) {
            gi->remaining_flags &= ~flag;
            continue;
        }

        uint32_t data_bytes = (uint32_t)wc * sizeof(uint32_t);

        if (picoboot_vendor_write_available() < data_bytes) {
            picoboot_vendor_write_flush();
            return;
        }

        uint8_t  buf[PB_INFO_MAX_WORDS * sizeof(uint32_t)];
        uint32_t bytes_written = 0u;

        pb_status_t st = s->ops->get_info_sys(flag, buf, data_bytes, &bytes_written, s->ctx);
        if (st != PB_STATUS_OK) {
            pb_stall(s, st);
            return;
        }

        uint32_t written = picoboot_vendor_write(buf, bytes_written);
        if (written != bytes_written) {
            ERR("pb_task_data_in: get_info write short %u/%u", written, bytes_written);
            pb_stall(s, PB_STATUS_UNKNOWN_ERROR);
            return;
        }

        gi->remaining_flags    &= ~flag;
        gi->transfer_remaining  = (gi->transfer_remaining > bytes_written)
                                  ? gi->transfer_remaining - bytes_written
                                  : 0u;
    }

    while (gi->transfer_remaining > 0u) {
        uint32_t space = picoboot_vendor_write_available();
        if (space == 0u) {
            picoboot_vendor_write_flush();
            return;
        }

        uint8_t  zeroes[16] = {0};
        uint32_t chunk = gi->transfer_remaining < sizeof(zeroes)
                         ? gi->transfer_remaining : sizeof(zeroes);
        if (chunk > space) chunk = space;
        uint32_t written = picoboot_vendor_write(zeroes, chunk);
        if (written != chunk) {
            ERR("pb_task_data_in: pad write short %u/%u", written, chunk);
            pb_stall(s, PB_STATUS_UNKNOWN_ERROR);
            return;
        }
        gi->transfer_remaining -= chunk;
    }

    picoboot_vendor_write_flush();
    pb_set_state(s, PB_STATE_AWAIT_ACK);
}

static void pb_otp_read_data_in(pb_state_block_t *s) {
    pb_in_otp_read_t *or = &s->xfer.otp_read;

    while (or->rows_remaining > 0u) {
        uint32_t space = picoboot_vendor_write_available();
        if (space == 0u) {
            picoboot_vendor_write_flush();
            return;
        }

        uint8_t  buf[64];
        uint32_t row_size = or->ecc ? 2u : 4u;
        uint32_t total_row_bytes = row_size * or->rows_remaining;
        uint32_t chunk = total_row_bytes < sizeof(buf) ? total_row_bytes : sizeof(buf);
        if (chunk > space) chunk = space;

        pb_status_t st = s->ops->otp_read(
            or->current_row,
            or->ecc,
            buf,
            chunk,
            s->ctx
        );
        if (st != PB_STATUS_OK) {
            pb_stall(s, st);
            return;
        }

        uint32_t written = picoboot_vendor_write(buf, chunk);
        if (written != chunk) {
            ERR("pb_otp_read_data_in: otp read write short %u/%u", written, chunk);
            pb_stall(s, PB_STATUS_UNKNOWN_ERROR);
            return;
        }
        uint32_t written_rows = written / row_size;
        or->current_row += written_rows;
        or->rows_remaining -= written_rows;
    }

    picoboot_vendor_write_flush();

    pb_set_state(s, PB_STATE_AWAIT_ACK);
}

static void pb_task_data_in(pb_state_block_t *s) {
    switch (s->cmd_id) {
        case (uint8_t)PB_CMD_READ:
            pb_read_data_in(s);
            break;

        case (uint8_t)PB_CMD_GET_INFO:
            pb_info_data_in(s);
            break;

        case (uint8_t)PB_CMD_OTP_READ:
            // Not yet implemented
            pb_otp_read_data_in(s);
            break;

        default:
            ERR("pb_task_data_in: unexpected cmd_id 0x%02x", s->cmd_id);
            pb_stall(s, PB_STATUS_UNKNOWN_ERROR);
            break;
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void picoboot_init(pb_state_block_t            *state,
                   const picoboot_ops_t        *ops,
                   const picoboot_custom_ops_t *custom,
                   uint8_t                     *flash_write_buf,
                   uint8_t                      rhport,
                   uint8_t                      ep_out,
                   uint8_t                      ep_in,
                   void                        *ctx) {
    memset(state, 0, sizeof(*state));
    state->ops             = ops;
    state->custom          = custom;
    state->flash_write_buf = flash_write_buf;
    state->rhport          = rhport;
    state->ep_out          = ep_out;
    state->ep_in           = ep_in;
    state->ctx             = ctx;
    state->state           = PB_STATE_IDLE;
}

void picoboot_task(pb_state_block_t *state) {
    switch (state->state) {
        case PB_STATE_IDLE:
            pb_task_idle(state);
            break;
        case PB_STATE_DATA_IN:
            pb_task_data_in(state);
            break;
        case PB_STATE_AWAIT_ZLP:
            // Transition to IDLE happens in picoboot_vendor_tx_cb()
            break;
        case PB_STATE_AWAIT_ACK:
            // Transition to IDLE happens in picoboot_vendor_rx_cb()
            break;
        case PB_STATE_DATA_OUT:
            // Not yet implemented
            break;
        case PB_STATE_STALLED:
            break;
    }
}

void picoboot_tx_cb(
    pb_state_block_t *state,
    uint32_t sent_bytes
) {
    (void)sent_bytes;

    if (state->state != PB_STATE_AWAIT_ZLP) {
        return;
    }

    if (state->cmd_id == (uint8_t)PB_CMD_REBOOT2) {
        if (state->ops->reboot2_execute) {
            state->ops->reboot2_execute(&state->reboot2_args, state->ctx);
        }
    }

    // For the non-reboot2 case (which should never get this far)
    pb_set_state(state, PB_STATE_IDLE);
}

void picoboot_rx_cb(
    pb_state_block_t *state,
    uint32_t available_bytes
) {
    if (available_bytes <= 1) {
        // Both 0 and 1 byte values are considered ZLP by this stack in case
        // the host implementation doesn't support sending real ZLPs.
        if (state->state == PB_STATE_AWAIT_ACK) {
            pb_set_status(state, PB_STATUS_OK, false);
            pb_set_state(state, PB_STATE_IDLE);
        }

        // No need to actually read the 0/1 byte value, just clear the OUT
        // endpoint buffer
        picoboot_vendor_read_clear();
    }
}

bool picoboot_control_xfer_cb(
    pb_state_block_t *state,
    uint8_t rhport,
    uint8_t stage,
    tusb_control_request_t const *req
) {
    if ((req->bmRequestType_bit.type != TUSB_REQ_TYPE_CLASS &&
         req->bmRequestType_bit.type != TUSB_REQ_TYPE_VENDOR) ||
        req->bmRequestType_bit.recipient != TUSB_REQ_RCPT_INTERFACE) {
        DEBUG("CTRL: ignore type=%u recipient=%u",
            req->bmRequestType_bit.type, req->bmRequestType_bit.recipient);
        return false;
    }

#if 0
#define USB_DPRAM_BASE      0x50100000u
#define EP3_OUT_BUF_CTRL    (*(volatile uint32_t *)(USB_DPRAM_BASE + 0x80 + (3 * 8) + 4))
#define USB_BUFF_STATUS     (*(volatile uint32_t *)(0x50110058u))

// Key bits in BUF_CTRL
#define BUF_CTRL_AVAIL      (1u << 10)
#define BUF_CTRL_STALL      (1u << 11)
#define BUF_CTRL_FULL       (1u << 15)
#endif

    switch (req->bRequest) {
        case PICOBOOT_BREQUEST_INTERFACE_RESET:
            if (stage == CONTROL_STAGE_SETUP) {
                DEBUG("CTRL: IR");

                // Unstall endpoints (if stalled - this function will check
                // before unstalling)
                picoboot_vendor_unstall_endpoint(state->ep_out);
                picoboot_vendor_unstall_endpoint(state->ep_in);

                // Clear both endpoints.  This ensures any pending read data
                // is read and thrown away, and also that the write buffer is
                // cleared and both endpoints are ready for the next command.
                picoboot_vendor_read_clear();
                picoboot_vendor_write_clear();
                // Clear out state
                pb_set_state(state, PB_STATE_IDLE);
                pb_set_status(state, PB_STATUS_OK, false);

#if 0
                DEBUG("bc3=0x%08lx a=%u s=%u f=%u bs=0x%08lx",
                    EP3_OUT_BUF_CTRL,
                    (EP3_OUT_BUF_CTRL & BUF_CTRL_AVAIL) ? 1 : 0,
                    (EP3_OUT_BUF_CTRL & BUF_CTRL_STALL) ? 1 : 0,
                    (EP3_OUT_BUF_CTRL & BUF_CTRL_FULL)  ? 1 : 0,
                    USB_BUFF_STATUS);
                for (volatile int ii = 0; ii < 10000000; ii++);
#endif

                return tud_control_status(rhport, req);
            }
            return true;

        case PICOBOOT_BREQUEST_GET_CMD_STATUS:
            if (stage == CONTROL_STAGE_SETUP) {
                DEBUG("CTRL: GCS s=%u sc=%u t=0x%08x ip=%u",
                    stage, state->status.status_code, state->status.token, state->status.in_progress);
                return tud_control_xfer(rhport, req,
                                        &state->status,
                                        sizeof(state->status));
            }
            return true;

        default:
            DEBUG("CTRL: unknown request 0x%02x", req->bRequest);
            return false;
    }
}

