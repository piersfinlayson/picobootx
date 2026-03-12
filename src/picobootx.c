// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

#include <string.h>
#include "tusb.h"
#include "picobootx_private.h"
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

#define USB_DPRAM_BASE      0x50100000u
#define EP3_OUT_BUF_CTRL    (*(volatile uint32_t *)(USB_DPRAM_BASE + 0x80 + (3 * 8) + 4))
#define EP83_IN_BUF_CTRL    (*(volatile uint32_t *)(USB_DPRAM_BASE + 0x80 + (4 * 8)))
#define USB_BUFF_STATUS     (*(volatile uint32_t *)(0x50110058u))

// Key bits in BUF_CTRL
#define BUF_CTRL_AVAIL      (1u << 10)
#define BUF_CTRL_STALL      (1u << 11)
#define BUF_CTRL_FULL       (1u << 15)

static void pb_set_state(pb_state_block_t *s, pb_state_t new_state) {
    DEBUG("STATE: %s -> %s", pb_state_to_str[s->state], pb_state_to_str[new_state]);
    s->state = new_state;
    DEBUG("bc3=0x%08lx a=%u s=%u f=%u bs=0x%08lx",
        EP3_OUT_BUF_CTRL,
        (EP3_OUT_BUF_CTRL & BUF_CTRL_AVAIL) ? 1 : 0,
        (EP3_OUT_BUF_CTRL & BUF_CTRL_STALL) ? 1 : 0,
        (EP3_OUT_BUF_CTRL & BUF_CTRL_FULL)  ? 1 : 0,
        USB_BUFF_STATUS);
    DEBUG("bc84=0x%08lx a=%u s=%u f=%u bs=0x%08lx",
        EP83_IN_BUF_CTRL,
        (EP83_IN_BUF_CTRL & BUF_CTRL_AVAIL) ? 1 : 0,
        (EP83_IN_BUF_CTRL & BUF_CTRL_STALL) ? 1 : 0,
        (EP83_IN_BUF_CTRL & BUF_CTRL_FULL)  ? 1 : 0,
        USB_BUFF_STATUS);
    //for (volatile int ii = 0; ii < 10000000; ii++);

}

void pb_set_status(pb_state_block_t *s, pb_status_t code, bool in_progress) {
    s->status.token       = s->token;
    s->status.status_code = (uint32_t)code;
    s->status.cmd_id      = s->cmd_id;
    s->status.in_progress = in_progress ? 1u : 0u;
    memset(s->status.reserved, 0, sizeof(s->status.reserved));
}

void pb_stall(pb_state_block_t *s, pb_status_t code) {
    // Stall is used per the picoboot specification (RP2350 datasheet 5.6.4)
    // if the command received was invalid or not recognised.  Both bulk
    // endpoints are stalled.  The specification also implies the stall
    // condition is set if a command failed (set GET_COMMAND_STATUS, RP2350
    // datasheet 5.6.5.2).
    // The RP2350 bootrom concurs, and sets in_progress to false.
    ERR("STALL: cmd_id=0x%02x status=%u", s->cmd_id, code);
    pb_set_status(s, code, false);
    picoboot_vendor_stall_endpoint(s->ep_out);
    picoboot_vendor_stall_endpoint(s->ep_in);
    s->status.in_progress = false;
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

// ---------------------------------------------------------------------------
// Data-in prepare functions
// ---------------------------------------------------------------------------

static pb_status_t pb_read_prepare(
    pb_state_block_t *s,
    const picoboot_cmd_t *cmd,
    void *ctx
) {
    if (!s->ops->read_prepare || !s->ops->read) {
        return PB_STATUS_UNKNOWN_CMD;
    }
    const pb_addr_size_args_t *args = (const pb_addr_size_args_t *)cmd->args;
    pb_status_t st = s->ops->read_prepare(args->addr, args->size, ctx);
    if (st != PB_STATUS_OK) {
        return st;
    }
    s->xfer.read.addr      = args->addr;
    s->xfer.read.remaining = args->size;
    return PB_STATUS_OK;
}

static pb_status_t pb_get_info_prepare(
    pb_state_block_t *s,
    const picoboot_cmd_t *cmd,
    void *ctx
) {
    (void)ctx;
    if (cmd->transfer_len == 0u ||
        (cmd->transfer_len & 0x3u) != 0u ||
        cmd->transfer_len > 256u) {
        return PB_STATUS_INVALID_TRANSFER_LEN;
    }
    const pb_get_info_args_t *args = (const pb_get_info_args_t *)cmd->args;
    switch (args->info_type) {
        case PB_INFO_SYS:
            if (!s->ops->get_info_sys) {
                return PB_STATUS_UNKNOWN_CMD;
            }
            s->xfer.get_info.is_partition       = false;
            s->xfer.get_info.header_sent        = false;
            s->xfer.get_info.remaining_flags    = args->param0;
            s->xfer.get_info.transfer_remaining = cmd->transfer_len;
            break;
        case PB_INFO_PARTITION:
            s->xfer.get_info.is_partition       = true;
            s->xfer.get_info.header_sent        = false;
            s->xfer.get_info.remaining_flags    = 0u;
            s->xfer.get_info.transfer_remaining = cmd->transfer_len;
            break;
        default:
            LOG("Unsupported info_type: 0x%02x", args->info_type);
            return PB_STATUS_UNKNOWN_CMD;
    }
    return PB_STATUS_OK;
}

static pb_status_t pb_otp_read_prepare(
    pb_state_block_t *s,
    const picoboot_cmd_t *cmd,
    void *ctx
) {
    (void)ctx;
    if (!s->ops->otp_read) {
        return PB_STATUS_UNKNOWN_CMD;
    }
    const pb_otp_args_t *args = (const pb_otp_args_t *)cmd->args;
    s->xfer.otp.current_row        = args->row;
    s->xfer.otp.rows_remaining     = args->row_count;
    s->xfer.otp.ecc                = args->ecc;
    s->xfer.otp.transfer_remaining = cmd->transfer_len;
    return PB_STATUS_OK;
}

// ---------------------------------------------------------------------------
// Data-in fill functions
// ---------------------------------------------------------------------------

static pb_status_t pb_read_fill(
    pb_state_block_t *s,
    uint8_t *buf,
    uint32_t max_len,
    uint32_t *bytes_written,
    bool *done,
    void *ctx
) {
    pb_in_read_t *r = &s->xfer.read;
    *bytes_written = 0u;
    *done = false;

    if (r->remaining == 0u) {
        *done = true;
        return PB_STATUS_OK;
    }

    uint32_t chunk = r->remaining < max_len ? r->remaining : max_len;
    pb_status_t st = s->ops->read(r->addr, buf, chunk, ctx);
    if (st != PB_STATUS_OK) {
        return st;
    }
    r->addr        += chunk;
    r->remaining   -= chunk;
    *bytes_written  = chunk;
    *done           = (r->remaining == 0u);
    return PB_STATUS_OK;
}

#define K_PARTITION_DATA_COUNT 5u
static const uint32_t k_partition_data[K_PARTITION_DATA_COUNT] = {
    0x00000004u, 0x00000031u, 0x00000000u, 0xffffe000u, 0xfc078000u,
};

static pb_status_t pb_get_info_fill(
    pb_state_block_t *s,
    uint8_t *buf,
    uint32_t max_len,
    uint32_t *bytes_written,
    bool *done,
    void *ctx
) {
    (void)ctx;
    pb_in_get_info_t *gi = &s->xfer.get_info;
    *bytes_written = 0u;
    *done = false;

    if (gi->transfer_remaining == 0u) {
        *done = true;
        return PB_STATUS_OK;
    }

    if (max_len < sizeof(uint32_t)) {
        return PB_STATUS_OK;  // signal retry
    }

    // PARTITION mode: stream one word of static data per call
    if (gi->is_partition) {
        uint32_t word = (gi->remaining_flags < K_PARTITION_DATA_COUNT)
                        ? k_partition_data[gi->remaining_flags]
                        : 0u;
        memcpy(buf, &word, sizeof(uint32_t));
        gi->remaining_flags++;
        gi->transfer_remaining -= sizeof(uint32_t);
        *bytes_written = sizeof(uint32_t);
        *done = (gi->transfer_remaining == 0u);
        return PB_STATUS_OK;
    }

    // SYS mode: send header word count first
    if (!gi->header_sent) {
        uint32_t word_count = pb_info_count_words(gi->remaining_flags);
        memcpy(buf, &word_count, sizeof(uint32_t));
        gi->transfer_remaining -= sizeof(uint32_t);
        gi->header_sent = true;
        *bytes_written = sizeof(uint32_t);
        if (gi->transfer_remaining == 0u || gi->remaining_flags == 0u) {
            gi->transfer_remaining = 0u;
            *done = true;
        }
        return PB_STATUS_OK;
    }

    // SYS mode: send flag data, skipping unknown flags internally
    while (gi->remaining_flags != 0u && gi->transfer_remaining > 0u) {
        uint32_t flag = gi->remaining_flags & (~gi->remaining_flags + 1u);
        uint8_t  wc   = pb_info_words_for_flag(flag);
        if (wc == 0u) {
            gi->remaining_flags &= ~flag;
            continue;
        }
        uint32_t data_bytes = (uint32_t)wc * sizeof(uint32_t);
        if (max_len < data_bytes) {
            return PB_STATUS_OK;  // signal retry without advancing state
        }
        pb_status_t st = s->ops->get_info_sys(flag, buf, data_bytes, bytes_written, ctx);
        if (st != PB_STATUS_OK) {
            return st;
        }
        if (data_bytes != *bytes_written) {
            ERR("get_info_sys for flag 0x%08x wrote %u bytes, expected %u",
                flag, *bytes_written, data_bytes);
            return PB_STATUS_UNKNOWN_ERROR;
        }
        gi->remaining_flags    &= ~flag;
        gi->transfer_remaining  = (gi->transfer_remaining > *bytes_written)
                                  ? gi->transfer_remaining - *bytes_written
                                  : 0u;
        *done = (gi->remaining_flags == 0u && gi->transfer_remaining == 0u);
        return PB_STATUS_OK;
    }

    // SYS mode: pad remaining transfer with zeros
    uint32_t chunk = gi->transfer_remaining < max_len ? gi->transfer_remaining : max_len;
    memset(buf, 0, chunk);
    gi->transfer_remaining -= chunk;
    *bytes_written = chunk;
    *done = (gi->transfer_remaining == 0u);
    return PB_STATUS_OK;
}

static pb_status_t pb_otp_read_fill(
    pb_state_block_t *s,
    uint8_t *buf,
    uint32_t max_len,
    uint32_t *bytes_written,
    bool *done,
    void *ctx
) {
    pb_otp_access_t *otp = &s->xfer.otp;
    *bytes_written = 0u;
    *done = false;

    if (otp->rows_remaining == 0u) {
        *done = true;
        return PB_STATUS_OK;
    }

    uint32_t row_size        = otp->ecc ? 2u : 4u;
    uint32_t total_remaining = row_size * otp->rows_remaining;
    uint32_t chunk           = total_remaining < max_len ? total_remaining : max_len;
    chunk = (chunk / row_size) * row_size;  // round down to row boundary

    if (chunk == 0u) {
        return PB_STATUS_OK;  // signal retry
    }

    pb_status_t st = s->ops->otp_read(otp->current_row, otp->ecc, buf, chunk, ctx);
    if (st != PB_STATUS_OK) {
        return st;
    }

    uint32_t rows_done  = chunk / row_size;
    otp->current_row    += (uint16_t)rows_done;
    otp->rows_remaining -= (uint16_t)rows_done;
    *bytes_written      = chunk;
    *done               = (otp->rows_remaining == 0u);
    return PB_STATUS_OK;
}

static pb_status_t pb_otp_write_prepare(
    pb_state_block_t *s,
    const picoboot_cmd_t *cmd,
    void *ctx
) {
    (void)ctx;
    if (!s->ops->otp_write) {
        return PB_STATUS_UNKNOWN_CMD;
    }
    const pb_otp_args_t *args = (const pb_otp_args_t *)cmd->args;
    s->xfer.otp.current_row        = args->row;
    s->xfer.otp.rows_remaining     = args->row_count;
    s->xfer.otp.ecc                = args->ecc;
    s->xfer.otp.transfer_remaining = cmd->transfer_len;
    return PB_STATUS_OK;
}

static pb_status_t pb_otp_write_consume(
    pb_state_block_t *s,
    const uint8_t *buf,
    uint32_t len,
    bool *done,
    void *ctx
) {
    pb_otp_access_t *otp = &s->xfer.otp;
    *done = false;

    uint32_t row_size = otp->ecc ? 2u : 4u;

    // len must be a multiple of row_size — should be guaranteed by transfer_len validation
    uint32_t rows = len / row_size;
    if (rows == 0u) {
        return PB_STATUS_OK;
    }

    pb_status_t st = s->ops->otp_write(otp->current_row, otp->ecc, buf, len, ctx);
    if (st != PB_STATUS_OK) {
        return st;
    }

    otp->current_row       += (uint16_t)rows;
    otp->rows_remaining    -= (uint16_t)rows;
    otp->transfer_remaining = (otp->transfer_remaining > len)
                              ? otp->transfer_remaining - len
                              : 0u;
    *done = (otp->rows_remaining == 0u);
    return PB_STATUS_OK;
}

// ---------------------------------------------------------------------------
// Data-out prepare and consume functions
// ---------------------------------------------------------------------------

static pb_status_t pb_write_prepare(
    pb_state_block_t *s,
    const picoboot_cmd_t *cmd,
    void *ctx
) {
    if (!s->ops->write_prepare) {
        return PB_STATUS_UNKNOWN_CMD;
    }
    const pb_addr_size_args_t *args = (const pb_addr_size_args_t *)cmd->args;
    bool is_flash = false;
    pb_status_t st = s->ops->write_prepare(args->addr, args->size, &is_flash, ctx);
    if (st != PB_STATUS_OK) {
        return st;
    }
    if (is_flash) {
        if (!s->flash_write_buf || !s->ops->flash_page_write) {
            return PB_STATUS_NOT_PERMITTED;
        }
    } else {
        if (!s->ops->write) {
            return PB_STATUS_UNKNOWN_CMD;
        }
    }
    s->xfer.write.addr        = args->addr;
    s->xfer.write.expected    = args->size;
    s->xfer.write.received    = 0u;
    s->xfer.write.is_flash    = is_flash;
    s->xfer.write.page_offset = 0u;
    return PB_STATUS_OK;
}

static pb_status_t pb_write_consume(
    pb_state_block_t *s,
    const uint8_t *buf,
    uint32_t len,
    bool *done,
    void *ctx
) {
    pb_out_write_t *w = &s->xfer.write;
    *done = false;

    if (w->is_flash) {
        const uint8_t *src = buf;
        uint32_t remaining = len;

        while (remaining > 0u) {
            uint32_t space = 256u - w->page_offset;
            uint32_t chunk = remaining < space ? remaining : space;
            memcpy(s->flash_write_buf + w->page_offset, src, chunk);
            w->page_offset += (uint16_t)chunk;
            src            += chunk;
            remaining      -= chunk;
            w->received    += chunk;

            bool page_full = (w->page_offset == 256u);
            bool all_done  = (w->received == w->expected);

            if (page_full || all_done) {
                // Zero-pad partial final page before writing
                if (w->page_offset < 256u) {
                    memset(s->flash_write_buf + w->page_offset, 0,
                           256u - w->page_offset);
                }
                pb_status_t st = s->ops->flash_page_write(
                    w->addr, s->flash_write_buf, ctx);
                if (st != PB_STATUS_OK) {
                    return st;
                }
                w->addr       += w->page_offset;
                w->page_offset = 0u;
            }
        }
    } else {
        pb_status_t st = s->ops->write(w->addr, buf, len, ctx);
        if (st != PB_STATUS_OK) {
            return st;
        }
        w->addr     += len;
        w->received += len;
    }

    *done = (w->received == w->expected);
    return PB_STATUS_OK;
}

// ---------------------------------------------------------------------------
// Per-command dispatch table
// ---------------------------------------------------------------------------

// Transfer length derivation functions for args-computed cases
static uint32_t tlen_addr_size(const picoboot_cmd_t *cmd) {
    const pb_addr_size_args_t *a = (const pb_addr_size_args_t *)cmd->args;
    return a->size;
}

static uint32_t tlen_otp(const picoboot_cmd_t *cmd) {
    const pb_otp_args_t *a = (const pb_otp_args_t *)cmd->args;
    return a->row_count * (a->ecc ? 2u : 4u);
}

static const pb_cmd_table_entry_t k_cmd_table[] = {
    { PB_CMD_EXCLUSIVE_ACCESS, PB_CAT_ACTION_SYNC,     0x01u, NULL,           false, NULL,                 { NULL }              },
    { PB_CMD_EXIT_XIP,         PB_CAT_ACTION_SYNC,     0x00u, NULL,           false, NULL,                 { NULL }              },
    { PB_CMD_ENTER_XIP,        PB_CAT_ACTION_SYNC,     0x00u, NULL,           false, NULL,                 { NULL }              },
    { PB_CMD_FLASH_ERASE,      PB_CAT_ACTION_ASYNC,    0x08u, NULL,           false, NULL,                 { NULL }              },
    { PB_CMD_REBOOT2,          PB_CAT_ACTION_DEFERRED, 0x10u, NULL,           false, NULL,                 { NULL }              },
    { PB_CMD_READ,             PB_CAT_DATA_IN,         0x08u, tlen_addr_size, false, pb_read_prepare,      { .fill = pb_read_fill }     },
    { PB_CMD_GET_INFO,         PB_CAT_DATA_IN,         0x10u, NULL,           true,  pb_get_info_prepare,  { .fill = pb_get_info_fill } },
    { PB_CMD_OTP_READ,         PB_CAT_DATA_IN,         0x05u, tlen_otp,       false, pb_otp_read_prepare,  { .fill = pb_otp_read_fill } },
    { PB_CMD_WRITE,            PB_CAT_DATA_OUT,        0x08u, tlen_addr_size, false, pb_write_prepare,     { .consume = pb_write_consume } },
    { PB_CMD_OTP_WRITE,        PB_CAT_DATA_OUT,        0x05u, tlen_otp,       false, pb_otp_write_prepare, { .consume = pb_otp_write_consume } },
    { PB_CMD_REBOOT,           PB_CAT_UNSUPPORTED,     0x00u, NULL,           false, NULL,                { NULL }              },
    { PB_CMD_EXEC,             PB_CAT_UNSUPPORTED,     0x00u, NULL,           false, NULL,                 { NULL }              },
    { PB_CMD_VECTORIZE_FLASH,  PB_CAT_UNSUPPORTED,     0x00u, NULL,           false, NULL,                 { NULL }              },
};

#define CMD_TABLE_COUNT (sizeof(k_cmd_table) / sizeof(k_cmd_table[0]))

static const pb_cmd_table_entry_t *pb_find_cmd(uint8_t cmd_id) {
    for (uint32_t i = 0u; i < CMD_TABLE_COUNT; i++) {
        if (k_cmd_table[i].cmd_id == cmd_id) {
            return &k_cmd_table[i];
        }
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// Category handlers
// ---------------------------------------------------------------------------

static void pb_handle_action_sync(pb_state_block_t *s, const picoboot_cmd_t *cmd) {
    pb_status_t st = PB_STATUS_OK;

    switch ((pb_cmd_id_t)cmd->cmd_id) {
        case PB_CMD_EXCLUSIVE_ACCESS:
            if (s->ops->exclusive_access) {
                st = s->ops->exclusive_access(
                    (const pb_exclusive_access_args_t *)cmd->args, s->ctx);
            }
            break;
        case PB_CMD_EXIT_XIP:
            if (s->ops->exit_xip) {
                st = s->ops->exit_xip(s->ctx);
            }
            break;
        case PB_CMD_ENTER_XIP:
            if (s->ops->enter_xip) {
                st = s->ops->enter_xip(s->ctx);
            }
            break;
        default:
            pb_stall(s, PB_STATUS_UNKNOWN_CMD);
            return;
    }

    if (st != PB_STATUS_OK) {
        pb_stall(s, st);
        return;
    }
    pb_send_zlp(s);
}

static void pb_handle_action_async(pb_state_block_t *s, const picoboot_cmd_t *cmd) {
    pb_status_t st = PB_STATUS_OK;

    switch ((pb_cmd_id_t)cmd->cmd_id) {
        case PB_CMD_FLASH_ERASE:
            if (!s->ops->flash_erase) {
                pb_stall(s, PB_STATUS_UNKNOWN_CMD);
                return;
            }
            LOG("Note FLASH_ERASE may need to be made properly async to avoid stalling USB");
            DEBUG("f erase: addr=0x%08x size=%u",
                ((const pb_addr_size_args_t *)cmd->args)->addr,
                ((const pb_addr_size_args_t *)cmd->args)->size);
            st = s->ops->flash_erase((const pb_addr_size_args_t *)cmd->args, s->ctx);
            break;
        default:
            pb_stall(s, PB_STATUS_UNKNOWN_CMD);
            return;
    }

    if (st != PB_STATUS_OK) {
        pb_stall(s, st);
        return;
    }
    pb_send_zlp(s);
}

static void pb_handle_action_deferred(pb_state_block_t *s, const picoboot_cmd_t *cmd) {
    switch ((pb_cmd_id_t)cmd->cmd_id) {
        case PB_CMD_REBOOT2: {
            if (!s->ops->reboot2_prepare) {
                pb_stall(s, PB_STATUS_UNKNOWN_CMD);
                return;
            }
            s->reboot2_args = *(const pb_reboot2_args_t *)cmd->args;
            pb_status_t st = s->ops->reboot2_prepare(&s->reboot2_args, s->ctx);
            if (st != PB_STATUS_OK) {
                pb_stall(s, st);
                return;
            }
            break;
        }
        default:
            pb_stall(s, PB_STATUS_UNKNOWN_CMD);
            return;
    }
    pb_send_zlp(s);
}

static void pb_handle_data_in(pb_state_block_t *s, const picoboot_cmd_t *cmd) {
    const pb_cmd_table_entry_t *entry = pb_find_cmd(cmd->cmd_id);
    if (!entry || !entry->prepare || !entry->fill) {
        pb_stall(s, PB_STATUS_UNKNOWN_CMD);
        return;
    }
    pb_status_t st = entry->prepare(s, cmd, s->ctx);
    if (st != PB_STATUS_OK) {
        pb_stall(s, st);
        return;
    }
    pb_set_state(s, PB_STATE_DATA_IN);
}

static void pb_handle_data_out(pb_state_block_t *s, const picoboot_cmd_t *cmd) {
    const pb_cmd_table_entry_t *entry = pb_find_cmd(cmd->cmd_id);
    if (!entry || !entry->prepare || !entry->consume) {
        pb_stall(s, PB_STATUS_UNKNOWN_CMD);
        return;
    }
    pb_status_t st = entry->prepare(s, cmd, s->ctx);
    if (st != PB_STATUS_OK) {
        pb_stall(s, st);
        return;
    }
    pb_set_state(s, PB_STATE_DATA_OUT);
}

static void pb_task_data_out(pb_state_block_t *s) {
    const pb_cmd_table_entry_t *entry = pb_find_cmd(s->cmd_id);
    if (!entry || !entry->consume) {
        ERR("pb_task_data_out: no consume fn for cmd 0x%02x", s->cmd_id);
        pb_stall(s, PB_STATUS_UNKNOWN_ERROR);
        return;
    }

    uint8_t  buf[64];
    uint32_t available = picoboot_vendor_available();
    if (available == 0u) {
        return;
    }

    uint32_t chunk = available < sizeof(buf) ? available : sizeof(buf);
    uint32_t n = picoboot_vendor_read(buf, chunk);
    if (n == 0u) {
        return;
    }

    bool done = false;
    pb_status_t st = entry->consume(s, buf, n, &done, s->ctx);
    if (st != PB_STATUS_OK) {
        pb_stall(s, st);
        return;
    }

    if (done) {
        pb_send_zlp(s);
    }
}

// ---------------------------------------------------------------------------
// Refactored dispatch entry point
// ---------------------------------------------------------------------------

static void pb_dispatch_cmd(pb_state_block_t *s, const picoboot_cmd_t *cmd) {
    s->token  = cmd->token;
    s->cmd_id = cmd->cmd_id;

    DEBUG("%s id=0x%02x token=0x%08x tlen=%u",
          command_to_str((pb_cmd_id_t)cmd->cmd_id), cmd->cmd_id, cmd->token, cmd->transfer_len);

    const pb_cmd_table_entry_t *entry = pb_find_cmd(cmd->cmd_id);
    if (!entry) {
        ERR("Unknown command ID 0x%02x", cmd->cmd_id);
        pb_stall(s, PB_STATUS_UNKNOWN_CMD);
        return;
    }

    if (entry->category == PB_CAT_UNSUPPORTED) {
        LOG("Unsupported command ID 0x%02x", cmd->cmd_id);
        pb_stall(s, PB_STATUS_UNKNOWN_CMD);
        return;
    }

    // Validate cmd_size
    if (cmd->cmd_size != entry->cmd_size) {
        LOG("Invalid cmd_size: expected %u, got %u", entry->cmd_size, cmd->cmd_size);
        pb_stall(s, PB_STATUS_INVALID_CMD_LENGTH);
        return;
    }

    // Validate transfer_len unless the command handles it itself
    if (entry->skip_tlen_check) {
        // category handler is responsible for transfer_len validation
    } else if (entry->get_transfer_len) {
        uint32_t expected_tlen = entry->get_transfer_len(cmd);
        if (cmd->transfer_len != expected_tlen) {
            LOG("Invalid transfer_len: expected %u, got %u", expected_tlen, cmd->transfer_len);
            pb_stall(s, PB_STATUS_INVALID_TRANSFER_LEN);
            return;
        }
    } else {
        if (cmd->transfer_len != 0u) {
            LOG("Invalid transfer_len: expected 0, got %u", cmd->transfer_len);
            pb_stall(s, PB_STATUS_INVALID_TRANSFER_LEN);
            return;
        }
    }

    switch (entry->category) {
        case PB_CAT_ACTION_SYNC:
            pb_handle_action_sync(s, cmd);
            break;

        case PB_CAT_ACTION_ASYNC:
            pb_handle_action_async(s, cmd);
            break;
            
        case PB_CAT_ACTION_DEFERRED:
            pb_handle_action_deferred(s, cmd);
            break;

        case PB_CAT_DATA_IN:
            pb_handle_data_in(s, cmd);
            break;

        case PB_CAT_DATA_OUT:
            pb_handle_data_out(s, cmd);
            break;

        default:
            ERR("Invalid command category %u for cmd_id 0x%02x", entry->category, cmd->cmd_id);
            pb_stall(s, PB_STATUS_UNKNOWN_CMD);
            break;
    }
}

// ---------------------------------------------------------------------------
// State machine handlers
// ---------------------------------------------------------------------------

static void pb_task_idle(pb_state_block_t *s) {
    uint32_t avail = picoboot_vendor_available();
    if (avail < (uint32_t)PICOBOOT_CMD_LEN) {
        if (avail > 1u) {
            LOG("Partial packet received, ignoring: %u bytes", avail);
            picoboot_vendor_read_clear();
        }
        // Note that 0/1 bytes are handled in all cases in _rx_cb()
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

static void pb_task_data_in(pb_state_block_t *s) {
    const pb_cmd_table_entry_t *entry = pb_find_cmd(s->cmd_id);
    if (!entry || !entry->fill) {
        ERR("pb_task_data_in: no fill fn for cmd 0x%02x", s->cmd_id);
        pb_stall(s, PB_STATUS_UNKNOWN_ERROR);
        return;
    }

    uint8_t buf[64];

    while (true) {
        uint32_t space = picoboot_vendor_write_available();
        if (space == 0u) {
            picoboot_vendor_write_flush();
            return;
        }

        uint32_t max_len      = space < sizeof(buf) ? space : sizeof(buf);
        uint32_t bytes_written = 0u;
        bool     done          = false;

        pb_status_t st = entry->fill(s, buf, max_len, &bytes_written, &done, s->ctx);
        if (st != PB_STATUS_OK) {
            pb_stall(s, st);
            return;
        }

        if (bytes_written > 0u) {
            uint32_t written = picoboot_vendor_write(buf, bytes_written);
            if (written != bytes_written) {
                ERR("pb_task_data_in: write short %u/%u", written, bytes_written);
                pb_stall(s, PB_STATUS_UNKNOWN_ERROR);
                return;
            }
        }

        if (done) {
            picoboot_vendor_write_flush();
            pb_set_state(s, PB_STATE_AWAIT_ACK);
            return;
        }

        if (bytes_written == 0u) {
            // Fill couldn't produce data this call (insufficient space for next item)
            picoboot_vendor_write_flush();
            return;
        }
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

    state->ops = ops;
    state->custom = custom;
    state->flash_write_buf = flash_write_buf;
    state->ctx = ctx;

    state->state = PB_STATE_IDLE;

    state->token = 0u;
    state->rhport = rhport;
    state->ep_out = ep_out;
    state->ep_in = ep_in;
    state->cmd_id = 0u;

    pb_set_status(state, PB_STATUS_OK, false);
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
            pb_task_data_out(state);
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

    //DEBUG("TX callback: sent_bytes=%u", sent_bytes);

    if (state->state != PB_STATE_AWAIT_ZLP) {
        // Ignore notifications for non-ZLP sent events
        return;
    }

    if (state->cmd_id == (uint8_t)PB_CMD_REBOOT2) {
        // As we have now sent the ZLP we can reboot
        if (state->ops->reboot2_execute) {
            state->ops->reboot2_execute(&state->reboot2_args, state->ctx);
        }
    }

    // For the non-reboot2 case (reboot2 should never get this far)
    LOG("ZLP ACK sent, returning to IDLE %u bytes", sent_bytes);
    pb_set_state(state, PB_STATE_IDLE);
}

void picoboot_rx_cb(
    pb_state_block_t *state,
    uint32_t available_bytes
) {
    //DEBUG("RX callback: available_bytes=%u", available_bytes);
    if (available_bytes <= 1) {
        if (state->state == PB_STATE_AWAIT_ACK) {
            // Both 0 and 1 byte values are considered ZLP by this stack in case
            // the host implementation doesn't support sending real ZLPs.
            LOG("Received ZLP ACK (available_bytes=%u)", available_bytes);
            pb_set_status(state, PB_STATUS_OK, false);
            pb_set_state(state, PB_STATE_IDLE);
        }

        // Consume the byte if it's 1 byte, otherwise no need to do a read at
        // all
        if (available_bytes == 1) {
            uint8_t dummy;
            picoboot_vendor_read(&dummy, 1);
        }
    }
}

bool picoboot_control_xfer_cb(
    pb_state_block_t *state,
    uint8_t rhport,
    uint8_t stage,
    tusb_control_request_t const *req
) {
    // Handle CLEAR_FEATURE(ENDPOINT_HALT) requests from the host to unstall our endpoints.
    if ((req->bmRequestType_bit.type == TUSB_REQ_TYPE_STANDARD) &&
        (req->bRequest == TUSB_REQ_CLEAR_FEATURE) &&
        (req->wValue == TUSB_REQ_FEATURE_EDPT_HALT)) {
        uint8_t ep = (uint8_t)(req->wIndex & 0xFFu);
        if (ep == state->ep_out || ep == state->ep_in) {
            if (stage == CONTROL_STAGE_SETUP) {
                DEBUG("CTRL: CLEAR_FEATURE(ENDPOINT_HALT) for EP%02x", ep);
                // tinyusb will have unstalled the endpoint by the time we get
                // here - we need to re-arm the endpoint
                if (ep == state->ep_out) {
                    DEBUG("Re-arming OUT endpoint");
                    picoboot_vendor_read_clear();
                } else if (ep == state->ep_in) {
                    DEBUG("Re-arming IN endpoint");
                    picoboot_vendor_write_clear();
                }
                // Do not touch the state machine, this is how the bootrom
                // implementation handles it.
                return tud_control_status(rhport, req);
            }
            return true;
        }
    }

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
                picoboot_vendor_unstall_endpoint(state->ep_out);
                picoboot_vendor_unstall_endpoint(state->ep_in);

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

                // See if either endpoint is stalled
                bool stalled_out = picoboot_vendor_is_endpoint_stalled(state->ep_out);
                bool stalled_in  = picoboot_vendor_is_endpoint_stalled(state->ep_in);
                if (stalled_out || stalled_in) {
                    DEBUG("GCS Endpoint stalled: OUT=%u EP%02X IN=%u EP%02X", stalled_out, state->ep_out, stalled_in, state->ep_in);
                    if (state->status.status_code == PB_STATUS_OK) {
                        ERR("GCS: endpoint stalled but status OK, setting to UNKNOWN_ERROR");
                        pb_set_status(state, PB_STATUS_UNKNOWN_ERROR, false);
                        pb_set_state(state, PB_STATE_STALLED);
                    }
                }
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

