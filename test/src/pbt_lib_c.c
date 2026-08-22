// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// pbt_lib.h answered for the C picobootx, which is built from source alongside
// the harness and whose private header is therefore on the include path.

#include "pbt_lib.h"

size_t pbt_lib_state_size(void) {
    return sizeof(struct pb_state_block);
}

size_t pbt_lib_state_align(void) {
    return _Alignof(struct pb_state_block);
}

pb_state_t pbt_lib_state_of(const pb_state_block_t *state) {
    return state->state;
}

const char *pbt_lib_state_name(pb_state_t state) {
    switch (state) {
        case PB_STATE_IDLE:
        case PB_STATE_DATA_OUT:
        case PB_STATE_DATA_IN:
        case PB_STATE_CUSTOM_IN:
        case PB_STATE_AWAIT_ZLP:
        case PB_STATE_AWAIT_ACK:
        case PB_STATE_STALLED:
            return pb_state_to_str[state];
        default:
            return NULL;
    }
}

uint32_t pbt_lib_layout(uint32_t *out, uint32_t len) {
    // The C library is built from the same header the scenarios read, so these
    // agree by construction.  They are answered anyway, because the check is
    // about a library's own types and this library's happen to be the
    // header's.
    const uint32_t values[PBT_LAYOUT_COUNT] = {
        [PBT_LAYOUT_STATUS_SIZE]           = (uint32_t)sizeof(pb_status_t),
        [PBT_LAYOUT_CMD_SIZE]              = (uint32_t)sizeof(picoboot_cmd_t),
        [PBT_LAYOUT_CMD_ALIGN]             = (uint32_t)_Alignof(picoboot_cmd_t),
        [PBT_LAYOUT_CMD_OFF_MAGIC]         = (uint32_t)offsetof(picoboot_cmd_t, magic),
        [PBT_LAYOUT_CMD_OFF_TOKEN]         = (uint32_t)offsetof(picoboot_cmd_t, token),
        [PBT_LAYOUT_CMD_OFF_CMD_ID]        = (uint32_t)offsetof(picoboot_cmd_t, cmd_id),
        [PBT_LAYOUT_CMD_OFF_CMD_SIZE]      = (uint32_t)offsetof(picoboot_cmd_t, cmd_size),
        [PBT_LAYOUT_CMD_OFF_TRANSFER_LEN]  = (uint32_t)offsetof(picoboot_cmd_t, transfer_len),
        [PBT_LAYOUT_CMD_OFF_ARGS]          = (uint32_t)offsetof(picoboot_cmd_t, args),
        [PBT_LAYOUT_STATUS_PACKET_SIZE]    = (uint32_t)sizeof(picoboot_status_t),
        [PBT_LAYOUT_OPS_SIZE]              = (uint32_t)sizeof(picoboot_ops_t),
        [PBT_LAYOUT_OPS_OFF_OTP_WRITE]     = (uint32_t)offsetof(picoboot_ops_t, otp_write),
        [PBT_LAYOUT_CUSTOM_OPS_SIZE]       = (uint32_t)sizeof(picoboot_custom_ops_t),
        [PBT_LAYOUT_CUSTOM_OPS_OFF_FILL]   = (uint32_t)offsetof(picoboot_custom_ops_t, fill),
        [PBT_LAYOUT_CTRL_REQUEST_SIZE]     = (uint32_t)sizeof(tusb_control_request_t),
    };
    uint32_t n = len < PBT_LAYOUT_COUNT ? len : PBT_LAYOUT_COUNT;
    for (uint32_t i = 0; i < n; i++) {
        out[i] = values[i];
    }
    return PBT_LAYOUT_COUNT;
}
