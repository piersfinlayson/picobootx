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
