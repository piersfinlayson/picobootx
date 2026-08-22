// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// pbt_lib.h answered for the Rust picobootx, which is a static library with no
// header of its own.  Everything it exports is declared here, so what the
// harness depends on from it is one short list.

#include <stdint.h>

#include "pbt_lib.h"

size_t      picobootx_ffi_state_size(void);
size_t      picobootx_ffi_state_align(void);
uint8_t     picobootx_ffi_state_of(const void *state);
const char *picobootx_ffi_state_name(uint8_t state);
uint32_t    picobootx_ffi_layout(uint32_t *out, uint32_t len);

size_t pbt_lib_state_size(void) {
    return picobootx_ffi_state_size();
}

size_t pbt_lib_state_align(void) {
    return picobootx_ffi_state_align();
}

pb_state_t pbt_lib_state_of(const pb_state_block_t *state) {
    return (pb_state_t)picobootx_ffi_state_of(state);
}

const char *pbt_lib_state_name(pb_state_t state) {
    return picobootx_ffi_state_name((uint8_t)state);
}

uint32_t pbt_lib_layout(uint32_t *out, uint32_t len) {
    return picobootx_ffi_layout(out, len);
}
