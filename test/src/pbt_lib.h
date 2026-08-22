// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// The library under test, behind the few things the harness needs that
// picobootx.h does not offer.
//
// picoboot_init takes a state block the integrator allocates and the library
// owns, and picobootx.h declares its type without its layout.  The harness has
// to allocate one, and a scenario has to be able to ask what the state machine
// is doing, and neither is answerable through the public API.  Reaching into
// pb_state_block for it ties the suite to one implementation's struct.
//
// The vocabulary stays the C headers': pb_state_t here, and pb_cmd_id_t and
// pb_status_t throughout the scenarios.  Those headers are what an
// implementation conforms to, so the suite reads them rather than declaring its
// own copy for an implementation to be mapped onto.
//
// So it is asked here instead, and answered once per implementation.  LIB= on
// the make command line chooses which answer is compiled in.

#if !defined(PICOBOOTX_TEST_PBT_LIB_H)
#define PICOBOOTX_TEST_PBT_LIB_H

#include <stddef.h>
#include <stdint.h>

#include "picobootx.h"
#include "picobootx_private.h"

// How much storage the state block needs, and how it must be aligned.
//
// Not PICOBOOT_STATE_SIZE: that is what a device allocates, where a pointer is
// four bytes wide, and this process's are wider.  The harness allocates from
// what the implementation in front of it actually asks for.
size_t pbt_lib_state_size(void);
size_t pbt_lib_state_align(void);

// What the library is doing.  The state machine is internal, so an
// implementation answers for itself rather than the harness reading a field.
pb_state_t pbt_lib_state_of(const pb_state_block_t *state);

// The library's own name for a state, so a failure message and a log line say
// the same word.  NULL for a value that is not a state.
const char *pbt_lib_state_name(pb_state_t state);

// What the library's own wire types measure, in the order pbt_layout_t names.
//
// The scenarios read the layouts in picobootx.h, which are compiled into the
// test binary whichever library is linked, so they say nothing about a library
// that declares its own.  This is where a library states what it actually
// built, and the suite checks that against the header.
//
// Writes min(len, PBT_LAYOUT_COUNT) values and returns how many there are.
typedef enum {
    PBT_LAYOUT_STATUS_SIZE,
    PBT_LAYOUT_CMD_SIZE,
    PBT_LAYOUT_CMD_ALIGN,
    PBT_LAYOUT_CMD_OFF_MAGIC,
    PBT_LAYOUT_CMD_OFF_TOKEN,
    PBT_LAYOUT_CMD_OFF_CMD_ID,
    PBT_LAYOUT_CMD_OFF_CMD_SIZE,
    PBT_LAYOUT_CMD_OFF_TRANSFER_LEN,
    PBT_LAYOUT_CMD_OFF_ARGS,
    PBT_LAYOUT_STATUS_PACKET_SIZE,
    PBT_LAYOUT_OPS_SIZE,
    PBT_LAYOUT_OPS_OFF_OTP_WRITE,
    PBT_LAYOUT_CUSTOM_OPS_SIZE,
    PBT_LAYOUT_CUSTOM_OPS_OFF_FILL,
    PBT_LAYOUT_CTRL_REQUEST_SIZE,
    PBT_LAYOUT_COUNT
} pbt_layout_t;

uint32_t pbt_lib_layout(uint32_t *out, uint32_t len);

#endif // PICOBOOTX_TEST_PBT_LIB_H
