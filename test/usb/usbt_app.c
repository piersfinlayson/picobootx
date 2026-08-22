// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// The application carrying picobootx.
//
// picobootx does not own its state block, and its vendor driver calls the
// application when the wire moves, exactly as it does on a device.  This file is
// that application: the state block, the flash write buffer, the callbacks the
// driver reaches for, and the task the main loop turns.
//
// It is apart from the host driving the bus because there are two such hosts and
// only one application.  usbt_host.c models a host inside the process, and the
// usbip bridge lets a real one drive it from outside the process.  Both link
// this, unchanged.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tusb.h"
#include "usbt.h"
#include "pbt_lib.h"
#include "usbt_dcd.h"


static uint8_t s_flash_write_buf[256] __attribute__((aligned(4)));

// Whether picoboot_init has been called.  Before it has, the state block holds
// nothing, and handing it to the library would be worse than declining.
static bool s_started;

// Whether usbt_app_task turns picobootx's task.  See usbt_run_picoboot_task.
static bool s_run_task = true;

// The library's state block, allocated to exactly the size and alignment the
// implementation under test asks for.  Exact rather than a fixed buffer with
// room to spare, because the slack in a buffer is somewhere a write past the
// end of the block lands without the sanitiser seeing it.
static pb_state_block_t *s_state;

pb_state_block_t *usbt_state(void) {
    if (!s_state) {
        size_t align = pbt_lib_state_align();
        size_t size  = (pbt_lib_state_size() + align - 1u) / align * align;
        s_state = aligned_alloc(align, size);
        if (!s_state) {
            fprintf(stderr, "could not allocate %zu bytes at %zu-byte "
                            "alignment for the state block\n", size, align);
            abort();
        }
        // Zeroed, so a read before picoboot_init has a defined answer rather
        // than whatever the allocator last held.  Every library here starts in
        // the state numbered zero.
        memset(s_state, 0, size);
    }
    return s_state;
}

pb_state_t usbt_cur_state(void) {
    return pbt_lib_state_of(usbt_state());
}

// Put the application back to before picoboot_init, which is where a device is
// when it powers up.  Whatever brings the stack up calls this first.
void usbt_app_reset(void) {
    s_started  = false;
    s_run_task = true;
}

void app_picoboot_rx_cb(uint32_t available_bytes) {
    picoboot_rx_cb(usbt_state(), available_bytes);
}

void app_picoboot_tx_cb(uint32_t sent_bytes) {
    picoboot_tx_cb(usbt_state(), sent_bytes);
}

// Defined in pbt_ops.c, which every suite shares.
void pbt_ops_reset(void);

// picobootx's state machine runs from the application's loop, exactly as it does
// on a device, so whatever pumps tud_task pumps this alongside it.
void usbt_app_task(void) {
    if (s_started && s_run_task) {
        picoboot_task(usbt_state());
    }
}

void usbt_run_picoboot_task(bool run) {
    s_run_task = run;
}

// A control transfer on the vendor interface belongs to picobootx.  tinyusb
// hands it to the application, and the application passes it on — this is what
// carries INTERFACE RESET and GET_COMMAND_STATUS.
bool tud_vendor_control_xfer_cb(uint8_t rhport, uint8_t stage,
                                tusb_control_request_t const *request) {
    if (!s_started) {
        return false;
    }
    return picoboot_control_xfer_cb(usbt_state(), rhport, stage, request);
}

void usbt_start_picoboot(void) {
    pbt_ops_reset();

    picoboot_init(usbt_state(), &pbt_ops, NULL, s_flash_write_buf,
                  USBT_RHPORT, USBT_EP_OUT, USBT_EP_IN, NULL);
    s_started = true;
}
