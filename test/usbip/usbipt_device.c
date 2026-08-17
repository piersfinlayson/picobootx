// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// Bringing the device up, and turning it.
//
// This is what usbt_host.c's usbt_begin does for a scenario, without the parts
// that belong to a host inside the process.  The application carrying picobootx
// is usbt_app.c, shared with the usb suite, and the device underneath is
// pbt_device.c, shared with both suites.

#include <time.h>

#include "tusb.h"
#include "usbt.h"
#include "usbt_dcd.h"
#include "usbipt.h"

// tinyusb reads this.  The suite freezes it so a scenario decides how much time
// passed, but here a real host is on the other end of the bus and real time is
// passing, so it answers with the clock.
uint32_t tusb_time_millis_api(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)((uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u);
}

// Passes of tud_task per turn.  Draining one event can queue another — a
// transfer completing makes the class driver start the next — and a URB is not
// answered until the device has settled, so a turn drains rather than stepping.
#define USBIPT_PUMP_PASSES 16u

void usbipt_device_pump(void) {
    for (unsigned i = 0; i < USBIPT_PUMP_PASSES; i++) {
        tud_task();
        usbt_app_task();
    }
}

void usbipt_device_start(void) {
    // The part as it comes up: flash erased, OTP blown nowhere, XIP running.
    // Without this the modelled part starts at whatever a static holds, which is
    // zeroed flash — a state no part is ever in, and one a host would read as a
    // device full of zeros rather than an empty one.
    pbt_device_reset();

    usbt_app_reset();
    usbt_dcd_reset();

    tusb_rhport_init_t init = {
        .role  = TUSB_ROLE_DEVICE,
        .speed = TUSB_SPEED_FULL,
    };
    tusb_init(USBT_RHPORT, &init);
    usbipt_device_pump();

    // The bus reset a host issues before it addresses a device.  vhci-hcd
    // answers port resets in the kernel and never sends one down the socket, so
    // the device is reset here instead, before the kernel is given the bus.
    usbt_dcd_bus_reset();
    usbipt_device_pump();

    usbt_start_picoboot();
    usbipt_device_pump();
}
