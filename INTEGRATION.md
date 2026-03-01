# Integration Guide

picobootx is designed to be integrated in a larger embedded application, that includes USB.  picobootx was developed specifically to work with the tinyusb USB stack.  The guidance that follows assumes you are using tinyusb, but the general principles should apply to other USB stacks as well.

There is a complete, working, bare-metal, picobootx tinyusb example in the [examples/tinyusb](examples/tinyusb) directory which acts as a reference implementation for the steps outlined below.  You can build and run this example as-is, and then modify it as needed to integrate picobootx into your own application.

Steps:

1. Include the picobootx header file
2. Implement picoboot protocol handling - or select the defaults
3. Allocate memory for picoboot
4. Initialise picobootx
5. Call the picoboot task function regularly in your main loop
6. Call picobootx's USB event callbacks from the appropriate places in your application
7. Add picobootx's files to your build system
8. Build and run

## 1. Include the Header

Include the picobootx header file in your code:

```c
#include "picobootx.h"
```

## 2. Protocol Handling

picobootx allows you to customize most aspects of how picobootx actually responds to the protocol, including whether to support specific commands or not.

This guide will cover using the default implemenations.  To implement custom handling, use the default implementations in [picobootx_impl.c](src/picobootx_impl.c) as a basis.

To use the defaults, put in this your code:

```c
// Use the default implementations
static const picoboot_ops_t picoboot_ops = {
    .exclusive_access   = picoboot_default_exclusive_access,
    .exit_xip           = picoboot_default_exit_xip,
    .enter_xip          = picoboot_default_enter_xip,
    .reboot2_prepare    = picoboot_default_reboot2_prepare,
    .reboot2_execute    = picoboot_default_reboot2_execute,
    .validate_read      = picoboot_default_validate_read, 
    .read               = picoboot_default_read,
    .otp_read           = picoboot_default_otp_read,
    .get_info_sys       = picoboot_default_get_info_sys,
};
```

## 3. Allocate Memory

The easiest way to allocate memory for picobootx is to statically allocate a `pb_state_block_t` structure.  However, if you have a heap or other allocate, you can allocate it dynamically.

To statically allocate:

```c
// Ensure 4 byte alignment and use PICOBOOT_STATE_SIZE from picobootx.h to
// size the buffer correctly
static uint32_t picoboot_state_buf[PICOBOOT_STATE_SIZE / 4];

// Set up a convenient pointer to the state block
#define picoboot_state ((pb_state_block_t *)picoboot_state_buf)
```

## 4. Initialise picobootx

In main, or elsewhere, but before picobootx is used, call `picoboot_init`, passing in:
- your operations struct
- the pointer to picobootx's state block
- optional pointer to custom protocol support (NULL if not used)
- optional pointer to 256 byte buffer for flash/OTP write support (NULL if those operations are not supported)
- the USB port number that picobootx should use, from tusb_configh.h (for RP2350 this is always 0)
- the endpoint number to use for the picoboot OUT endpoint (must be a valid EP OUT endpoint that is not used for other purposes in your application)
- the endpoint number to use for the picoboot IN endpoint (must be a valid EP IN endpoint that is not used for other purposes in your application)
- optional pointer to custom context to be passed to protocol support functions (NULL if not required, e.g. because your protocol support functions don't need any context).

Example:

```c
picoboot_init(
    picoboot_state,
    &picoboot_ops,
    NULL,                   // No custom protocol support
    NULL,                   // Flash/OTP write not supported
    BOARD_TUD_RHPORT,       // Always 0 on RP2350
    EPNUM_PICOBOOTX_OUT,    // EP OUT
    EPNUM_PICOBOOTX_IN,     // EP IN
    NULL                    // No custom context needed
);
```

## 5. picoboot Task Function

picobootx must be called regularly to do its work.  The simplest way to do this is to call `picoboot_task` in your main loop alongside other tasks, such as `tud_task()` if you are using tinyusb.

```c
while (1) {
    tud_task();
    picoboot_task(picoboot_state);
}
```

## 6. USB Event Callbacks

picobootx requires notification of certain USB events, in particular:
1. Received data on the picoboot OUT endpoint
2. Transmission complete on the picoboot IN endpoint
3. Control requests to the picoboot interface

The first two of these are provided with you implementing `app_picoboot_rx_cb()` and `app_picoboot_tx_cb()` respectively.  All your code needs to do is call the appropriate picobootx function from these callbacks with picobootx state.

This is shown in the following example:

```c
void app_picoboot_rx_cb(uint32_t available_bytes) {
    picoboot_rx_cb(picoboot_state, available_bytes);
}
void app_picoboot_tx_cb(uint32_t sent_bytes) {
    picoboot_tx_cb(picoboot_state, sent_bytes);
}
```

Your application must also implement the appropriate control request handler for your tinyusb stack and call `picoboot_control_xfer_cb()` from it.  For tinyusb this might look like this:

```c
bool tud_vendor_control_xfer_cb(
    uint8_t rhport,
    uint8_t stage,
    tusb_control_request_t const *request
) {
    // Try picobootx first
    if (picoboot_control_xfer_cb(picoboot_state, rhport, stage, request)) {
        // picobootx handled this request, so we are done
        return true;
    }

    // Handle other control requests here as required by your application,
    // such as MS OS 2.0 descriptor requests.

    return false;
}
```

## 7. Build System

The Makefile fragment [picobootx.mk](picobootx.mk) contains definitions of the source files and include path that are required to build picobootx.  Include this in your build system as appropriate and link the object files into your final binary.

## 8. Build and Run

Assuming your device is exposing VID/PID 2e8a:000f (the default RP2350 VID/PID), you can test using `picotool` as follows:

```bash
picotool info -a
```

Sample result:

```text
Program Information
 target chip:         RP2350
 image type:          ARM Secure

Fixed Pin Information
 none

Build Information
 none

Metadata Block 1
 address:             0x100001c0
 next block address:  0x100001c0
 block type:          image def
 target chip:         RP2350
 image type:          ARM Secure

Metadata Block 2
 address:             0x100001c0
 next block address:  0x100001c0
 block type:          image def
 target chip:         RP2350
 image type:          ARM Secure

Device Information
 type:                RP2350
 revision:            Unknown
 package:             QFN60
 chipid:              0x0000000058ad06d6
 rom gitrev:          0xa8bfe860
 flash size:          2048
```

`picotool` has options to allow it to be run against other VIDs/PIDs, so if you have changed the default VID/PID in picobootx, you can specify that when running `picotool` with the `-d` option, for example:

```bash
picotool info --vid 0x2e8a --pid 0x000f -a
```