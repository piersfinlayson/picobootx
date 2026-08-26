# Integration Guide - the C library

This is the C picobootx in [src](src) and [include](include).  The Rust crates in [rust](rust) are integrated by adding them to a `Cargo.toml`, and each carries its own documentation on [docs.rs](https://docs.rs/picobootx), with [examples/embassy](examples/embassy) a complete device built on them.

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
8. Place the `.ramfunc` section in RAM, and copy it at startup
9. Build and run

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
    .read_prepare       = picoboot_default_read_prepare, 
    .read               = picoboot_default_read,
    .write_prepare      = picoboot_default_write_prepare,
    .write              = picoboot_default_write,
    .otp_read           = picoboot_default_otp_read,
    .otp_write          = picoboot_default_otp_write,
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
- optional pointer to custom protocol support (NULL if not used) - see [Custom Commands](#4a-custom-commands-optional)
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

## 4a. Custom Commands (optional)

The PICOBOOT command header carries a magic value, and picobootx dispatches any command whose magic matches your own to you instead of handling it itself.  That gives you a command ID space entirely separate from PICOBOOT's, with no risk of colliding with it now or in future.

Supply a `picoboot_custom_ops_t` to `picoboot_init` (the third argument, `NULL` above):

```c
static pb_status_t my_dispatch(
    const picoboot_cmd_t *cmd,
    uint8_t *buf,
    uint32_t buf_len,
    uint32_t *bytes_written,
    void *ctx
);

static const picoboot_custom_ops_t my_custom_ops = {
    .magic    = MY_MAGIC,       // must differ from PICOBOOT_MAGIC
    .dispatch = my_dispatch,
    .fill     = NULL,           // optional; see below
};
```

`dispatch` runs for every command carrying your magic.  For a command with no data phase (`transfer_len == 0`) that is all that happens: return `PB_STATUS_OK` and picobootx sends the host a zero-length packet, or return any other status to stall.

To return data to the host, set the optional `fill` callback as well.  A command whose `cmd_id` has `PICOBOOT_DIR_IN` set and whose `transfer_len` is non-zero is then handled in two stages: `dispatch` runs first, taking the "prepare" role - validate the request there, and stall by returning a non-`PB_STATUS_OK` status - and then `fill` is called repeatedly until the transfer is complete.  Each call writes up to `max_len` bytes, sets `*bytes_written`, and sets `*done` when there is nothing further to send.  Writing nothing without setting `*done` means "no room for the next item, call me again".

**`fill` keeps its own position.** picobootx holds no cursor on your behalf; it hands you the command on every call, so track your progress in your own `ctx`.  Leaving `fill` as `NULL` means custom commands cannot return data, and such a command is stalled with `PB_STATUS_UNKNOWN_CMD`.

A host-to-device data phase on a custom command is not supported, and is stalled with `PB_STATUS_UNKNOWN_CMD`.

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

## 8. Place `.ramfunc` in RAM

An erase takes flash out of execute-in-place, so the part of the sequence that runs while flash is unreadable is placed in the `.ramfunc` section.  A section name places nothing on its own — your linker script decides where `.ramfunc` lands, and your startup decides whether its bytes are carried there.  A build missing either links without a warning, and what the erase jumps into is a flash that has stopped answering or a RAM nothing filled.

Your linker script needs an output section for it, in RAM and loaded from flash.  This is [the example's](examples/tinyusb/pico-sdkless-repo/examples/common/common.ld):

```text
.ramfunc ORIGIN(RAM) : AT(__text_end) {
    __ramfunc_start = .;
    *(.ramfunc*)
    . = ALIGN(4);
    __ramfunc_end = .;
}
__ramfunc_load = LOADADDR(.ramfunc);
```

and your reset handler needs to copy it, before anything erases flash:

```c
extern uint32_t __ramfunc_start;  // Start of .ramfunc in RAM
extern uint32_t __ramfunc_end;    // End of .ramfunc in RAM
extern uint32_t __ramfunc_load;   // Where its bytes are loaded from

memcpy(&__ramfunc_start, &__ramfunc_load,
       (unsigned int)((char *)&__ramfunc_end - (char *)&__ramfunc_start));
```

The two casts are what makes the length a count of bytes.  A linker symbol declared `extern uint32_t` — which is how these are usually written, and how the section addresses in your `.data` and `.bss` copies are written too — subtracts to a count of **words**, so a `memcpy` handed that copies a quarter of the section and leaves the rest of the erase routine as whatever RAM held at reset.  That is a working boot and a flash erase that runs into rubbish, so nothing points at the copy when it goes wrong.

## 9. Build and Run

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