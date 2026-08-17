// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// tinyusb's configuration for the usb suite.
//
// OPT_MCU_NONE is tinyusb's own name for a port it does not supply a device
// controller driver for, which is what lets the suite provide one in
// usbt_dcd.c.  Everything above that — usbd, the control transfer machinery and
// picobootx's vendor driver — is the shipped code, unmodified.
//
// The endpoint and buffer sizes match examples/tinyusb, since those are what a
// device carrying picobootx is expected to present, and the vendor driver's
// behaviour at a buffer boundary is part of what this suite asserts.

#ifndef TUSB_CONFIG_H_
#define TUSB_CONFIG_H_

#define CFG_TUSB_MCU              OPT_MCU_NONE
#define CFG_TUSB_OS               OPT_OS_NONE
#define CFG_TUSB_DEBUG            0

// tinyusb warns when an unknown MCU leaves this to its default.  The number is
// the host controller's, not a device's, so it only has to be enough for the
// two bulk endpoints and control.
#define TUP_DCD_ENDPOINT_MAX      8

// The endpoint FIFO is written directly, rather than copied through a buffer
// the port owns.  tusb_option.h sets this per USB IP and defaults it off, and
// OPT_MCU_NONE matches no IP, so it has to be said here.  It matches the
// RP2350, whose endpoint buffers are DPRAM, and it is what picobootx's vendor
// driver needs: it opens its streams with no endpoint buffer, so every transfer
// it makes goes through dcd_edpt_xfer_fifo, which usbd refuses outright when
// this is off.
#define CFG_TUD_EDPT_DEDICATED_HWFIFO 1

#define CFG_TUD_ENABLED           1
#define CFG_TUD_MAX_SPEED         OPT_MODE_FULL_SPEED
#define CFG_TUD_ENDPOINT0_SIZE    64
#define CFG_TUD_ENDPOINT_MAX      4
#define CFG_TUD_TASK_QUEUE_SZ     8

#define CFG_TUD_VENDOR            1
#define CFG_TUD_CDC               0
#define CFG_TUD_MSC               0
#define CFG_TUD_HID               0
#define CFG_TUD_MIDI              0

// picobootx's vendor driver takes these as the size of its own FIFOs.  64 is a
// full-speed bulk packet, so a transfer longer than one packet exercises the
// driver's refill path rather than being handed over whole.
#define CFG_TUD_VENDOR_RX_BUFSIZE 64
#define CFG_TUD_VENDOR_TX_BUFSIZE 64

#endif // TUSB_CONFIG_H_
