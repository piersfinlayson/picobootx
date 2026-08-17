// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// The usbip bridge: picobootx on the local USB bus, so a real host tool drives
// it.
//
// The usb suite reaches picobootx through a model of a host inside the process.
// This reaches it through the real one.  The kernel's virtual host controller,
// vhci-hcd, is a USB host controller whose bus is a socket, and this program is
// what answers on the other end of that socket — turning the URBs the kernel
// sends into the transfers usbt_dcd.c's endpoints move.  Everything below that
// is the usb suite's device, unchanged: real tinyusb, picobootx's real vendor
// driver, the library, and the device model in pbt_device.c.
//
// So picotool talks to a device that exists nowhere, over a bus that is a socket
// on the loopback interface, and picobootx cannot tell the difference.
//
// Linux only, and it needs root — loading a kernel module and handing the
// controller a socket are both privileged.

#if !defined(PICOBOOTX_TEST_USBIPT_H)
#define PICOBOOTX_TEST_USBIPT_H

#include <stdbool.h>
#include <stdint.h>

// How loud to be.  Off says nothing but errors, on traces every URB, which is
// what a session that picotool disagreed with needs.
extern bool usbipt_verbose;

void usbipt_trace(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void usbipt_error(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

// ---------------------------------------------------------------------------
// The device  (usbipt_device.c)
// ---------------------------------------------------------------------------

// Bring the device up: tinyusb, picobootx behind its vendor driver, and the bus
// reset a host issues before it addresses anything.  The kernel's virtual
// controller answers port resets itself and never forwards one, so this is the
// only reset the device sees.
void usbipt_device_start(void);

// Turn the loops a device turns: tinyusb's task, and picobootx's own.  A device
// runs both from its main loop, and so does this.
void usbipt_device_pump(void);

// ---------------------------------------------------------------------------
// The virtual host controller  (usbipt_vhci.c)
// ---------------------------------------------------------------------------

// Hand a connected socket to vhci-hcd, which then drives it as a USB bus.  The
// kernel takes its own reference to the socket, so the caller's copy can be
// closed once this returns.  Answers the port the device was given, or -1,
// having said why.
int usbipt_vhci_attach(int sockfd);

// Give the port back.  A port that was never attached is not an error.
void usbipt_vhci_detach(int port);

// ---------------------------------------------------------------------------
// URBs  (usbipt_urb.c)
// ---------------------------------------------------------------------------

// One turn of the bus: turn the device, answer whatever it can now satisfy, and
// take whatever the kernel has sent.  Waits on the socket for a moment rather
// than returning at once, so a caller can loop on it without spinning, and comes
// back promptly whether or not anything arrived.  Returns false once the
// connection has gone, which is how a detach reaches the loop.
bool usbipt_urb_poll(int sockfd);

#endif // PICOBOOTX_TEST_USBIPT_H
