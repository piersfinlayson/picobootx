// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// What the host model in usbt_host.c uses to reach the device controller in
// usbt_dcd.c.  Separate from usbt.h, which is what a scenario sees: a scenario
// speaks in host actions, and never touches an endpoint queue directly.

#ifndef PICOBOOTX_TEST_USBT_DCD_H
#define PICOBOOTX_TEST_USBT_DCD_H

#include <stdbool.h>
#include <stdint.h>

// The one root hub port the model has.
#define USBT_RHPORT 0u

// Put every endpoint back to how it is before tinyusb has been initialised.
void usbt_dcd_reset(void);

// Reset the model and tell tinyusb the bus was reset.
void usbt_dcd_bus_reset(void);

// Deliver a SETUP packet, which is how every control transfer starts.
void usbt_dcd_setup(const uint8_t setup[8]);

// Take up to one packet from a queued IN transfer, completing it if that
// finishes it.  Returns the bytes taken.
uint32_t usbt_dcd_take_in(uint8_t ep_addr, uint8_t *out, uint32_t max);

// Give up to one packet to a queued OUT transfer, completing it if that fills
// it or if the packet is short.  Returns the bytes accepted.
uint32_t usbt_dcd_give_out(uint8_t ep_addr, const uint8_t *in, uint32_t len);

// State a host could observe, or that a scenario asserts about the controller.
bool     usbt_dcd_ep_open(uint8_t ep_addr);
bool     usbt_dcd_ep_stalled(uint8_t ep_addr);
bool     usbt_dcd_ep_pending(uint8_t ep_addr);
uint8_t  usbt_dcd_address(void);
bool     usbt_dcd_connected(void);

#endif // PICOBOOTX_TEST_USBT_DCD_H
