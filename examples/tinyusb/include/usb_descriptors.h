// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

#if !defined(USB_DESCRIPTORS_H)
#define USB_DESCRIPTORS_H

// VID/PID - use standard RP2350 VID/PID
#define VID 0x2e8a
#define PID 0x000f

// Endpoint numbers
#define EPNUM_PICOBOOTX_OUT     0x01
#define EPNUM_PICOBOOTX_IN      0x81

enum
{
  VENDOR_REQUEST_WEBUSB = 1,
  VENDOR_REQUEST_MICROSOFT = 2
};

extern uint8_t const desc_ms_os_20[];

#define MS_OS_20_DESC_LEN        0xB2

#endif // USB_DESCRIPTORS_H