// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// A host stand-in for the part of tinyusb's surface picobootx's core compiles
// against.
//
// picobootx's core is nearly USB-stack agnostic: the bulk endpoints are reached
// only through the picoboot_vendor_* API, which the harness implements itself.
// The control endpoint is the exception.  picoboot_control_xfer_cb takes a
// tinyusb SETUP packet, compares against tinyusb's request enumerations, and
// answers through tud_control_xfer and tud_control_status.  Those are the only
// tinyusb names the core uses, and they are reproduced here so a host build can
// exercise the control path — which is where GET_COMMAND_STATUS, INTERFACE
// RESET and the unstall protocol live, and therefore where a large part of what
// the suite has to pin lives too.
//
// The declarations below match tinyusb's byte for byte and value for value.
// Nothing else from tinyusb is reproduced, and nothing here is a redefinition
// of picoboot behaviour — the code under test is the shipped code.
//
// This header is reached only by the phase-1 host test build, which puts
// test/shim on the include path ahead of anything else.  A build that links
// real tinyusb must not have that directory on its path.

#if !defined(PICOBOOTX_TEST_TUSB_H)
#define PICOBOOTX_TEST_TUSB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// picoboot requires a 64-byte control endpoint, and picobootx.h asserts it.
#if !defined(CFG_TUD_ENDPOINT0_SIZE)
#define CFG_TUD_ENDPOINT0_SIZE 64
#endif

#define TU_ATTR_PACKED       __attribute__((packed))
#define TU_ATTR_ALWAYS_INLINE __attribute__((always_inline))

// tusb_types.h: request codes
typedef enum {
    TUSB_REQ_GET_STATUS        = 0,
    TUSB_REQ_CLEAR_FEATURE     = 1,
    TUSB_REQ_RESERVED          = 2,
    TUSB_REQ_SET_FEATURE       = 3,
    TUSB_REQ_RESERVED2         = 4,
    TUSB_REQ_SET_ADDRESS       = 5,
    TUSB_REQ_GET_DESCRIPTOR    = 6,
    TUSB_REQ_SET_DESCRIPTOR    = 7,
    TUSB_REQ_GET_CONFIGURATION = 8,
    TUSB_REQ_SET_CONFIGURATION = 9,
    TUSB_REQ_GET_INTERFACE     = 10,
    TUSB_REQ_SET_INTERFACE     = 11,
    TUSB_REQ_SYNCH_FRAME       = 12
} tusb_request_code_t;

// tusb_types.h: feature selectors
typedef enum {
    TUSB_REQ_FEATURE_EDPT_HALT     = 0,
    TUSB_REQ_FEATURE_REMOTE_WAKEUP = 1,
    TUSB_REQ_FEATURE_TEST_MODE     = 2
} tusb_request_feature_selector_t;

// tusb_types.h: request types
typedef enum {
    TUSB_REQ_TYPE_STANDARD = 0u,
    TUSB_REQ_TYPE_CLASS,
    TUSB_REQ_TYPE_VENDOR,
    TUSB_REQ_TYPE_INVALID
} tusb_request_type_t;

// tusb_types.h: request recipients
typedef enum {
    TUSB_REQ_RCPT_DEVICE = 0,
    TUSB_REQ_RCPT_INTERFACE,
    TUSB_REQ_RCPT_ENDPOINT,
    TUSB_REQ_RCPT_OTHER
} tusb_request_recipient_t;

// tusb_types.h: transfer directions, as they appear in an endpoint address
typedef enum {
    TUSB_DIR_OUT = 0,
    TUSB_DIR_IN  = 1
} tusb_dir_t;

#define TUSB_DIR_IN_MASK 0x80u

// usbd.h: the stages a control transfer is presented to a class driver in
enum {
    CONTROL_STAGE_IDLE  = 0,
    CONTROL_STAGE_SETUP = 1,
    CONTROL_STAGE_DATA  = 2,
    CONTROL_STAGE_ACK   = 3
};

// tusb_types.h: the eight-byte USB SETUP packet
typedef struct TU_ATTR_PACKED {
    union {
        struct TU_ATTR_PACKED {
            uint8_t recipient : 5;
            uint8_t type      : 2;
            uint8_t direction : 1;
        } bmRequestType_bit;

        uint8_t bmRequestType;
    };

    uint8_t  bRequest;
    uint16_t wValue;
    uint16_t wIndex;
    uint16_t wLength;
} tusb_control_request_t;

_Static_assert(sizeof(tusb_control_request_t) == 8u,
               "tusb_control_request_t must be the eight-byte SETUP packet");

// tusb_types.h: the nine-byte interface descriptor, and the result a completed
// endpoint transfer is reported with.  Neither is used by picobootx's core —
// they are here because picobootx_vendor.h declares the tinyusb class-driver
// hooks that take them, and that header is included for the picoboot_vendor_*
// API alongside them.
typedef struct TU_ATTR_PACKED {
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint8_t bInterfaceNumber;
    uint8_t bAlternateSetting;
    uint8_t bNumEndpoints;
    uint8_t bInterfaceClass;
    uint8_t bInterfaceSubClass;
    uint8_t bInterfaceProtocol;
    uint8_t iInterface;
} tusb_desc_interface_t;

_Static_assert(sizeof(tusb_desc_interface_t) == 9u,
               "tusb_desc_interface_t must be the nine-byte interface descriptor");

typedef enum {
    XFER_RESULT_SUCCESS = 0,
    XFER_RESULT_FAILED,
    XFER_RESULT_STALLED,
    XFER_RESULT_TIMEOUT,
    XFER_RESULT_INVALID
} xfer_result_t;

// usbd.h: answer a control transfer with a data stage, and with a status stage
// only.  Implemented by the harness, which records what was answered.
bool tud_control_xfer(uint8_t rhport, const tusb_control_request_t *request,
                      void *buffer, uint16_t len);
bool tud_control_status(uint8_t rhport, const tusb_control_request_t *request);

#endif // PICOBOOTX_TEST_TUSB_H
