// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// The descriptors the usb suite's device presents.
//
// tinyusb asks the application for these, so they belong to the harness rather
// than to picobootx — a device carrying picobootx supplies its own.  What is
// here is shaped like examples/tinyusb, because that is the shape picotool has
// to recognise, and the accommodations picotool needs are asserted against it.
//
// Two of those accommodations are descriptor content, and are the reason this
// file exists rather than the suite borrowing the example's:
//
// - picotool takes the picoboot interface to be interface 0 when the device has
//   one interface, so ITF_NUM_PICOBOOTX is 0 and the configuration declares one
//   interface.
// - picotool insists interface 0 carries class 0xFF, subclass 0x00 and protocol
//   0x00, or it does not recognise the device at all.
//
// Both are recorded in the README under picotool Specification Deficiencies.
//
// A second configuration is declared here as well, carrying an interface after
// picoboot's.  It is what a device exposing something else alongside picoboot
// presents, and reaching it needs a driver for that other interface, so the
// stand-in for one lives here too — it exists only to own the interface this
// file declares.

#include <string.h>

#include "device/usbd_pvt.h"
#include "tusb.h"
#include "usbt.h"

// Raspberry Pi's vendor id and the RP2350's product id in BOOTSEL, which is
// what a picoboot host looks for.
#define USBT_VID 0x2E8Au
#define USBT_PID 0x000Fu

enum {
    USBT_ITF_PICOBOOTX = 0,
    USBT_ITF_TOTAL
};

// The second configuration's extra interface, which follows picoboot's.
#define USBT_ITF_SPARE 1u
#define USBT_ITF_TOTAL_TWO 2u

// Any class but vendor specific.  picobootx's driver claims the first vendor
// class interface it is offered, so a spare interface that carried that class
// would be taken for picoboot's.
#define USBT_SPARE_CLASS TUSB_CLASS_APPLICATION_SPECIFIC

enum {
    USBT_STR_LANGID = 0,
    USBT_STR_MANUFACTURER,
    USBT_STR_PRODUCT,
    USBT_STR_SERIAL,
    USBT_STR_INTERFACE,
};

static const tusb_desc_device_t k_desc_device = {
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = 0x0200,
    .bDeviceClass       = 0x00,
    .bDeviceSubClass    = 0x00,
    .bDeviceProtocol    = 0x00,
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor           = USBT_VID,
    .idProduct          = USBT_PID,
    .bcdDevice          = 0x0100,
    .iManufacturer      = USBT_STR_MANUFACTURER,
    .iProduct           = USBT_STR_PRODUCT,
    .iSerialNumber      = USBT_STR_SERIAL,
    .bNumConfigurations = 0x01,
};

#define USBT_CONFIG_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_VENDOR_DESC_LEN)

static const uint8_t k_desc_configuration[] = {
    TUD_CONFIG_DESCRIPTOR(USBT_CONFIG_VALUE, USBT_ITF_TOTAL, 0,
                          USBT_CONFIG_TOTAL_LEN, 0x80, 100),

    // TUD_VENDOR_DESCRIPTOR emits class 0xFF, subclass 0x00, protocol 0x00,
    // which is what picotool requires of interface 0.
    TUD_VENDOR_DESCRIPTOR(USBT_ITF_PICOBOOTX, USBT_STR_INTERFACE,
                          USBT_EP_OUT, USBT_EP_IN, USBT_PACKET_MAX),
};

// The same device with one more interface behind picoboot's.  The extra
// interface declares no endpoints, because what it is for is being a descriptor
// picobootx's driver has to stop at.
#define USBT_ITF_DESC_LEN (sizeof(tusb_desc_interface_t))

#define USBT_CONFIG_TWO_TOTAL_LEN \
    (TUD_CONFIG_DESC_LEN + TUD_VENDOR_DESC_LEN + USBT_ITF_DESC_LEN)

static const uint8_t k_desc_configuration_two[] = {
    TUD_CONFIG_DESCRIPTOR(USBT_CONFIG_VALUE, USBT_ITF_TOTAL_TWO, 0,
                          USBT_CONFIG_TWO_TOTAL_LEN, 0x80, 100),

    TUD_VENDOR_DESCRIPTOR(USBT_ITF_PICOBOOTX, USBT_STR_INTERFACE,
                          USBT_EP_OUT, USBT_EP_IN, USBT_PACKET_MAX),

    // bLength, bDescriptorType, bInterfaceNumber, bAlternateSetting,
    // bNumEndpoints, class, subclass, protocol, iInterface
    USBT_ITF_DESC_LEN, TUSB_DESC_INTERFACE, USBT_ITF_SPARE, 0, 0,
    USBT_SPARE_CLASS, 0, 0, 0,
};

// Which of the two the device presents.  usbt_begin puts it back to one.
static bool s_two_interfaces;

// The interface number the spare driver was given, or -1 if it was never
// offered one.  This is how a scenario sees where picobootx's driver stopped:
// a driver that ran past the second interface descriptor would have consumed
// this interface too, and the spare would never be asked to open it.
static int s_spare_itf = -1;

void usbt_two_interfaces(bool two) {
    s_two_interfaces = two;
}

int usbt_spare_interface(void) {
    return s_spare_itf;
}

// ---------------------------------------------------------------------------
// The spare interface's driver
//
// usbd refuses a configuration with an interface no driver claims, so the
// second interface needs one.  It does nothing but claim it and say so.
//
// tinyusb asks for the application's drivers once, when the stack comes up, so
// this one is offered every interface of every scenario.  It refuses any class
// but its own, which is why the one-interface configuration is unaffected.
// ---------------------------------------------------------------------------

static void spare_init(void) {
    s_spare_itf = -1;
}

static void spare_reset(uint8_t rhport) {
    (void)rhport;
    s_spare_itf = -1;
}

static uint16_t spare_open(uint8_t rhport, const tusb_desc_interface_t *desc_itf,
                           uint16_t max_len) {
    (void)rhport;
    (void)max_len;
    TU_VERIFY(USBT_SPARE_CLASS == desc_itf->bInterfaceClass, 0);
    s_spare_itf = desc_itf->bInterfaceNumber;
    return (uint16_t)USBT_ITF_DESC_LEN;
}

static bool spare_xfer_cb(uint8_t rhport, uint8_t ep_addr, xfer_result_t result,
                          uint32_t xferred_bytes) {
    (void)rhport;
    (void)ep_addr;
    (void)result;
    (void)xferred_bytes;
    return false;  // it has no endpoints, so nothing can complete on it
}

static const usbd_class_driver_t k_spare_driver = {
    .name            = "spare",
    .init            = spare_init,
    .deinit          = NULL,
    .reset           = spare_reset,
    .open            = spare_open,
    .control_xfer_cb = NULL,
    .xfer_cb         = spare_xfer_cb,
    .xfer_isr        = NULL,
    .sof             = NULL,
};

const usbd_class_driver_t *usbd_app_driver_get_cb(uint8_t *driver_count) {
    *driver_count = 1;
    return &k_spare_driver;
}

static const char *const k_desc_strings[] = {
    [USBT_STR_LANGID]       = NULL,          // handled below
    [USBT_STR_MANUFACTURER] = "picobootx",
    [USBT_STR_PRODUCT]      = "picobootx conformance device",
    [USBT_STR_SERIAL]       = "0123456789ABCDEF",
    [USBT_STR_INTERFACE]    = "picoboot",
};

#define USBT_STR_COUNT (sizeof(k_desc_strings) / sizeof(k_desc_strings[0]))

// What the suites read.  Exposed as bytes because a scenario asserting the
// interface numbering or the class triple walks the descriptor the host was
// given, rather than reading these definitions back.
const uint8_t *usbt_desc_device            = (const uint8_t *)&k_desc_device;
uint32_t       usbt_desc_device_len        = sizeof(k_desc_device);
const uint8_t *usbt_desc_configuration     = k_desc_configuration;
uint32_t       usbt_desc_configuration_len = sizeof(k_desc_configuration);
const uint8_t *usbt_desc_configuration_two     = k_desc_configuration_two;
uint32_t       usbt_desc_configuration_two_len = sizeof(k_desc_configuration_two);

// ---------------------------------------------------------------------------
// What tinyusb asks for
// ---------------------------------------------------------------------------

uint8_t const *tud_descriptor_device_cb(void) {
    return (uint8_t const *)&k_desc_device;
}

uint8_t const *tud_descriptor_configuration_cb(uint8_t index) {
    (void)index;  // one configuration, in one of two shapes
    return s_two_interfaces ? k_desc_configuration_two : k_desc_configuration;
}

uint16_t const *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    (void)langid;

    // A string descriptor is UTF-16, with its length and type in the first
    // code unit.  63 characters is far more than any string here.
    static uint16_t desc[64];

    if (index == USBT_STR_LANGID) {
        desc[1] = 0x0409;  // English (United States)
        desc[0] = (uint16_t)((TUSB_DESC_STRING << 8) | 4u);
        return desc;
    }

    if (index >= USBT_STR_COUNT || k_desc_strings[index] == NULL) {
        return NULL;
    }

    const char *str   = k_desc_strings[index];
    size_t      chars = strlen(str);
    if (chars > (sizeof(desc) / sizeof(desc[0])) - 1u) {
        chars = (sizeof(desc) / sizeof(desc[0])) - 1u;
    }

    for (size_t i = 0; i < chars; i++) {
        desc[1 + i] = (uint16_t)str[i];
    }
    desc[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2u * chars + 2u));

    return desc;
}
