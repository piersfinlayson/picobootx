// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// What a host sees when it enumerates a device carrying picobootx.
//
// None of this is reachable from the core suite: enumeration is tinyusb's work,
// and picobootx's part in it — vendord_open claiming the interface and its two
// endpoints — only runs when a real configuration descriptor is parsed by a
// real usbd.

#include <string.h>

#include "pbt.h"
#include "usbt.h"
#include "usbt_dcd.h"

// Walk a configuration descriptor to the first interface descriptor.  Returns
// NULL if there is not one, which is itself a failure a scenario reports.
static const tusb_desc_interface_t *first_interface(const uint8_t *cfg,
                                                    uint32_t len) {
    uint32_t offset = 0;
    while (offset + 2u <= len) {
        uint8_t item_len  = cfg[offset];
        uint8_t item_type = cfg[offset + 1u];
        if (item_len == 0) {
            return NULL;
        }
        if (item_type == TUSB_DESC_INTERFACE) {
            return (const tusb_desc_interface_t *)(cfg + offset);
        }
        offset += item_len;
    }
    return NULL;
}

static void scenario_device_descriptor(void) {
    usbt_begin();
    usbt_bus_reset();

    usbt_ctrl_result_t r =
        usbt_get_descriptor(TUSB_DESC_DEVICE, 0, sizeof(tusb_desc_device_t));

    PBT_REQUIRE(r.ok);
    PBT_CHECK_EQ(r.len, sizeof(tusb_desc_device_t));

    const tusb_desc_device_t *dev = (const tusb_desc_device_t *)r.data;
    PBT_CHECK_EQ(dev->bDescriptorType, TUSB_DESC_DEVICE);
    PBT_CHECK_EQ(dev->bNumConfigurations, 1);

    // What the host was given is what the device declares, byte for byte.
    PBT_CHECK(memcmp(r.data, usbt_desc_device, usbt_desc_device_len) == 0);
}

static void scenario_enumerates(void) {
    usbt_begin();

    PBT_REQUIRE(usbt_enumerate());

    // The address the host assigned reached the controller, and the two bulk
    // endpoints the configuration declares are open.  Neither is true before
    // SET_CONFIGURATION, so this discriminates a device that answered the
    // descriptors but never opened anything.
    PBT_CHECK_EQ(usbt_dcd_address(), USBT_ADDR_ASSIGNED);
    PBT_CHECK(usbt_dcd_ep_open(USBT_EP_OUT));
    PBT_CHECK(usbt_dcd_ep_open(USBT_EP_IN));
    PBT_CHECK(tud_mounted());
}

static void scenario_endpoints_closed_before_configured(void) {
    usbt_begin();
    usbt_bus_reset();

    // Deliberately stopping short of SET_CONFIGURATION.  The endpoints must
    // still be shut, or the check in the scenario above would pass on a device
    // that opened them at any point at all.
    usbt_ctrl_result_t r =
        usbt_get_descriptor(TUSB_DESC_DEVICE, 0, sizeof(tusb_desc_device_t));
    PBT_REQUIRE(r.ok);

    PBT_CHECK(!usbt_dcd_ep_open(USBT_EP_OUT));
    PBT_CHECK(!usbt_dcd_ep_open(USBT_EP_IN));
    PBT_CHECK(!tud_mounted());
}

static void scenario_configuration_descriptor(void) {
    usbt_begin();
    usbt_bus_reset();

    // Ask for the header alone first, as a host does when it does not yet know
    // how long the whole thing is.
    usbt_ctrl_result_t r = usbt_get_descriptor(
        TUSB_DESC_CONFIGURATION, 0, sizeof(tusb_desc_configuration_t));
    PBT_REQUIRE(r.ok);
    PBT_CHECK_EQ(r.len, sizeof(tusb_desc_configuration_t));

    const tusb_desc_configuration_t *cfg =
        (const tusb_desc_configuration_t *)r.data;
    uint16_t total = cfg->wTotalLength;
    PBT_CHECK_EQ(total, usbt_desc_configuration_len);

    r = usbt_get_descriptor(TUSB_DESC_CONFIGURATION, 0, total);
    PBT_REQUIRE(r.ok);
    PBT_CHECK_EQ(r.len, total);
    PBT_CHECK(memcmp(r.data, usbt_desc_configuration, total) == 0);
}

// picotool takes the picoboot interface to be interface 0 on a device with one
// interface, and refuses to recognise the device unless interface 0 carries
// class 0xFF, subclass 0x00 and protocol 0x00.  Both are recorded in the README
// under picotool Specification Deficiencies, and neither is reachable from the
// core suite, which never sees a descriptor.
static void scenario_picotool_interface_expectations(void) {
    usbt_begin();
    usbt_bus_reset();

    usbt_ctrl_result_t r = usbt_get_descriptor(TUSB_DESC_CONFIGURATION, 0,
                                               usbt_desc_configuration_len);
    PBT_REQUIRE(r.ok);

    const tusb_desc_configuration_t *cfg =
        (const tusb_desc_configuration_t *)r.data;
    PBT_CHECK_EQ(cfg->bNumInterfaces, 1);

    const tusb_desc_interface_t *itf = first_interface(r.data, r.len);
    PBT_REQUIRE(itf != NULL);

    PBT_CHECK_EQ(itf->bInterfaceNumber, 0);
    PBT_CHECK_EQ(itf->bInterfaceClass, TUSB_CLASS_VENDOR_SPECIFIC);
    PBT_CHECK_EQ(itf->bInterfaceSubClass, 0);
    PBT_CHECK_EQ(itf->bInterfaceProtocol, 0);
    PBT_CHECK_EQ(itf->bNumEndpoints, 2);
}

// A configuration carrying an interface behind picoboot's.  picobootx's driver
// claims the vendor interface and stops at the next interface descriptor,
// leaving that one to whichever driver owns it — which is what lets a device
// expose something else alongside picoboot.  Nothing else reaches that stop:
// with one interface the walk runs to the end of the configuration instead.
//
// picotool reads the picoboot interface as interface 1 on a two-interface
// device, and as interface 0 on a one-interface device, which the README
// records under picotool Specification Deficiencies.  This is the device's side
// of a two-interface configuration, not picotool's reading of one.
static void scenario_second_interface_is_left_to_its_driver(void) {
    usbt_begin();
    usbt_two_interfaces(true);
    usbt_start_picoboot();

    PBT_REQUIRE(usbt_enumerate());

    const tusb_desc_configuration_t *cfg =
        (const tusb_desc_configuration_t *)usbt_desc_configuration_two;
    PBT_CHECK_EQ(cfg->bNumInterfaces, 2);

    // The second interface was offered to its own driver, and that driver
    // opened it.  A vendor driver that walked past the interface descriptor
    // would have consumed this interface as part of its own, and the second
    // driver would never have been asked.
    PBT_CHECK_EQ(usbt_spare_interface(), 1);

    // picobootx took the vendor interface and its two endpoints, and nothing
    // beyond them: the spare interface declares none.
    PBT_CHECK(usbt_dcd_ep_open(USBT_EP_OUT));
    PBT_CHECK(usbt_dcd_ep_open(USBT_EP_IN));
    PBT_CHECK(tud_mounted());

    // And picoboot works on it, so the interface it claimed is the one it
    // bound its endpoints to.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_EXIT_XIP, 0, 0);
    PBT_REQUIRE(usbt_bulk_out((const uint8_t *)&cmd, sizeof(cmd)));

    uint8_t buf[USBT_PACKET_MAX];
    PBT_CHECK_EQ(usbt_bulk_in(buf, sizeof(buf)), 1);
    PBT_CHECK_EQ(buf[0], 0);
}

// Every scenario starts on a device that has just been plugged in, and that
// depends on tinyusb actually being torn down first.  A teardown that stopped
// part way would leave the stack initialised, tusb_init would skip, and a
// scenario would run against the previous scenario's device.
static void scenario_the_stack_is_torn_down_and_rebuilt(void) {
    usbt_begin();
    usbt_start_picoboot();
    PBT_REQUIRE(usbt_enumerate());
    PBT_REQUIRE(tud_mounted());
    PBT_REQUIRE(usbt_dcd_address() == USBT_ADDR_ASSIGNED);

    usbt_begin();

    // Configured, addressed and open are all gone.  The configuration number is
    // tinyusb's own, and only the teardown clears it, so a stack that skipped
    // its teardown still reports itself mounted here.
    PBT_CHECK(!tud_mounted());
    PBT_CHECK(!usbt_dcd_ep_open(USBT_EP_OUT));
    PBT_CHECK(!usbt_dcd_ep_open(USBT_EP_IN));
    PBT_CHECK_EQ(usbt_dcd_address(), USBT_ADDR_DEFAULT);

    // Rebuilt, not merely emptied: the stack enumerates again from scratch.
    PBT_CHECK(tusb_inited());
    usbt_start_picoboot();
    PBT_CHECK(usbt_enumerate());
    PBT_CHECK(tud_mounted());
}

static const pbt_scenario_t k_scenarios[] = {
    { "the device descriptor reaches the host intact",
      scenario_device_descriptor },
    { "a host enumerates the device and its endpoints open",
      scenario_enumerates },
    { "the endpoints stay shut until the configuration is selected",
      scenario_endpoints_closed_before_configured },
    { "the configuration descriptor is read in two passes",
      scenario_configuration_descriptor },
    { "interface 0 is what picotool insists on",
      scenario_picotool_interface_expectations },
    { "an interface behind picoboot's is left to its own driver",
      scenario_second_interface_is_left_to_its_driver },
    { "the stack is torn down and rebuilt between scenarios",
      scenario_the_stack_is_torn_down_and_rebuilt },
};

PBT_SUITE(usbt_suite_enumeration, "enumeration", k_scenarios);
