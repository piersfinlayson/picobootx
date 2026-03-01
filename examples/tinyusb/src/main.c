// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// picobootx tinyusb example

#define PICO_SL_IMPLEMENTATION
#include "pico.h"
#include "tusb_config.h"
#include "picobootx.h"
#include "picobootx_impl.h"
#include "usb_descriptors.h"

// Forward declarations of functions in main
void setup_xosc(void);
void setup_ms_timer(void);
void setup_usb(void);
void cdc_task(void);
uint32_t tusb_time_millis_api(void);

// Use the default picobootx implementations
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

// Ensure 4 byte alignment and use PICOBOOT_STATE_SIZE from picobootx.h to
// size the buffer correctly
static uint32_t picoboot_state_buf[PICOBOOT_STATE_SIZE / 4];

// Set up a convenient pointer to the state block
#define picoboot_state ((pb_state_block_t *)picoboot_state_buf)

//
// Main entry point
//
void example_main(void) {
    // Set up system to run from the 12MHz external crystal
    setup_xosc();

    // Set up timer0 for the ms timer used by tinyusb.
    setup_ms_timer();

    // Set up USB hardware and PLL
    setup_usb();

    // Initialize picoboot with the ops and state block we've set up
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

    // Initialize tinyusb (takes USBCTRL out of reset)
    tusb_rhport_init_t dev_init = {
        .role = TUSB_ROLE_DEVICE,
        .speed = TUSB_SPEED_AUTO
    };
    tusb_init(BOARD_TUD_RHPORT, &dev_init);

    while (1) {
        // tinyusb task handler
        tud_task();

        // picobootx task handler
        picoboot_task(picoboot_state);
    }
}

//
// Functions to implement the picobootx vendor device in tinyusb
//
void app_picoboot_rx_cb(uint32_t available_bytes) {
    picoboot_rx_cb(picoboot_state, available_bytes);
}
void app_picoboot_tx_cb(uint32_t sent_bytes) {
    picoboot_tx_cb(picoboot_state, sent_bytes);
}

// Invoked when a control transfer is received on vendor interface
// Used to respond to MS OS 2.0 descriptor request from Windows
bool tud_vendor_control_xfer_cb(
    uint8_t rhport,
    uint8_t stage,
    tusb_control_request_t const *request
) {
    // Try PICOBOOT first
    if (picoboot_control_xfer_cb(picoboot_state, rhport, stage, request)) {
        return true;
    }

    // Handle MS OS 2.0 descriptor request, for WCID on Windoows 8.1+.  Avoids
    // the need for Zadig to setup WinUSB on Windows.
    if ((request->bRequest == VENDOR_REQUEST_MICROSOFT) && (stage == CONTROL_STAGE_SETUP)) {
        if (request->wIndex == 7) {
            // Return MS OS 2.0 descriptor
            return tud_control_xfer(rhport, request, (void *)desc_ms_os_20, MS_OS_20_DESC_LEN);
        }
    }

    return false;
}

//
// MS timer required by tinyusb.  Uses TIMER0_IRQ_0 and TICKS peripherals
//

static volatile uint32_t timer_ms = 0;

// Implementation of the board_millis required by tinyusb for timing
__attribute__((always_inline)) inline uint32_t tusb_time_millis_api(void) {
    return timer_ms;
}

// Timer0 IRQ handler to increment the timer_ms field when the timer alarm
// fires
void timer0_irq_0_handler(void) {
    TIMER0_INTR = (1 << 0);
    TIMER0_ALARM0 = TIMER0_TIMELR + 1000;
    timer_ms++;
}

// Sets up TIMER0 to generate an interrupt every 1ms, which we use for the
// board_millis implementation required by tinyusb
void setup_ms_timer(void) {
    // Release TIMER0 from reset
    reset_block(RESETS_RESET_TIMER0_BITS);
    unreset_block_wait(RESETS_RESET_TIMER0_BITS);

    uint32_t clk_ref_div = (CLOCK_REF_DIV >> 16) & 0xFF;
    clk_ref_div = clk_ref_div ? clk_ref_div : 1;
    uint32_t clkref_mhz = 12 / clk_ref_div;

    // Set up TICKS
    TICKS_TIMER0_CYCLES = clkref_mhz;
    TICKS_TIMER0_CTRL = 1; 

    // First time setup - enable the interrupt and set the first alarm
    TIMER0_INTE |= (1 << 0);
    TIMER0_ALARM0 = TIMER0_TIMELR + 1000;

    // Register the IRQ handler for TIMER0 and enable it
    irq_add_shared_handler(TIMER0_IRQ_0, timer0_irq_0_handler, 0);
    irq_set_enabled(TIMER0_IRQ_0, true);
}

//
// Clock setup
//
void setup_xosc(void) {
    // Initialize XOSC peripheral.  We are using the 12MHz xtal from the
    // reference hardware design, so we can use values from the datasheet.
    // See S8.2 for more details.
    //
    // Specifically:
    // - Set the startup delay to 1ms
    // - Enable the XOSC giving it the appropriate frequency range (1-15MHz)
    // - Wait for the XOSC to be enabled and stable
    XOSC_STARTUP = XOSC_STARTUP_DELAY_1MS;
    XOSC_CTRL = XOSC_ENABLE | XOSC_RANGE_1_15MHz;
    while (!(XOSC_STATUS & XOSC_STATUS_STABLE));

    // Switch CLK_REF to use XOSC instead of the ROSC
    CLOCK_REF_CTRL = CLOCK_REF_SRC_XOSC;
    while ((CLOCK_REF_SELECTED & CLOCK_REF_SRC_SEL_XOSC) != CLOCK_REF_SRC_SEL_XOSC);
}

//
// USB Peripheral setup
//

// Sets up the USB PLL to generate a 48MHz clock from the 12MHz external
// crystal and start USBCTRL.
void setup_usb(void) {
    // Release PLL_USB from reset
    reset_block(RESETS_RESET_PLL_USB_BITS);
    unreset_block_wait(RESETS_RESET_PLL_USB_BITS);

    // Power down the PLL, set the feedback divider
    PLL_USB_PWR = PLL_PWR_PD | PLL_PWR_VCOPD;

    // For 48MHz: 12MHz × 40 ÷ 5 ÷ 2 = 48MHz
    PLL_USB_FBDIV_INT = 40;
    PLL_USB_CS = PLL_CS_REFDIV(1);

    // Power up VCO (keep post-dividers powered down)
    PLL_USB_PWR = PLL_PWR_POSTDIVPD;

    // Wait for lock
    while (!(PLL_USB_CS & PLL_CS_LOCK));

    // Set post dividers: 40 × 12MHz = 480MHz → ÷5 ÷2 = 48MHz
    PLL_USB_PRIM = PLL_PRIM_POSTDIV1(5) | PLL_PRIM_POSTDIV2(2);

    // Power up
    PLL_USB_PWR = 0;

    // Route USB clock to PLL_USB
    CLOCK_CLK_USB_CTRL = CLOCK_USB_CTRL_ENABLE | CLOCK_USB_CTRL_AUXSRC_PLL_USB;

    reset_block(RESETS_RESET_USBCTRL_BITS);
    unreset_block_wait(RESETS_RESET_USBCTRL_BITS);
}
