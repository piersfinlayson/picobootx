// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// The C half of picobootx's hardware test.
//
// An instrument rather than an example.  It serves PICOBOOT on tinyusb the way
// examples/tinyusb does, and adds two things a shipping device does not need -
// a way back into BOOTSEL over USB, so the board is jumpered once and reflashed
// from the host after that, and a window it tells the host it may write to.
//
// test/hw/device-embassy is the same instrument in Rust and test/hw/host drives
// either.  Only the embassy one reports picobootx's own state and queues, since
// the C library publishes nothing to report.

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
uint32_t tusb_time_millis_api(void);

// ---------------------------------------------------------------------------
// The vendor control requests
// ---------------------------------------------------------------------------

// These are the test's own, on the control endpoint, and not picobootx custom
// commands - those travel over the bulk endpoints, which the test halts on
// purpose.  A halt does not touch the control endpoint, which is why both live
// here.  0x41 and 0x42 are picoboot's own, so these are clear of them.

// Reboot into BOOTSEL.  wValue is checked as well, so a stray vendor request
// cannot reboot the board.
#define REQ_BOOTSEL         0x45
#define REQ_BOOTSEL_VALUE   0xb007

// Ask where the host may work.  Every address the defaults accept for a write
// is this firmware's own memory or the flash it runs from, so the window is the
// device's to nominate.  Asked for rather than written out at each end, so the
// two cannot drift.
#define REQ_SCRATCH         0x47
#define SCRATCH_REPLY_LEN   16

// Reboot into BOOTSEL, from the RP2350 bootrom's own reboot routine.
#define REBOOT_TYPE_BOOTSEL 0x2

// Long enough for the control transfer's status stage to finish before the
// reboot takes the bus away.  The request is answered first and the reboot
// happens on the delay.
#define REBOOT_DELAY_MS     50

// How much room the host is given in RAM.  Enough for a transfer of several
// packets with room to write past the end and see that it was not written.
#define SCRATCH_LEN         1024

// Where the host may erase and program - the upper half of the part's flash.
// The linker is offered the whole part, so the Makefile's check-window measures
// the image afterwards to keep this firmware out.  A whole 64K block, the unit
// a bulk erase works in and the longest the part is away from the bus.
#define FLASH_SCRATCH_BASE  0x10100000
#define FLASH_SCRATCH_LEN   (64 * 1024)

// The host writes here, so it is the firmware's to set aside and nothing else
// may use it.
static uint8_t scratch[SCRATCH_LEN] __attribute__((aligned(4)));

// picobootx accumulates a whole flash page out of 64-byte packets here.  The
// boot ROM reads it once flash has been taken out of execute-in-place, so it
// has to be somewhere that still answers then - which is anywhere but flash.
static uint8_t flash_page_buf[256] __attribute__((aligned(4)));

// Whether a BOOTSEL request has been answered and is waiting for the status
// stage to complete.  The reboot is left until then so the host sees the
// request taken rather than the bus vanishing under it.
static bool bootsel_pending = false;

// ---------------------------------------------------------------------------
// picobootx
// ---------------------------------------------------------------------------

// Every default the RP2350 implementations offer, which is what the embassy
// half serves through Rp2350.  OTP included, which is written once and never
// again - no check here asks for it, and both halves answer a host that does.
static const picoboot_ops_t picoboot_ops = {
    .exclusive_access    = picoboot_default_exclusive_access,
    .exit_xip            = picoboot_default_exit_xip,
    .enter_xip           = picoboot_default_enter_xip,
    .reboot2_prepare     = picoboot_default_reboot2_prepare,
    .reboot2_execute     = picoboot_default_reboot2_execute,
    .read_prepare        = picoboot_default_read_prepare,
    .read                = picoboot_default_read,
    .write_prepare       = picoboot_default_write_prepare,
    .write               = picoboot_default_write,
    .flash_page_write    = picoboot_default_flash_page_write,
    .flash_erase_prepare = picoboot_default_flash_erase_prepare,
    .flash_erase         = picoboot_default_flash_erase,
    // No prepare either side: the RP2350 restricts no OTP range, and NULL is
    // how that is said.
    .otp_read            = picoboot_default_otp_read,
    .otp_write           = picoboot_default_otp_write,
    // GET_INFO takes a pair, one for every information type.  These serve
    // system and partition table information from the boot ROM, and the UF2
    // target partition as nowhere - see picobootx.h for what each answers.
    .get_info_prepare    = picoboot_default_get_info_prepare,
    .get_info            = picoboot_default_get_info,
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
        NULL,                   // No custom protocol support.  The refusal the
                                // test needs comes from the standard read,
                                // which the defaults refuse for an address
                                // outside ROM, flash or SRAM.
        flash_page_buf,         // WRITE to flash is served, which the flash
                                // checks need
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

// Answers the test's own vendor request asking where the host may work: the
// RAM window, then the flash window, each as an address and a length.  The RAM
// address is taken from the object itself, so moving or resizing it needs no
// change here and cannot leave the host writing where the buffer used to be.
static bool handle_scratch(
    uint8_t rhport,
    tusb_control_request_t const *request
) {
    static uint32_t reply[SCRATCH_REPLY_LEN / 4];

    reply[0] = (uint32_t)(uintptr_t)scratch;
    reply[1] = SCRATCH_LEN;
    reply[2] = FLASH_SCRATCH_BASE;
    reply[3] = FLASH_SCRATCH_LEN;

    return tud_control_xfer(rhport, request, reply, SCRATCH_REPLY_LEN);
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

    // The reboot is left until the status stage has gone, so the host learns
    // the request was taken before the bus goes away under it.
    if ((stage == CONTROL_STAGE_ACK) && bootsel_pending) {
        bootsel_pending = false;
        pb_reboot2_args_t args = {
            .flags = REBOOT_TYPE_BOOTSEL,
            .delay_ms = REBOOT_DELAY_MS,
            .p0 = 0,
            .p1 = 0,
        };
        picoboot_default_reboot2_execute(&args, NULL);
        return true;
    }

    if (stage != CONTROL_STAGE_SETUP) {
        return true;
    }

    // The test's own requests, on the vendor interface.  Every field is
    // checked, so nothing else can reach either of them.
    if ((request->bmRequestType_bit.type == TUSB_REQ_TYPE_VENDOR) &&
        (request->bmRequestType_bit.recipient == TUSB_REQ_RCPT_INTERFACE)) {
        if ((request->bRequest == REQ_BOOTSEL) &&
            (request->bmRequestType_bit.direction == TUSB_DIR_OUT) &&
            (request->wValue == REQ_BOOTSEL_VALUE) &&
            (request->wLength == 0)) {
            bootsel_pending = true;
            return tud_control_status(rhport, request);
        }

        if ((request->bRequest == REQ_SCRATCH) &&
            (request->bmRequestType_bit.direction == TUSB_DIR_IN)) {
            return handle_scratch(rhport, request);
        }
    }

    // Handle MS OS 2.0 descriptor request, for WCID on Windoows 8.1+.  Avoids
    // the need for Zadig to setup WinUSB on Windows.
    if (request->bRequest == VENDOR_REQUEST_MICROSOFT) {
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
    // First set CLK_REF and ROSC to the values the A4 bootrom sets them to, so
    // we start from a known state.

    // Set CLK_REF divider to 5
    CLOCK_REF_DIV = CLOCK_CLK_REF_DIV_INT(5);

    // Set ROSC divider to 2
    ROSC_DIV = ROSC_DIV_VAL(2);

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

    // Set CLK_REF divider to 1
    CLOCK_REF_DIV = CLOCK_CLK_REF_DIV_INT(1);

    // Set the system clock to use CLK_REF (which is now running from XOSC)
    // as its source

    // Switch SRC to CLK_REF first (safe on both A2 and A4)
    CLOCK_SYS_CTRL &= ~CLOCK_SYS_CTRL_SRC_MASK;
    while ((CLOCK_SYS_SELECTED & CLOCK_SYS_SELECTED_MASK) != CLOCK_SYS_SELECTED_CLKREF);
    // Now safe to configure AUXSRC
    CLOCK_SYS_CTRL &= ~CLOCK_SYS_AUX_SRC_MASK;
    CLOCK_SYS_CTRL |= CLOCK_SYS_AUX_SRC_ROSC_CLK_SRC;
    // Now switch SRC to AUX
    CLOCK_SYS_CTRL |= CLOCK_SYS_CTRL_SRC_CLK_AUX;
    while ((CLOCK_SYS_SELECTED & CLOCK_SYS_SELECTED_MASK) != CLOCK_SYS_SELECTED_AUX);
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
    PLL_USB_CS = PLL_CS_REFDIV(1);
    PLL_USB_FBDIV_INT = 40;

    // Power up VCO (keep post-dividers powered down)
    PLL_USB_PWR = PLL_PWR_POSTDIVPD;

    // Wait for lock
    while (!(PLL_USB_CS & PLL_CS_LOCK));

    // Set post dividers: 40 × 12MHz = 480MHz → ÷5 ÷2 = 48MHz
    PLL_USB_PRIM = PLL_PRIM_POSTDIV1(5) | PLL_PRIM_POSTDIV2(2);

    // Power up
    PLL_USB_PWR = 0;

    // Route USB clock to PLL_USB
    CLOCK_CLK_USB_DIV = CLOCK_USB_DIV_INT(1);
    CLOCK_CLK_USB_CTRL = CLOCK_USB_CTRL_ENABLE | CLOCK_USB_CTRL_AUXSRC_PLL_USB;

    reset_block(RESETS_RESET_USBCTRL_BITS);
    unreset_block_wait(RESETS_RESET_USBCTRL_BITS);
}
