// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! The device half of picobootx's hardware test.
//!
//! An instrument rather than an example.  It serves PICOBOOT on embassy the way
//! [examples/embassy](../../../examples/embassy) does, and adds the one thing a
//! test needs and a device shipping to somebody does not: a way back into
//! BOOTSEL over USB, so a board is jumpered once and reflashed from the host
//! from then on.
//!
//! What it is for is the refusal-and-recovery path.  A host asks for something
//! the device refuses, picobootx halts both bulk endpoints, and the host clears
//! the halts and sends INTERFACE RESET.  The transfer after that recovery is
//! the one at risk, and serving it is what this device exists to demonstrate.
//! [test/hw/host](../../host) drives that and decides whether it worked.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_rp::bind_interrupts;
use embassy_rp::peripherals::USB;
use embassy_rp::usb::{Driver, InterruptHandler};
use embassy_usb::control::{InResponse, OutResponse, Recipient, Request, RequestType};
use embassy_usb::{Builder, Config, Handler};

use picobootx::wire::FLASH_PAGE_SIZE;
use picobootx::{Endpoints, NoCustom, Reboot};
use picobootx_embassy::{Picoboot, Rp2350Halt};
use picobootx_rp2350::{Rp2350, reboot_execute};

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<USB>;
});

// The descriptor and picobootx must be given the same addresses, since
// picobootx halts an endpoint by address.  64 is what a full-speed bulk
// endpoint carries.
const EP_OUT: u8 = 0x01;
const EP_IN: u8 = 0x81;
const MAX_PACKET_SIZE: u16 = 64;

// ---------------------------------------------------------------------------
// The way back into BOOTSEL
// ---------------------------------------------------------------------------

// A vendor request on the control endpoint, not one of picobootx's custom
// commands, which travel over the bulk endpoints.  This has to work at the
// moment the test has deliberately halted those, and the control endpoint is
// the one thing a halt does not touch.
//
// 0x41 and 0x42 are picoboot's own, so this is clear of them.  wValue is
// checked as well, so a stray vendor request cannot reboot the board.
const REQ_BOOTSEL: u8 = 0x45;
const REQ_BOOTSEL_VALUE: u16 = 0xb007;

// Read what the protocol and its queues are doing.  On the control endpoint,
// so it answers while the bulk pair is halted or wedged, which is exactly when
// the answer is wanted.
const REQ_DIAG: u8 = 0x46;
const DIAG_LEN: usize = 8;

// Reboot into BOOTSEL, from the RP2350 bootrom's own reboot routine.  Verified
// against embassy-rp's reset_to_usb_boot, which passes the same value.
const REBOOT_TYPE_BOOTSEL: u32 = 0x2;

// Long enough for the control transfer's status stage to finish before the
// watchdog fires.  NO_RETURN_ON_SUCCESS is deliberately not set: the call has
// to come back so the request can be acknowledged, and the reboot then happens
// on the delay.
const REBOOT_DELAY_MS: u32 = 50;

struct Bootsel<'d, 'a> {
    picoboot: &'d Picoboot<'a, Rp2350, NoCustom, Rp2350Halt>,
    diag: [u8; DIAG_LEN],
}

impl Handler for Bootsel<'_, '_> {
    fn control_out(&mut self, req: Request, _data: &[u8]) -> Option<OutResponse> {
        // Every field is checked, and anything else is passed on rather than
        // answered.  Returning None leaves the request for another handler,
        // so this cannot refuse on picoboot's behalf.
        if req.request_type != RequestType::Vendor
            || req.recipient != Recipient::Interface
            || req.request != REQ_BOOTSEL
            || req.value != REQ_BOOTSEL_VALUE
            || req.length != 0
        {
            return None;
        }

        reboot_execute(&Reboot {
            flags: REBOOT_TYPE_BOOTSEL,
            delay_ms: REBOOT_DELAY_MS,
            p0: 0,
            p1: 0,
        });

        Some(OutResponse::Accepted)
    }

    fn control_in<'r>(&'r mut self, req: Request, _buf: &'r mut [u8]) -> Option<InResponse<'r>> {
        if req.request_type != RequestType::Vendor
            || req.recipient != Recipient::Interface
            || req.request != REQ_DIAG
        {
            return None;
        }

        let d = self.picoboot.diagnostics();
        self.diag = [
            d.state,
            u8::from(d.halted_out),
            u8::from(d.halted_in),
            u8::from(d.in_flight),
            d.rx_len as u8,
            (d.rx_len >> 8) as u8,
            d.tx_len as u8,
            (d.tx_len >> 8) as u8,
        ];
        Some(InResponse::Accepted(&self.diag))
    }
}

// ---------------------------------------------------------------------------
// The device
// ---------------------------------------------------------------------------

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let p = embassy_rp::init(Default::default());

    // The same ids a real part in BOOTSEL carries, so picotool and picoboot-rs
    // drive it with no arguments.  The product string is this device's own, so
    // a host can tell the instrument from the example.
    let mut config = Config::new(0x2e8a, 0x000f);
    config.manufacturer = Some("Raspberry Pi");
    config.product = Some("RP2350 picobootx hwtest");
    config.max_power = 100;

    let mut config_descriptor = [0u8; 64];
    let mut bos_descriptor = [0u8; 16];
    let mut control_buf = [0u8; 64];

    // picobootx requires a buffer for flash writes.
    let mut flash_page = [0u8; FLASH_PAGE_SIZE];

    // No commands of this device's own.  The refusal the test needs comes from
    // the standard read, which the RP2350 defaults refuse for an address
    // outside ROM, flash or SRAM, so nothing here has to invent one.
    let picoboot = Picoboot::new(
        Rp2350,
        NoCustom,
        Some(&mut flash_page),
        Endpoints {
            out: EP_OUT,
            r#in: EP_IN,
        },
        MAX_PACKET_SIZE,
        Rp2350Halt,
    );
    let mut handler = picoboot.handler();
    let mut bootsel = Bootsel {
        picoboot: &picoboot,
        diag: [0; DIAG_LEN],
    };

    let mut builder = Builder::new(
        Driver::new(p.USB, Irqs),
        config,
        &mut config_descriptor,
        &mut bos_descriptor,
        &mut [],
        &mut control_buf,
    );
    // picobootx first, so a request it owns reaches it before anything else is
    // asked.  Bootsel answers only its own and passes everything else on.
    builder.handler(&mut handler);
    builder.handler(&mut bootsel);

    // picotool only recognises a device whose interface 0 is vendor, subclass
    // zero, protocol zero, and only looks for picoboot on interface 0 or 1.
    let mut function = builder.function(0xff, 0, 0);
    let mut interface = function.interface();
    let mut alt = interface.alt_setting(0xff, 0, 0, None);
    let ep_out = alt.endpoint_bulk_out(Some(EP_OUT.into()), MAX_PACKET_SIZE);
    let ep_in = alt.endpoint_bulk_in(Some(EP_IN.into()), MAX_PACKET_SIZE);
    drop(function);

    let mut usb = builder.build();

    // Both must run: control carries a command's status, INTERFACE RESET and
    // the reboot request, and bulk carries the commands.
    join(usb.run(), picoboot.run(ep_out, ep_in)).await;
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
