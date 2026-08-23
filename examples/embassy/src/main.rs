// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! A complete picobootx device for the RP2350, on embassy.
//!
//! It presents as a plain RP2350, so picotool and any other picoboot host
//! drives it with no arguments.  picobootx-rp2350 serves the whole of
//! PICOBOOT, and the two commands below are this device's own.
//!
//! Each comment says why the line beneath it is there.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_rp::bind_interrupts;
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::USB;
use embassy_rp::usb::{Driver, InterruptHandler};
use embassy_usb::{Builder, Config};

use picobootx::wire::FLASH_PAGE_SIZE;
use picobootx::{Command, Custom, Endpoints, Filled, Status};
use picobootx_embassy::{Picoboot, Rp2350Halt};
use picobootx_rp2350::Rp2350;

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
// Two commands of this device's own
// ---------------------------------------------------------------------------

// A command is routed by its magic, so these identifiers cannot collide with
// PICOBOOT's.  A device with no commands of its own passes NoCustom instead.
const MAGIC: u32 = 0x3b7f_1e05;

// Bit 7 set means the device replies with data.
const CMD_LED: u8 = 0x01;
const CMD_NAME: u8 = 0x81;

const NAME: &[u8] = b"picobootx on embassy";

struct Commands {
    led: Output<'static>,
    sent: usize,
}

impl Custom for Commands {
    fn magic(&self) -> Option<u32> {
        Some(MAGIC)
    }

    // Every command carrying MAGIC arrives here for handling.  Validate
    // now rather than in fill, so a refusal reaches the host before any
    // reply goes out.
    fn dispatch(&mut self, cmd: &Command) -> picobootx::Result {
        match cmd.cmd_id {
            CMD_LED => {
                let level = if cmd.args[0] == 0 {
                    Level::Low
                } else {
                    Level::High
                };
                self.led.set_level(level);
                Ok(())
            }
            CMD_NAME => {
                if cmd.transfer_len as usize != NAME.len() {
                    return Err(Status::InvalidTransferLen);
                }
                self.sent = 0;
                Ok(())
            }
            _ => Err(Status::UnknownCmd),
        }
    }

    // Called repeatedly until the transfer completes.  picobootx keeps no
    // cursor, so the position is this device's to track.
    fn fill(&mut self, _cmd: &Command, buf: &mut [u8]) -> Result<Filled, Status> {
        let left = &NAME[self.sent..];
        let n = left.len().min(buf.len());
        buf[..n].copy_from_slice(&left[..n]);
        self.sent += n;
        Ok(if self.sent == NAME.len() {
            Filled::Done(n)
        } else {
            Filled::More(n)
        })
    }
}

// ---------------------------------------------------------------------------
// The device
// ---------------------------------------------------------------------------

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let p = embassy_rp::init(Default::default());

    let mut config = Config::new(0x2e8a, 0x000f);
    config.manufacturer = Some("Raspberry Pi");
    config.product = Some("RP2350 picobootx");
    config.max_power = 100;

    let mut config_descriptor = [0u8; 64];
    let mut bos_descriptor = [0u8; 16];
    let mut control_buf = [0u8; 64];

    // picobootx requires a buffer for flash writes.
    let mut flash_page = [0u8; FLASH_PAGE_SIZE];

    // Built before the USB builder, which borrows the handler for its lifetime.
    // Hence endpoint addresses here, not the endpoints themselves.
    let picoboot = Picoboot::new(
        // Serves the standard PICOBOOT commands.  Write your own impl Ops to
        // change what one does, or to serve a part that is not an RP2350.
        Rp2350,
        // This device's own commands.  Use NoCustom to serve the standard
        // ones alone.
        Commands {
            led: Output::new(p.PIN_25, Level::Low),
            sent: 0,
        },
        // Give the host a buffer to allow it to write to flash.
        Some(&mut flash_page),
        // The same pair the descriptor declares below.
        Endpoints {
            out: EP_OUT,
            r#in: EP_IN,
        },
        MAX_PACKET_SIZE,
        // Needed on every RP2350 embassy device: picoboot refuses a command by
        // halting its endpoints, and this reaches the chip's registers to do it.
        Rp2350Halt,
    );
    let mut handler = picoboot.handler();

    let mut builder = Builder::new(
        Driver::new(p.USB, Irqs),
        config,
        &mut config_descriptor,
        &mut bos_descriptor,
        &mut [],
        &mut control_buf,
    );
    builder.handler(&mut handler);

    // picotool only recognises a device whose interface 0 is vendor, subclass
    // zero, protocol zero, and only looks for picoboot on interface 0 or 1.
    let mut function = builder.function(0xff, 0, 0);
    let mut interface = function.interface();
    let mut alt = interface.alt_setting(0xff, 0, 0, None);
    let ep_out = alt.endpoint_bulk_out(Some(EP_OUT.into()), MAX_PACKET_SIZE);
    let ep_in = alt.endpoint_bulk_in(Some(EP_IN.into()), MAX_PACKET_SIZE);
    drop(function);

    let mut usb = builder.build();

    // Both must run: control carries a command's status and INTERFACE RESET,
    // bulk carries the commands.  Joined rather than spawned because Picoboot
    // is shared between them.
    join(usb.run(), picoboot.run(ep_out, ep_in)).await;
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
