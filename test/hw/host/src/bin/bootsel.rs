// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! Put the hardware test board back into BOOTSEL, over USB.
//!
//! The board is jumpered by hand once, to take the test firmware in the first
//! place.  After that this is what puts it back in the bootloader, so a rebuild
//! is flashed without anyone reaching for the board - including a rebuild that
//! is the other firmware, which is how one board serves both halves of the
//! test.
//!
//! Either firmware answers.  `--device embassy` or `--device tinyusb` says
//! which, and is needed only where both are somehow on the bus at once.

use std::process::ExitCode;

use picobootx_hw_host::{Board, port_reset, take_device_arg};

#[tokio::main]
async fn main() -> ExitCode {
    let want = match take_device_arg(std::env::args().skip(1)) {
        Ok((want, _)) => want,
        Err(e) => {
            eprintln!("picobootx-hw-bootsel: {e}");
            return ExitCode::FAILURE;
        }
    };

    let board = match Board::open(want).await {
        Ok(b) => b,
        Err(e) => {
            // A board that stopped answering keeps the descriptors the host
            // already has, so what it looks like is what it was running rather
            // than what it is.  Resetting the port is what settles that, and it
            // is the difference between reaching for the jumper and not.
            eprintln!("picobootx-hw-bootsel: {e}");
            match port_reset().await {
                Ok(Some(now)) => eprintln!("  after a port reset it presents as {now}"),
                Ok(None) => eprintln!("  after a port reset it names nothing"),
                Err(e) => eprintln!("  the port reset got nowhere either: {e}"),
            }
            return ExitCode::FAILURE;
        }
    };

    // The device acknowledges and then reboots on a delay, so this returns
    // rather than failing on a device that vanished mid-transfer.
    match board.bootsel().await {
        Ok(()) => {
            println!("asked the {} board to reboot into BOOTSEL", board.firmware);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("picobootx-hw-bootsel: {e}");
            ExitCode::FAILURE
        }
    }
}
