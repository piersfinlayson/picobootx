// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! Put the hardware test board back into BOOTSEL, over USB.
//!
//! The board is jumpered by hand once, to take the test firmware in the first
//! place.  After that this is what puts it back in the bootloader, so a rebuild
//! is flashed without anyone reaching for the board.

use std::process::ExitCode;

use picobootx_hw_host::Board;

#[tokio::main]
async fn main() -> ExitCode {
    let board = match Board::open().await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("picobootx-hw-bootsel: {e}");
            return ExitCode::FAILURE;
        }
    };

    // The device acknowledges and then reboots on a delay, so this returns
    // rather than failing on a device that vanished mid-transfer.
    match board.bootsel().await {
        Ok(()) => {
            println!("asked the board to reboot into BOOTSEL");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("picobootx-hw-bootsel: {e}");
            ExitCode::FAILURE
        }
    }
}
