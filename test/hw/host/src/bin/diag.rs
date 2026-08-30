// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! Watch what the device's protocol does across a sequence of commands.
//!
//! Every step reads the device's own view over the control endpoint, which
//! answers whether or not the bulk pair is moving.  That is the difference
//! between seeing where the protocol stopped and inferring it from the outside.
//!
//! It speaks the protocol properly, acknowledgement included, so what it shows
//! is what an ordinary session looks like rather than what one missing half of
//! every exchange looks like.
//!
//! Only the embassy firmware answers.  The C picobootx publishes no state, so
//! the tinyusb device has nothing to report and this refuses it by name.

use std::process::ExitCode;

use picobootx::wire::DIR_IN;
use picobootx_hw_host::{Board, EP_IN, EP_OUT, Firmware, take_device_arg};

const CMD_READ: u8 = 0x04 | DIR_IN;
const ROM_MAGIC_ADDR: u32 = 0x0000_0010;
const READ_LEN: u32 = 4;

async fn show(board: &Board, when: &str) {
    match board.diagnostics().await {
        Ok(d) => println!("        [{when}] {d}"),
        Err(e) => println!("        [{when}] unavailable: {e}"),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let want = match take_device_arg(std::env::args().skip(1)) {
        Ok((want, _)) => want.unwrap_or(Firmware::Embassy),
        Err(e) => {
            eprintln!("picobootx-hw-diag: {e}");
            return ExitCode::FAILURE;
        }
    };

    if !want.serves_diagnostics() {
        eprintln!("picobootx-hw-diag: the {want} firmware publishes no state to watch");
        return ExitCode::FAILURE;
    }

    let mut board = match Board::open(Some(want)).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    show(&board, "opened").await;

    // From a known state, so what follows is this run and not the last one.
    match board.quiesce().await {
        Ok(()) => println!("quiesced"),
        Err(e) => println!("quiesce FAILED: {e}"),
    }
    show(&board, "quiesced").await;

    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&ROM_MAGIC_ADDR.to_le_bytes());
    args[4..8].copy_from_slice(&READ_LEN.to_le_bytes());

    for i in 1..=4 {
        println!("read {i}:");
        match board.send_cmd(CMD_READ, READ_LEN, &args) {
            Ok(()) => println!("        command sent"),
            Err(e) => println!("        command FAILED: {e}"),
        }
        show(&board, "after send").await;

        match board.read_reply(READ_LEN as usize) {
            Ok(d) => println!("        reply {d:02x?}"),
            Err(e) => println!("        reply FAILED: {e}"),
        }
        show(&board, "after reply").await;

        match board.ack() {
            Ok(()) => println!("        acknowledged"),
            Err(e) => println!("        acknowledgement FAILED: {e}"),
        }
        show(&board, "after ack").await;
    }

    println!("recover:");
    let _ = board.clear_halt(EP_IN).await;
    let _ = board.clear_halt(EP_OUT).await;
    let _ = board.interface_reset().await;
    show(&board, "after recovery").await;

    ExitCode::SUCCESS
}
