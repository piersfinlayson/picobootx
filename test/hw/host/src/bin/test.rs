// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! Does a real device serve the command after a refusal?
//!
//! picobootx refuses a command by halting both bulk endpoints.  The host clears
//! the halts and sends INTERFACE RESET, and the transfer after that is the one
//! at risk: USB numbers packets alternately so each end can spot a repeat, and
//! clearing a halt is supposed to put both ends back to zero.  embassy-rp does
//! not reset its side, so picobootx-embassy does it in the INTERFACE RESET
//! handler.  Whether that works is what this asks, and it can only be asked of
//! real silicon.
//!
//! The failure it exists to catch is quiet: the device reads the command and
//! writes its reply, and the host never collects it.  Losing exactly one packet
//! puts the two ends back in step, so a retry succeeds and the whole thing
//! reads as flakiness.  Every read here is therefore tried twice, and a first
//! attempt that fails where the second succeeds is reported as the failure it
//! is rather than being smoothed over.

use std::process::ExitCode;

use picobootx::Status;
use picobootx::wire::DIR_IN;
use picobootx_hw_host::{Board, EP_IN, EP_OUT};

// PICOBOOT's read, and an address the RP2350 defaults refuse.  The refusal is
// the stimulus, so it has to be one the device is certain to give: 0x4000_0000
// is a peripheral, and read_prepare admits ROM, flash and SRAM alone.
const CMD_READ: u8 = 0x04 | DIR_IN;
const ROM_MAGIC_ADDR: u32 = 0x0000_0010;
const REFUSED_ADDR: u32 = 0x4000_0000;
const READ_LEN: u32 = 4;

struct Report {
    passed: usize,
    failed: usize,
}

impl Report {
    fn check(&mut self, what: &str, outcome: Result<(), String>) {
        match outcome {
            Ok(()) => {
                self.passed += 1;
                println!("  ok    {what}");
            }
            Err(e) => {
                self.failed += 1;
                println!("  FAIL  {what}: {e}");
            }
        }
    }
}

/// One read, and whether it needed a second go.
enum Read {
    /// Served when it was first asked, which is what a working device does.
    FirstTime(Vec<u8>),
    /// Lost once and served on the retry - the signature of a toggle that was
    /// left out of step.
    OnRetry(String),
    /// Not served at all.
    Never(String),
}

fn read_word(board: &Board, addr: u32) -> Read {
    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&addr.to_le_bytes());
    args[4..8].copy_from_slice(&READ_LEN.to_le_bytes());

    for attempt in 0..2 {
        if let Err(e) = board.send_cmd(CMD_READ, READ_LEN, &args) {
            if attempt == 1 {
                return Read::Never(format!("the command would not go out: {e}"));
            }
            continue;
        }
        match board.read_reply(READ_LEN as usize) {
            Ok(data) if attempt == 0 => return Read::FirstTime(data),
            Ok(_) => return Read::OnRetry("the first attempt was lost".into()),
            Err(e) if attempt == 1 => return Read::Never(e),
            Err(_) => continue,
        }
    }
    Read::Never("no attempt was served".into())
}

#[tokio::main]
async fn main() -> ExitCode {
    println!("picobootx on real hardware, after a refusal");
    println!();

    let board = match Board::open().await {
        Ok(b) => b,
        Err(e) => {
            println!("  FAIL  find the board: {e}");
            println!();
            println!("1 checks, 1 failed");
            return ExitCode::FAILURE;
        }
    };
    let mut report = Report {
        passed: 0,
        failed: 0,
    };

    // Serving at all, before anything is broken.  Without this a later failure
    // cannot be told from a device that was never answering.  What comes back
    // is kept, because the read after recovery has to return the same bytes -
    // a reply of the right length carrying the wrong content would otherwise
    // pass.
    let mut baseline = Vec::new();
    report.check(
        "the board serves a read before any refusal",
        match read_word(&board, ROM_MAGIC_ADDR) {
            Read::FirstTime(data) => {
                baseline = data;
                Ok(())
            }
            Read::OnRetry(e) | Read::Never(e) => Err(e),
        },
    );

    // The stimulus.  This is expected to fail on the wire - the device halts
    // both endpoints rather than answering - so a refusal here is the point,
    // and being served would mean the address was not refused after all.
    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&REFUSED_ADDR.to_le_bytes());
    args[4..8].copy_from_slice(&READ_LEN.to_le_bytes());
    let _ = board.send_cmd(CMD_READ, READ_LEN, &args);
    let refused = board.read_reply(READ_LEN as usize).is_err();
    report.check(
        "a read of a peripheral address is refused rather than served",
        if refused {
            Ok(())
        } else {
            Err("the device served it".into())
        },
    );

    // The control endpoint answers while the bulk pair is halted, which is what
    // makes a refusal diagnosable at all.
    report.check(
        "the device reports the refusal on the control endpoint",
        match board.command_status().await {
            Ok(status) if status.len() >= 8 => {
                let code = u32::from_le_bytes([status[4], status[5], status[6], status[7]]);
                if code == Status::InvalidArg as u32 {
                    Ok(())
                } else {
                    Err(format!(
                        "it reported {code} rather than an invalid argument"
                    ))
                }
            }
            Ok(s) => Err(format!("the status block was {} bytes", s.len())),
            Err(e) => Err(e),
        },
    );

    // Both halts, then the reset.  Both, because the device put both ends back
    // to zero and a host that clears one leaves the other mismatched.
    let recovered = async {
        board.clear_halt(EP_IN).await?;
        board.clear_halt(EP_OUT).await?;
        board.interface_reset().await
    }
    .await;
    report.check("the device accepts the recovery sequence", recovered);

    // The question the whole thing exists to ask.
    report.check(
        "the first read after recovery is served, not lost",
        match read_word(&board, ROM_MAGIC_ADDR) {
            Read::FirstTime(data) if data == baseline => Ok(()),
            Read::FirstTime(data) => Err(format!(
                "it was served, but returned {data:02x?} where the same address gave \
                 {baseline:02x?} before the refusal"
            )),
            Read::OnRetry(_) => Err(
                "the first attempt was lost and the retry worked - the data toggle was left \
                 out of step, which is the defect this design exists to work around"
                    .into(),
            ),
            Read::Never(e) => Err(e),
        },
    );

    println!();
    println!(
        "{} checks, {} failed",
        report.passed + report.failed,
        report.failed
    );

    if report.failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
