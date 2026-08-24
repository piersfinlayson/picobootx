// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! picobootx on real silicon, driven by a real host.
//!
//! The conformance suites answer what the protocol does.  What a USB controller
//! does is a separate question — data toggles, halts, a host that waits for what
//! it is owed before it sends again — and this is for that.
//!
//! Checks are grouped, and a group name on the command line runs the groups
//! whose name contains it, the way `FILTER=` does in the conformance suite.
//!
//! # Every run starts and ends quiet
//!
//! The device keeps its state across the host process exiting, so a run that
//! began wherever the last one stopped would be measuring the previous run as
//! much as this one.  [`Board::quiesce`] is what establishes the starting point,
//! and the same call at the end is what says this run left nothing behind.

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

/// A second ROM address, whose contents differ from the first.  Two addresses
/// that answer differently is what lets a reply say which read produced it.
const ROM_OTHER_ADDR: u32 = 0x0000_0000;

/// Prints as it goes and counts what it saw.
///
/// A group is a heading and a set of checks under it.  [`Runner::group`] says
/// whether the group the caller is about to run was asked for, so a filtered
/// run skips the work as well as the printing.
struct Runner {
    passed: usize,
    failed: usize,
    skipped: usize,
    filter: Option<String>,
}

impl Runner {
    fn new(filter: Option<String>) -> Self {
        Self {
            passed: 0,
            failed: 0,
            skipped: 0,
            filter,
        }
    }

    /// Start a group, and say whether it is one this run was asked for.
    fn group(&mut self, name: &str) -> bool {
        let wanted = match &self.filter {
            None => true,
            Some(f) => name.contains(f.as_str()),
        };
        if wanted {
            println!("{name}");
        } else {
            self.skipped += 1;
        }
        wanted
    }

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

    fn finish(&self) -> ExitCode {
        println!();
        print!(
            "{} checks, {} failed",
            self.passed + self.failed,
            self.failed
        );
        if self.skipped > 0 {
            print!(", {} groups not asked for", self.skipped);
        }
        println!();

        if self.failed == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
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

/// Read one word, acknowledging the transfer the way the protocol says.
///
/// Tried twice, because losing exactly one packet puts both ends back in step
/// and a retry then works.  Reporting that as a pass would turn the defect this
/// exists to catch into flakiness, so the retry is reported as the failure it
/// is.
fn read_word(board: &mut Board, addr: u32) -> Read {
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
            Ok(data) => {
                // The host's half of the acknowledgement.  Without it the
                // device stays in AwaitAck and the next command arrives where
                // one was expected.
                if let Err(e) = board.ack() {
                    return Read::Never(format!("the transfer would not be acknowledged: {e}"));
                }
                return if attempt == 0 {
                    Read::FirstTime(data)
                } else {
                    Read::OnRetry("the first attempt was lost".into())
                };
            }
            Err(e) if attempt == 1 => return Read::Never(e),
            Err(_) => continue,
        }
    }
    Read::Never("no attempt was served".into())
}

#[tokio::main]
async fn main() -> ExitCode {
    let filter = std::env::args().nth(1);

    println!("picobootx on real hardware");
    println!();

    let mut board = match Board::open().await {
        Ok(b) => b,
        Err(e) => {
            println!("  FAIL  find the board: {e}");
            println!();
            println!("1 checks, 1 failed");
            return ExitCode::FAILURE;
        }
    };
    let mut run = Runner::new(filter);

    if run.group("start") {
        // Before anything is asked of it.  A device left part way through a
        // command by whatever ran last would otherwise answer the first check
        // out of the previous run's transfer.
        run.check(
            "the board can be put back to waiting for a command",
            board.quiesce().await,
        );

        // The other arm of the refusal group's halt check, and the one a host
        // acts on more often.  picotool decides whether to send CLEAR_FEATURE
        // from this answer alone, and clearing a halt that was never set resets
        // the host's data toggle - so a device that over-reports a halt has its
        // hosts lose a transfer for a halt that never happened.
        run.check(
            "an idle board reports neither endpoint halted",
            match (
                board.endpoint_halted(EP_IN).await,
                board.endpoint_halted(EP_OUT).await,
            ) {
                (Ok(false), Ok(false)) => Ok(()),
                (Ok(i), Ok(o)) => Err(format!("it reports IN halted={i}, OUT halted={o}")),
                (Err(e), _) | (_, Err(e)) => Err(e),
            },
        );
    }

    if run.group("refusal") {
        refusal(&mut run, &mut board).await;
    }

    if run.group("abandoned") {
        abandoned(&mut run, &mut board).await;
    }

    // Leave nothing behind, and say so where it would not go.  A run that ends
    // with the device holding a packet is one that has set up the next run to
    // fail for a reason that is not the next run's.
    run.check(
        "the board is left waiting for a command",
        board.quiesce().await,
    );

    run.finish()
}

/// A refusal and the recovery after it, which is the sequence a wire is needed
/// to judge.
///
/// picobootx refuses by halting both bulk endpoints.  The host clears the halts
/// and sends INTERFACE RESET, and the transfer after that is the one at risk:
/// USB numbers packets alternately so each end can spot a repeat, and clearing
/// a halt is supposed to put both ends back to zero.  embassy-rp does not reset
/// its side, so picobootx-embassy does it in the INTERFACE RESET handler.
/// Whether that works can only be asked of real silicon.
async fn refusal(run: &mut Runner, board: &mut Board) {
    // Serving at all, before anything is broken.  Without this a later failure
    // cannot be told from a device that was never answering.  What comes back
    // is kept, because the read after recovery has to return the same bytes -
    // a reply of the right length carrying the wrong content would otherwise
    // pass.
    let mut baseline = Vec::new();
    run.check(
        "the board serves a read before any refusal",
        match read_word(board, ROM_MAGIC_ADDR) {
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
    run.check(
        "a read of a peripheral address is refused rather than served",
        if refused {
            Ok(())
        } else {
            Err("the device served it".into())
        },
    );

    // The control endpoint answers while the bulk pair is halted, which is what
    // makes a refusal diagnosable at all.
    run.check(
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

    // Both real hosts decide what to clear by asking, so what the device says
    // here is on the path every recovery takes.  A device that halted both ends
    // and reports neither leaves a host with nothing to clear, and one that
    // reports a halt it does not have has the host clear an endpoint that was
    // fine - which resets the host's data toggle and loses the next transfer.
    run.check(
        "the device reports both endpoints halted",
        match (
            board.endpoint_halted(EP_IN).await,
            board.endpoint_halted(EP_OUT).await,
        ) {
            (Ok(true), Ok(true)) => Ok(()),
            (Ok(i), Ok(o)) => Err(format!("it reports IN halted={i}, OUT halted={o}")),
            (Err(e), _) | (_, Err(e)) => Err(e),
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
    run.check("the device accepts the recovery sequence", recovered);

    // The question the whole thing exists to ask.
    run.check(
        "the first read after recovery is served, not lost",
        match read_word(board, ROM_MAGIC_ADDR) {
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
}

/// A host that walks away mid-transfer does not cost the next host its reply.
///
/// The device arms a reply and the host never collects it.  Left on the
/// controller, that packet is handed to whoever reads next, who then has the
/// previous session's answer to a question it never asked - and every answer
/// after that is one command behind, which reads as a device that is randomly
/// wrong rather than as a host that left something behind.
///
/// The RP2350 boot ROM takes the packet back when it is sent INTERFACE RESET,
/// and this is the same claim asked of picobootx.  It needs a wire: nothing
/// below the controller's own buffer is visible to a model.
async fn abandoned(run: &mut Runner, board: &mut Board) {
    // Two addresses that answer differently, so a reply names its own command.
    // Checked rather than assumed, since a part where they matched would make
    // everything below vacuous.
    let (first, second) = match (
        read_word(board, ROM_MAGIC_ADDR),
        read_word(board, ROM_OTHER_ADDR),
    ) {
        (Read::FirstTime(a), Read::FirstTime(b)) => (a, b),
        _ => {
            run.check(
                "the two addresses can be told apart",
                Err("one of them would not read".into()),
            );
            return;
        }
    };
    run.check(
        "the two addresses answer differently",
        if first == second {
            Err(format!(
                "both read {first:02x?}, so a reply cannot name its command"
            ))
        } else {
            Ok(())
        },
    );

    // Ask, and walk away without collecting.  This is the whole stimulus.
    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&ROM_MAGIC_ADDR.to_le_bytes());
    args[4..8].copy_from_slice(&READ_LEN.to_le_bytes());
    if let Err(e) = board.send_cmd(CMD_READ, READ_LEN, &args) {
        run.check("a reply can be left uncollected", Err(e));
        return;
    }

    run.check(
        "the device accepts INTERFACE RESET",
        board.interface_reset().await,
    );

    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&ROM_OTHER_ADDR.to_le_bytes());
    args[4..8].copy_from_slice(&READ_LEN.to_le_bytes());
    if let Err(e) = board.send_cmd(CMD_READ, READ_LEN, &args) {
        run.check("the next command goes out", Err(e));
        return;
    }

    // The next question.  Its own answer is the only right one.
    run.check(
        "the reply left behind is not served to the next command",
        match board.read_reply(READ_LEN as usize) {
            Err(e) => Err(format!("nothing came back at all: {e}")),
            Ok(got) if got == second => Ok(()),
            Ok(got) if got == first => Err(
                "it served the abandoned reply, so the pipe is one command behind and \
                 every answer after this belongs to the question before it"
                    .into(),
            ),
            Ok(got) => Err(format!("it returned {got:02x?}, which is neither address")),
        },
    );
}
