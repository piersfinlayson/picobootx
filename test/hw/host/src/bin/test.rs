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
use std::time::Duration;

use picobootx::Status;
use picobootx::wire::DIR_IN;
use picobootx_hw_host::{
    Board, CMD_FLASH_ERASE, CMD_GET_INFO, CMD_REBOOT_OLD, CMD_REBOOT2, CMD_WRITE, EP_IN, EP_OUT,
    FLASH_BLOCK, FLASH_PAGE, FLASH_SECTOR, INFO_ARGS_LEN, INFO_SYS, MAX_PACKET, REBOOT_ARGS_LEN,
    REBOOT_NORMAL, wait_back, wait_gone,
};

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

/// Where the boot ROM starts, and where flash is mapped.  Both answer reads,
/// and between them they give a long transfer somewhere to come from.
const ROM_BASE: u32 = 0x0000_0000;
const FLASH_BASE: u32 = 0x1000_0000;

/// The system information flags, and how many words each carries.  The device
/// answers whichever of them it was asked for, one after another in this order,
/// which is what a host reads the reply apart by.
const FLAG_CHIP: u32 = 0x0001;
const FLAG_CHIP_WORDS: u32 = 3;
const FLAG_CPU: u32 = 0x0004;
const FLAG_CPU_WORDS: u32 = 1;
const FLAG_BOOT_RANDOM: u32 = 0x0010;
const FLAG_BOOT_RANDOM_WORDS: u32 = 4;

/// A flag no part carries, for asking what the device does with one.
const FLAG_UNKNOWN: u32 = 0x0080;

/// How long the device waits before rebooting, so the acknowledgement has time
/// to be collected first.  Long enough to be the device's wait rather than a
/// race, short enough not to stretch the run.
const REBOOT_DELAY_MS: u32 = 100;

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

    if run.group("multi-packet") {
        multi_packet(&mut run, &mut board).await;
    }

    if run.group("get-info") {
        get_info(&mut run, &mut board).await;
    }

    if run.group("flash") {
        flash(&mut run, &mut board).await;
    }

    if run.group("reboot") {
        match reboot(&mut run, board).await {
            Some(b) => board = b,
            // Nothing after this can be asked of a board that did not come
            // back, and saying so once beats every later check failing with a
            // reason that is not its own.
            None => return run.finish(),
        }
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

/// A pattern that repeats in neither byte nor packet.
///
/// The index is in it, so a transfer that dropped a packet, repeated one, or
/// put two in the wrong order reads back as something other than this rather
/// than as a shift nothing notices.
fn pattern(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// Transfers longer than the 64 bytes a full-speed bulk endpoint carries.
///
/// A packet is where a USB device's bookkeeping lives, so every question about
/// it starts at the second one: whether the data toggle alternates across a
/// long transfer, whether a transfer that is an exact number of packets ends
/// without the host waiting for more, and whether one that is not ends on the
/// short packet.  The protocol suites cannot ask any of it — they hand the
/// library a byte queue, and a queue has no packets in it.
async fn multi_packet(run: &mut Runner, board: &mut Board) {
    // Device to host, growing past one packet.  Each is checked against the
    // same bytes taken four at a time, which is the length already known to
    // work, so a long transfer is judged against the device's own answer
    // rather than against what this test expects the ROM to hold.
    let mut reference = Vec::new();
    for offset in (0..256).step_by(4) {
        match board.read_mem(ROM_BASE + offset, 4) {
            Ok(mut d) => reference.append(&mut d),
            Err(e) => {
                run.check("the ROM can be read four bytes at a time", Err(e));
                return;
            }
        }
    }

    for len in [64u32, 100, 256] {
        let want = reference[..len as usize].to_vec();
        run.check(
            &format!("a {len} byte read returns the same bytes as reading it in fours"),
            match board.read_mem(ROM_BASE, len) {
                Err(e) => Err(e),
                Ok(got) if got == want => Ok(()),
                Ok(got) if got.len() != len as usize => {
                    Err(format!("{} bytes came back, not {len}", got.len()))
                }
                Ok(got) => Err(format!(
                    "byte {} differs",
                    got.iter().zip(&want).position(|(a, b)| a != b).unwrap_or(0)
                )),
            },
        );
    }

    // Long enough that nothing about it fits in one of anything.
    run.check(
        "a 4096 byte read of flash returns 4096 bytes",
        match board.read_mem(FLASH_BASE, 4096) {
            Err(e) => Err(e),
            Ok(got) if got.len() == 4096 => Ok(()),
            Ok(got) => Err(format!("{} bytes came back", got.len())),
        },
    );

    // Host to device, which has never been on this board at all.
    let scratch = match board.scratch().await {
        Ok(s) => (s.ram, s.ram_len),
        Err(e) => {
            run.check("the device says where a host may write", Err(e));
            return;
        }
    };
    let (scratch, scratch_len) = scratch;
    run.check(
        "the device says where a host may write",
        if scratch_len >= 512 {
            Ok(())
        } else {
            Err(format!(
                "it offered {scratch_len} bytes, which is not enough to test with"
            ))
        },
    );

    for len in [1usize, 63, 64, 512] {
        let want = pattern(len as u8, len);
        run.check(
            &format!("a {len} byte write reads back as what went in"),
            match board.write_mem(scratch, &want) {
                Err(e) => Err(format!("the write would not go: {e}")),
                Ok(()) => match board.read_mem(scratch, len as u32) {
                    Err(e) => Err(format!("the read back would not go: {e}")),
                    Ok(got) if got == want => Ok(()),
                    Ok(got) => Err(format!(
                        "byte {} differs",
                        got.iter().zip(&want).position(|(a, b)| a != b).unwrap_or(0)
                    )),
                },
            },
        );
    }

    // A write stops at the length it was given.  Without this the checks above
    // would pass on a device that wrote the whole packet every time, since they
    // only ever look at the bytes they asked for.
    let guard = 0xA5u8;
    let filled = vec![guard; 128];
    let short = pattern(0x11, 65);
    run.check(
        "a write stops where its length says, not where its packet does",
        match board
            .write_mem(scratch, &filled)
            .and_then(|()| board.write_mem(scratch, &short))
            .and_then(|()| board.read_mem(scratch, 128))
        {
            Err(e) => Err(e),
            Ok(got) if got[..65] != short[..] => Err("what was written did not land".into()),
            Ok(got) if got[65..].iter().all(|b| *b == guard) => Ok(()),
            Ok(got) => Err(format!(
                "{} bytes past the end of the transfer were overwritten",
                got[65..].iter().filter(|b| **b != guard).count()
            )),
        },
    );

    // A host that says more than it sends.  The device is left holding a
    // transfer that will not finish, and the reset has to be enough to get it
    // back - a device that cannot is one a single interrupted write wedges.
    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&scratch.to_le_bytes());
    args[4..8].copy_from_slice(&256u32.to_le_bytes());
    let promised = board
        .send_cmd(CMD_WRITE, 256, &args)
        .and_then(|()| board.send_data(&pattern(0x77, MAX_PACKET)));
    run.check(
        "a write that promises more than it sends is accepted",
        promised,
    );

    run.check(
        "the board comes back from a transfer the host abandoned",
        board.quiesce().await,
    );
    run.check(
        "and serves the next command",
        match board.read_mem(ROM_BASE, 4) {
            Ok(got) if got == reference[..4] => Ok(()),
            Ok(got) => Err(format!("it returned {got:02x?}")),
            Err(e) => Err(e),
        },
    );
}

/// Send a command that should be refused, and return the status the device
/// gives for it, leaving the board ready for the next one.
///
/// The read is expected to fail — a refusal halts both endpoints rather than
/// answering — so what it returned is not looked at.  The reason comes from the
/// control endpoint, which is the whole point of a refusal being reported
/// there.
async fn refusal_code(
    board: &mut Board,
    cmd: u8,
    cmd_size: u8,
    tlen: u32,
    args: &[u8],
) -> Result<u32, String> {
    board.send_cmd_sized(cmd, cmd_size, tlen, args)?;
    let _ = board.read_reply(4);

    let status = board.command_status().await?;
    if status.len() < 8 {
        return Err(format!("the status block was {} bytes", status.len()));
    }
    let code = u32::from_le_bytes([status[4], status[5], status[6], status[7]]);

    board.quiesce().await?;
    Ok(code)
}

/// `GET_INFO` arguments asking for these system flags.
fn info_args(flags: u32) -> [u8; INFO_ARGS_LEN] {
    let mut args = [0u8; INFO_ARGS_LEN];
    args[0] = INFO_SYS;
    args[4..8].copy_from_slice(&flags.to_le_bytes());
    args
}

/// What the device says about itself, and what it does with a request it
/// cannot answer.
///
/// The values come from the boot ROM rather than from picobootx, so what is
/// asked here is not whether they are right — that needs the same question put
/// to the boot ROM on the same part — but whether the device assembles them
/// correctly.  The reply is a word saying how many words follow, then each
/// flag's words in the order the protocol lists them, so the arithmetic joining
/// those is the device's own and is what can be wrong.
async fn get_info(run: &mut Runner, board: &mut Board) {
    let chip = match board.get_info_sys(FLAG_CHIP, FLAG_CHIP_WORDS) {
        Ok((header, data)) => {
            run.check(
                "one flag is answered with the word count it carries",
                if header == FLAG_CHIP_WORDS && data.len() == FLAG_CHIP_WORDS as usize * 4 {
                    Ok(())
                } else {
                    Err(format!(
                        "it said {header} words and sent {} bytes",
                        data.len()
                    ))
                },
            );
            data
        }
        Err(e) => {
            run.check(
                "one flag is answered with the word count it carries",
                Err(e),
            );
            return;
        }
    };

    let cpu = match board.get_info_sys(FLAG_CPU, FLAG_CPU_WORDS) {
        Ok((header, data)) => {
            run.check(
                "a flag carrying one word is answered with one word",
                if header == FLAG_CPU_WORDS && data.len() == 4 {
                    Ok(())
                } else {
                    Err(format!(
                        "it said {header} words and sent {} bytes",
                        data.len()
                    ))
                },
            );
            data
        }
        Err(e) => {
            run.check("a flag carrying one word is answered with one word", Err(e));
            return;
        }
    };

    // The discriminating one.  Two flags at once have to give exactly what the
    // two gave separately, in the protocol's order — that is the join the
    // device does itself, and a device that answered a fixed buffer, dropped a
    // flag, or put them the other way round fails here and passes everything
    // above.
    let mut both = chip.clone();
    both.extend_from_slice(&cpu);
    run.check(
        "two flags together are the two flags separately, in order",
        match board.get_info_sys(FLAG_CHIP | FLAG_CPU, FLAG_CHIP_WORDS + FLAG_CPU_WORDS) {
            Err(e) => Err(e),
            Ok((header, _)) if header != FLAG_CHIP_WORDS + FLAG_CPU_WORDS => {
                Err(format!("it said {header} words"))
            }
            Ok((_, data)) if data == both => Ok(()),
            Ok((_, data)) => Err(format!(
                "it sent {data:02x?} where the two separately gave {both:02x?}"
            )),
        },
    );

    // A second flag whose value has nothing to do with the first, so a device
    // handing back the same buffer whatever it was asked is caught.
    run.check(
        "a different flag answers with something different",
        match board.get_info_sys(FLAG_BOOT_RANDOM, FLAG_BOOT_RANDOM_WORDS) {
            Err(e) => Err(e),
            Ok((_, data)) if data[..4] != chip[..4] => Ok(()),
            Ok(_) => Err("it gave the same first word as the chip flag".into()),
        },
    );

    // A flag the part does not carry is dropped rather than answered, and the
    // count says so before any of it is sent.
    run.check(
        "a flag the part does not carry is counted as no words",
        match board.get_info_sys(FLAG_UNKNOWN, 0) {
            Err(e) => Err(e),
            Ok((0, _)) => Ok(()),
            Ok((header, _)) => Err(format!("it said {header} words")),
        },
    );

    // The transfer length is the host's to state, so a device has to judge it.
    for (len, what) in [
        (0u32, "of nothing"),
        (6, "that is not a whole number of words"),
        (260, "longer than the reply can be"),
    ] {
        run.check(
            &format!("a transfer length {what} is refused"),
            match refusal_code(
                board,
                CMD_GET_INFO,
                INFO_ARGS_LEN as u8,
                len,
                &info_args(FLAG_CHIP),
            )
            .await
            {
                Err(e) => Err(e),
                Ok(code) if code == Status::InvalidTransferLen as u32 => Ok(()),
                Ok(code) => Err(format!("it reported {code}")),
            },
        );
    }

    // And a kind of information that is neither of the two the protocol names.
    let mut args = info_args(FLAG_CHIP);
    args[0] = 0x03;
    run.check(
        "an information type the protocol does not name is refused",
        match refusal_code(board, CMD_GET_INFO, INFO_ARGS_LEN as u8, 8, &args).await {
            Err(e) => Err(e),
            Ok(code) if code == Status::UnknownCmd as u32 => Ok(()),
            Ok(code) => Err(format!("it reported {code}")),
        },
    );
}

/// `REBOOT2` args: how to reboot, how long to wait first, and two parameters.
fn reboot_args(flags: u32, delay_ms: u32) -> [u8; REBOOT_ARGS_LEN] {
    let mut args = [0u8; REBOOT_ARGS_LEN];
    args[0..4].copy_from_slice(&flags.to_le_bytes());
    args[4..8].copy_from_slice(&delay_ms.to_le_bytes());
    args
}

/// The command that answers before it acts, and the bus going away underneath
/// it.
///
/// `REBOOT2` is acknowledged first and carried out once the acknowledgement has
/// gone, so a device that treated an armed packet as a delivered one reboots
/// with the answer still on the controller and the host never learns the
/// command was taken.  Which of the two happened is only visible on a wire: a
/// model has no moment where a packet is written but not yet collected.
///
/// Takes the board rather than borrowing it, because a reboot ends the
/// connection - the handle afterwards is a different one, and the reopening is
/// half of what is being tested.
async fn reboot(run: &mut Runner, mut board: Board) -> Option<Board> {
    // What the protocol will not serve, before anything that ends the session.
    run.check(
        "the reboot the protocol replaced is not served",
        match refusal_code(&mut board, CMD_REBOOT_OLD, 0, 0, &[]).await {
            Err(e) => Err(e),
            Ok(code) if code == Status::UnknownCmd as u32 => Ok(()),
            Ok(code) => Err(format!("it reported {code}")),
        },
    );

    run.check(
        "a reboot declaring the wrong argument size is refused",
        match refusal_code(
            &mut board,
            CMD_REBOOT2,
            (REBOOT_ARGS_LEN - 1) as u8,
            0,
            &reboot_args(REBOOT_NORMAL, 0),
        )
        .await
        {
            Err(e) => Err(e),
            Ok(code) if code == Status::InvalidCmdLength as u32 => Ok(()),
            Ok(code) => Err(format!("it reported {code}")),
        },
    );

    run.check(
        "a reboot promising a data phase is refused",
        match refusal_code(
            &mut board,
            CMD_REBOOT2,
            REBOOT_ARGS_LEN as u8,
            4,
            &reboot_args(REBOOT_NORMAL, 0),
        )
        .await
        {
            Err(e) => Err(e),
            Ok(code) if code == Status::InvalidTransferLen as u32 => Ok(()),
            Ok(code) => Err(format!("it reported {code}")),
        },
    );

    // What a read gives now, so the board that comes back can be shown to be
    // the same one answering the same way.
    let before = board.read_mem(ROM_BASE, 4).ok();

    // The reboot itself.  A delay, so the acknowledgement has somewhere to be
    // collected before the part goes - which is the ordering under test.
    let acknowledged = board
        .send_cmd(CMD_REBOOT2, 0, &reboot_args(REBOOT_NORMAL, REBOOT_DELAY_MS))
        .and_then(|()| board.read_ack());
    run.check(
        "the device acknowledges a reboot before it goes",
        acknowledged,
    );

    // Let go before the part does, so the bus is not being held by a handle to
    // something that has stopped answering.
    drop(board);

    run.check(
        "the board leaves the bus",
        wait_gone(Duration::from_secs(5)).await,
    );

    let board = match wait_back(Duration::from_secs(15)).await {
        Ok(b) => b,
        Err(e) => {
            run.check("the board comes back", Err(e));
            return None;
        }
    };
    run.check("the board comes back", Ok(()));

    let mut board = board;
    run.check(
        "the board that came back is the same one, answering the same way",
        match (board.read_mem(ROM_BASE, 4), before) {
            (Err(e), _) => Err(e),
            (Ok(now), Some(then)) if now == then => Ok(()),
            (Ok(now), Some(then)) => Err(format!("it reads {now:02x?} where it read {then:02x?}")),
            (Ok(_), None) => Err("there was nothing to compare with".into()),
        },
    );

    bus_reset(run, board).await
}

/// The bus going down under a command the device is part way through.
///
/// A reset re-enumerates the device, so whatever was in flight is not something
/// any host is still waiting for.  picobootx drops both queues and puts the
/// protocol back to waiting for a command, and the stack re-enables the
/// endpoints as the host configures the device again.  What has to be true
/// afterwards is that nothing survives to be served to the next question — the
/// same claim the abandoned group makes of INTERFACE RESET, reached by the one
/// path a device does not choose to take.
async fn bus_reset(run: &mut Runner, mut board: Board) -> Option<Board> {
    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&ROM_BASE.to_le_bytes());
    args[4..8].copy_from_slice(&READ_LEN.to_le_bytes());
    if let Err(e) = board.send_cmd(CMD_READ, READ_LEN, &args) {
        run.check("a command can be left in flight", Err(e));
        return Some(board);
    }

    // The reply is deliberately not collected.  The bus goes down under it.
    //
    // Everything below the device is given up first: a port reset is refused
    // while an interface is claimed, and a reset that was refused would leave
    // the checks below passing for the wrong reason.
    let device = board.into_device();
    let reset = device.reset().await.map_err(|e| format!("{e}"));
    drop(device);
    run.check("the device accepts a bus reset", reset);

    let mut board = match wait_back(Duration::from_secs(15)).await {
        Ok(b) => b,
        Err(e) => {
            run.check("the board comes back from a bus reset", Err(e));
            return None;
        }
    };
    run.check("the board comes back from a bus reset", Ok(()));

    let want = match board.read_mem(ROM_OTHER_ADDR, READ_LEN) {
        Ok(v) => v,
        Err(e) => {
            run.check("it serves a command after a bus reset", Err(e));
            return Some(board);
        }
    };
    run.check("it serves a command after a bus reset", Ok(()));

    // And the answer is that command's, not the one the reset interrupted.
    run.check(
        "the command the reset interrupted left nothing behind",
        match board.read_mem(ROM_OTHER_ADDR, READ_LEN) {
            Err(e) => Err(e),
            Ok(got) if got == want => Ok(()),
            Ok(got) => Err(format!(
                "it returned {got:02x?} where the same address gave {want:02x?}"
            )),
        },
    );

    Some(board)
}

/// Erasing and programming flash, which is the only thing here that changes the
/// board.
///
/// It is also the only place the CPU leaves the bus: an erase runs with
/// interrupts off and with flash answering commands instead of reads, from a
/// routine copied into RAM, because code cannot be fetched from a flash that is
/// mid-erase.  So the acknowledgement arriving at all is half of what is asked,
/// and reading an address outside the erased range afterwards is the other
/// half — that says execute-in-place came back and the cache was flushed rather
/// than still holding what was there before.
///
/// The window comes from the device, and [memory.x](../../device/memory.x)
/// keeps the firmware out of it, so nothing here can erase what it is running.
async fn flash(run: &mut Runner, board: &mut Board) {
    let scratch = match board.scratch().await {
        Ok(s) => s,
        Err(e) => {
            run.check("the device says where a host may erase", Err(e));
            return;
        }
    };
    run.check(
        "the device says where a host may erase",
        if scratch.flash_len >= FLASH_BLOCK {
            Ok(())
        } else {
            Err(format!("it offered {} bytes", scratch.flash_len))
        },
    );
    let base = scratch.flash;

    // What flash outside the window holds, to be read again after every erase.
    // This firmware's own first bytes, which is as good a witness as any that
    // reads still answer and answer the same.
    let elsewhere = match board.read_mem(FLASH_BASE, 64) {
        Ok(v) => v,
        Err(e) => {
            run.check("flash outside the window can be read", Err(e));
            return;
        }
    };

    run.check(
        "an erased sector reads as ones",
        match board
            .flash_erase(base, FLASH_SECTOR)
            .and_then(|()| board.read_mem(base, FLASH_SECTOR))
        {
            Err(e) => Err(e),
            Ok(back) if back.iter().all(|b| *b == 0xFF) => Ok(()),
            Ok(back) => Err(format!(
                "{} of {} bytes are not 0xFF",
                back.iter().filter(|b| **b != 0xFF).count(),
                back.len()
            )),
        },
    );

    run.check(
        "flash outside the erased range still reads, and reads the same",
        match board.read_mem(FLASH_BASE, 64) {
            Err(e) => Err(format!("it would not read at all: {e}")),
            Ok(now) if now == elsewhere => Ok(()),
            Ok(_) => Err("it reads something else, so the cache was not flushed".into()),
        },
    );

    let first = pattern(0x11, FLASH_PAGE as usize);
    run.check(
        "a page programmed reads back as what was programmed",
        match board
            .write_mem(base, &first)
            .and_then(|()| board.read_mem(base, FLASH_PAGE))
        {
            Err(e) => Err(e),
            Ok(back) if back == first => Ok(()),
            Ok(back) => Err(format!(
                "wrote {:02x?}, read {:02x?}",
                &first[..8],
                &back[..8]
            )),
        },
    );

    // Programming clears bits and never sets one, so a second page written over
    // the first without an erase between has to read as the two ANDed.  That is
    // what says the erase above did something rather than the flash having been
    // blank already, and it is the check a device that quietly skipped the erase
    // fails.
    let second = pattern(0x9e, FLASH_PAGE as usize);
    let anded: Vec<u8> = first.iter().zip(&second).map(|(a, b)| a & b).collect();
    run.check(
        "programming over a page without erasing clears bits and sets none",
        match board
            .write_mem(base, &second)
            .and_then(|()| board.read_mem(base, FLASH_PAGE))
        {
            Err(e) => Err(e),
            Ok(back) if back == anded => Ok(()),
            Ok(back) if back == second => {
                Err("the page was replaced, so something erased it first".into())
            }
            Ok(_) => Err("what came back is neither page nor the two together".into()),
        },
    );

    // The bulk path, which the device asks the boot ROM for by handing it the
    // block size and the block erase command, and the longest the part is away
    // from the bus in one go.
    run.check(
        "a whole block erases, and the device is still answering afterwards",
        match board
            .flash_erase(base, FLASH_BLOCK)
            .and_then(|()| board.read_mem(base + FLASH_BLOCK - FLASH_SECTOR, FLASH_SECTOR))
        {
            Err(e) => Err(e),
            Ok(back) if back.iter().all(|b| *b == 0xFF) => Ok(()),
            Ok(back) => Err(format!(
                "the last sector has {} bytes that are not 0xFF",
                back.iter().filter(|b| **b != 0xFF).count()
            )),
        },
    );

    run.check(
        "flash outside the block still reads, and reads the same",
        match board.read_mem(FLASH_BASE, 64) {
            Err(e) => Err(format!("it would not read at all: {e}")),
            Ok(now) if now == elsewhere => Ok(()),
            Ok(_) => Err("it reads something else, so the cache was not flushed".into()),
        },
    );

    // What an erase will not do.  Each is followed by a recovery, so the next
    // one starts from a device that is answering.
    let erase_args = |addr: u32, size: u32| {
        let mut a = [0u8; 8];
        a[0..4].copy_from_slice(&addr.to_le_bytes());
        a[4..8].copy_from_slice(&size.to_le_bytes());
        a
    };

    for (addr, size, want, what) in [
        (
            base + 1,
            FLASH_SECTOR,
            Status::BadAlignment,
            "an erase that does not start on a sector",
        ),
        (
            base,
            FLASH_SECTOR - 4,
            Status::BadAlignment,
            "an erase of part of a sector",
        ),
        (
            0x4000_0000,
            FLASH_SECTOR,
            Status::InvalidAddress,
            "an erase of something that is not flash",
        ),
    ] {
        let args = erase_args(addr, size);
        run.check(
            &format!("{what} is refused"),
            match refusal_code(board, CMD_FLASH_ERASE, 8, 0, &args).await {
                Err(e) => Err(e),
                Ok(code) if code == want as u32 => Ok(()),
                Ok(code) => Err(format!("it reported {code} rather than {}", want as u32)),
            },
        );
    }

    // And what a program will not do.  Flash is written a page at a time, so an
    // address inside one is refused rather than shifted onto the next.
    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&(base + 1).to_le_bytes());
    args[4..8].copy_from_slice(&FLASH_PAGE.to_le_bytes());
    run.check(
        "a program that does not start on a page is refused",
        match refusal_code(board, CMD_WRITE, 8, FLASH_PAGE, &args).await {
            Err(e) => Err(e),
            Ok(code) if code == Status::BadAlignment as u32 => Ok(()),
            Ok(code) => Err(format!("it reported {code}")),
        },
    );
}
