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
use picobootx::wire::MAGIC;
use picobootx_hw_host::{
    ACCESS_EXCLUSIVE, ACCESS_EXCLUSIVE_AND_EJECT, ACCESS_NOT_EXCLUSIVE, Board, CMD_ENTER_XIP,
    CMD_EXCLUSIVE_ACCESS, CMD_EXEC, CMD_EXIT_XIP, CMD_FLASH_ERASE, CMD_GET_INFO, CMD_READ,
    CMD_REBOOT_OLD, CMD_REBOOT2, CMD_VECTORIZE_FLASH, CMD_WRITE, EP_IN, EP_OUT, FLASH_BLOCK,
    FLASH_PAGE, FLASH_SECTOR, INFO_ARGS_LEN, INFO_COUNT_LEN, INFO_HEADER_LEN, INFO_SYS,
    INFO_UF2_STATUS, INFO_UF2_TARGET, INFO_UNNAMED, MAX_PACKET, REBOOT_ARGS_LEN, REBOOT_NORMAL,
    take_device_arg, wait_back, wait_gone,
};

// PICOBOOT's read, and an address the RP2350 defaults refuse.  The refusal is
// the stimulus, so it has to be one the device is certain to give: 0x4000_0000
// is a peripheral, and read_prepare admits ROM, flash and SRAM alone.
const ROM_MAGIC_ADDR: u32 = 0x0000_0010;
const REFUSED_ADDR: u32 = 0x4000_0000;
const READ_LEN: u32 = 4;

/// A second ROM address, whose contents differ from the first.  Two addresses
/// that answer differently is what lets a reply say which read produced it.
const ROM_OTHER_ADDR: u32 = 0x0000_0000;

// A read long enough to be several packets, so a host can stop in the middle of
// one.  Clear of ROM_MAGIC_ADDR, so a packet left over from it cannot be
// mistaken for the answer to the read that checks recovery.
const LONG_READ_ADDR: u32 = 0x0000_0100;
const LONG_READ_LEN: u32 = 256;

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
const FLAG_BOOT_INFO: u32 = 0x0040;
const FLAG_BOOT_INFO_WORDS: u32 = 4;

/// A flag no part carries, for asking what the device does with one.
const FLAG_UNKNOWN: u32 = 0x0080;

/// The flag 5.4.8.17 names and says is not supported.  A part that answers
/// every other documented flag still cannot answer this one, so it is the
/// part's own refusal rather than a flag nothing has heard of.
const FLAG_NONCE: u32 = 0x0020;

/// Every flag 5.4.8.17 names, and the words the ones a part can answer carry
/// between them: three for CHIP_INFO, one each for CRITICAL, CPU_INFO and
/// FLASH_DEV_INFO, four each for BOOT_RANDOM and BOOT_INFO, and none for
/// NONCE.  Asking for the lot at once is where a wrongly composed flags word
/// or a miscounted answer has the most room to show.
const FLAG_ALL_DOCUMENTED: u32 = 0x007f;
const FLAG_ALL_DOCUMENTED_WORDS: u32 = 14;

/// Where BOOT_INFO's four words land in that answer: after CHIP_INFO's three,
/// CRITICAL's one, CPU_INFO's one, FLASH_DEV_INFO's one and BOOT_RANDOM's
/// four, with NONCE between them contributing nothing.
const BOOT_INFO_AT_WORD: usize = 10;

/// Partition information about the table as a whole (5.4.8.16 PT_INFO): the
/// partition count and present bit, then the unpartitioned space's two words.
const PART_PT_INFO: u32 = 0x0001;
const PART_PT_INFO_WORDS: u32 = 3;

/// A per-partition flag, which a part with no partitions answers with no words
/// at all — the flags word says it was answered and nothing follows for it.
const PART_LOCATION_AND_FLAGS: u32 = 0x0010;

/// What the UF2 target question answers with: a target partition, then that
/// partition's two words.  A device serving picobootx has no drive to drag a
/// UF2 onto, so the target is always -1 and the two words beside it are the
/// unpartitioned space the partition question reports.
const UF2_TARGET_WORDS: u32 = 3;
const UF2_TARGET_NOWHERE: u32 = 0xffff_ffff;

/// Three UF2 family ids that have nothing in common: the two this part's own
/// architectures use, and one no family register names.  The answer may not
/// depend on which of them was asked about.
const UF2_FAMILIES: [u32; 3] = [0xe48b_ff59, 0xe48b_ff5a, 0x0000_0000];

/// How long the device waits before rebooting, so the acknowledgement has time
/// to be collected first.  Long enough to be the device's wait rather than a
/// race, short enough not to stretch the run.
const REBOOT_DELAY_MS: u32 = 100;

/// Left in the device's RAM window before a reboot, and gone after one: the
/// startup zeroes what it lands in.  Four bytes no read of that window would
/// give by accident.
const REBOOT_MARK: [u8; 4] = [0xa5, 0x5a, 0xc3, 0x3c];

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

    /// A measurement worth printing beside the check it came from.  Not a
    /// check: nothing about it can fail, and counting it would put a number in
    /// the total that nothing judged.
    fn note(&self, what: &str) {
        println!("        {what}");
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
    // --device names which firmware to drive, and the rest is the group filter.
    let (want, rest) = match take_device_arg(std::env::args().skip(1)) {
        Ok(parsed) => parsed,
        Err(e) => {
            println!("  FAIL  read the command line: {e}");
            println!();
            println!("1 checks, 1 failed");
            return ExitCode::FAILURE;
        }
    };
    let filter = rest.into_iter().next();

    println!("picobootx on real hardware");
    println!();

    let mut board = match Board::open(want).await {
        Ok(b) => b,
        Err(e) => {
            println!("  FAIL  find the board: {e}");
            println!();
            println!("1 checks, 1 failed");
            return ExitCode::FAILURE;
        }
    };
    println!("  the {} firmware", board.firmware);
    println!();
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
        abandoned_mid_reply(&mut run, &mut board).await;
        command_inside_an_unfinished_reply(&mut run, &mut board).await;
    }

    if run.group("multi-packet") {
        multi_packet(&mut run, &mut board).await;
    }

    if run.group("session") {
        session(&mut run, &mut board).await;
    }

    if run.group("framing") {
        framing(&mut run, &mut board).await;
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

/// A host that stops part way through collecting a reply leaves the device
/// unable to take its next command.
///
/// [`abandoned`] walks away before collecting anything, and its reply is one
/// packet.  Stopping inside a longer one leaves the device mid data phase with
/// its OUT endpoint closed and neither endpoint halted, so the host has no halt
/// to clear and INTERFACE RESET is its only remedy.  The RP2350 boot ROM
/// recovers from every one of these (datasheet 5.6.5.1).
async fn abandoned_mid_reply(run: &mut Runner, board: &mut Board) {
    // What every recovery below is judged against.  A device that cannot serve
    // it now makes all of them vacuous.
    let want = match read_word(board, ROM_MAGIC_ADDR) {
        Read::FirstTime(w) => w,
        Read::OnRetry(e) | Read::Never(e) => {
            run.check("the address the recovery is judged by reads", Err(e));
            return;
        }
    };

    let packets = (LONG_READ_LEN as usize).div_ceil(MAX_PACKET);
    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&LONG_READ_ADDR.to_le_bytes());
    args[4..8].copy_from_slice(&LONG_READ_LEN.to_le_bytes());

    for collected in 0..packets {
        if let Err(e) = board.send_cmd(CMD_READ, LONG_READ_LEN, &args) {
            run.check(
                &format!("a {LONG_READ_LEN} byte read can be asked for"),
                Err(e),
            );
            return;
        }

        // Take some of the reply and walk away.  This is the whole stimulus.
        for packet in 0..collected {
            if let Err(e) = board.read_raw(MAX_PACKET) {
                run.check(
                    &format!("packet {packet} of the reply comes when it is asked for"),
                    Err(e),
                );
                return;
            }
        }

        // Said once, since it is the same at every stopping point.  Nothing
        // here for a host to clear is why the reset has to be what works.
        if collected == 1 {
            run.check(
                "neither endpoint reports itself halted, so the host has nothing to clear",
                match (
                    board.endpoint_halted(EP_IN).await,
                    board.endpoint_halted(EP_OUT).await,
                ) {
                    (Ok(false), Ok(false)) => Ok(()),
                    (Ok(i), Ok(o)) => Err(format!("IN halted {i}, OUT halted {o}")),
                    (Err(e), _) | (_, Err(e)) => Err(e),
                },
            );
        }

        run.check(
            &format!(
                "the device accepts INTERFACE RESET having sent {collected} of {packets} packets"
            ),
            board.interface_reset().await,
        );

        // Nothing is read before the reset, so an answer right here is right
        // because the reset made it so.
        run.check(
            &format!("it serves the next command having sent {collected} of {packets} packets"),
            match read_word(board, ROM_MAGIC_ADDR) {
                Read::FirstTime(got) if got == want => Ok(()),
                Read::FirstTime(got) => Err(format!(
                    "it returned {got:02x?} rather than {want:02x?}, so the reply it \
                     was left holding went out in place of this one"
                )),
                Read::OnRetry(e) => Err(e),
                Read::Never(e) => Err(format!(
                    "the reset did not put it back, and only clearing a halt the device \
                     does not report will: {e}"
                )),
            },
        );
    }
}

/// A command sent inside a reply the host has not finished is not taken.
///
/// The device still owes the host packets.  The RP2350 boot ROM refuses until
/// the phase ends, so a host that walks away and asks something else is refused
/// rather than served the tail of what it abandoned.
///
/// It needs a wire.  Whether a queued packet has reached the host is not
/// something a model of the controller knows.
async fn command_inside_an_unfinished_reply(run: &mut Runner, board: &mut Board) {
    let packets = (LONG_READ_LEN as usize).div_ceil(MAX_PACKET);
    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&LONG_READ_ADDR.to_le_bytes());
    args[4..8].copy_from_slice(&LONG_READ_LEN.to_le_bytes());

    let mut next = [0u8; 8];
    next[0..4].copy_from_slice(&ROM_MAGIC_ADDR.to_le_bytes());
    next[4..8].copy_from_slice(&READ_LEN.to_le_bytes());

    for collected in 0..packets {
        if let Err(e) = board.send_cmd(CMD_READ, LONG_READ_LEN, &args) {
            run.check(
                &format!("a {LONG_READ_LEN} byte read can be asked for"),
                Err(e),
            );
            return;
        }
        for packet in 0..collected {
            if let Err(e) = board.read_raw(MAX_PACKET) {
                run.check(
                    &format!("packet {packet} of the reply comes when it is asked for"),
                    Err(e),
                );
                return;
            }
        }

        run.check(
            &format!("a command sent having taken {collected} of {packets} packets is refused"),
            match board.send_cmd(CMD_READ, READ_LEN, &next) {
                Err(_) => Ok(()),
                Ok(()) => Err(format!(
                    "the device took it, so the packets it still owes go out to meet \
                     it and answer a question it was not asked - it reported {}",
                    match board.diagnostics().await {
                        Ok(d) => format!("{d}"),
                        Err(e) => e,
                    }
                )),
            },
        );

        // Back to a starting point, so the next stopping point measures itself.
        if let Err(e) = board.quiesce().await {
            run.check(
                &format!("the board settles after taking {collected} of {packets} packets"),
                Err(e),
            );
            return;
        }
    }
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
    refusal_code_magic(board, MAGIC, cmd, cmd_size, tlen, args).await
}

/// The same, for a command carrying a magic of its own.
async fn refusal_code_magic(
    board: &mut Board,
    magic: u32,
    cmd: u8,
    cmd_size: u8,
    tlen: u32,
    args: &[u8],
) -> Result<u32, String> {
    board.send_cmd_magic(magic, cmd, cmd_size, tlen, args)?;
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
    info_args_of(INFO_SYS, flags)
}

/// `GET_INFO` arguments asking for a kind of information, with its parameter.
fn info_args_of(info_type: u8, param0: u32) -> [u8; INFO_ARGS_LEN] {
    let mut args = [0u8; INFO_ARGS_LEN];
    args[0] = info_type;
    args[4..8].copy_from_slice(&param0.to_le_bytes());
    args
}

/// Hand back what a request that was meant to be served produced, putting the
/// board back where it was not.
///
/// A device that refuses halts both bulk endpoints, and every question here is
/// one whose answer is meant to be served — so a refusal is the failure being
/// looked for, and without putting the board back one wrong answer would take
/// every check after it down with a reason that is not its own.
async fn served<T>(board: &mut Board, got: Result<T, String>) -> Result<T, String> {
    match got {
        Ok(v) => Ok(v),
        Err(e) => match board.quiesce().await {
            Ok(()) => Err(e),
            Err(q) => Err(format!("{e}, and it would not go back to waiting: {q}")),
        },
    }
}

/// Ask for system information at the length its answer exactly fits in,
/// leaving the board ready for the next command whichever way it went.
async fn info_sys(
    board: &mut Board,
    flags: u32,
    words: u32,
) -> Result<(u32, u32, Vec<u8>), String> {
    let got = board.get_info_sys(flags, words);
    served(board, got).await
}

/// The same, for partition information, which comes back in the same shape.
async fn info_partition(
    board: &mut Board,
    flags: u32,
    words: u32,
) -> Result<(u32, u32, Vec<u8>), String> {
    let got = board.get_info_partition(flags, words);
    served(board, got).await
}

/// The same, for a kind of information whose answer has no flags word in front
/// of it, which is how the two UF2 types answer.
async fn info_words(
    board: &mut Board,
    info_type: u8,
    param0: u32,
    words: u32,
) -> Result<(u32, Vec<u8>), String> {
    let got = board.get_info_words(info_type, param0, words);
    served(board, got).await
}

/// Read one word out of a reply's data, counting from the first data word.
fn word_at(data: &[u8], index: usize) -> Option<u32> {
    let at = index * 4;
    let bytes = data.get(at..at + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Ask for system information at a stated transfer length, and report how many
/// bytes the device actually put on the pipe for it.
///
/// The reply is taken with [`Board::read_raw`] rather than [`Board::read_reply`]
/// because the second cuts what came back down to the length asked for, which
/// is exactly the excess this is looking for.  What is left queued afterwards
/// is taken too, since a device sending the answer and then more sends the
/// second part in packets of its own and the transfer ends on the first short
/// one.
async fn info_reply_len(board: &mut Board, flags: u32, tlen: u32) -> Result<usize, String> {
    board.send_cmd(CMD_GET_INFO, tlen, &info_args(flags))?;

    // A whole spare packet beyond the length asked for, so an overrun has
    // somewhere to land instead of filling the buffer and looking like an
    // answer that ended.
    let reply = board.read_raw(tlen as usize + MAX_PACKET)?;
    let trailing = board.drain();

    board.ack()?;
    board.quiesce().await?;

    if trailing > 0 {
        return Err(format!(
            "{} bytes came back, and {trailing} more packets were still queued behind them",
            reply.len()
        ));
    }
    Ok(reply.len())
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
///
/// For the two kinds of information the part answers, that count word is
/// followed by a flags word naming which of the flags asked for were answered.
/// The flags word is itself counted, so the count is one more than the data
/// words.  The UF2 kinds have no flags word, so their count is the data words
/// alone.
///
/// Two things the part decides rather than the device.  A flag the part cannot
/// answer is dropped from the flags word and is worth no words, so what the
/// answer is worth is not what was asked for — and the transfer length is
/// judged against the answer.  And a flag the part answers with nothing at all
/// is named in the flags word and followed by no words, so what follows cannot
/// be worked out from the flags word either.
async fn get_info(run: &mut Runner, board: &mut Board) {
    let chip = match info_sys(board, FLAG_CHIP, FLAG_CHIP_WORDS).await {
        Ok((count, answered, data)) => {
            run.check(
                "one flag is answered with the word count it carries",
                if count == FLAG_CHIP_WORDS + 1
                    && answered == FLAG_CHIP
                    && data.len() == FLAG_CHIP_WORDS as usize * 4
                {
                    Ok(())
                } else {
                    Err(format!(
                        "it said {count} words, answered {answered:#x} and sent {} bytes",
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

    let cpu = match info_sys(board, FLAG_CPU, FLAG_CPU_WORDS).await {
        Ok((count, answered, data)) => {
            run.check(
                "a flag carrying one word is answered with one word",
                if count == FLAG_CPU_WORDS + 1 && answered == FLAG_CPU && data.len() == 4 {
                    Ok(())
                } else {
                    Err(format!(
                        "it said {count} words, answered {answered:#x} and sent {} bytes",
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
        match info_sys(
            board,
            FLAG_CHIP | FLAG_CPU,
            FLAG_CHIP_WORDS + FLAG_CPU_WORDS,
        )
        .await
        {
            Err(e) => Err(e),
            Ok((count, _, _)) if count != FLAG_CHIP_WORDS + FLAG_CPU_WORDS + 1 => {
                Err(format!("it said {count} words"))
            }
            Ok((_, answered, _)) if answered != FLAG_CHIP | FLAG_CPU => {
                Err(format!("it answered {answered:#x}"))
            }
            Ok((_, _, data)) if data == both => Ok(()),
            Ok((_, _, data)) => Err(format!(
                "it sent {data:02x?} where the two separately gave {both:02x?}"
            )),
        },
    );

    // A second flag whose value has nothing to do with the first, so a device
    // handing back the same buffer whatever it was asked is caught.
    run.check(
        "a different flag answers with something different",
        match info_sys(board, FLAG_BOOT_RANDOM, FLAG_BOOT_RANDOM_WORDS).await {
            Err(e) => Err(e),
            Ok((_, _, data)) if data[..4] != chip[..4] => Ok(()),
            Ok(_) => Err("it gave the same first word as the chip flag".into()),
        },
    );

    // A flag the part does not carry is dropped rather than answered.  The
    // count says so before any of it is sent, and the flags word says which of
    // what was asked for survived — here, none of it.
    run.check(
        "a flag the part does not carry is counted as no words",
        match info_sys(board, FLAG_UNKNOWN, 0).await {
            Err(e) => Err(e),
            Ok((1, 0, _)) => Ok(()),
            Ok((count, answered, _)) => {
                Err(format!("it said {count} words and answered {answered:#x}"))
            }
        },
    );

    // A request naming nothing at all.  The flags word is the head of
    // get_sys_info's own buffer rather than something the device adds when it
    // has flags to report, so it is sent for a request that named none, and
    // the count says one word follows rather than none.
    run.check(
        "a request for no flags at all is answered with the flags word",
        match info_sys(board, 0, 0).await {
            Err(e) => Err(e),
            Ok((1, 0, data)) if data.is_empty() => Ok(()),
            Ok((count, answered, data)) => Err(format!(
                "it said {count} words, answered {answered:#x} and sent {} bytes after them",
                data.len()
            )),
        },
    );

    // A flag the part does not carry, asked for beside one it does and
    // numbered above it, so the answer stops short of what was asked for.  The
    // reply is a whole one - nothing says a flag went unserved except the
    // flags word, and a device that counted the missing flag's words, or left
    // its bit set, or shifted the served flag's word along to make room for it,
    // fails here and passes the flag on its own.
    run.check(
        "a flag the part does not carry does not disturb one beside it",
        match info_sys(board, FLAG_UNKNOWN | FLAG_CPU, FLAG_CPU_WORDS).await {
            Err(e) => Err(e),
            Ok((count, _, _)) if count != FLAG_CPU_WORDS + 1 => {
                Err(format!("it said {count} words"))
            }
            Ok((_, answered, _)) if answered != FLAG_CPU => {
                Err(format!("it answered {answered:#x}"))
            }
            Ok((_, _, data)) if data == cpu => Ok(()),
            Ok((_, _, data)) => Err(format!(
                "it sent {data:02x?} where the flag on its own gave {cpu:02x?}"
            )),
        },
    );

    // The flag 5.4.8.17 names and says the part does not support, which is a
    // different thing from FLAG_UNKNOWN above: this one the protocol has heard
    // of and the silicon cannot answer.  A device that decided for itself which
    // flags exist would refuse the request as naming something it could not
    // serve, and the whole answer would go with it.
    run.check(
        "the flag the part cannot answer is dropped rather than refused",
        match info_sys(board, FLAG_NONCE, 0).await {
            Err(e) => Err(e),
            Ok((1, 0, data)) if data.is_empty() => Ok(()),
            Ok((count, answered, data)) => Err(format!(
                "it said {count} words, answered {answered:#x} and sent {} bytes after them",
                data.len()
            )),
        },
    );

    // The same flag beside one the part does answer, and numbered below it, so
    // the served flag's words have to move up to where the dropped one would
    // have been.  A device that left a hole for it, counted its words, or left
    // its bit in the flags word fails here and passes it on its own.
    let boot_info = match info_sys(board, FLAG_BOOT_INFO, FLAG_BOOT_INFO_WORDS).await {
        Ok((_, _, data)) => Some(data),
        Err(e) => {
            run.check(
                "a flag the part cannot answer leaves the one after it whole",
                Err(e),
            );
            None
        }
    };
    if let Some(boot_info) = &boot_info {
        run.check(
            "a flag the part cannot answer leaves the one after it whole",
            match info_sys(board, FLAG_NONCE | FLAG_BOOT_INFO, FLAG_BOOT_INFO_WORDS).await {
                Err(e) => Err(e),
                Ok((count, _, _)) if count != FLAG_BOOT_INFO_WORDS + 1 => {
                    Err(format!("it said {count} words"))
                }
                Ok((_, answered, _)) if answered != FLAG_BOOT_INFO => {
                    Err(format!("it answered {answered:#x}"))
                }
                Ok((_, _, data)) if data == *boot_info => Ok(()),
                Ok((_, _, data)) => Err(format!(
                    "it sent {data:02x?} where the flag on its own gave {boot_info:02x?}"
                )),
            },
        );
    }

    // The transfer length is judged against what the answer will be and not
    // against what was asked for, which are different numbers as soon as a flag
    // is dropped.  This length has room for the chip flag alone, and the
    // request names the dropped one beside it - so a device sizing its
    // judgement by the request refuses a length that is exactly right.
    run.check(
        "a length sized to the answer rather than to the request is served",
        match info_sys(board, FLAG_CHIP | FLAG_NONCE, FLAG_CHIP_WORDS).await {
            Err(e) => Err(e),
            Ok((count, _, _)) if count != FLAG_CHIP_WORDS + 1 => {
                Err(format!("it said {count} words"))
            }
            Ok((_, answered, _)) if answered != FLAG_CHIP => {
                Err(format!("it answered {answered:#x}"))
            }
            Ok((_, _, data)) if data == chip => Ok(()),
            Ok((_, _, data)) => Err(format!(
                "it sent {data:02x?} where the chip flag on its own gave {chip:02x?}"
            )),
        },
    );

    // And the other side of that boundary, so the length is still being judged
    // rather than waved through for a request naming a dropped flag.
    run.check(
        "and one word less than that answer needs is still refused",
        match refusal_code(
            board,
            CMD_GET_INFO,
            INFO_ARGS_LEN as u8,
            INFO_HEADER_LEN as u32 + (FLAG_CHIP_WORDS - 1) * 4,
            &info_args(FLAG_CHIP | FLAG_NONCE),
        )
        .await
        {
            Err(e) => Err(e),
            Ok(code) if code == Status::BufferTooSmall as u32 => Ok(()),
            Ok(code) => Err(format!("it reported {code}")),
        },
    );

    // Every flag the datasheet names, at once.  This is where a wrongly
    // composed flags word has the most room to show: the one flag 5.4.8.17 says
    // is not supported has to be the only one missing from it, and the count
    // has to be what the flags that survived are worth rather than what the
    // request was worth.
    let all = match info_sys(board, FLAG_ALL_DOCUMENTED, FLAG_ALL_DOCUMENTED_WORDS).await {
        Ok((count, answered, data)) => {
            run.check(
                "every documented flag but the unsupported one is answered",
                if count == FLAG_ALL_DOCUMENTED_WORDS + 1
                    && answered == FLAG_ALL_DOCUMENTED & !FLAG_NONCE
                {
                    Ok(())
                } else {
                    Err(format!(
                        "it said {count} words and answered {answered:#x}, where {:#x} was asked \
                         for and {:#x} expected",
                        FLAG_ALL_DOCUMENTED,
                        FLAG_ALL_DOCUMENTED & !FLAG_NONCE
                    ))
                },
            );
            Some(data)
        }
        Err(e) => {
            run.check(
                "every documented flag but the unsupported one is answered",
                Err(e),
            );
            None
        }
    };

    // And what came back is those flags' own words, at the offsets dropping the
    // unsupported one leaves them at.  A device that reserved words for it puts
    // everything after it four bytes late, which the flags word and the count
    // both fail to notice - the first and last flags asked for are what says
    // where the answer really starts and ends.
    if let (Some(all), Some(boot_info)) = (&all, &boot_info) {
        run.check(
            "and they are those flags' own words, with no room left for the dropped one",
            match (
                all.len() == FLAG_ALL_DOCUMENTED_WORDS as usize * 4,
                all.starts_with(&chip),
                all.get(BOOT_INFO_AT_WORD * 4..) == Some(&boot_info[..]),
            ) {
                (true, true, true) => Ok(()),
                (false, _, _) => Err(format!("it sent {} bytes of data", all.len())),
                (_, false, _) => Err(format!(
                    "it opens {:02x?} where the chip flag gave {chip:02x?}",
                    &all[..chip.len().min(all.len())]
                )),
                (_, _, false) => Err(format!(
                    "the last four words are {:02x?} where the boot-info flag gave {boot_info:02x?}",
                    &all[all.len().saturating_sub(16)..]
                )),
            },
        );
    }

    // The other kind of information the part answers.  PT_INFO describes the
    // table as a whole, so it is answered whether or not the part has any
    // partitions, and it comes back in the same shape system information does.
    let pt_info = match info_partition(board, PART_PT_INFO, PART_PT_INFO_WORDS).await {
        Ok((count, answered, data)) => {
            run.check(
                "partition information is answered with the word count it carries",
                if count == PART_PT_INFO_WORDS + 1
                    && answered == PART_PT_INFO
                    && data.len() == PART_PT_INFO_WORDS as usize * 4
                {
                    Ok(())
                } else {
                    Err(format!(
                        "it said {count} words, answered {answered:#x} and sent {} bytes",
                        data.len()
                    ))
                },
            );
            Some(data)
        }
        Err(e) => {
            run.check(
                "partition information is answered with the word count it carries",
                Err(e),
            );
            None
        }
    };

    // The discriminating one for it.  The same parameter asked of the two kinds
    // picks two different routines on the part, and both are worth three words
    // here - so the count and the flags word cannot tell them apart and only
    // the data can.  A device answering both from one routine, or from
    // something of its own that does not vary, gives the same bytes twice.
    if let Some(pt_info) = &pt_info {
        run.check(
            "the two kinds of information come from two different places",
            if *pt_info == chip {
                Err(format!(
                    "partition {PART_PT_INFO:#x} and system {FLAG_CHIP:#x} both gave {chip:02x?}"
                ))
            } else {
                Ok(())
            },
        );
    }

    // A partition flag that names something this part does not have.  It is
    // answered - the flags word says so - and it is worth no words, so what
    // follows the flags word cannot be worked out from the flags word.  A
    // device carrying its own table of what each flag is worth, rather than
    // taking the count from the part, sends words nothing put there.
    run.check(
        "a partition flag with nothing to report is answered with no words",
        match info_partition(board, PART_LOCATION_AND_FLAGS, 0).await {
            Err(e) => Err(e),
            Ok((1, PART_LOCATION_AND_FLAGS, data)) if data.is_empty() => Ok(()),
            Ok((count, answered, data)) => Err(format!(
                "it said {count} words, answered {answered:#x} and sent {} bytes after them",
                data.len()
            )),
        },
    );

    // The UF2 target question, which asks where a family would be downloaded
    // to.  This device presents no mass storage drive for a UF2 to be dragged
    // onto, and installs no answer of its own, so the default answers nowhere.  This is one the protocol names and the device
    // answers with its words alone, so a device that put a flags word in front
    // of them fails on the count as well as on the first word.
    let target = match info_words(board, INFO_UF2_TARGET, UF2_FAMILIES[0], UF2_TARGET_WORDS).await {
        Ok((count, data)) => {
            run.check(
                "the UF2 target question is answered, as nowhere",
                match (count, word_at(&data, 0)) {
                    (UF2_TARGET_WORDS, Some(UF2_TARGET_NOWHERE)) => Ok(()),
                    (count, Some(w)) => {
                        Err(format!("it said {count} words and a target of {w:#x}"))
                    }
                    (count, None) => Err(format!("it said {count} words and sent none")),
                },
            );
            Some(data)
        }
        Err(e) => {
            run.check("the UF2 target question is answered, as nowhere", Err(e));
            None
        }
    };

    // And the family id is not consulted at all.  Two of the part's own
    // architectures and one no family register names, which is as far apart as
    // three families get - a device that looked any of them up would have to
    // find the same nothing for all three, and one that answered from the
    // parameter in any way gives three different replies.
    run.check(
        "the answer does not depend on which family was asked about",
        {
            let mut answers = Vec::new();
            let mut failure = None;
            for family in UF2_FAMILIES {
                match info_words(board, INFO_UF2_TARGET, family, UF2_TARGET_WORDS).await {
                    Ok(got) => answers.push((family, got)),
                    Err(e) => {
                        failure = Some(format!("{family:#x} was not served: {e}"));
                        break;
                    }
                }
            }
            match failure {
                Some(e) => Err(e),
                None => match answers.iter().find(|(_, got)| *got != answers[0].1) {
                    None => Ok(()),
                    Some((family, got)) => Err(format!(
                        "{family:#x} gave {got:02x?} where {:#x} gave {:02x?}",
                        answers[0].0, answers[0].1
                    )),
                },
            }
        },
    );

    // What sits beside the target is the unpartitioned space, which is what the
    // partition question reports for a part with no partition table.  Asked of
    // the device twice by two routes, so what is pinned is that the two agree
    // rather than a number this test decided in advance.  A device answering
    // the UF2 question out of anything but the partition table fails here and
    // passes both checks above.
    if let (Some(target), Some(pt_info)) = (&target, &pt_info) {
        run.check(
            "and the space beside it is the space the partition question reports",
            if target.len() != UF2_TARGET_WORDS as usize * 4 {
                Err(format!("the target answer was {} bytes", target.len()))
            } else if target[4..] == pt_info[4..] {
                Ok(())
            } else {
                Err(format!(
                    "the target carries {:02x?} where the partition table gave {:02x?}",
                    &target[4..],
                    &pt_info[4..]
                ))
            },
        );
    }

    // The transfer length is judged for this kind too, and its answer has no
    // flags word - so a device allowing for one it does not send has room for
    // an answer four bytes longer than the one it gives.
    run.check(
        "a length one word short of the UF2 target answer is refused",
        match refusal_code(
            board,
            CMD_GET_INFO,
            INFO_ARGS_LEN as u8,
            INFO_COUNT_LEN as u32 + (UF2_TARGET_WORDS - 1) * 4,
            &info_args_of(INFO_UF2_TARGET, UF2_FAMILIES[0]),
        )
        .await
        {
            Err(e) => Err(e),
            Ok(code) if code == Status::BufferTooSmall as u32 => Ok(()),
            Ok(code) => Err(format!("it reported {code}")),
        },
    );

    // The UF2 download question, which the part's own bootrom answers and this
    // device will not.  It reports on a download over a mass storage drive,
    // and this device presents none, so there is nothing to report on.  Asked at a length its answer
    // would fit in, so a device that served it is answered rather than refused
    // for the length - and the type beside it is served, so a device refusing
    // every type past the partition one fails the target check above instead.
    run.check(
        "the UF2 download question is refused as a bad argument",
        match refusal_code(
            board,
            CMD_GET_INFO,
            INFO_ARGS_LEN as u8,
            32,
            &info_args_of(INFO_UF2_STATUS, 0),
        )
        .await
        {
            Err(e) => Err(e),
            Ok(code) if code == Status::InvalidArg as u32 => Ok(()),
            Ok(code) => Err(format!("it reported {code}")),
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

    // A length the protocol allows and the answer will not fit in, which is a
    // different judgement from the three above: those are lengths no GET_INFO
    // could ever be served at, and this one is refused for what was asked for
    // rather than for its shape.  Both sides of the boundary, because a device
    // that refused every length but the one it liked would pass the refusal on
    // its own.
    run.check(
        "a transfer length the answer exactly fits in is served",
        match info_sys(board, FLAG_CHIP, FLAG_CHIP_WORDS).await {
            Err(e) => Err(e),
            Ok((count, answered, _)) if count == FLAG_CHIP_WORDS + 1 && answered == FLAG_CHIP => {
                Ok(())
            }
            Ok((count, answered, _)) => {
                Err(format!("it said {count} words and answered {answered:#x}"))
            }
        },
    );
    run.check(
        "and one word less than the answer needs is refused",
        match refusal_code(
            board,
            CMD_GET_INFO,
            INFO_ARGS_LEN as u8,
            INFO_HEADER_LEN as u32 + (FLAG_CHIP_WORDS - 1) * 4,
            &info_args(FLAG_CHIP),
        )
        .await
        {
            Err(e) => Err(e),
            Ok(code) if code == Status::BufferTooSmall as u32 => Ok(()),
            Ok(code) => Err(format!("it reported {code}")),
        },
    );

    // What reached the bus, rather than what the device meant to send.  The
    // protocol gives the host the length and says that many bytes are then
    // transferred, so a reply longer than the length asked for is bytes no
    // host has anywhere to put - and a host reading the answer never sees
    // them, because it takes the length it asked for and leaves the rest.
    // Asked at the length the answer exactly fits and at one with room to
    // spare, since a device sending its own idea of the answer and a device
    // filling the length it was given go wrong at different lengths.
    for (tlen, what) in [
        (
            INFO_HEADER_LEN as u32 + FLAG_CHIP_WORDS * 4,
            "exactly the answer's size",
        ),
        (
            INFO_HEADER_LEN as u32 + (FLAG_CHIP_WORDS + 3) * 4,
            "with room to spare",
        ),
    ] {
        run.check(
            &format!("a transfer length {what} gets that many bytes and no more"),
            match info_reply_len(board, FLAG_CHIP, tlen).await {
                Err(e) => Err(e),
                Ok(got) if got as u32 == tlen => Ok(()),
                Ok(got) => Err(format!("{got} bytes came back for a length of {tlen}")),
            },
        );
    }

    // And a kind of information that is none of the four the protocol names.
    // The one immediately past the last of them and one nowhere near it, since
    // a device whose test of the type is off by one refuses the second and
    // serves the first.  Zero as well, because it is what an argument block
    // nobody filled in carries.
    for info_type in [0x00, INFO_UNNAMED, 0xff] {
        run.check(
            &format!(
                "information type {info_type:#04x}, which the protocol does not name, is refused"
            ),
            match refusal_code(
                board,
                CMD_GET_INFO,
                INFO_ARGS_LEN as u8,
                8,
                &info_args_of(info_type, FLAG_CHIP),
            )
            .await
            {
                Err(e) => Err(e),
                Ok(code) if code == Status::InvalidArg as u32 => Ok(()),
                Ok(code) => Err(format!("it reported {code}")),
            },
        );
    }
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

    // A mark in the device's RAM window, which the startup zeroes.  Finding it
    // gone afterwards is what says the part restarted, and it says so whatever
    // the bus did - a device back on the bus in single-digit milliseconds has
    // rebooted just as much as one away for a fifth of a second.
    let mark = match board.scratch().await {
        Ok(s) => {
            let written = board
                .write_mem(s.ram, &REBOOT_MARK)
                .and_then(|()| board.read_mem(s.ram, REBOOT_MARK.len() as u32))
                .and_then(|back| {
                    if back == REBOOT_MARK {
                        Ok(())
                    } else {
                        Err(format!("it reads {back:02x?}"))
                    }
                });
            let ok = written.is_ok();
            run.check("a mark can be left in RAM before the reboot", written);
            ok.then_some(s.ram)
        }
        Err(e) => {
            run.check("a mark can be left in RAM before the reboot", Err(e));
            None
        }
    };

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
    let firmware = board.firmware;
    drop(board);

    match wait_gone(firmware, Duration::from_secs(5)).await {
        Ok(seen) => {
            run.check("the board leaves the bus", Ok(()));
            run.note(&format!(
                "gone within {}ms of the acknowledgement",
                seen.as_millis()
            ));
        }
        Err(e) => run.check("the board leaves the bus", Err(e)),
    }

    let board = match wait_back(firmware, Duration::from_secs(15)).await {
        Ok(b) => b,
        Err(e) => {
            run.check("the board comes back", Err(e));
            return None;
        }
    };
    run.check("the board comes back", Ok(()));

    let mut board = board;
    if let Some(addr) = mark {
        run.check(
            "the mark left in RAM is gone, so the startup ran",
            match board.read_mem(addr, REBOOT_MARK.len() as u32) {
                Err(e) => Err(e),
                Ok(now) if now.iter().all(|b| *b == 0) => Ok(()),
                Ok(now) if now == REBOOT_MARK => {
                    Err("it is still there, so the part never restarted".into())
                }
                Ok(now) => Err(format!("it reads {now:02x?}, which is neither")),
            },
        );
    }
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
    let firmware = board.firmware;
    let device = board.into_device();
    let reset = device.reset().await.map_err(|e| format!("{e}"));
    drop(device);
    run.check("the device accepts a bus reset", reset);

    let mut board = match wait_back(firmware, Duration::from_secs(15)).await {
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

    // More than one page in a single transfer, which is what a host writing an
    // image does.  The device accumulates a page at a time and programs each as
    // it fills, so this is the loop that carries the offset between packets and
    // the one nothing on this board had reached.
    let two = pattern(0x5a, 2 * FLASH_PAGE as usize);
    run.check(
        "a write of two pages lands as two pages",
        match board
            .flash_erase(base, FLASH_SECTOR)
            .and_then(|()| board.write_mem(base, &two))
            .and_then(|()| board.read_mem(base, 2 * FLASH_PAGE))
        {
            Err(e) => Err(e),
            Ok(back) if back == two => Ok(()),
            Ok(back) => Err(format!(
                "byte {} differs",
                back.iter().zip(&two).position(|(a, b)| a != b).unwrap_or(0)
            )),
        },
    );

    // A transfer that ends inside a page.  The rest of that page is zero filled
    // before it is programmed, so what follows the data is 0x00 and not the
    // 0xFF an erase leaves - and the page after it is untouched.  A device that
    // programmed only what it was given would leave 0xFF and pass a check that
    // looked at the data alone.
    let odd_len = FLASH_PAGE as usize + 44;
    let odd = pattern(0x3c, odd_len);
    run.check(
        "a write ending inside a page zero fills the rest of it",
        match board
            .flash_erase(base, FLASH_SECTOR)
            .and_then(|()| board.write_mem(base, &odd))
            .and_then(|()| board.read_mem(base, 3 * FLASH_PAGE))
        {
            Err(e) => Err(e),
            Ok(back) if back[..odd_len] != odd[..] => Err("the data did not land".into()),
            Ok(back)
                if back[odd_len..2 * FLASH_PAGE as usize]
                    .iter()
                    .any(|b| *b != 0x00) =>
            {
                Err(
                    "the rest of the part written page is not zero, so it was left unprogrammed"
                        .into(),
                )
            }
            Ok(back) if back[2 * FLASH_PAGE as usize..].iter().any(|b| *b != 0xFF) => {
                Err("the page after the transfer was written to".into())
            }
            Ok(_) => Ok(()),
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

/// The commands a host brackets a session with.
///
/// picotool takes exclusive access and leaves execute-in-place before it reads
/// or writes flash, so these are on the path of every real session even though
/// none of them moves any data.  What each one does on an RP2350 is agree, so
/// the claim is that they are agreed to and that the device still works
/// afterwards — a device that took `EXIT_XIP` literally could not fetch its own
/// next instruction.
async fn session(run: &mut Runner, board: &mut Board) {
    for (mode, what) in [
        (ACCESS_NOT_EXCLUSIVE, "sharing the device"),
        (ACCESS_EXCLUSIVE, "taking the device"),
        (ACCESS_EXCLUSIVE_AND_EJECT, "taking the device and ejecting"),
    ] {
        run.check(
            &format!("{what} is agreed to"),
            board.sync_cmd(CMD_EXCLUSIVE_ACCESS, &[mode]),
        );
    }

    run.check(
        "an exclusivity the protocol does not define is refused",
        match refusal_code(board, CMD_EXCLUSIVE_ACCESS, 1, 0, &[0x7f]).await {
            Err(e) => Err(e),
            Ok(code) if code == Status::InvalidArg as u32 => Ok(()),
            Ok(code) => Err(format!("it reported {code}")),
        },
    );

    run.check(
        "leaving execute-in-place is agreed to",
        board.sync_cmd(CMD_EXIT_XIP, &[]),
    );

    // The one that matters: this firmware runs from flash, so a device that
    // genuinely left execute-in-place would have stopped here.
    run.check(
        "the board still reads flash after being told to leave it",
        match board.read_mem(FLASH_BASE, 64) {
            Ok(v) if v.len() == 64 => Ok(()),
            Ok(v) => Err(format!("{} bytes came back", v.len())),
            Err(e) => Err(e),
        },
    );

    run.check(
        "re-entering execute-in-place is agreed to",
        board.sync_cmd(CMD_ENTER_XIP, &[]),
    );
}

/// What the device will not accept as a command at all.
///
/// Everything here is refused before any argument is looked at, so what is
/// being asked is whether the framing is judged rather than what the command
/// would have done.
async fn framing(run: &mut Runner, board: &mut Board) {
    // The magic is what says a command belongs to the protocol.  This device
    // has no commands of its own, so anything else is nobody's.
    let wrong_magic = refusal_code_magic(board, 0xdead_beef, CMD_READ, 8, 4, &[0u8; 8]).await;
    run.check(
        "a command carrying the wrong magic is refused",
        match wrong_magic {
            Err(e) => Err(e),
            Ok(code) if code == Status::UnknownCmd as u32 => Ok(()),
            Ok(code) => Err(format!("it reported {code}")),
        },
    );

    for (cmd, what) in [
        (0x7fu8, "a command identifier the protocol does not name"),
        (CMD_EXEC, "the command that runs code on the device"),
        (CMD_VECTORIZE_FLASH, "the command that vectors flash"),
    ] {
        run.check(
            &format!("{what} is refused"),
            match refusal_code(board, cmd, 0, 0, &[]).await {
                Err(e) => Err(e),
                Ok(code) if code == Status::UnknownCmd as u32 => Ok(()),
                Ok(code) => Err(format!("it reported {code}")),
            },
        );
    }

    // A range whose end runs off the top of the address space.  It is inside no
    // region, and the check that says so is done in wider arithmetic than the
    // addresses themselves - which it has to be, because this was once accepted.
    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&0xffff_ff00u32.to_le_bytes());
    args[4..8].copy_from_slice(&0x200u32.to_le_bytes());
    run.check(
        "a range that wraps the address space is refused",
        match refusal_code(board, CMD_READ, 8, 0x200, &args).await {
            Err(e) => Err(e),
            Ok(code) if code == Status::InvalidArg as u32 => Ok(()),
            Ok(code) => Err(format!("it reported {code}")),
        },
    );
}
