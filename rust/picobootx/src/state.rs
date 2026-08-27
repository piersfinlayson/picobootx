// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! The protocol: framing, the state machine, the command table, and dispatch
//! of the integrator's own commands.

use crate::control::{Control, Recipient, Request, RequestType, Stage};
use crate::control::{REQUEST_GET_CMD_STATUS, REQUEST_INTERFACE_RESET};
use crate::ops::{Custom, Ecc, Exclusive, Filled, Info, Ops, Reboot, Target};
use crate::transport::{Direction, Transport};
use crate::wire::{
    CMD_LEN, Command, DIR_IN, FLASH_PAGE_SIZE, GET_INFO_MAX_LEN, INFO_MAX_ANSWER_WORDS, MAGIC,
    StatusBlock,
};
use crate::{Result, Status};

/// What the state machine is doing.
///
/// The values are the C library's, so a conformance harness reads the same
/// number from either.
///
/// Reported and not acted on, so it is `non_exhaustive`: a state added later
/// is not a break for anyone reading this.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum State {
    /// Waiting for a command.
    Idle = 0,
    /// Taking a host-to-device data phase.
    DataOut = 1,
    /// Sending a device-to-host data phase.
    DataIn = 2,
    /// Sending a device-to-host data phase for a command of the integrator's.
    CustomIn = 3,
    /// Acknowledgement queued, waiting for it to go.
    AwaitZlp = 4,
    /// Data sent, waiting for the host's acknowledgement.
    AwaitAck = 5,
    /// Both endpoints halted, waiting to be asked why.
    Stalled = 6,
}

impl TryFrom<u8> for State {
    type Error = u8;

    /// The discriminant back to the state, for a reader that took it off a wire
    /// or out of a diagnostic block.
    ///
    /// # Errors
    ///
    /// The value itself, when it names no state.
    fn try_from(v: u8) -> core::result::Result<Self, u8> {
        match v {
            0 => Ok(Self::Idle),
            1 => Ok(Self::DataOut),
            2 => Ok(Self::DataIn),
            3 => Ok(Self::CustomIn),
            4 => Ok(Self::AwaitZlp),
            5 => Ok(Self::AwaitAck),
            6 => Ok(Self::Stalled),
            other => Err(other),
        }
    }
}

/// The two bulk endpoint addresses, as the descriptor gives them.
#[derive(Clone, Copy, Debug)]
pub struct Endpoints {
    /// Host to device.
    pub out: u8,
    /// Device to host.
    pub r#in: u8,
}

// The command identifiers, which are the protocol's.
const CMD_EXCLUSIVE_ACCESS: u8 = 0x01;
const CMD_REBOOT: u8 = 0x02;
const CMD_FLASH_ERASE: u8 = 0x03;
const CMD_WRITE: u8 = 0x05;
const CMD_EXIT_XIP: u8 = 0x06;
const CMD_ENTER_XIP: u8 = 0x07;
const CMD_EXEC: u8 = 0x08;
const CMD_VECTORIZE_FLASH: u8 = 0x09;
const CMD_REBOOT2: u8 = 0x0a;
const CMD_OTP_WRITE: u8 = 0x0d;
const CMD_READ: u8 = 0x84;
const CMD_GET_INFO: u8 = 0x8b;
const CMD_OTP_READ: u8 = 0x8c;

// How a command's declared transfer length is checked.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TLen {
    // It must be zero.
    Zero,
    // It must equal the size in the address/size arguments.
    AddrSize,
    // It must equal the rows asked for, times the size of a row.
    Otp,
    // The command checks it itself.
    Own,
}

// What the protocol does with a command, as distinct from what it means.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Category {
    // Call the operation, acknowledge when it returns.
    Sync,
    // Prepare, then act, then acknowledge.
    Async,
    // Acknowledge first, act once the acknowledgement has gone.
    Deferred,
    // Device to host.
    DataIn,
    // Host to device.
    DataOut,
    // Known, and refused here.
    Unsupported,
}

struct Spec {
    cmd_size: u8,
    tlen: TLen,
    category: Category,
}

fn spec(cmd_id: u8) -> Option<Spec> {
    use Category::{Async, DataIn, DataOut, Deferred, Sync, Unsupported};
    let (cmd_size, tlen, category) = match cmd_id {
        CMD_EXCLUSIVE_ACCESS => (0x01, TLen::Zero, Sync),
        CMD_EXIT_XIP => (0x00, TLen::Zero, Sync),
        CMD_ENTER_XIP => (0x00, TLen::Zero, Sync),
        CMD_FLASH_ERASE => (0x08, TLen::Zero, Async),
        CMD_REBOOT2 => (0x10, TLen::Zero, Deferred),
        CMD_READ => (0x08, TLen::AddrSize, DataIn),
        CMD_GET_INFO => (0x10, TLen::Own, DataIn),
        CMD_OTP_READ => (0x05, TLen::Otp, DataIn),
        CMD_WRITE => (0x08, TLen::AddrSize, DataOut),
        CMD_OTP_WRITE => (0x05, TLen::Otp, DataOut),
        CMD_REBOOT | CMD_EXEC | CMD_VECTORIZE_FLASH => (0x00, TLen::Zero, Unsupported),
        _ => return None,
    };
    Some(Spec {
        cmd_size,
        tlen,
        category,
    })
}

// What a data phase is carrying.  Only one command runs at a time, so these
// are alternatives rather than a struct of everything.
//
// The C holds the same thing in a union with no discriminant, so it cannot ask
// which command's state it is looking at.  Every arm below that refuses a
// transfer state the command did not set is therefore the Rust's alone, and has
// no counterpart in src/picobootx.c to compare against.
enum Xfer {
    None,
    Read {
        addr: u32,
        remaining: u32,
    },
    GetInfo {
        info: Info,
        // dParam0, handed back to every get_info call.
        param0: u32,
        transfer_remaining: u32,
        // Words the answer is, as get_info_prepare said, and how many have gone.
        answer_words: u8,
        answer_sent: u8,
        // Whether the leading count word has gone.
        count_sent: bool,
    },
    Otp {
        row: u16,
        rows_remaining: u16,
        ecc: Ecc,
    },
    Write {
        addr: u32,
        expected: u32,
        received: u32,
        target: Target,
        page_offset: usize,
    },
    Reboot(Reboot),
    Custom(Command),
}

/// The protocol, driven by whatever calls `poll`.
///
/// Owns the integrator's operations and, if there are any, the integrator's own
/// commands.  The transport is handed in per call rather than owned, so an
/// asynchronous driver can hold the endpoints itself.
pub struct Picoboot<'a, O: Ops, C: Custom = crate::ops::NoCustom> {
    ops: O,
    custom: C,
    flash_page: Option<&'a mut [u8; FLASH_PAGE_SIZE]>,
    endpoints: Endpoints,
    state: State,
    token: u32,
    cmd_id: u8,
    status: StatusBlock,
    xfer: Xfer,
    // Bytes of the current device to host transfer the host has still to be
    // sent, counting down from its declared length.  task_data_in offers a fill
    // no more than this, so no fill can put more on the bulk pipe than the host
    // asked for.
    data_in_remaining: u32,
}

impl<'a, O: Ops, C: Custom> Picoboot<'a, O, C> {
    /// Start, with the operations this device serves and where its bulk
    /// endpoints are.
    ///
    /// `flash_page` is the page a flash `WRITE` is accumulated into.  Without
    /// one, a `WRITE` to somewhere `Ops::write_prepare` calls `Target::Flash`
    /// is refused with `Status::NotPermitted`.  Writes to memory and to OTP do
    /// not use it.
    pub fn new(
        ops: O,
        custom: C,
        flash_page: Option<&'a mut [u8; FLASH_PAGE_SIZE]>,
        endpoints: Endpoints,
    ) -> Self {
        Self {
            ops,
            custom,
            flash_page,
            endpoints,
            state: State::Idle,
            token: 0,
            cmd_id: 0,
            status: StatusBlock::new(),
            xfer: Xfer::None,
            data_in_remaining: 0,
        }
    }

    /// What the state machine is doing.
    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }

    /// The operations, for an integrator that needs to reach them again.
    pub fn ops(&mut self) -> &mut O {
        &mut self.ops
    }

    /// The integrator's own commands, likewise.
    pub fn custom(&mut self) -> &mut C {
        &mut self.custom
    }

    // -----------------------------------------------------------------
    // Status and halting
    // -----------------------------------------------------------------

    fn set_status(&mut self, code: Status, in_progress: bool) {
        self.status.set(self.token, code, self.cmd_id, in_progress);
    }

    // Adopt a command as the one being worked on.  GET_COMMAND_STATUS has to
    // answer for a command that is still running as well as one that has
    // finished, so the block names this one from the moment it arrives.
    fn begin(&mut self, cmd: &Command) {
        self.token = cmd.token;
        self.cmd_id = cmd.cmd_id;
        self.set_status(Status::Ok, true);
    }

    fn stall<T: Transport>(&mut self, t: &mut T, code: Status) {
        self.set_status(code, false);
        t.set_stalled(Direction::Out, true);
        t.set_stalled(Direction::In, true);
        self.status.set_in_progress(false);
        self.state = State::Stalled;
    }

    fn ack<T: Transport>(&mut self, t: &mut T) {
        self.set_status(Status::Ok, false);
        self.state = State::AwaitZlp;
        if !t.send_ack() {
            self.stall(t, Status::UnknownError);
        }
    }

    // -----------------------------------------------------------------
    // The task
    // -----------------------------------------------------------------

    /// Move the protocol along.  Call from the loop that also turns the USB
    /// stack.
    pub fn poll<T: Transport>(&mut self, t: &mut T) {
        match self.state {
            State::Idle => self.task_idle(t),
            State::DataIn | State::CustomIn => self.task_data_in(t),
            State::DataOut => self.task_data_out(t),
            State::AwaitZlp | State::AwaitAck | State::Stalled => {}
        }
    }

    fn task_idle<T: Transport>(&mut self, t: &mut T) {
        let avail = t.rx_available();
        if avail < CMD_LEN as u32 {
            if avail > 1 {
                // A partial command is not a command.  Drop it and re-arm,
                // rather than leaving it to be read as the head of the next.
                t.rx_clear();
            }
            return;
        }

        let mut buf = [0u8; CMD_LEN];
        let n = t.rx_read(&mut buf);
        if n != CMD_LEN as u32 {
            self.stall(t, Status::UnknownError);
            return;
        }
        let Some(cmd) = Command::from_bytes(&buf) else {
            // Unreachable: buf is a 32-byte array, and the only thing
            // from_bytes rejects is a length other than 32.
            const _: () = assert!(CMD_LEN == 32);
            // LCOV_UNREACHABLE_START
            self.stall(t, Status::UnknownError);
            return;
            // LCOV_UNREACHABLE_STOP
        };

        if cmd.magic == MAGIC {
            self.dispatch(t, &cmd);
        } else if self.custom.magic() == Some(cmd.magic) {
            self.dispatch_custom(t, &cmd);
        } else {
            self.begin(&cmd);
            self.stall(t, Status::UnknownCmd);
        }
    }

    fn dispatch<T: Transport>(&mut self, t: &mut T, cmd: &Command) {
        self.begin(cmd);

        let Some(spec) = spec(cmd.cmd_id) else {
            self.stall(t, Status::UnknownCmd);
            return;
        };

        if spec.category == Category::Unsupported {
            self.stall(t, Status::UnknownCmd);
            return;
        }

        if cmd.cmd_size != spec.cmd_size {
            self.stall(t, Status::InvalidCmdLength);
            return;
        }

        let tlen = cmd.transfer_len;
        let expected = match spec.tlen {
            TLen::Own => None,
            TLen::Zero => Some(0),
            TLen::AddrSize => Some(cmd.arg_u32(4)),
            TLen::Otp => {
                let count = u32::from(cmd.arg_u16(2));
                Some(count * Ecc::from(cmd.args[4]).row_size())
            }
        };
        if expected.is_some_and(|e| tlen != e) {
            self.stall(t, Status::InvalidTransferLen);
            return;
        }

        match spec.category {
            Category::Sync => self.action_sync(t, cmd),
            Category::Async => self.action_async(t, cmd),
            Category::Deferred => self.action_deferred(t, cmd),
            Category::DataIn => match self.prepare_in(cmd) {
                Ok(()) => {
                    self.data_in_remaining = tlen;
                    self.state = State::DataIn;
                }
                Err(e) => self.stall(t, e),
            },
            Category::DataOut => match self.prepare_out(cmd) {
                Ok(()) => self.state = State::DataOut,
                Err(e) => self.stall(t, e),
            },
            // Unreachable: an Unsupported category stalls and returns earlier
            // in this function, so it never arrives at this match.
            // LCOV_UNREACHABLE_START
            Category::Unsupported => unreachable!(),
            // LCOV_UNREACHABLE_STOP
        }
    }

    fn action_sync<T: Transport>(&mut self, t: &mut T, cmd: &Command) {
        let r = match cmd.cmd_id {
            CMD_EXCLUSIVE_ACCESS => self.ops.exclusive_access(Exclusive::from(cmd.args[0])),
            CMD_EXIT_XIP => self.ops.exit_xip(),
            CMD_ENTER_XIP => self.ops.enter_xip(),
            // Unreachable: spec marks only these three commands Sync, and only
            // a Sync command is routed here.
            // LCOV_UNREACHABLE_START
            _ => unreachable!(),
            // LCOV_UNREACHABLE_STOP
        };
        match r {
            Ok(()) => self.ack(t),
            Err(e) => self.stall(t, e),
        }
    }

    fn action_async<T: Transport>(&mut self, t: &mut T, cmd: &Command) {
        let (addr, size) = (cmd.arg_u32(0), cmd.arg_u32(4));
        let r = self
            .ops
            .flash_erase_prepare(addr, size)
            .and_then(|()| self.ops.flash_erase(addr, size));
        match r {
            Ok(()) => self.ack(t),
            Err(e) => self.stall(t, e),
        }
    }

    fn action_deferred<T: Transport>(&mut self, t: &mut T, cmd: &Command) {
        let args = Reboot {
            flags: cmd.arg_u32(0),
            delay_ms: cmd.arg_u32(4),
            p0: cmd.arg_u32(8),
            p1: cmd.arg_u32(12),
        };
        self.xfer = Xfer::Reboot(args);
        match self.ops.reboot_prepare(&args) {
            Ok(()) => self.ack(t),
            Err(e) => self.stall(t, e),
        }
    }

    // -----------------------------------------------------------------
    // Preparing a data phase
    // -----------------------------------------------------------------

    fn prepare_in(&mut self, cmd: &Command) -> Result {
        match cmd.cmd_id {
            CMD_READ => {
                let (addr, size) = (cmd.arg_u32(0), cmd.arg_u32(4));
                self.ops.read_prepare(addr, size)?;
                self.xfer = Xfer::Read {
                    addr,
                    remaining: size,
                };
                Ok(())
            }
            CMD_GET_INFO => {
                let tlen = cmd.transfer_len;
                if tlen == 0 || tlen & 0x3 != 0 || tlen > GET_INFO_MAX_LEN {
                    return Err(Status::InvalidTransferLen);
                }
                // The four types the protocol defines.  Gating here rather than
                // in the callback means a type outside them is refused without
                // reaching an integrator, and Ops only ever sees a named one.
                // GET_INFO itself was recognised, so the command identifier was
                // not the problem — the type asked for is outside the range the
                // library serves, which is what InvalidArg says.
                let Some(info) = Info::from_wire(cmd.args[0]) else {
                    return Err(Status::InvalidArg);
                };
                let param0 = cmd.arg_u32(4);

                let words = self.ops.get_info_prepare(info, param0)?;
                if words as usize > INFO_MAX_ANSWER_WORDS {
                    return Err(Status::UnknownError);
                }
                // The whole answer or none of it, judged against the answer this
                // device says it will actually give rather than against what was
                // asked for.  BufferTooSmall is what PICOBOOT carries that
                // refusal in.
                if tlen < (1 + words) * 4 {
                    return Err(Status::BufferTooSmall);
                }

                self.xfer = Xfer::GetInfo {
                    info,
                    param0,
                    transfer_remaining: tlen,
                    answer_words: words as u8,
                    answer_sent: 0,
                    count_sent: false,
                };
                Ok(())
            }
            CMD_OTP_READ => {
                let (row, count) = (cmd.arg_u16(0), cmd.arg_u16(2));
                let ecc = Ecc::from(cmd.args[4]);
                self.ops.otp_read_prepare(row, count, ecc)?;
                self.xfer = Xfer::Otp {
                    row,
                    rows_remaining: count,
                    ecc,
                };
                Ok(())
            }
            // Unreachable: spec marks only these three commands DataIn, and
            // only a DataIn command is routed here.
            // LCOV_UNREACHABLE_START
            _ => unreachable!(),
            // LCOV_UNREACHABLE_STOP
        }
    }

    fn prepare_out(&mut self, cmd: &Command) -> Result {
        match cmd.cmd_id {
            CMD_WRITE => {
                let (addr, size) = (cmd.arg_u32(0), cmd.arg_u32(4));
                let target = self.ops.write_prepare(addr, size)?;
                if target == Target::Flash && self.flash_page.is_none() {
                    return Err(Status::NotPermitted);
                }
                self.xfer = Xfer::Write {
                    addr,
                    expected: size,
                    received: 0,
                    target,
                    page_offset: 0,
                };
                Ok(())
            }
            CMD_OTP_WRITE => {
                let (row, count) = (cmd.arg_u16(0), cmd.arg_u16(2));
                let ecc = Ecc::from(cmd.args[4]);
                self.ops.otp_write_prepare(row, count, ecc)?;
                self.xfer = Xfer::Otp {
                    row,
                    rows_remaining: count,
                    ecc,
                };
                Ok(())
            }
            // Unreachable: spec marks only these two commands DataOut, and
            // only a DataOut command is routed here.
            // LCOV_UNREACHABLE_START
            _ => unreachable!(),
            // LCOV_UNREACHABLE_STOP
        }
    }

    // -----------------------------------------------------------------
    // Device to host
    // -----------------------------------------------------------------

    // Drives a device to host data phase, calling fill until the transfer
    // completes or the endpoint runs out of room.
    //
    // The host is sent the length it declared and no more (RP2350 datasheet
    // 5.6.4), and that is held here rather than in each fill: the room offered
    // is never more than the transfer has left, so no fill can put a further
    // byte on the pipe — an integrator's own fill included, which is the one
    // the library cannot reach into.
    fn task_data_in<T: Transport>(&mut self, t: &mut T) {
        let mut buf = [0u8; 64];
        loop {
            let space = t.tx_available();
            if space == 0 {
                t.tx_flush();
                return;
            }
            let mut max_len = core::cmp::min(space as usize, buf.len());
            // Whether what is left of the transfer, rather than the endpoint,
            // is what limits the room on offer.  If it is, this is as much room
            // as there will ever be, and a fill that declines it is asking for
            // more than the host made room for.
            let transfer_capped = self.data_in_remaining as usize <= max_len;
            if transfer_capped {
                max_len = self.data_in_remaining as usize;
            }

            let filled = if self.state == State::CustomIn {
                match self.xfer {
                    Xfer::Custom(cmd) => self.custom.fill(&cmd, &mut buf[..max_len]),
                    // Unreachable: the one place that sets the CustomIn state
                    // assigns Xfer::Custom on the line before it, and nothing
                    // writes the transfer again until the state moves on.
                    // LCOV_UNREACHABLE_START
                    _ => Err(Status::UnknownError),
                    // LCOV_UNREACHABLE_STOP
                }
            } else {
                self.fill(&mut buf[..max_len])
            };

            let (written, done) = match filled {
                Ok(Filled::Done(n)) => (n, true),
                Ok(Filled::More(n)) => (n, false),
                Ok(Filled::NoRoom) => (0, false),
                Err(e) => {
                    self.stall(t, e);
                    return;
                }
            };

            // The count comes from the integrator, and a count larger than the
            // room it was offered would read past the end of the buffer it was
            // handed and would take the counter below zero, leaving the clamp
            // above meaningless for the rest of the transfer.
            if written > max_len {
                self.stall(t, Status::UnknownError);
                return;
            }

            if written > 0 && t.tx_write(&buf[..written]) != written as u32 {
                self.stall(t, Status::UnknownError);
                return;
            }
            self.data_in_remaining -= written as u32;

            if done {
                t.tx_flush();
                self.state = State::AwaitAck;
                return;
            }

            if written == 0 {
                if transfer_capped {
                    // The fill declined the whole of what the transfer has
                    // left, and the room on offer cannot grow.  The host asked
                    // for a length its answer does not fit in.
                    self.stall(t, Status::BufferTooSmall);
                    return;
                }
                t.tx_flush();
                return;
            }
        }
    }

    fn fill(&mut self, buf: &mut [u8]) -> Result<Filled> {
        match self.cmd_id {
            CMD_READ => self.fill_read(buf),
            CMD_GET_INFO => self.fill_get_info(buf),
            CMD_OTP_READ => self.fill_otp(buf),
            // Unreachable: only the DataIn state gets this far, and spec marks
            // just these three commands DataIn.
            // LCOV_UNREACHABLE_START
            _ => Err(Status::UnknownError),
            // LCOV_UNREACHABLE_STOP
        }
    }

    fn fill_read(&mut self, buf: &mut [u8]) -> Result<Filled> {
        let Xfer::Read { addr, remaining } = self.xfer else {
            // Unreachable: fill calls this only for a READ, and prepare_in set
            // Xfer::Read before a READ could start its data phase.
            // LCOV_UNREACHABLE_START
            return Err(Status::UnknownError);
            // LCOV_UNREACHABLE_STOP
        };
        if remaining == 0 {
            return Ok(Filled::Done(0));
        }
        let chunk = core::cmp::min(remaining as usize, buf.len());
        self.ops.read(addr, &mut buf[..chunk])?;
        let left = remaining - chunk as u32;
        self.xfer = Xfer::Read {
            addr: addr + chunk as u32,
            remaining: left,
        };
        Ok(if left == 0 {
            Filled::Done(chunk)
        } else {
            Filled::More(chunk)
        })
    }

    fn fill_get_info(&mut self, buf: &mut [u8]) -> Result<Filled> {
        let Xfer::GetInfo {
            info,
            param0,
            mut transfer_remaining,
            answer_words,
            mut answer_sent,
            mut count_sent,
        } = self.xfer
        else {
            // Unreachable: fill calls this only for a GET_INFO, and prepare_in
            // set Xfer::GetInfo before a GET_INFO could start its data phase.
            // LCOV_UNREACHABLE_START
            return Err(Status::UnknownError);
            // LCOV_UNREACHABLE_STOP
        };

        let save = |s: &mut Self, tr, sent, cs| {
            s.xfer = Xfer::GetInfo {
                info,
                param0,
                transfer_remaining: tr,
                answer_words,
                answer_sent: sent,
                count_sent: cs,
            };
        };

        // Unreachable.  prepare_in refuses a transfer length of zero before the
        // command reaches a data phase, so the first call here always has bytes
        // owed, and each of the three places below that takes the count down
        // reports Done in the same call when it reaches zero — on which
        // task_data_in leaves the data-in state.  So there is no call with
        // nothing left to send.  The arm stays because the same guard opens all
        // three data-in fills, and READ and OTP_READ do carry a zero-length
        // transfer.
        if transfer_remaining == 0 {
            // LCOV_UNREACHABLE_START
            return Ok(Filled::Done(0));
            // LCOV_UNREACHABLE_STOP
        }
        if buf.len() < 4 {
            return Ok(Filled::NoRoom);
        }

        // The count of the significant words that follow.  This word is the
        // library's, and everything after it is the device's answer, whatever
        // shape its type gives that.
        if !count_sent {
            buf[..4].copy_from_slice(&u32::from(answer_words).to_le_bytes());
            count_sent = true;
            transfer_remaining -= 4;
            save(self, transfer_remaining, answer_sent, count_sent);
            return Ok(if transfer_remaining == 0 {
                Filled::Done(4)
            } else {
                Filled::More(4)
            });
        }

        // The answer, from where the last call left off.  The room offered is
        // never more than the answer has left to give, so the callback cannot
        // put a byte past what the count word promised.
        if answer_sent < answer_words {
            let owed = usize::from(answer_words - answer_sent) * 4;
            let room = core::cmp::min(buf.len(), owed) & !3;
            let written =
                self.ops
                    .get_info(info, param0, u32::from(answer_sent), &mut buf[..room])?;
            // The count comes from the integrator.  More than the room offered
            // would read past the end of buf, and a part word would leave
            // at_word naming a boundary that is not one.
            if written > room || written % 4 != 0 {
                return Err(Status::UnknownError);
            }
            answer_sent += (written / 4) as u8;
            transfer_remaining -= written as u32;
            save(self, transfer_remaining, answer_sent, count_sent);
            return Ok(if transfer_remaining == 0 {
                Filled::Done(written)
            } else if written == 0 {
                Filled::NoRoom
            } else {
                Filled::More(written)
            });
        }

        // Whatever the host still expects, and nothing left to say.  Padded in
        // whole words, like everything else this reply carries, which is what
        // keeps transfer_remaining a multiple of four: the call above declines
        // room for less than a word, and a part word left behind here would
        // leave it declining that room for the rest of the transfer.
        let chunk = core::cmp::min(transfer_remaining as usize, buf.len()) & !3;
        buf[..chunk].fill(0);
        transfer_remaining -= chunk as u32;
        save(self, transfer_remaining, answer_sent, count_sent);
        Ok(if transfer_remaining == 0 {
            Filled::Done(chunk)
        } else {
            Filled::More(chunk)
        })
    }

    fn fill_otp(&mut self, buf: &mut [u8]) -> Result<Filled> {
        let Xfer::Otp {
            row,
            rows_remaining,
            ecc,
        } = self.xfer
        else {
            // Unreachable: fill calls this only for an OTP_READ, and
            // prepare_in set Xfer::Otp before an OTP_READ could start its data
            // phase.
            // LCOV_UNREACHABLE_START
            return Err(Status::UnknownError);
            // LCOV_UNREACHABLE_STOP
        };
        if rows_remaining == 0 {
            return Ok(Filled::Done(0));
        }
        let row_size = ecc.row_size() as usize;
        let total = row_size * rows_remaining as usize;
        let chunk = core::cmp::min(total, buf.len()) / row_size * row_size;
        if chunk == 0 {
            return Ok(Filled::NoRoom);
        }
        self.ops.otp_read(row, ecc, &mut buf[..chunk])?;
        let done_rows = (chunk / row_size) as u16;
        let left = rows_remaining - done_rows;
        self.xfer = Xfer::Otp {
            row: row + done_rows,
            rows_remaining: left,
            ecc,
        };
        Ok(if left == 0 {
            Filled::Done(chunk)
        } else {
            Filled::More(chunk)
        })
    }

    // -----------------------------------------------------------------
    // Host to device
    // -----------------------------------------------------------------

    fn task_data_out<T: Transport>(&mut self, t: &mut T) {
        let mut buf = [0u8; 64];
        let avail = t.rx_available();
        if avail == 0 {
            return;
        }
        let chunk = core::cmp::min(avail as usize, buf.len());
        let n = core::cmp::min(t.rx_read(&mut buf[..chunk]) as usize, chunk);
        if n == 0 {
            return;
        }

        match self.consume(&buf[..n]) {
            Ok(true) => self.ack(t),
            Ok(false) => {}
            Err(e) => self.stall(t, e),
        }
    }

    fn consume(&mut self, buf: &[u8]) -> Result<bool> {
        match self.cmd_id {
            CMD_WRITE => self.consume_write(buf),
            CMD_OTP_WRITE => self.consume_otp(buf),
            // Unreachable: only the DataOut state gets this far, and spec
            // marks just these two commands DataOut.
            // LCOV_UNREACHABLE_START
            _ => Err(Status::UnknownError),
            // LCOV_UNREACHABLE_STOP
        }
    }

    fn consume_write(&mut self, buf: &[u8]) -> Result<bool> {
        let Xfer::Write {
            mut addr,
            expected,
            mut received,
            target,
            mut page_offset,
        } = self.xfer
        else {
            // Unreachable: consume calls this only for a WRITE, and
            // prepare_out set Xfer::Write before a WRITE could start its data
            // phase.
            // LCOV_UNREACHABLE_START
            return Err(Status::UnknownError);
            // LCOV_UNREACHABLE_STOP
        };

        if target == Target::Flash {
            let mut src = buf;
            while !src.is_empty() {
                let space = FLASH_PAGE_SIZE - page_offset;
                let chunk = core::cmp::min(src.len(), space);
                {
                    let page = self.flash_page.as_deref_mut().ok_or(Status::NotPermitted)?;
                    page[page_offset..page_offset + chunk].copy_from_slice(&src[..chunk]);
                }
                page_offset += chunk;
                received = received.wrapping_add(chunk as u32);
                src = &src[chunk..];

                if page_offset == FLASH_PAGE_SIZE || received == expected {
                    {
                        let page = self.flash_page.as_deref_mut().ok_or(Status::NotPermitted)?;
                        page[page_offset..].fill(0);
                    }
                    // The borrow has to end before the operation is called, so
                    // the page is copied out of the state and back in.
                    let page = *self.flash_page.as_deref().ok_or(Status::NotPermitted)?;
                    self.ops.flash_page_write(addr, &page)?;
                    addr = addr.wrapping_add(page_offset as u32);
                    page_offset = 0;
                }
            }
        } else {
            self.ops.write(addr, buf)?;
            addr = addr.wrapping_add(buf.len() as u32);
            received = received.wrapping_add(buf.len() as u32);
        }

        self.xfer = Xfer::Write {
            addr,
            expected,
            received,
            target,
            page_offset,
        };
        Ok(received == expected)
    }

    fn consume_otp(&mut self, buf: &[u8]) -> Result<bool> {
        let Xfer::Otp {
            row,
            rows_remaining,
            ecc,
        } = self.xfer
        else {
            // Unreachable: consume calls this only for an OTP_WRITE, and
            // prepare_out set Xfer::Otp before an OTP_WRITE could start its
            // data phase.
            // LCOV_UNREACHABLE_START
            return Err(Status::UnknownError);
            // LCOV_UNREACHABLE_STOP
        };
        let row_size = ecc.row_size() as usize;
        let rows = buf.len() / row_size;
        if rows == 0 {
            return Ok(false);
        }
        self.ops.otp_write(row, ecc, buf)?;
        let left = rows_remaining - rows as u16;
        self.xfer = Xfer::Otp {
            row: row + rows as u16,
            rows_remaining: left,
            ecc,
        };
        Ok(left == 0)
    }

    // -----------------------------------------------------------------
    // The integrator's own commands
    // -----------------------------------------------------------------

    fn dispatch_custom<T: Transport>(&mut self, t: &mut T, cmd: &Command) {
        self.begin(cmd);

        if cmd.transfer_len != 0 && cmd.cmd_id & DIR_IN == 0 {
            // A host-to-device data phase on a custom command is not served.
            self.stall(t, Status::UnknownCmd);
            return;
        }

        if let Err(e) = self.custom.dispatch(cmd) {
            self.stall(t, e);
            return;
        }

        if cmd.transfer_len == 0 {
            self.ack(t);
            return;
        }

        // fill is handed the command on every call, so it is kept here rather
        // than borrowed from a caller whose copy is about to go out of scope.
        self.xfer = Xfer::Custom(*cmd);
        self.data_in_remaining = cmd.transfer_len;
        self.state = State::CustomIn;
    }

    // -----------------------------------------------------------------
    // What the USB stack tells us
    // -----------------------------------------------------------------

    /// Tell the protocol a transmission finished.
    pub fn on_tx(&mut self) {
        if self.state != State::AwaitZlp {
            return;
        }
        if self.cmd_id == CMD_REBOOT2
            && let Xfer::Reboot(args) = self.xfer
        {
            self.ops.reboot_execute(&args);
        }
        self.state = State::Idle;
    }

    /// Tell the protocol bytes arrived on the receive endpoint.
    ///
    /// How many is read from the transport rather than passed, so the count
    /// acted on is the one the transport will hand over.
    pub fn on_rx<T: Transport>(&mut self, t: &mut T) {
        let available = t.rx_available();
        if available <= 1 {
            if self.state == State::AwaitAck {
                // Both an empty packet and a single byte count as the host's
                // acknowledgement, since a host that cannot send the first
                // sends the second.
                self.set_status(Status::Ok, false);
                self.state = State::Idle;
            }
            if available == 1 && self.state != State::DataOut {
                let mut discard = [0u8; 1];
                t.rx_read(&mut discard);
            }
        }

        if self.state == State::AwaitAck {
            // Data where an acknowledgement was expected means the
            // acknowledgement was missed, so take the data as the next thing.
            self.set_status(Status::Ok, false);
            self.state = State::Idle;
        }
    }

    /// Answer a control request, or say it is not picoboot's.
    pub fn on_control<T: Transport>(
        &mut self,
        t: &mut T,
        req: &Request,
        stage: Stage,
    ) -> Control<'_> {
        // The host clearing a halt on one of our endpoints.  The stack has
        // already cleared it by the time this runs, so what is left is to make
        // the endpoint ready to be used again.
        if req.request_type == RequestType::Standard
            && req.request == 0x01 // CLEAR_FEATURE
            && req.value == 0x00
        // ENDPOINT_HALT
        {
            let ep = (req.index & 0xff) as u8;
            if ep == self.endpoints.out || ep == self.endpoints.r#in {
                if stage == Stage::Setup {
                    if ep == self.endpoints.out {
                        t.rx_clear();
                    } else {
                        t.tx_clear();
                    }
                }
                // The state machine is left alone, which is what the bootrom
                // does.
                return Control::Ack;
            }
        }

        if (req.request_type != RequestType::Class && req.request_type != RequestType::Vendor)
            || req.recipient != Recipient::Interface
        {
            return Control::NotHandled;
        }

        match req.request {
            REQUEST_INTERFACE_RESET => {
                if stage == Stage::Setup {
                    t.set_stalled(Direction::Out, false);
                    t.set_stalled(Direction::In, false);
                    self.state = State::Idle;
                    self.set_status(Status::Ok, false);
                }
                Control::Ack
            }
            REQUEST_GET_CMD_STATUS => {
                if stage != Stage::Setup {
                    return Control::Ack;
                }
                if (t.is_stalled(Direction::Out) || t.is_stalled(Direction::In))
                    && self.status.code() == Status::Ok as u32
                {
                    // Halted with nothing to say for itself is a state the host
                    // cannot act on, so it is reported as an error rather than
                    // as success.
                    self.set_status(Status::UnknownError, false);
                    self.state = State::Stalled;
                }
                Control::Reply(&self.status.0)
            }
            _ => Control::NotHandled,
        }
    }
}
