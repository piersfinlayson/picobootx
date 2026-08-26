// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! What a device does when a host asks it something.

use crate::wire::Command;
use crate::{Result, Status};

/// What `EXCLUSIVE_ACCESS` is asking for.
///
/// `Other` carries a value the protocol does not define, because a host may
/// send one and the device has to be able to answer for it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Exclusive {
    /// Share the device with whatever else is using it.
    NotExclusive,
    /// Take the device.
    Exclusive,
    /// Take the device and eject the mass storage interface.
    ExclusiveAndEject,
    /// Something the protocol does not define.
    Other(u8),
}

impl From<u8> for Exclusive {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::NotExclusive,
            1 => Self::Exclusive,
            2 => Self::ExclusiveAndEject,
            other => Self::Other(other),
        }
    }
}

impl From<Exclusive> for u8 {
    fn from(v: Exclusive) -> Self {
        match v {
            Exclusive::NotExclusive => 0,
            Exclusive::Exclusive => 1,
            Exclusive::ExclusiveAndEject => 2,
            Exclusive::Other(other) => other,
        }
    }
}

/// How OTP rows are addressed: as raw words, or through the error-correcting
/// view that carries two bytes per row instead of four.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ecc {
    /// Four bytes per row.
    Raw = 0,
    /// Two bytes per row.
    Ecc = 1,
}

impl From<u8> for Ecc {
    /// Any non-zero value selects the error-correcting view, which is what the
    /// protocol says and what a host relies on.
    fn from(v: u8) -> Self {
        if v == 0 { Self::Raw } else { Self::Ecc }
    }
}

impl Ecc {
    /// How many bytes one row carries in this view.
    #[must_use]
    pub const fn row_size(self) -> u32 {
        match self {
            Self::Raw => 4,
            Self::Ecc => 2,
        }
    }
}

/// Where a `WRITE` is going, as `Ops::write_prepare` reports it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Target {
    /// Ordinary memory, written as the packets arrive.
    Memory,
    /// Flash, accumulated a page at a time before being programmed.
    Flash,
}

/// The arguments `REBOOT2` carries.
#[derive(Clone, Copy, Debug)]
pub struct Reboot {
    /// What kind of reboot, per the protocol.
    pub flags: u32,
    /// How long to wait first.
    pub delay_ms: u32,
    /// First parameter, meaning set by `flags`.
    pub p0: u32,
    /// Second parameter, meaning set by `flags`.
    pub p1: u32,
}

/// What this device does.
///
/// Every method has a default, so `impl Ops for MyDevice {}` is a complete
/// implementation — of a device that agrees to the three advisory commands and
/// refuses everything else.  Write a method and that command starts working.
///
/// **A `_prepare` method promises the operation beside it.**  The library calls
/// the prepare before any data moves, and takes what it returns as the answer
/// to "does this device serve this command".  Writing `read_prepare` and
/// leaving `read` to its default is a device that accepts a transfer it then
/// abandons partway.
///
/// # Refusing
///
/// A method refuses by returning a [`Status`], which the library puts in the
/// block the host reads back with `GET_COMMAND_STATUS` before halting both bulk
/// endpoints.  Which one to return is yours, and the protocol uses them like
/// this:
///
/// - [`Status::UnknownCmd`] — this device does not serve the command at all.
///   Every default returns it, which is what makes an unwritten method a
///   command the device does not have.
/// - [`Status::NotPermitted`] — the command is served, and not here.  A range
///   this device keeps a host out of, an OTP row it will not blow.
/// - [`Status::InvalidAddress`] — outside anything this device answers for.
/// - [`Status::InvalidArg`] — an argument out of range or not one this command
///   accepts.
/// - [`Status::BadAlignment`] — the right address, on the wrong boundary.
/// - [`Status::PreconditionNotMet`] — something the operation relies on does
///   not hold.
/// - [`Status::UnknownError`] — a failure with nothing more specific to say.
///
/// The library answers three of them itself, before any method here is reached:
/// [`Status::InvalidCmdLength`] and [`Status::InvalidTransferLen`] for a
/// command whose header disagrees with what that command carries, and
/// [`Status::UnknownCmd`] for an identifier or a magic it does not know.  It
/// also answers [`Status::NotPermitted`] for a flash `WRITE` when
/// `Picoboot::new` was given no page buffer, and [`Status::UnknownError`] when
/// the transport refuses a write it accepted room for.
pub trait Ops {
    /// Take or release the device.  Absent means the device simply agrees.
    fn exclusive_access(&mut self, mode: Exclusive) -> Result {
        let _ = mode;
        Ok(())
    }

    /// Leave execute-in-place.  Absent means the device simply agrees.
    fn exit_xip(&mut self) -> Result {
        Ok(())
    }

    /// Re-enter execute-in-place.  Absent means the device simply agrees.
    fn enter_xip(&mut self) -> Result {
        Ok(())
    }

    /// Whether this range may be read, before any of it is.
    fn read_prepare(&mut self, addr: u32, size: u32) -> Result {
        let _ = (addr, size);
        Err(Status::UnknownCmd)
    }

    /// Fill `buf` from `addr`.  Called once per packet's worth.
    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result {
        let _ = (addr, buf);
        Err(Status::UnknownCmd)
    }

    /// Whether this range may be written, and what kind of storage it is.
    fn write_prepare(&mut self, addr: u32, size: u32) -> Result<Target> {
        let _ = (addr, size);
        Err(Status::UnknownCmd)
    }

    /// Write `buf` at `addr`.  Serves a range `write_prepare` called
    /// `Target::Memory`.
    fn write(&mut self, addr: u32, buf: &[u8]) -> Result {
        let _ = (addr, buf);
        Err(Status::UnknownCmd)
    }

    /// Program one flash page at `addr`.  Serves a range `write_prepare`
    /// called `Target::Flash`, and is given a whole page, zero-padded if the
    /// host's data ran out inside it.
    fn flash_page_write(&mut self, addr: u32, page: &[u8; crate::wire::FLASH_PAGE_SIZE]) -> Result {
        let _ = (addr, page);
        Err(Status::NotPermitted)
    }

    /// Whether this range may be erased, before any of it is.
    fn flash_erase_prepare(&mut self, addr: u32, size: u32) -> Result {
        let _ = (addr, size);
        Err(Status::UnknownCmd)
    }

    /// Erase the range.
    fn flash_erase(&mut self, addr: u32, size: u32) -> Result {
        let _ = (addr, size);
        Err(Status::UnknownCmd)
    }

    /// Whether these OTP rows may be read, before any are.
    fn otp_read_prepare(&mut self, row: u16, count: u16, ecc: Ecc) -> Result {
        let _ = (row, count, ecc);
        Err(Status::UnknownCmd)
    }

    /// Fill `buf` from consecutive OTP rows starting at `row`.
    fn otp_read(&mut self, row: u16, ecc: Ecc, buf: &mut [u8]) -> Result {
        let _ = (row, ecc, buf);
        Err(Status::UnknownCmd)
    }

    /// Whether these OTP rows may be written, before any are.
    fn otp_write_prepare(&mut self, row: u16, count: u16, ecc: Ecc) -> Result {
        let _ = (row, count, ecc);
        Err(Status::UnknownCmd)
    }

    /// Write consecutive OTP rows starting at `row`.
    fn otp_write(&mut self, row: u16, ecc: Ecc, buf: &[u8]) -> Result {
        let _ = (row, ecc, buf);
        Err(Status::UnknownCmd)
    }

    /// Whether the device answers `GET_INFO` for the system flags asked for.
    ///
    /// Only the system info type reaches this.  The partition type is answered
    /// by the library.
    fn get_info_sys_prepare(&mut self, flags: u32) -> Result {
        let _ = flags;
        Err(Status::UnknownCmd)
    }

    /// Write the words one system info flag carries.
    ///
    /// Exactly one flag per call, and `buf` is sized for it, so the whole of it
    /// is filled or the call fails.
    fn get_info_sys(&mut self, flag: u32, buf: &mut [u8]) -> Result {
        let _ = (flag, buf);
        Err(Status::UnknownCmd)
    }

    /// Whether the device will reboot as asked.  Runs before the host is
    /// acknowledged.
    fn reboot_prepare(&mut self, args: &Reboot) -> Result {
        let _ = args;
        Err(Status::UnknownCmd)
    }

    /// Reboot.  Runs after the host has been acknowledged, so the
    /// acknowledgement reaches it.  Absent means the device answers and stays
    /// where it is.
    fn reboot_execute(&mut self, args: &Reboot) {
        let _ = args;
    }
}

/// What `Custom::fill` produced on one call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Filled {
    /// This many bytes, and the transfer is complete.
    Done(usize),
    /// This many bytes, and there may be more.
    More(usize),
    /// Nothing, because what comes next did not fit.  Call again with room.
    NoRoom,
}

/// Commands of the integrator's own, carrying the integrator's own magic.
///
/// The command identifiers are entirely yours: the library reads only the
/// magic, `transfer_len` and the direction bit.
pub trait Custom {
    /// The magic these commands carry, which must not be `wire::MAGIC`.
    ///
    /// `None` means the device has no commands of its own, and a command
    /// carrying anything but the standard magic is refused.
    fn magic(&self) -> Option<u32> {
        None
    }

    /// Serve a command.  For one with a data phase this is where the arguments
    /// are checked and whatever `fill` needs is set up.
    fn dispatch(&mut self, cmd: &Command) -> Result;

    /// Produce the device-to-host payload, over as many calls as it takes.
    ///
    /// The command is handed back every time, and the position between calls
    /// is yours to keep — the library holds no cursor on your behalf.
    ///
    /// Defaulted, so a device with no data-carrying commands need not write it.
    /// Returning data from `dispatch` without writing this is the same
    /// half-implementation the `Ops` documentation warns about.
    fn fill(&mut self, cmd: &Command, buf: &mut [u8]) -> Result<Filled> {
        let _ = (cmd, buf);
        Err(Status::UnknownCmd)
    }
}

/// A device with no commands of its own.  The default for `Picoboot`.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoCustom;

impl Custom for NoCustom {
    fn dispatch(&mut self, cmd: &Command) -> Result {
        let _ = cmd;
        Err(Status::UnknownCmd)
    }
}
