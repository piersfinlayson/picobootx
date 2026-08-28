// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! An RP2350 as one type, for a device that wants the whole default set.

use picobootx::wire::FLASH_PAGE_SIZE;
use picobootx::{Ecc, Exclusive, Info, Ops, Reboot, Result, Target};

use crate::defaults;

/// Every default implementation in this crate, as one `Ops`.
///
/// Hand this to `Picoboot` and the device serves the whole of the protocol on
/// an RP2350's own terms.
///
/// For `GET_INFO` that means [`Info::Sys`] passed straight through to
/// `get_sys_info`, and [`Info::Uf2Target`] answered as nowhere — a UF2 reaches a
/// device by being dragged onto a mass storage drive, and this crate presents
/// none and is told of none, so it has nowhere to name.  [`Info::Uf2Status`] is
/// refused with [`picobootx::Status::InvalidArg`], since it reports a download
/// over such a drive.  A device that presents one writes both in an `Ops` of its
/// own and calls the free functions here for the rest.
///
/// [`Info::Partition`] is a constant — no partitions, no partition table
/// loaded, and all of flash unpartitioned and readable and writable by
/// everyone, which is what every RP2350 without a partition table looks like.
/// This crate reads no partition table, and a device that has one answers the
/// type itself.
/// [`Info::Uf2Target`] is a constant too — a target of -1, then the same two
/// words, so the same region reads the same way whichever question a host asks.
///
/// So `get_sys_info` is the only ROM routine `GET_INFO` reaches, and only
/// [`Info::Sys`] reaches it.  On a part that publishes no bootrom routine at
/// all, [`Info::Sys`] is refused with [`picobootx::Status::NotFound`] and the
/// other two are answered as usual.
///
/// The system information answer is written whole, in one call.  The ROM
/// routine produces it from its start and takes no offset, so this cannot hand
/// out a piece of one and has nothing to keep the rest in.  A buffer too short for the
/// whole answer is declined.
///
/// So a device taking these defaults needs a transmit FIFO that holds a whole
/// answer, [`crate::SYS_INFO_MAX_BYTES`] of it, since the room the library
/// offers is bounded by that FIFO.  A device built on a smaller one makes no
/// progress on the request.  `picobootx-embassy`'s transmit queue is 64 bytes.
///
/// A device that cannot give it that much writes `get_info` in an `Ops` of its
/// own and serves the answer in pieces, keeping it in `self` between calls, and
/// calls the free functions here for the rest.  These defaults are free
/// functions with no state of their own, which is why they answer whole.
#[derive(Clone, Copy, Debug, Default)]
pub struct Rp2350;

impl Ops for Rp2350 {
    // get_info produces a system information answer whole, so this is the room it
    // has to be offered in one call.
    const MIN_TX_CAPACITY: usize = defaults::SYS_INFO_MAX_BYTES;

    fn exclusive_access(&mut self, mode: Exclusive) -> Result {
        defaults::exclusive_access(mode)
    }

    fn exit_xip(&mut self) -> Result {
        defaults::exit_xip()
    }

    fn enter_xip(&mut self) -> Result {
        defaults::enter_xip()
    }

    fn read_prepare(&mut self, addr: u32, size: u32) -> Result {
        defaults::read_prepare(addr, size)
    }

    // read and write re-run the check their _prepare makes.  The free
    // functions behind them are unsafe and take the checked range as their
    // caller's promise, and a trait method reached through Ops carries no such
    // promise — anyone holding an Rp2350 can call it.  For a call the library
    // made this is a second look at a range already accepted, which is a
    // handful of comparisons per packet.
    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result {
        defaults::read_prepare(addr, buf.len() as u32)?;
        // SAFETY: the line above is what establishes the range.
        unsafe { defaults::read(addr, buf) }
    }

    fn write_prepare(&mut self, addr: u32, size: u32) -> Result<Target> {
        defaults::write_prepare(addr, size)
    }

    fn write(&mut self, addr: u32, buf: &[u8]) -> Result {
        defaults::write_prepare(addr, buf.len() as u32)?;
        // SAFETY: the line above is what establishes the range.
        unsafe { defaults::write(addr, buf) }
    }

    fn flash_page_write(&mut self, addr: u32, page: &[u8; FLASH_PAGE_SIZE]) -> Result {
        defaults::flash_page_write(addr, page)
    }

    fn flash_erase_prepare(&mut self, addr: u32, size: u32) -> Result {
        defaults::flash_erase_prepare(addr, size)
    }

    fn flash_erase(&mut self, addr: u32, size: u32) -> Result {
        defaults::flash_erase(addr, size)
    }

    // The two prepares below say only whether the device serves the command at
    // all, and an RP2350 serves both.  What a request asks for is judged where
    // it is acted on: a length that is not a whole number of rows by otp_read
    // and otp_write.
    fn otp_read_prepare(&mut self, row: u16, count: u16, ecc: Ecc) -> Result {
        let _ = (row, count, ecc);
        Ok(())
    }

    fn otp_read(&mut self, row: u16, ecc: Ecc, buf: &mut [u8]) -> Result {
        defaults::otp_read(row, ecc, buf)
    }

    fn otp_write_prepare(&mut self, row: u16, count: u16, ecc: Ecc) -> Result {
        let _ = (row, count, ecc);
        Ok(())
    }

    fn otp_write(&mut self, row: u16, ecc: Ecc, buf: &[u8]) -> Result {
        defaults::otp_write(row, ecc, buf)
    }

    // Every type is answered here rather than left to the trait's defaults.
    // System information reaches the ROM as it stands.  The partition table is
    // a constant, since this crate reads no table.  The UF2 target is answered
    // as nowhere and the UF2 download status is refused, both because they
    // describe a mass storage download and this crate has no drive.
    fn get_info_prepare(&mut self, info: Info, param0: u32) -> Result<u32> {
        defaults::get_info_prepare(info, param0)
    }

    fn get_info(&mut self, info: Info, param0: u32, at_word: u32, buf: &mut [u8]) -> Result<usize> {
        defaults::get_info(info, param0, at_word, buf)
    }

    fn reboot_prepare(&mut self, args: &Reboot) -> Result {
        defaults::reboot_prepare(args)
    }

    fn reboot_execute(&mut self, args: &Reboot) {
        defaults::reboot_execute(args);
    }
}
