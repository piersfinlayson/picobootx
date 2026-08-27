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
/// For `GET_INFO` that means [`Info::Sys`] and [`Info::Partition`], each passed
/// straight through to the ROM routine that answers it, and [`Info::Uf2Target`]
/// answered as nowhere — a UF2 reaches a device by being dragged onto a mass
/// storage drive, and this crate presents none and is told of none, so it has
/// nowhere to name.  [`Info::Uf2Status`] is refused with
/// [`picobootx::Status::InvalidArg`], since it reports a download over such a
/// drive.  A device that presents one writes both in an `Ops` of its own and
/// calls the free functions here for the rest.
#[derive(Clone, Copy, Debug, Default)]
pub struct Rp2350;

impl Ops for Rp2350 {
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
    // The two a ROM routine answers reach it as they stand.  The UF2 target is
    // answered as nowhere and the UF2 download status is refused, both because
    // they describe a mass storage download and this crate has no drive.
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
