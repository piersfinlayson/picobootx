// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! An RP2350 as one type, for a device that wants the whole default set.

use picobootx::wire::FLASH_PAGE_SIZE;
use picobootx::{Ecc, Exclusive, Ops, Reboot, Result, Status, Target};

use crate::defaults;

/// Every default implementation in this crate, as one `Ops`.
///
/// Hand this to `Picoboot` and the device serves the whole of the protocol on
/// an RP2350's own terms.  The free functions beside it are the same work a
/// piece at a time, for a device that answers some commands its own way — an
/// `Ops` of your own can call whichever of them you are not replacing.
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

    fn write_prepare(&mut self, addr: u32, size: u32) -> core::result::Result<Target, Status> {
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

    // The three prepares below say only whether the device serves the command
    // at all, and an RP2350 serves all three.  What a request asks for is
    // judged where it is acted on: a length that is not a whole number of rows
    // by otp_read and otp_write, and a flag the part does not carry by the
    // bootrom itself.
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

    fn get_info_sys_prepare(&mut self, flags: u32) -> Result {
        let _ = flags;
        Ok(())
    }

    fn get_info_sys(&mut self, flag: u32, buf: &mut [u8]) -> core::result::Result<usize, Status> {
        defaults::get_info_sys(flag, buf)
    }

    fn reboot_prepare(&mut self, args: &Reboot) -> Result {
        defaults::reboot_prepare(args)
    }

    fn reboot_execute(&mut self, args: &Reboot) {
        defaults::reboot_execute(args);
    }
}
