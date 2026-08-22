// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! What an RP2350 does when a host asks it something.

use picobootx::wire::{FLASH_BLOCK_SIZE, FLASH_PAGE_SIZE, FLASH_SECTOR_SIZE, INFO_MAX_WORDS};
use picobootx::{Ecc, Exclusive, Reboot, Result, Status, Target};

use crate::bootrom::{
    self, FlashExitXipFn, FlashFlushCacheFn, FlashRangeEraseFn, FlashSelectXipReadModeFn,
    OTP_ACCESS_FLAG_ECC, OTP_ACCESS_FLAG_WRITE,
};
use crate::chip;
use crate::{FLASH_BASE, FLASH_SIZE, ROM_BASE, ROM_SIZE, SRAM_BASE, SRAM_SIZE};

/// The command a bulk erase issues, where the range allows one.
const FLASH_BLOCK_ERASE_CMD: u8 = 0xd8;

/// The XIP read mode restored after an erase.  Mode 3 is quad-IO, the fastest
/// of the four the part offers.
const XIP_READ_MODE: u8 = 3;

/// How many code units a serial number and its terminator take.
const SERIAL_LEN: usize = 17;

/// An execute-in-place address as an offset into flash, which is what every
/// bootrom flash routine is addressed by.
///
/// The two callers serve an address a `_prepare` accepted and check nothing
/// themselves, so an address below the flash window reaches here only as a
/// mistake in the caller.  It wraps rather than aborting, so what an integrator
/// calling these directly gets is the same offset on any build of this crate,
/// rather than one that depends on whether their profile checks arithmetic.
fn flash_offs(addr: u32) -> u32 {
    addr.wrapping_sub(FLASH_BASE)
}

/// Whether `addr` through `addr + size` lies inside one region.
///
/// Done in 64 bits, so a range that would wrap the address space is outside
/// every region rather than inside whichever one its wrapped end lands in.
fn within(addr: u32, size: u32, base: u32, len: u32) -> bool {
    let end = u64::from(addr) + u64::from(size);
    addr >= base && end <= u64::from(base) + u64::from(len)
}

/// Take or release the device.
///
/// Every kind of exclusivity the protocol defines is agreed to, and one it does
/// not define is refused.
pub fn exclusive_access(mode: Exclusive) -> Result {
    match mode {
        Exclusive::NotExclusive | Exclusive::Exclusive | Exclusive::ExclusiveAndEject => Ok(()),
        Exclusive::Other(_) => Err(Status::InvalidArg),
    }
}

/// Leave execute-in-place.  Nothing to do on this part.
pub fn exit_xip() -> Result {
    Ok(())
}

/// Re-enter execute-in-place.  Nothing to do on this part.
pub fn enter_xip() -> Result {
    Ok(())
}

/// Whether this part can reboot as asked.
///
/// The arguments are the bootrom's to judge, so all this establishes is that
/// there is a routine to hand them to.
pub fn reboot_prepare(args: &Reboot) -> Result {
    let _ = args;
    if bootrom::reboot().is_none() {
        return Err(Status::NotFound);
    }
    Ok(())
}

/// Reboot.
///
/// The pair keeps nothing between the two calls, so the routine is looked up
/// here as well as in [`reboot_prepare`].  The check on it is made again
/// because this returns nothing: a part that does not publish the routine
/// cannot be reported from here, and the only thing left to do about it is stay
/// where we are.
pub fn reboot_execute(args: &Reboot) {
    let Some(reboot) = bootrom::reboot() else {
        return;
    };
    unsafe { reboot(args.flags, args.delay_ms, args.p0, args.p1) };
}

/// Whether this range may be read.
///
/// The whole of it has to lie inside one of the three regions the part answers
/// reads from.  A range spanning two of them is refused, since the gap between
/// them is not memory.
pub fn read_prepare(addr: u32, size: u32) -> Result {
    let valid = within(addr, size, ROM_BASE, ROM_SIZE)
        || within(addr, size, FLASH_BASE, FLASH_SIZE)
        || within(addr, size, SRAM_BASE, SRAM_SIZE);
    if !valid {
        return Err(Status::InvalidArg);
    }
    Ok(())
}

/// Fill `buf` from `addr`.
///
/// An aligned word is read as one word, since a peripheral register answers a
/// word access and not four byte accesses.
///
/// # Safety
///
/// `addr` through `addr + buf.len()` is a range this part answers, which
/// [`read_prepare`] establishes.
pub unsafe fn read(addr: u32, buf: &mut [u8]) -> Result {
    let len = buf.len();
    let src = unsafe { chip::dev_ptr(addr, len as u32) };

    if addr.is_multiple_of(4) && len == 4 {
        let word = unsafe { src.cast::<u32>().read_volatile() };
        buf.copy_from_slice(&word.to_ne_bytes());
        return Ok(());
    }

    unsafe { core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), len) };
    Ok(())
}

/// Whether this range may be written, and what kind of storage it is.
///
/// Flash is written a page at a time, so a write that does not start on a page
/// boundary is refused rather than shifted onto one.
pub fn write_prepare(addr: u32, size: u32) -> core::result::Result<Target, Status> {
    let is_sram = within(addr, size, SRAM_BASE, SRAM_SIZE);
    let is_flash = within(addr, size, FLASH_BASE, FLASH_SIZE);

    if !is_sram && !is_flash {
        return Err(Status::InvalidArg);
    }

    if is_flash {
        if !addr.is_multiple_of(FLASH_PAGE_SIZE as u32) {
            return Err(Status::BadAlignment);
        }
        return Ok(Target::Flash);
    }

    Ok(Target::Memory)
}

/// Write `buf` at `addr`.
///
/// # Safety
///
/// `addr` through `addr + buf.len()` is a range this part answers, which
/// [`write_prepare`] establishes.
pub unsafe fn write(addr: u32, buf: &[u8]) -> Result {
    let len = buf.len();
    let dst = unsafe { chip::dev_ptr(addr, len as u32) };
    unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), dst, len) };
    Ok(())
}

/// Program one flash page at `addr`.
///
/// Serves an address [`write_prepare`] called [`Target::Flash`], and checks
/// nothing itself.
pub fn flash_page_write(addr: u32, page: &[u8; FLASH_PAGE_SIZE]) -> Result {
    let Some(program) = bootrom::flash_range_program() else {
        return Err(Status::NotFound);
    };

    unsafe { program(flash_offs(addr), page.as_ptr(), FLASH_PAGE_SIZE) };
    Ok(())
}

/// Whether this range may be erased.
///
/// An erase works in whole sectors, so a range that starts or ends inside one
/// is refused rather than widened to the sectors it touches.
pub fn flash_erase_prepare(addr: u32, size: u32) -> Result {
    if !within(addr, size, FLASH_BASE, FLASH_SIZE) {
        return Err(Status::InvalidAddress);
    }

    if !addr.is_multiple_of(FLASH_SECTOR_SIZE) || !size.is_multiple_of(FLASH_SECTOR_SIZE) {
        return Err(Status::BadAlignment);
    }

    Ok(())
}

/// The part of an erase that runs while flash cannot be read.
///
/// It runs from RAM, because a function fetched from flash cannot be executed
/// while flash is answering serial commands instead of reads, and with
/// interrupts off, because a handler taken here would be fetched from that same
/// flash.
#[cfg_attr(target_os = "none", unsafe(link_section = ".ramfunc"))]
#[inline(never)]
fn erase_critical(
    exit_xip: FlashExitXipFn,
    range_erase: FlashRangeEraseFn,
    flush_cache: FlashFlushCacheFn,
    select_xip: FlashSelectXipReadModeFn,
    flash_offs: u32,
    size: u32,
    clkdiv: u8,
) {
    chip::irq_disable();

    // Leaving XIP puts the QSPI interface into serial command mode, which is
    // what an erase needs and what stops code being fetched from flash.
    unsafe { exit_xip() };

    // The bootrom decides whether the range allows a bulk erase or has to be
    // done sector by sector, which is why it is handed the block command as
    // well as the block size.
    unsafe {
        range_erase(
            flash_offs,
            size as usize,
            FLASH_BLOCK_SIZE,
            FLASH_BLOCK_ERASE_CMD,
        )
    };

    // Reads answer again from here.
    unsafe { select_xip(XIP_READ_MODE, clkdiv) };

    // What the cache holds is what was there before the erase.
    unsafe { flush_cache() };

    chip::irq_enable();
}

/// Erase the range.
///
/// Serves a range [`flash_erase_prepare`] accepted, and checks nothing itself.
///
/// Every routine the sequence needs is looked up before any of it runs, since
/// stopping part way through would leave flash out of execute-in-place.
pub fn flash_erase(addr: u32, size: u32) -> Result {
    let connect_internal_flash = bootrom::connect_internal_flash().ok_or(Status::NotFound)?;
    let exit_xip = bootrom::flash_exit_xip().ok_or(Status::NotFound)?;
    let range_erase = bootrom::flash_range_erase().ok_or(Status::NotFound)?;
    let flush_cache = bootrom::flash_flush_cache().ok_or(Status::NotFound)?;
    let select_xip = bootrom::flash_select_xip_read_mode().ok_or(Status::NotFound)?;

    unsafe { connect_internal_flash() };

    // Execute-in-place is restored on the divisor the firmware's own QMI setup
    // put in force, which is why it is read here rather than assumed.  The
    // bootrom also leaves the setup routine it discovered in boot RAM, and
    // calling that would restore exactly what the flash scan found.
    let clkdiv = chip::xip_clkdiv();

    erase_critical(
        exit_xip,
        range_erase,
        flush_cache,
        select_xip,
        flash_offs(addr),
        size,
        clkdiv,
    );

    Ok(())
}

/// Fill `buf` from consecutive OTP rows starting at `row`.
///
/// OTP is read a whole row at a time, so a length that is not a whole number of
/// rows is refused rather than rounded — rounding either way would touch a row
/// the caller did not name.
pub fn otp_read(row: u16, ecc: Ecc, buf: &mut [u8]) -> Result {
    if !(buf.len() as u32).is_multiple_of(ecc.row_size()) {
        return Err(Status::InvalidArg);
    }

    let Some(access) = bootrom::otp_access() else {
        return Err(Status::NotFound);
    };

    let mut access_row = u32::from(row);
    if ecc == Ecc::Ecc {
        access_row |= OTP_ACCESS_FLAG_ECC;
    }

    let ret = unsafe { access(buf.as_mut_ptr(), buf.len() as u32, access_row) };
    if ret < 0 {
        return Err(bootrom::status_from(ret));
    }
    Ok(())
}

/// Write consecutive OTP rows starting at `row`.
///
/// The same whole-row rule as [`otp_read`], and it matters more here: a fuse
/// blown is blown.
pub fn otp_write(row: u16, ecc: Ecc, buf: &[u8]) -> Result {
    if !(buf.len() as u32).is_multiple_of(ecc.row_size()) {
        return Err(Status::InvalidArg);
    }

    let Some(access) = bootrom::otp_access() else {
        return Err(Status::NotFound);
    };

    let mut access_row = u32::from(row) | OTP_ACCESS_FLAG_WRITE;
    if ecc == Ecc::Ecc {
        access_row |= OTP_ACCESS_FLAG_ECC;
    }

    // The bootrom takes one buffer for both directions and reads this one.
    let ret = unsafe { access(buf.as_ptr().cast_mut(), buf.len() as u32, access_row) };
    if ret < 0 {
        return Err(bootrom::status_from(ret));
    }
    Ok(())
}

/// Write the words one system information flag carries, and say how many bytes.
///
/// The bootrom answers into a temporary here and the flag's data is copied out
/// of it, so a buffer larger than the largest flag carries is refused: there
/// would be nothing to fill the rest of it from.
pub fn get_info_sys(flag: u32, buf: &mut [u8]) -> core::result::Result<usize, Status> {
    let Some(get_sys_info) = bootrom::get_sys_info() else {
        return Err(Status::NotFound);
    };

    if buf.len() > INFO_MAX_WORDS * size_of::<u32>() {
        return Err(Status::UnknownError);
    }

    // A word for the flags the bootrom answered, then the data itself.
    let mut tmp = [0u32; INFO_MAX_WORDS + 1];
    let words = (buf.len() / size_of::<u32>()) as u32;

    let ret = unsafe { get_sys_info(tmp.as_mut_ptr(), words + 1, flag) };
    if ret < 0 {
        return Err(bootrom::status_from(ret));
    }

    // The bootrom says which of the flags it was asked for it answered, and a
    // flag missing from that is one this part does not carry.
    if (tmp[0] & flag) == 0 {
        return Err(Status::InvalidArg);
    }

    for (dst, src) in buf.chunks_mut(size_of::<u32>()).zip(&tmp[1..]) {
        let bytes = src.to_ne_bytes();
        dst.copy_from_slice(&bytes[..dst.len()]);
    }
    Ok(buf.len())
}

/// Write this part's identifier into `buf` as UTF-16, for a USB string
/// descriptor, and say how many code units that took.
///
/// Sixteen hex digits and a terminator, most significant word first.  Zero when
/// the identifier cannot be read, since half a serial number in a descriptor is
/// worse than none.
pub fn serial(buf: &mut [u16]) -> usize {
    if buf.len() < SERIAL_LEN {
        return 0;
    }

    let Some(access) = bootrom::otp_access() else {
        return 0;
    };

    // The identifier is four rows read through the error-correcting view, which
    // is two bytes of each.
    let mut chipid = [0u8; 8];
    let ret = unsafe {
        access(
            chipid.as_mut_ptr(),
            chipid.len() as u32,
            OTP_ACCESS_FLAG_ECC,
        )
    };
    if ret != 0 {
        return 0;
    }

    const HEX: [u8; 16] = *b"0123456789ABCDEF";
    let mut pos = 0;
    for word in chipid.as_chunks::<2>().0.iter().rev() {
        let value = u16::from_le_bytes(*word);
        for nibble in (0..4).rev() {
            buf[pos] = u16::from(HEX[((value >> (nibble * 4)) & 0xf) as usize]);
            pos += 1;
        }
    }
    buf[pos] = 0;

    pos
}
