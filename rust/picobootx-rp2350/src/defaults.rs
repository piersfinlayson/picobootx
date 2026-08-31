// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! What an RP2350 does when a host asks it something.

use picobootx::wire::{FLASH_BLOCK_SIZE, FLASH_PAGE_SIZE, FLASH_SECTOR_SIZE};
use picobootx::{Ecc, Exclusive, Info, Reboot, Result, Status, Target};

use crate::bootrom::{
    self, ConnectInternalFlashFn, FlashExitXipFn, FlashFlushCacheFn, FlashRangeEraseFn,
    FlashRangeProgramFn, FlashSelectXipReadModeFn, OTP_ACCESS_FLAG_ECC, OTP_ACCESS_FLAG_WRITE,
};
use crate::chip;
use crate::{FLASH_BASE, FLASH_SIZE, ROM_BASE, ROM_SIZE, SRAM_BASE, SRAM_SIZE};

/// The command a bulk erase issues, where the range allows one.
const FLASH_BLOCK_ERASE_CMD: u8 = 0xd8;

/// The XIP read mode restored after an erase.  Mode 3 is quad-IO, the fastest
/// of the four the part offers.
const XIP_READ_MODE: u8 = 3;

/// How many code units [`serial`] needs: sixteen hex digits and a terminator.
///
/// The buffer handed to it has to be at least this long.
pub const SERIAL_LEN: usize = 17;

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
///
/// # Errors
///
/// [`Status::InvalidArg`] for a mode the protocol does not define.
pub fn exclusive_access(mode: Exclusive) -> Result {
    match mode {
        Exclusive::NotExclusive | Exclusive::Exclusive | Exclusive::ExclusiveAndEject => Ok(()),
        Exclusive::Other(_) => Err(Status::InvalidArg),
    }
}

/// Leave execute-in-place.  Nothing to do on this part.
///
/// # Errors
///
/// None.  It returns a `Result` because the operation it serves does.
pub fn exit_xip() -> Result {
    Ok(())
}

/// Re-enter execute-in-place.  Nothing to do on this part.
///
/// # Errors
///
/// None.  It returns a `Result` because the operation it serves does.
pub fn enter_xip() -> Result {
    Ok(())
}

/// Whether this part can reboot as asked.
///
/// The arguments are the bootrom's to judge, so all this establishes is that
/// there is a routine to hand them to.
///
/// # Errors
///
/// [`Status::NotFound`] when the part publishes no reboot routine.
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
///
/// # Errors
///
/// [`Status::InvalidArg`] for a range that is not inside one region.
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
/// # Errors
///
/// None.  The range was established by [`read_prepare`], which is this
/// function's safety condition rather than something it checks.
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
///
/// # Errors
///
/// [`Status::InvalidArg`] for a range that is neither SRAM nor flash, and
/// [`Status::BadAlignment`] for a flash range not starting on a page.
pub fn write_prepare(addr: u32, size: u32) -> Result<Target> {
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
/// # Errors
///
/// None.  The range was established by [`write_prepare`], which is this
/// function's safety condition rather than something it checks.
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
/// Serves an address [`write_prepare`] called [`Target::Flash`], and checks the
/// address no further itself.
///
/// The boot ROM's programming routine talks to flash over its serial interface,
/// which means execute-in-place has to be left first and put back afterwards —
/// the same bracket [`flash_erase`] needs, for the same reason, and the part of
/// it that runs while flash cannot be read is in RAM with interrupts off.  A
/// program issued without that bracket writes nothing and reports success,
/// which a host reads as an image successfully written onto blank flash.
///
/// `page` is read by the boot ROM while flash is unreadable, so it has to be
/// somewhere that still answers then.  That is the caller's to arrange and is
/// not checked here — which memory a device has, and which of it is free, is
/// the caller's business rather than this crate's.
///
/// # Errors
///
/// [`Status::NotFound`] when the part publishes none of the five bootrom
/// routines the sequence needs.  On a build for the part,
/// [`Status::PreconditionNotMet`] when the routine that runs while flash is
/// unreadable is not resident in RAM.
pub fn flash_page_write(addr: u32, page: &[u8; FLASH_PAGE_SIZE]) -> Result {
    #[cfg(target_os = "none")]
    if !ramfunc_resident(program_critical as *const ()) {
        return Err(Status::PreconditionNotMet);
    }

    let connect_internal_flash = bootrom::connect_internal_flash().ok_or(Status::NotFound)?;
    let exit_xip = bootrom::flash_exit_xip().ok_or(Status::NotFound)?;
    let range_program = bootrom::flash_range_program().ok_or(Status::NotFound)?;
    let flush_cache = bootrom::flash_flush_cache().ok_or(Status::NotFound)?;
    let select_xip = bootrom::flash_select_xip_read_mode().ok_or(Status::NotFound)?;

    program_critical(
        connect_internal_flash,
        exit_xip,
        range_program,
        flush_cache,
        select_xip,
        flash_offs(addr),
        page.as_ptr(),
    );
    Ok(())
}

/// Whether this range may be erased.
///
/// An erase works in whole sectors, so a range that starts or ends inside one
/// is refused rather than widened to the sectors it touches.
///
/// # Errors
///
/// [`Status::InvalidAddress`] for a range outside flash, and
/// [`Status::BadAlignment`] for one that does not start and end on a sector.
pub fn flash_erase_prepare(addr: u32, size: u32) -> Result {
    if !within(addr, size, FLASH_BASE, FLASH_SIZE) {
        return Err(Status::InvalidAddress);
    }

    if !addr.is_multiple_of(FLASH_SECTOR_SIZE) || !size.is_multiple_of(FLASH_SECTOR_SIZE) {
        return Err(Status::BadAlignment);
    }

    Ok(())
}

/// Placed with [`erase_critical`], and read before it is called.
///
/// An address in SRAM says the linker script put the section in RAM.  It does
/// not say the bytes arrived, since a script can place a section in RAM and
/// leave the startup with nothing that copies it.  SRAM does not power up
/// holding this word, so reading it back says a copy ran and reached this
/// word.
///
/// It says no more than that.  Where in the section the word sits is decided
/// by the order the linker takes the input sections in, which nothing here or
/// in `picobootx.x` states, so a copy that stopped short of the section's end
/// may or may not have stopped short of this.  Whether the copy covers the
/// whole section is a property of the link, and `ci/check-ramfunc.sh` is what
/// asks it of one.
#[cfg(target_os = "none")]
#[unsafe(link_section = ".ramfunc")]
static RAMFUNC_MARK: u32 = RAMFUNC_MARK_VALUE;

/// What [`RAMFUNC_MARK`] holds once it has been copied.
#[cfg(target_os = "none")]
const RAMFUNC_MARK_VALUE: u32 = 0x7062_785f;

/// Whether a routine that runs while flash is unreadable can be run.
///
/// It has to be resident in SRAM and it has to hold what was linked, and
/// neither follows from the `.ramfunc` section name alone — that names a
/// section, and the consumer's linker script and startup are what decide where
/// the section goes and whether its bytes are carried there.  A project that
/// has not done both links clean, and what an erase or a program then jumps
/// into is either flash that has stopped answering or RAM nothing filled, so
/// this is checked while flash still answers rather than discovered by a fetch
/// that never completes.
#[cfg(target_os = "none")]
fn ramfunc_resident(routine: *const ()) -> bool {
    let addr = routine as usize;
    let sram = (SRAM_BASE as usize)..(SRAM_BASE as usize + SRAM_SIZE as usize);
    if !sram.contains(&addr) {
        return false;
    }

    // SAFETY: the address is this crate's own static, aligned and initialised
    // by the link.  Volatile because what is wanted is what SRAM holds now,
    // and the value the compiler knows was linked is the answer only once the
    // startup copy has put it there.
    let mark = unsafe { core::ptr::read_volatile(&raw const RAMFUNC_MARK) };
    mark == RAMFUNC_MARK_VALUE
}

/// The part of an erase that runs while flash cannot be read.
///
/// It runs from RAM, because a function fetched from flash cannot be executed
/// while flash is answering serial commands instead of reads, and with
/// interrupts off, because a handler taken here would be fetched from that same
/// flash.
///
/// `.ramfunc` is a name, not a placement.  What puts the section in RAM and
/// carries its bytes there is the consumer's linker script and startup —
/// `picobootx.x`, which this crate ships, is one that does.
#[cfg_attr(target_os = "none", unsafe(link_section = ".ramfunc"))]
#[inline(never)]
fn erase_critical(
    connect_internal_flash: ConnectInternalFlashFn,
    exit_xip: FlashExitXipFn,
    range_erase: FlashRangeEraseFn,
    flush_cache: FlashFlushCacheFn,
    select_xip: FlashSelectXipReadModeFn,
    flash_offs: u32,
    size: u32,
) {
    chip::irq_disable();

    // Connecting the flash leaves execute-in-place no longer guaranteed, so it
    // and everything after it runs from RAM with interrupts already down.  The
    // divisor is read here for the same reason.
    unsafe { connect_internal_flash() };
    let clkdiv = chip::xip_clkdiv();

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

/// The part of a program that runs while flash cannot be read.
///
/// Everything [`erase_critical`] says applies here for the same reasons: it
/// runs from RAM, because a function fetched from flash cannot be executed
/// while flash is answering serial commands instead of reads, and with
/// interrupts off, because a handler taken here would be fetched from that same
/// flash.
///
/// `data` is one page, read while flash is unreadable, so it has to point into
/// RAM.  [`flash_page_write`] is what establishes that.
#[cfg_attr(target_os = "none", unsafe(link_section = ".ramfunc"))]
#[inline(never)]
fn program_critical(
    connect_internal_flash: ConnectInternalFlashFn,
    exit_xip: FlashExitXipFn,
    range_program: FlashRangeProgramFn,
    flush_cache: FlashFlushCacheFn,
    select_xip: FlashSelectXipReadModeFn,
    flash_offs: u32,
    data: *const u8,
) {
    chip::irq_disable();

    // Connecting the flash leaves execute-in-place no longer guaranteed, so it
    // and everything after it runs from RAM with interrupts already down.  The
    // divisor is read here for the same reason.
    unsafe { connect_internal_flash() };
    let clkdiv = chip::xip_clkdiv();

    // Leaving XIP puts the QSPI interface into serial command mode, which is
    // what a program needs and what stops code being fetched from flash.
    unsafe { exit_xip() };

    // One page, which is the unit the protocol writes flash in and the only
    // length this is ever asked for.
    unsafe { range_program(flash_offs, data, FLASH_PAGE_SIZE) };

    // Reads answer again from here.
    unsafe { select_xip(XIP_READ_MODE, clkdiv) };

    // What the cache holds is what was there before the program.
    unsafe { flush_cache() };

    chip::irq_enable();
}

/// Erase the range.
///
/// Serves a range [`flash_erase_prepare`] accepted, and checks nothing itself.
///
/// Every routine the sequence needs is looked up before any of it runs, since
/// stopping part way through would leave flash out of execute-in-place.  For
/// the same reason the part that runs while flash is unreadable is checked to
/// be in RAM first — see [the crate documentation](crate) for the linker
/// script and startup that put it there.
///
/// # Errors
///
/// [`Status::NotFound`] when the part publishes none of the five bootrom
/// routines the sequence needs.  On a build for the part,
/// [`Status::PreconditionNotMet`] when the routine that runs while flash is
/// unreadable is not resident in RAM.
pub fn flash_erase(addr: u32, size: u32) -> Result {
    #[cfg(target_os = "none")]
    if !ramfunc_resident(erase_critical as *const ()) {
        return Err(Status::PreconditionNotMet);
    }

    let connect_internal_flash = bootrom::connect_internal_flash().ok_or(Status::NotFound)?;
    let exit_xip = bootrom::flash_exit_xip().ok_or(Status::NotFound)?;
    let range_erase = bootrom::flash_range_erase().ok_or(Status::NotFound)?;
    let flush_cache = bootrom::flash_flush_cache().ok_or(Status::NotFound)?;
    let select_xip = bootrom::flash_select_xip_read_mode().ok_or(Status::NotFound)?;

    // Execute-in-place is restored on the divisor the firmware's own QMI setup
    // put in force, read inside the critical section rather than assumed.  The
    // bootrom also leaves the setup routine it discovered in boot RAM, and
    // calling that would restore exactly what the flash scan found.
    erase_critical(
        connect_internal_flash,
        exit_xip,
        range_erase,
        flush_cache,
        select_xip,
        flash_offs(addr),
        size,
    );

    Ok(())
}

/// Fill `buf` from consecutive OTP rows starting at `row`.
///
/// OTP is read a whole row at a time, so a length that is not a whole number of
/// rows is refused rather than rounded — rounding either way would touch a row
/// the caller did not name.
///
/// # Errors
///
/// [`Status::InvalidArg`] for a length that is not whole rows,
/// [`Status::NotFound`] when the part publishes no OTP routine, and whatever
/// [`bootrom::status_from`] makes of a refusal by that routine.
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
///
/// # Errors
///
/// The same as [`otp_read`]: [`Status::InvalidArg`] for a length that is not
/// whole rows, [`Status::NotFound`] when the part publishes no OTP routine, and
/// whatever [`bootrom::status_from`] makes of a refusal by that routine.
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

/// PT_INFO, in `get_partition_table_info`'s `flags_and_partition`.  Its answer is
/// the flags word, a word of partition counts, and two words describing the
/// unpartitioned space.
const PT_INFO_FLAG: u32 = 0x0001;
const PT_INFO_WORDS: usize = 4;

/// The rest of the partition table flags.  The first four ask for a field of a
/// partition rather than of the table.  `SINGLE` narrows those four to the one
/// partition named in the top byte of `flags_and_partition`.
const PT_LOCATION_AND_FLAGS: u32 = 0x0010;
const PT_ID: u32 = 0x0020;
const PT_FAMILY_IDS: u32 = 0x0040;
const PT_NAME: u32 = 0x0080;
const PT_SINGLE: u32 = 0x8000;

/// The flags this crate answers.  A flag outside the set is dropped from the
/// answer, as `get_partition_table_info` drops one the part cannot answer.
///
/// `SINGLE` is answered like the rest.  The boot ROM echoes it whenever it is
/// asked for, including on its own with nothing to answer, and narrowing to one
/// partition is honoured by a device with none.  Masking with this also drops
/// the partition number, which the boot ROM leaves out of the answered-flags
/// word too.  Asked about partition 3 with `0x0300_8030` it answers `0x8030`.
const PT_ANSWERED_FLAGS: u32 =
    PT_INFO_FLAG | PT_LOCATION_AND_FLAGS | PT_ID | PT_FAMILY_IDS | PT_NAME | PT_SINGLE;

/// Where the unpartitioned space of an RP2350 with no partition table is, and
/// who may touch it.
///
/// First sector 0 and last sector 8191, which is every bit of the 13-bit field
/// and the largest range it can express, with all six permissions set — secure,
/// non-secure and NS boot may each read and write.  All of flash, unpartitioned,
/// open to everyone, which is what having no partition table means and is the
/// same on every RP2350.
const UNPARTITIONED_LOCATION: u32 = 0xffff_e000;

/// Which UF2 families that unpartitioned space accepts.
///
/// The same six permissions, and every family bit clear.  A family bit says a
/// UF2 of that family would be accepted, and a UF2 reaches a device by being
/// dragged onto a mass storage drive.  The bootrom sets four of them because
/// BOOTSEL mode presents such a drive.  A device running picobootx is running
/// its application and presents none, so it accepts no family, and the RP2040
/// family was never this part's.
const UNPARTITIONED_FLAGS: u32 = 0xfc00_0000;

/// Word 0 of a UF2 target answer, saying the family goes nowhere.
const UF2_TARGET_NONE: u32 = 0xffff_ffff;

/// The words of an answer from `at_word` on, copied into the caller's buffer,
/// and how many bytes that was.
///
/// Whole words only, so a `buf` that is not a whole number of them has the
/// remainder left alone.
fn copy_answer(answer: &[u32], at_word: u32, buf: &mut [u8]) -> usize {
    let at = at_word as usize;
    if at >= answer.len() {
        return 0;
    }
    let left = &answer[at..];
    let n = core::cmp::min(left.len() * 4, buf.len() & !3);
    for (dst, word) in buf[..n].chunks_mut(4).zip(left) {
        dst.copy_from_slice(&word.to_le_bytes());
    }
    n
}

/// The words `get_sys_info` answers each flag with.  `NONCE` is the flag the
/// datasheet marks unsupported, and it carries none.
///
/// These size a bound and nothing else.  Nothing here consults them to produce
/// or to measure an answer — [`get_info_prepare`] asks the ROM about one flag at
/// a time and adds up what it reports, so a flag a part answers differently, or
/// at all, is counted from the part rather than from here.
const SYS_CHIP_INFO_WORDS: usize = 3;
const SYS_CRITICAL_WORDS: usize = 1;
const SYS_CPU_INFO_WORDS: usize = 1;
const SYS_FLASH_DEV_INFO_WORDS: usize = 1;
const SYS_BOOT_RANDOM_WORDS: usize = 4;
const SYS_NONCE_WORDS: usize = 0;
const SYS_BOOT_INFO_WORDS: usize = 4;

/// The longest system information answer, in bytes — the flags word, then
/// every flag's data.
///
/// A host asking for all of them gets this, and it is the room [`get_info`]
/// needs in a single call — it produces a system information answer whole and
/// declines a buffer too short for it.  A transport whose transmit FIFO holds
/// less than this can never offer enough, so a device built on one makes no
/// progress on the request.
pub const SYS_INFO_MAX_BYTES: usize = (1
    + SYS_CHIP_INFO_WORDS
    + SYS_CRITICAL_WORDS
    + SYS_CPU_INFO_WORDS
    + SYS_FLASH_DEV_INFO_WORDS
    + SYS_BOOT_RANDOM_WORDS
    + SYS_NONCE_WORDS
    + SYS_BOOT_INFO_WORDS)
    * 4;

/// How many words this part's system information answer will be, without
/// producing any of it.
///
/// `get_sys_info` answers a single flag as the flags word followed by that
/// flag's data, so a probe of one flag returns one more word than the flag
/// contributes, and one word for a flag the part does not answer.  Summing the
/// contributions over the flags asked for gives the length of the answer to all
/// of them, with the ROM saying how long each is — so a flag a future part adds
/// is counted here with no change to this.
///
/// `tmp` holds one flag's data at a time.  The widest flag the datasheet defines
/// is four words.
fn sys_info_words(param0: u32) -> Result<u32> {
    let Some(f) = bootrom::get_sys_info() else {
        return Err(Status::NotFound);
    };

    let mut tmp = [0u32; 8];
    let mut total = 1; // the flags word, which every answer carries

    for bit in 0..u32::BITS {
        let flag = 1u32 << bit;
        if param0 & flag == 0 {
            continue;
        }
        let ret = unsafe { f(tmp.as_mut_ptr(), tmp.len() as u32, flag) };
        if ret < 0 {
            return Err(bootrom::status_from(ret));
        }
        if ret > 1 {
            total += ret as u32 - 1;
        }
    }

    Ok(total)
}

/// The system information answer, written where the caller asked for it, and how
/// many bytes that was.
///
/// The ROM produces the whole answer or none of it, and takes no offset, so this
/// serves it in one call from its first word and needs no buffer of its own.
/// `buf` is word aligned, which is what the library promises a fill and what
/// lets the ROM write through it.
///
/// Room too small for the whole answer is declined rather than refused.
/// Nothing is written, and the caller offers more next time.  So the transmit FIFO has
/// to hold [`SYS_INFO_MAX_BYTES`] — see [`crate::Rp2350`] for what a FIFO that
/// does not means.
fn sys_info_fill(param0: u32, at_word: u32, buf: &mut [u8]) -> Result<usize> {
    // The answer goes in one call, so there is no later window to serve.
    if at_word != 0 {
        return Ok(0);
    }

    let Some(f) = bootrom::get_sys_info() else {
        return Err(Status::NotFound);
    };

    let words = buf.len() / 4;
    // SAFETY: the ROM writes at most that many whole words into buf, and the
    // library hands a fill a word aligned buffer.
    let ret = unsafe { f(buf.as_mut_ptr().cast::<u32>(), words as u32, param0) };
    if ret == bootrom::ERROR_BUFFER_TOO_SMALL {
        // Not room for the whole answer, and the ROM writes none of it rather
        // than what fits.
        return Ok(0);
    }
    if ret < 0 {
        return Err(bootrom::status_from(ret));
    }
    Ok(ret as usize * 4)
}

/// The partition table answer, in `answer`, and how many words it is.
///
/// A constant.  This crate does not read a partition table, so this says the one
/// thing true of every RP2350 without one — no partitions, no table loaded,
/// and all of flash unpartitioned and open to everyone.  A device that does have a
/// partition table answers [`Info::Partition`] itself rather than taking this
/// default.
///
/// A per-partition field — location and flags, id, family ids, name —
/// contributes no words, there being no partitions, and the flags word still
/// names it as answered.
fn partition_answer(param0: u32, answer: &mut [u32; PT_INFO_WORDS]) -> usize {
    answer[0] = param0 & PT_ANSWERED_FLAGS;
    if param0 & PT_INFO_FLAG == 0 {
        return 1;
    }
    answer[1] = 0; // no partitions, and no partition table loaded
    answer[2] = UNPARTITIONED_LOCATION;
    answer[3] = UNPARTITIONED_FLAGS;
    PT_INFO_WORDS
}

/// Where a UF2 of some family would be downloaded to, in three words.
///
/// Nowhere.  A UF2 is dragged onto a mass storage drive, as it is onto the one
/// BOOTSEL mode presents.  This crate presents none and is told of none, so
/// there is nowhere for it to name, whatever family was asked about — which is
/// why this takes no family id.  A device that does present such a drive answers
/// this itself rather than taking this default.
///
/// The two words behind the target are the unpartitioned space, and they are the
/// two [`Info::Partition`] reports for it.  The datasheet makes them the target
/// partition's own location "if the partition number is not -1", and it is -1,
/// so they describe a download that cannot happen — which leaves agreeing with
/// what this device says about that region when asked directly as the one thing
/// they can usefully do.  Reading them from the ROM instead made the same region
/// come back two ways, differing in the accept-family bits this device has no
/// drive to accept a family onto.
///
/// All three go, short of anything to say with the last two — picotool checks
/// the reply is three words before it reads the first.
const UF2_TARGET_WORDS: usize = 3;

fn uf2_target_answer() -> [u32; UF2_TARGET_WORDS] {
    [UF2_TARGET_NONE, UNPARTITIONED_LOCATION, UNPARTITIONED_FLAGS]
}

/// How many words this part's answer to an information request will be.
///
/// # Errors
///
/// [`Status::InvalidArg`] for a type this crate does not answer,
/// [`Status::NotFound`] when the part publishes no `get_sys_info`, and whatever
/// [`bootrom::status_from`] makes of a refusal by it.  [`Info::Partition`] and
/// [`Info::Uf2Target`] are constants and reach no ROM routine, so neither can
/// fail.
pub fn get_info_prepare(info: Info, param0: u32) -> Result<u32> {
    match info {
        Info::Sys => sys_info_words(param0),
        Info::Partition => {
            let mut answer = [0u32; PT_INFO_WORDS];
            Ok(partition_answer(param0, &mut answer) as u32)
        }
        Info::Uf2Target => Ok(UF2_TARGET_WORDS as u32),
        // Info::Uf2Status reports a download in progress over the drive BOOTSEL
        // mode presents, and this crate has none to report on.
        _ => Err(Status::InvalidArg),
    }
}

/// Produce that answer, from `at_word` onwards, and say how many bytes were
/// written.
///
/// Whole words only, so a `buf` that is not a whole number of them has the
/// remainder left alone.
///
/// Nothing is kept between calls.  Only system information comes from the ROM,
/// its routine takes no offset, so what it produces is produced again — and
/// every system information flag reads a value fixed for the life of the boot.
/// The other two types are constants, so a repeat is the same arithmetic twice.
///
/// The system information answer goes in a single call, and a `buf` too short
/// for the whole of it — shorter than [`SYS_INFO_MAX_BYTES`] where every flag
/// was asked for — is declined with `Ok(0)`, asking to be called again with
/// more.  `buf` must be word aligned, which is what the library promises a fill.
/// [`crate::Rp2350`] says what that asks of a transmit FIFO, and what a device
/// that cannot meet it does instead.
///
/// # Errors
///
/// As [`get_info_prepare`].
pub fn get_info(info: Info, param0: u32, at_word: u32, buf: &mut [u8]) -> Result<usize> {
    match info {
        Info::Sys => sys_info_fill(param0, at_word, buf),
        Info::Partition => {
            let mut answer = [0u32; PT_INFO_WORDS];
            let filled = partition_answer(param0, &mut answer);
            Ok(copy_answer(&answer[..filled], at_word, buf))
        }
        Info::Uf2Target => Ok(copy_answer(&uf2_target_answer(), at_word, buf)),
        _ => Err(Status::InvalidArg),
    }
}

/// Write this part's identifier into `buf` as UTF-16, for a USB string
/// descriptor, and say how many code units it takes.
///
/// Sixteen hex digits, most significant word first, followed by a terminator.
/// The count returned is the digits, so the string is `buf[..n]` and the
/// terminator sits after it.  `buf` has to hold at least [`SERIAL_LEN`].
///
/// Nothing is written unless all of it is, since half a serial number in a
/// descriptor is worse than none.
///
/// # Errors
///
/// [`Status::BufferTooSmall`] for a buffer shorter than [`SERIAL_LEN`],
/// [`Status::NotFound`] when the part publishes no OTP routine, and whatever
/// [`bootrom::status_from`] makes of a refusal by that routine.
pub fn serial(buf: &mut [u16]) -> Result<usize> {
    if buf.len() < SERIAL_LEN {
        return Err(Status::BufferTooSmall);
    }

    let Some(access) = bootrom::otp_access() else {
        return Err(Status::NotFound);
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
        return Err(bootrom::status_from(ret));
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

    Ok(pos)
}
