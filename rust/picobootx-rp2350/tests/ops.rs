// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! `Rp2350`, the whole default set as one `Ops`.
//!
//! The conformance suite reaches these implementations as the C ABI presents
//! them: a `picoboot_ops_t` of function pointers, filled from the
//! `picoboot_default_*` names.  That table is a different route to the same
//! free functions, and it never holds an `Rp2350`, so nothing there says
//! whether the trait implementation routes each command to the part's own
//! answer or leaves it at the trait's refusing default.  That is what this
//! asks, one command at a time, by showing an answer only the part gives.
//!
//! The free functions themselves are the suite's to test, and it does, with one
//! exception: the library asks the part's information routine twice for one
//! request, once for the answer's length and again for the answer, and no host
//! can make the second answer differ from the first.  What
//! stands in for the chip here is a recorder, not a model of a part: it says
//! which seam was reached and with what, and its bootrom publishes one routine
//! so that a lookup which finds something and a lookup which does not are both
//! reachable.

use core::cell::UnsafeCell;
use core::ffi::c_int;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use picobootx::{Ecc, Exclusive, Info, Ops, Reboot, Status, Target};
use picobootx_rp2350::{
    FLASH_BASE, Rp2350, SRAM_BASE,
    bootrom::{GetSysInfoFn, RebootFn},
};

/// How much of SRAM and of flash the stand-in answers for, from each base.
const MAPPED: usize = 0x200;

/// One flash page, which is the unit `flash_page_write` takes.
const PAGE: usize = 256;

// ---------------------------------------------------------------------------
// What stands in for the chip
// ---------------------------------------------------------------------------

/// The memory the two mapped windows are served out of: SRAM's window first,
/// then flash's.
///
/// Reached through raw pointers by the code under test, which is the whole
/// point of the seam, so it is a cell rather than an array of atomics.  What
/// keeps one test's accesses out of another's is `CHIP`, which every test here
/// holds for its whole run.
struct Memory(UnsafeCell<[u8; MAPPED * 2]>);

// SAFETY: every access goes through a `dev_ptr` call made while the caller
// holds `CHIP`, so there is one at a time.
unsafe impl Sync for Memory {}

static MEMORY: Memory = Memory(UnsafeCell::new([0; MAPPED * 2]));

/// Taken for the whole of every test, so the recorder below answers about one
/// test at a time.
static CHIP: Mutex<()> = Mutex::new(());

/// How many times an address was turned into a pointer.  A refusal that never
/// reaches the chip is a refusal this can see.
static DEV_PTR_CALLS: AtomicUsize = AtomicUsize::new(0);

/// Whether the stand-in bootrom publishes its reboot routine.
static PUBLISH_REBOOT: AtomicBool = AtomicBool::new(true);

/// What the reboot routine was called with, if it was.
static REBOOTED: Mutex<Option<[u32; 4]>> = Mutex::new(None);

/// Whether the stand-in bootrom publishes a system information routine, and
/// how many words that routine answers when it does.
///
/// The count is settable between calls because the library asks the routine
/// twice for one request — once for the answer's length and again for the
/// answer — and a part whose second answer is shorter than its first is what
/// the guard in `get_info` is there for.
static PUBLISH_SYS_INFO: AtomicBool = AtomicBool::new(false);
static SYS_INFO_WORDS: AtomicUsize = AtomicUsize::new(0);

/// Take the chip, and put it back the way a part comes out of its packaging.
fn chip() -> MutexGuard<'static, ()> {
    let guard = CHIP.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    DEV_PTR_CALLS.store(0, Ordering::SeqCst);
    PUBLISH_REBOOT.store(true, Ordering::SeqCst);
    PUBLISH_SYS_INFO.store(false, Ordering::SeqCst);
    SYS_INFO_WORDS.store(0, Ordering::SeqCst);
    *REBOOTED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    // SAFETY: the guard above is what says nothing else is using this.
    unsafe { (*MEMORY.0.get()).fill(0) };
    guard
}

/// The mapped bytes, as a test reads and writes them.
///
/// # Safety
///
/// The caller holds `CHIP`.
unsafe fn memory() -> &'static mut [u8; MAPPED * 2] {
    // SAFETY: the caller's guard is what says nothing else is using this.
    unsafe { &mut *MEMORY.0.get() }
}

/// Where a device address lands in the mapped bytes, or `None`.
fn mapped(addr: u32, len: u32) -> Option<usize> {
    let len = len as usize;
    for (base, offset) in [(SRAM_BASE, 0), (FLASH_BASE, MAPPED)] {
        if addr >= base && ((addr - base) as usize) + len <= MAPPED {
            return Some(offset + (addr - base) as usize);
        }
    }
    None
}

extern "C" fn reboot_stub(flags: u32, delay_ms: u32, p0: u32, p1: u32) -> c_int {
    *REBOOTED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some([flags, delay_ms, p0, p1]);
    0
}

/// The word the stand-in information routine puts at one index.  Distinct per
/// index, so a test can say which word of the answer it is looking at rather
/// than only how many came back.
fn info_word(at: usize) -> u32 {
    0x5100_0000 | at as u32
}

/// One word of what a fill wrote, as the wire carries it.
fn word(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(buf[at * 4..at * 4 + 4].try_into().expect("four bytes"))
}

/// Publish the information routine, answering this many words from now on.
fn publish_sys_info(words: usize) {
    SYS_INFO_WORDS.store(words, Ordering::SeqCst);
    PUBLISH_SYS_INFO.store(true, Ordering::SeqCst);
}

extern "C" fn get_sys_info_stub(out: *mut u32, out_words: u32, _flags: u32) -> c_int {
    let words = SYS_INFO_WORDS.load(Ordering::SeqCst);
    assert!(
        words <= out_words as usize,
        "the routine was offered {out_words} words and asked to write {words}"
    );
    for at in 0..words {
        // SAFETY: the assertion above is what says out has room for this.
        unsafe { out.add(at).write(info_word(at)) };
    }
    c_int::try_from(words).expect("a word count that fits a return code")
}

/// The bootrom code two characters make, as `bootrom::lookup` assembles it.
fn code(a: u8, b: u8) -> u32 {
    (u32::from(b) << 8) | u32::from(a)
}

#[unsafe(no_mangle)]
extern "C" fn picobootx_host_test_bootrom_lookup(asked: u32, mask: u32) -> *const () {
    // The Arm secure entry, which is the only one these implementations ask
    // for.  A mask of anything else is a change in the caller, not a lookup.
    assert_eq!(
        mask, 0x0004,
        "the bootrom was asked for a non-Arm-secure entry"
    );

    if asked == code(b'R', b'B') && PUBLISH_REBOOT.load(Ordering::SeqCst) {
        let f: RebootFn = reboot_stub;
        return f as *const ();
    }
    if asked == code(b'G', b'S') && PUBLISH_SYS_INFO.load(Ordering::SeqCst) {
        let f: GetSysInfoFn = get_sys_info_stub;
        return f as *const ();
    }
    core::ptr::null()
}

#[unsafe(no_mangle)]
extern "C" fn picobootx_host_test_xip_clkdiv() -> u8 {
    4
}

#[unsafe(no_mangle)]
extern "C" fn picobootx_host_test_irq_disable() {}

#[unsafe(no_mangle)]
extern "C" fn picobootx_host_test_irq_enable() {}

#[unsafe(no_mangle)]
extern "C" fn picobootx_host_test_dev_ptr(addr: u32, len: u32) -> *mut u8 {
    DEV_PTR_CALLS.fetch_add(1, Ordering::SeqCst);
    let Some(offset) = mapped(addr, len) else {
        // An address the stand-in cannot map means the range check let
        // something through, which is the thing these tests are about.  Saying
        // so beats handing back a pointer to somewhere plausible.
        panic!("nothing answers {len} bytes at {addr:#010x}");
    };
    // SAFETY: the caller of the code under test holds CHIP.
    unsafe { memory()[offset..].as_mut_ptr() }
}

fn dev_ptr_calls() -> usize {
    DEV_PTR_CALLS.load(Ordering::SeqCst)
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

#[test]
fn the_part_takes_a_view_on_what_exclusivity_it_was_asked_for() {
    let _chip = chip();
    let mut d = Rp2350;

    assert_eq!(d.exclusive_access(Exclusive::NotExclusive), Ok(()));
    assert_eq!(d.exclusive_access(Exclusive::Exclusive), Ok(()));
    assert_eq!(d.exclusive_access(Exclusive::ExclusiveAndEject), Ok(()));

    // A device that leaves the method to its default agrees to this too.  The
    // part does not, and that is how this says the trait implementation
    // reached the part's answer.
    assert_eq!(
        d.exclusive_access(Exclusive::Other(9)),
        Err(Status::InvalidArg)
    );

    // Execute-in-place needs nothing done on this part.
    assert_eq!(d.exit_xip(), Ok(()));
    assert_eq!(d.enter_xip(), Ok(()));
}

#[test]
fn a_read_reaching_the_part_through_the_trait_is_range_checked_again() {
    let _chip = chip();
    let mut d = Rp2350;

    assert_eq!(d.read_prepare(SRAM_BASE, 4), Ok(()));
    assert_eq!(d.read_prepare(0x5000_0000, 4), Err(Status::InvalidArg));

    // SAFETY: the guard is held.
    unsafe { memory()[0x40..0x44].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]) };

    let mut buf = [0u8; 4];
    assert_eq!(d.read(SRAM_BASE + 0x40, &mut buf), Ok(()));
    assert_eq!(buf, [0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(dev_ptr_calls(), 1);

    // The free function behind this one is unsafe and takes the range on its
    // caller's word.  Anyone holding an Rp2350 can call the trait method, so it
    // makes the check itself — and the refusal happens before the address is
    // turned into a pointer, not after.
    DEV_PTR_CALLS.store(0, Ordering::SeqCst);
    let mut buf = [0xa5u8; 4];
    assert_eq!(d.read(0x5000_0000, &mut buf), Err(Status::InvalidArg));
    assert_eq!(dev_ptr_calls(), 0);
    assert_eq!(buf, [0xa5; 4]);
}

#[test]
fn a_write_reaching_the_part_through_the_trait_is_range_checked_again() {
    let _chip = chip();
    let mut d = Rp2350;

    assert_eq!(d.write_prepare(SRAM_BASE, 4), Ok(Target::Memory));
    assert_eq!(d.write_prepare(FLASH_BASE, PAGE as u32), Ok(Target::Flash));
    assert_eq!(
        d.write_prepare(FLASH_BASE + 1, PAGE as u32),
        Err(Status::BadAlignment)
    );
    assert_eq!(d.write_prepare(0x5000_0000, 4), Err(Status::InvalidArg));

    assert_eq!(d.write(SRAM_BASE + 0x80, &[1, 2, 3, 4]), Ok(()));
    // SAFETY: the guard is held.
    assert_eq!(unsafe { &memory()[0x80..0x84] }, &[1, 2, 3, 4]);
    assert_eq!(dev_ptr_calls(), 1);

    DEV_PTR_CALLS.store(0, Ordering::SeqCst);
    assert_eq!(d.write(0x5000_0000, &[1, 2, 3, 4]), Err(Status::InvalidArg));
    assert_eq!(dev_ptr_calls(), 0);
}

#[test]
fn an_erase_is_judged_by_the_sectors_the_range_covers() {
    let _chip = chip();
    let mut d = Rp2350;

    assert_eq!(d.flash_erase_prepare(FLASH_BASE, 4096), Ok(()));
    assert_eq!(
        d.flash_erase_prepare(FLASH_BASE + 1, 4096),
        Err(Status::BadAlignment)
    );
    assert_eq!(
        d.flash_erase_prepare(FLASH_BASE, 100),
        Err(Status::BadAlignment)
    );
    // Not BadAlignment: SRAM is not somewhere an erase can name at all.
    assert_eq!(
        d.flash_erase_prepare(SRAM_BASE, 4096),
        Err(Status::InvalidAddress)
    );
}

#[test]
fn otp_is_served_whatever_is_asked_for() {
    let _chip = chip();
    let mut d = Rp2350;

    // These say only whether the part serves the command, and it serves both.
    // A device left at the trait's default refuses every one of them, so an Ok
    // here is the part's answer and not the default's.  What a request asks for
    // is judged where it is acted on.
    assert_eq!(d.otp_read_prepare(0, 0xffff, Ecc::Raw), Ok(()));
    assert_eq!(d.otp_read_prepare(0xffff, 1, Ecc::Ecc), Ok(()));
    assert_eq!(d.otp_write_prepare(0, 0xffff, Ecc::Raw), Ok(()));
    assert_eq!(d.otp_write_prepare(0xffff, 1, Ecc::Ecc), Ok(()));
}

#[test]
fn the_information_types_the_part_answers_reach_its_own_routines() {
    let _chip = chip();
    let mut d = Rp2350;

    // The stand-in bootrom publishes the reboot routine and nothing else, so a
    // request routed to the part reports the routine it wanted as missing.  The
    // trait's default refuses with UnknownCmd, so NotFound is the part
    // answering rather than the default.
    assert_eq!(
        d.get_info_prepare(Info::Sys, 0xffff_ffff),
        Err(Status::NotFound)
    );
    assert_eq!(
        d.get_info_prepare(Info::Partition, 0x0001),
        Err(Status::NotFound)
    );
    assert_eq!(
        d.get_info(Info::Sys, 0x0001, 0, &mut [0u8; 32]),
        Err(Status::NotFound)
    );

    // The UF2 target is answered from the partition table routine too, so it
    // reports that routine missing rather than refusing the type.
    assert_eq!(
        d.get_info_prepare(Info::Uf2Target, 0x1234),
        Err(Status::NotFound)
    );
}

#[test]
fn the_uf2_download_status_is_refused_before_any_lookup() {
    let _chip = chip();
    let mut d = Rp2350;

    // It reports a download over the drive BOOTSEL mode presents, and this
    // crate has none.  InvalidArg is what says the part does not serve the
    // type, and it is not NotFound, which is what a routine asked for and
    // missing would give — so this refusal is reached without a lookup.
    assert_eq!(
        d.get_info_prepare(Info::Uf2Status, 0),
        Err(Status::InvalidArg)
    );
    assert_eq!(
        d.get_info(Info::Uf2Status, 0, 0, &mut [0u8; 32]),
        Err(Status::InvalidArg)
    );
}

#[test]
fn an_information_answer_that_shrinks_between_calls_is_not_read_past() {
    let _chip = chip();
    let mut d = Rp2350;

    // One request reaches the ROM routine more than once: the library asks how
    // long the answer is, then asks for the answer itself a piece at a time.
    // The routine fills from the start every call and reports afresh how much
    // it wrote, and nothing holds it to the same figure twice — so a part that
    // answers less the second time leaves the library asking for a word that is
    // no longer there.

    // A part that answers the same both times, taken whole.
    publish_sys_info(4);
    assert_eq!(d.get_info_prepare(Info::Sys, 0x0001), Ok(4));
    let mut buf = [0xa5u8; 32];
    assert_eq!(d.get_info(Info::Sys, 0x0001, 0, &mut buf), Ok(16));
    assert_eq!(word(&buf, 0), info_word(0));
    assert_eq!(word(&buf, 3), info_word(3));

    // The same part now answers two words, and the library asks for the fourth
    // — an index the first answer covered and this one does not.
    publish_sys_info(2);
    let mut buf = [0xa5u8; 32];
    assert_eq!(d.get_info(Info::Sys, 0x0001, 3, &mut buf), Ok(0));
    assert!(
        buf.iter().all(|b| *b == 0xa5),
        "an index past the answer wrote bytes rather than reporting none"
    );

    // The index the shorter answer ends at is refused the same way, so the
    // refusal covers the boundary and not only what lies beyond it.
    assert_eq!(d.get_info(Info::Sys, 0x0001, 2, &mut buf), Ok(0));
    assert!(
        buf.iter().all(|b| *b == 0xa5),
        "the index the answer ends at wrote bytes rather than reporting none"
    );

    // An index the shorter answer does cover is served from it, so what was
    // refused was the index rather than the answer having changed.
    assert_eq!(d.get_info(Info::Sys, 0x0001, 1, &mut buf), Ok(4));
    assert_eq!(word(&buf, 0), info_word(1));
}

#[test]
fn an_otp_request_that_is_not_whole_rows_is_refused_before_the_bootrom() {
    let _chip = chip();
    let mut d = Rp2350;

    // Four bytes to a raw row and two to an error-corrected one.  Rounding
    // either way would touch a row the host did not name.
    assert_eq!(
        d.otp_read(0, Ecc::Raw, &mut [0u8; 3]),
        Err(Status::InvalidArg)
    );
    assert_eq!(
        d.otp_read(0, Ecc::Ecc, &mut [0u8; 3]),
        Err(Status::InvalidArg)
    );
    assert_eq!(d.otp_write(0, Ecc::Raw, &[0u8; 3]), Err(Status::InvalidArg));
    assert_eq!(d.otp_write(0, Ecc::Ecc, &[0u8; 3]), Err(Status::InvalidArg));

    // A whole number of rows gets past that check and asks the bootrom, which
    // on this stand-in does not publish the routine.  A device left at the
    // trait's default answers UnknownCmd to both of these instead, and never
    // looks at the length at all.
    assert_eq!(
        d.otp_read(0, Ecc::Raw, &mut [0u8; 4]),
        Err(Status::NotFound)
    );
    assert_eq!(
        d.otp_read(0, Ecc::Ecc, &mut [0u8; 2]),
        Err(Status::NotFound)
    );
    assert_eq!(d.otp_write(0, Ecc::Raw, &[0u8; 4]), Err(Status::NotFound));
    assert_eq!(d.otp_write(0, Ecc::Ecc, &[0u8; 2]), Err(Status::NotFound));
}

#[test]
fn a_routine_the_bootrom_does_not_publish_is_reported_as_one_that_is_not_there() {
    let _chip = chip();
    let mut d = Rp2350;

    // Every one of these is a NotFound the part gives and the trait's default
    // does not: the default answers UnknownCmd, except flash_page_write, which
    // answers NotPermitted.
    assert_eq!(
        d.flash_page_write(FLASH_BASE, &[0xa5; PAGE]),
        Err(Status::NotFound)
    );
    assert_eq!(d.flash_erase(FLASH_BASE, 4096), Err(Status::NotFound));
    assert_eq!(
        d.get_info(Info::Sys, 0x0001, 0, &mut [0u8; 4]),
        Err(Status::NotFound)
    );

    // None of it reached the chip through an address, either.
    assert_eq!(dev_ptr_calls(), 0);
}

#[test]
fn a_reboot_is_agreed_to_when_the_part_publishes_the_routine_and_then_run() {
    let _chip = chip();
    let mut d = Rp2350;
    let args = Reboot {
        flags: 2,
        delay_ms: 50,
        p0: 0x1000_0000,
        p1: 0x0002_0000,
    };

    assert_eq!(d.reboot_prepare(&args), Ok(()));
    assert_eq!(*REBOOTED.lock().unwrap(), None);

    d.reboot_execute(&args);
    assert_eq!(
        *REBOOTED.lock().unwrap(),
        Some([2, 50, 0x1000_0000, 0x0002_0000])
    );

    // The one thing changed: a part whose bootrom does not publish the routine
    // refuses before the host is acknowledged, and stays where it is if it is
    // asked to go anyway.
    PUBLISH_REBOOT.store(false, Ordering::SeqCst);
    *REBOOTED.lock().unwrap() = None;

    assert_eq!(d.reboot_prepare(&args), Err(Status::NotFound));
    d.reboot_execute(&args);
    assert_eq!(*REBOOTED.lock().unwrap(), None);
}
