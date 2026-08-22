// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! Where these implementations reach past the picoboot protocol to the chip.
//!
//! There are five such places: a bootrom table at an absolute address, the QMI
//! register carrying the XIP clock divisor, the interrupt-enable bit, placing a
//! function in RAM, and turning a device address into a pointer that can be
//! dereferenced.  Each is somewhere a machine that is not an RP2350 would fault
//! rather than misbehave, so each goes through this module.
//!
//! A bare-metal target is a build for the part, and reaches the chip.  Any
//! other target has no chip under it, and each seam instead calls a
//! `picobootx_host_test_` function the program around this library supplies —
//! the same five `include/picobootx_impl.h` names under `PICOBOOTX_HOST_TEST`,
//! so one harness answers both implementations of picobootx.
//!
//! Placing a function in RAM is the one seam that is not a call.  It is written
//! at the function it applies to, as
//! `#[cfg_attr(target_os = "none", unsafe(link_section = ".ramfunc"))]`, since
//! an attribute cannot be handed out from here without a macro crate to carry
//! it.

/// The bootrom publishes its function table through a lookup routine whose own
/// address is stored, as a 16-bit value, at this fixed address low in the
/// address map.
#[cfg(target_os = "none")]
const ROM_TABLE_LOOKUP_ADDR: usize = 0x0000_0016;

/// The QMI's mode-0 timing register carries the XIP clock divisor.  The erase
/// sequence has to read it before taking flash out of XIP, so that XIP can be
/// restored on the same divisor afterwards.
#[cfg(target_os = "none")]
const XIP_QMI_M0_TIMING_ADDR: usize = 0x400d_000c;

/// Where the divisor sits in that register.
#[cfg(target_os = "none")]
const XIP_QMI_M0_CLKDIV_SHIFT: u32 = 0;

/// How wide it is.
#[cfg(target_os = "none")]
const XIP_QMI_M0_CLKDIV_MASK: u32 = 0xff;

/// The lookup routine the bootrom publishes its table through.
#[cfg(target_os = "none")]
type RomTableLookup = unsafe extern "C" fn(code: u32, mask: u32) -> *const ();

/// Ask the bootrom for the routine a code and flag set name.
///
/// Null when the part does not publish it, which is a property of the part and
/// is what every caller here checks before jumping.  Null also when the part
/// publishes no table at all, so a machine holding zero at the fixed address
/// answers the same way a routine the table omits does.
#[cfg(target_os = "none")]
pub(crate) fn bootrom_lookup(code: u32, mask: u32) -> *const () {
    // SAFETY: the bootrom stores the lookup routine's address here, and this
    // half of the module is compiled only for a build for the part.  Read
    // through a volatile access because the address names a fixed cell of the
    // address map rather than an object the compiler laid out.
    let entry = unsafe { (ROM_TABLE_LOOKUP_ADDR as *const u16).read_volatile() };

    // SAFETY: a `usize` and an `Option<fn>` are the same width, and the option
    // is what makes a zero well defined — a bare function pointer is a type
    // Rust guarantees non-null and niche-optimises on, so building one out of a
    // zero halfword would let the compiler discard the code around it.  Written
    // out with both types named so the width of the address is checked against
    // the width of the pointer it becomes.
    let lookup: Option<RomTableLookup> =
        unsafe { core::mem::transmute::<usize, Option<RomTableLookup>>(entry as usize) };

    let Some(lookup) = lookup else {
        return core::ptr::null();
    };

    // SAFETY: the address came from the cell the bootrom publishes its lookup
    // routine's address in, and the signature is the one the part's
    // documentation gives that routine.
    unsafe { lookup(code, mask) }
}

/// The XIP clock divisor in force.
#[cfg(target_os = "none")]
pub(crate) fn xip_clkdiv() -> u8 {
    // SAFETY: the QMI's mode-0 timing register sits at this fixed address on
    // the part, and this half of the module is compiled only for a build for
    // it.  Volatile because reading a peripheral register is the point of the
    // access and not a value the compiler may fold.
    let timing = unsafe { (XIP_QMI_M0_TIMING_ADDR as *const u32).read_volatile() };
    ((timing >> XIP_QMI_M0_CLKDIV_SHIFT) & XIP_QMI_M0_CLKDIV_MASK) as u8
}

/// Stop taking interrupts.
///
/// Interrupt handlers are themselves served from flash, so one taken while
/// flash is unreadable would fetch from a bus that is not answering.
#[cfg(target_os = "none")]
pub(crate) fn irq_disable() {
    // SAFETY: masking interrupts touches no memory and leaves the flags alone,
    // which is what the options say.  No `nomem`: the point of this instruction
    // is the window it opens, and memory accesses either side of it must stay
    // either side of it.
    unsafe { core::arch::asm!("cpsid i", options(nostack, preserves_flags)) };
}

/// Take interrupts again.
#[cfg(target_os = "none")]
pub(crate) fn irq_enable() {
    // SAFETY: as irq_disable, in the other direction.
    unsafe { core::arch::asm!("cpsie i", options(nostack, preserves_flags)) };
}

/// A pointer for a device address, over the `len` bytes about to be accessed.
///
/// On the part the address already is the pointer, and `len` says nothing.
///
/// # Safety
///
/// The caller has established that `addr` through `addr + len` is a range this
/// device answers.  `read_prepare` and `write_prepare` do.
#[cfg(target_os = "none")]
pub(crate) unsafe fn dev_ptr(addr: u32, len: u32) -> *mut u8 {
    let _ = len;
    addr as usize as *mut u8
}

// The same five, on a machine that is not an RP2350.
#[cfg(not(target_os = "none"))]
unsafe extern "C" {
    fn picobootx_host_test_bootrom_lookup(code: u32, mask: u32) -> *const ();
    fn picobootx_host_test_xip_clkdiv() -> u8;
    fn picobootx_host_test_irq_disable();
    fn picobootx_host_test_irq_enable();
    fn picobootx_host_test_dev_ptr(addr: u32, len: u32) -> *mut u8;
}

/// Ask what stands in for the bootrom for the routine a code names.
#[cfg(not(target_os = "none"))]
pub(crate) fn bootrom_lookup(code: u32, mask: u32) -> *const () {
    // SAFETY: the harness supplies this, with the signature declared above.
    unsafe { picobootx_host_test_bootrom_lookup(code, mask) }
}

/// The XIP clock divisor the stand-in reports.
#[cfg(not(target_os = "none"))]
pub(crate) fn xip_clkdiv() -> u8 {
    // SAFETY: the harness supplies this, with the signature declared above.
    unsafe { picobootx_host_test_xip_clkdiv() }
}

/// Tell the stand-in that interrupts are off from here.
#[cfg(not(target_os = "none"))]
pub(crate) fn irq_disable() {
    // SAFETY: the harness supplies this, with the signature declared above.
    unsafe { picobootx_host_test_irq_disable() };
}

/// Tell the stand-in that they are back on.
#[cfg(not(target_os = "none"))]
pub(crate) fn irq_enable() {
    // SAFETY: the harness supplies this, with the signature declared above.
    unsafe { picobootx_host_test_irq_enable() };
}

/// A pointer for a device address, from whatever memory stands in for it.
///
/// # Safety
///
/// The caller has established that `addr` through `addr + len` is a range this
/// device answers.  A range the stand-in cannot map is a mistake in the caller
/// rather than a condition to handle, and it says so and stops.
#[cfg(not(target_os = "none"))]
pub(crate) unsafe fn dev_ptr(addr: u32, len: u32) -> *mut u8 {
    // SAFETY: the harness supplies this, with the signature declared above,
    // and this function's own contract carries the range the caller has
    // established on to it.
    unsafe { picobootx_host_test_dev_ptr(addr, len) }
}
