// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! The bootrom: the routines these implementations call, and what its error
//! numbers mean to a host.
//!
//! Two things can go wrong with a bootrom routine and they are not the same.
//! The part may not publish it at all, which every lookup here reports as
//! `None` and the caller turns into `Status::NotFound` before anything is
//! attempted.  Or it may be published and refuse, which arrives as a negative
//! return code that [`status_from`] turns into the status a host reads back.

use core::ffi::c_int;

use picobootx::Status;

use crate::chip;

// The error codes the bootrom returns.  The ones marked unused are the
// documented set the RP2350 itself never returns — they are here because an
// unmapped code has to become a status rather than reach a host as a negative
// number.
const ERROR_TIMEOUT: c_int = -1; // unused on RP2350
const ERROR_GENERIC: c_int = -2; // unused on RP2350
const ERROR_NO_DATA: c_int = -3; // unused on RP2350
const ERROR_NOT_PERMITTED: c_int = -4;
const ERROR_INVALID_ARG: c_int = -5;
const ERROR_IO: c_int = -6; // unused on RP2350
const ERROR_BADAUTH: c_int = -7; // unused on RP2350
const ERROR_CONNECT_FAILED: c_int = -8; // unused on RP2350
const ERROR_INSUFFICIENT_RESOURCES: c_int = -9; // unused on RP2350
const ERROR_INVALID_ADDRESS: c_int = -10;
const ERROR_BAD_ALIGNMENT: c_int = -11;
const ERROR_INVALID_STATE: c_int = -12;
const ERROR_BUFFER_TOO_SMALL: c_int = -13;
const ERROR_PRECONDITION_NOT_MET: c_int = -14;
const ERROR_MODIFIED_DATA: c_int = -15;
const ERROR_INVALID_DATA: c_int = -16;
const ERROR_NOT_FOUND: c_int = -17;
const ERROR_UNSUPPORTED_MODIFICATION: c_int = -18;
const ERROR_LOCK_REQUIRED: c_int = -19;

/// Selects the Arm secure entry in a bootrom table entry's flag set.
const ROM_TABLE_FLAG_FUNC_ARM_SEC: u32 = 0x0004;

/// Set in the row word to make an OTP access a write rather than a read.
pub(crate) const OTP_ACCESS_FLAG_WRITE: u32 = 0x0001_0000;

/// Set in the row word to address OTP through the error-correcting view.
pub(crate) const OTP_ACCESS_FLAG_ECC: u32 = 0x0002_0000;

/// Reboot the part.
pub type RebootFn = unsafe extern "C" fn(flags: u32, delay_ms: u32, p0: u32, p1: u32) -> c_int;

/// Answer one or more system information flags into a word buffer.
pub type GetSysInfoFn = unsafe extern "C" fn(out: *mut u32, out_words: u32, flags: u32) -> c_int;

/// Read or write whole OTP rows.
pub type OtpAccessFn =
    unsafe extern "C" fn(buf: *mut u8, buf_len: u32, row_and_flags: u32) -> c_int;

/// Erase a range of flash, in sectors or in blocks as the range allows.
pub type FlashRangeEraseFn =
    unsafe extern "C" fn(flash_offs: u32, count: usize, block_size: u32, block_cmd: u8);

/// Program a range of flash from a buffer.
pub type FlashRangeProgramFn = unsafe extern "C" fn(flash_offs: u32, data: *const u8, count: usize);

/// Put the QSPI pins under the flash interface's control.
pub type ConnectInternalFlashFn = unsafe extern "C" fn();

/// Leave execute-in-place, so flash takes serial commands.
pub type FlashExitXipFn = unsafe extern "C" fn();

/// Discard what the XIP cache holds.
pub type FlashFlushCacheFn = unsafe extern "C" fn();

/// Re-enter execute-in-place, in a read mode and at a clock divisor.
pub type FlashSelectXipReadModeFn = unsafe extern "C" fn(mode: u8, clkdiv: u8);

/// What a host is told when a bootrom routine returns `ret`.
///
/// A code with no status of its own becomes [`Status::UnknownError`], so a
/// negative number never reaches a host as though it were a result.
#[must_use]
pub fn status_from(ret: c_int) -> Status {
    match ret {
        0 => Status::Ok,
        ERROR_NOT_PERMITTED => Status::NotPermitted,
        ERROR_INVALID_ARG => Status::InvalidArg,
        ERROR_INVALID_ADDRESS => Status::InvalidAddress,
        ERROR_BAD_ALIGNMENT => Status::BadAlignment,
        ERROR_INVALID_STATE => Status::InvalidState,
        ERROR_BUFFER_TOO_SMALL => Status::BufferTooSmall,
        ERROR_PRECONDITION_NOT_MET => Status::PreconditionNotMet,
        ERROR_MODIFIED_DATA => Status::ModifiedData,
        ERROR_INVALID_DATA => Status::InvalidData,
        ERROR_NOT_FOUND => Status::NotFound,
        ERROR_UNSUPPORTED_MODIFICATION => Status::UnsupportedMod,
        // Documented codes with no status of their own, named so the set here
        // is the part's set and not a subset of it.
        ERROR_TIMEOUT
        | ERROR_GENERIC
        | ERROR_NO_DATA
        | ERROR_IO
        | ERROR_BADAUTH
        | ERROR_CONNECT_FAILED
        | ERROR_INSUFFICIENT_RESOURCES
        | ERROR_LOCK_REQUIRED => Status::UnknownError,
        _ => Status::UnknownError,
    }
}

/// The address of the bootrom routine two characters name, or null.
///
/// The two characters are the routine's code, as the part's documentation
/// writes it, and the entry asked for is the Arm secure one.
#[must_use]
pub fn lookup(a: u8, b: u8) -> *const () {
    let code = (u32::from(b) << 8) | u32::from(a);
    chip::bootrom_lookup(code, ROM_TABLE_FLAG_FUNC_ARM_SEC)
}

/// Declares the getter for one bootrom routine.
///
/// The transmute is written out per routine rather than through one generic
/// helper, so the compiler checks each function pointer against the width of
/// the address it is being made from.  A helper taking the type as a parameter
/// would have to reach for `transmute_copy`, which checks nothing.
macro_rules! routine {
    ($(#[$doc:meta])* $name:ident, $ty:ty, $a:literal, $b:literal) => {
        $(#[$doc])*
        #[must_use]
        pub fn $name() -> Option<$ty> {
            let found = lookup($a, $b);
            if found.is_null() {
                None
            } else {
                Some(unsafe { core::mem::transmute::<*const (), $ty>(found) })
            }
        }
    };
}

routine!(
    /// The routine that reboots the part, if it publishes one.
    reboot, RebootFn, b'R', b'B'
);
routine!(
    /// The routine that answers system information, if it publishes one.
    get_sys_info, GetSysInfoFn, b'G', b'S'
);
routine!(
    /// The routine that reads and writes OTP, if it publishes one.
    otp_access, OtpAccessFn, b'O', b'A'
);
routine!(
    /// The routine that erases flash, if it publishes one.
    flash_range_erase, FlashRangeEraseFn, b'R', b'E'
);
routine!(
    /// The routine that programs flash, if it publishes one.
    flash_range_program, FlashRangeProgramFn, b'R', b'P'
);
routine!(
    /// The routine that connects the internal flash, if it publishes one.
    connect_internal_flash, ConnectInternalFlashFn, b'I', b'F'
);
routine!(
    /// The routine that leaves execute-in-place, if it publishes one.
    flash_exit_xip, FlashExitXipFn, b'E', b'X'
);
routine!(
    /// The routine that flushes the XIP cache, if it publishes one.
    flash_flush_cache, FlashFlushCacheFn, b'F', b'C'
);
routine!(
    /// The routine that re-enters execute-in-place, if it publishes one.
    flash_select_xip_read_mode, FlashSelectXipReadModeFn, b'X', b'M'
);
