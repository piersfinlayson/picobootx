// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! The default RP2350 implementations behind the C ABI `picobootx_impl.h`
//! describes.
//!
//! An integrator fills a `picoboot_ops_t` with these, so they have to be
//! callable from C by the names that header declares.  The conformance suite
//! does exactly that, and calls a few of them directly besides — the argument
//! checks the protocol layer can never put a bad value past are part of the
//! published interface, and are tested where an integrator would meet them.

use core::ffi::{c_char, c_int, c_void};

use picobootx::{Ecc, Exclusive, Reboot, Result, Status, Target, wire::FLASH_PAGE_SIZE};

use crate::cabi::{CAddrSizeArgs, CExclusiveArgs, CRebootArgs, CStatus};

/// The status code C reads back from a `Result`.
fn code(result: Result) -> CStatus {
    match result {
        Ok(()) => Status::Ok as CStatus,
        Err(status) => status as CStatus,
    }
}

/// A pointer and a length as a slice.
///
/// A zero-length transfer arrives with whatever pointer the caller had, which
/// may be null, and a slice may not be built from one however empty it is.
///
/// # Safety
///
/// `p` names `len` readable bytes, or `len` is zero.
unsafe fn in_slice<'a, T>(p: *const T, len: usize) -> &'a [T] {
    if len == 0 {
        return &[];
    }
    unsafe { core::slice::from_raw_parts(p, len) }
}

/// A pointer and a length as a slice written through.
///
/// # Safety
///
/// `p` names `len` writable bytes, or `len` is zero.
unsafe fn out_slice<'a, T>(p: *mut T, len: usize) -> &'a mut [T] {
    if len == 0 {
        return &mut [];
    }
    unsafe { core::slice::from_raw_parts_mut(p, len) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn picoboot_default_exclusive_access(
    args: *const CExclusiveArgs,
    ctx: *mut c_void,
) -> CStatus {
    let _ = ctx;
    let mode = Exclusive::from(unsafe { (*args).ea_type });
    code(picobootx_rp2350::exclusive_access(mode))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn picoboot_default_exit_xip(ctx: *mut c_void) -> CStatus {
    let _ = ctx;
    code(picobootx_rp2350::exit_xip())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn picoboot_default_enter_xip(ctx: *mut c_void) -> CStatus {
    let _ = ctx;
    code(picobootx_rp2350::enter_xip())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn picoboot_default_reboot2_prepare(
    args: *const CRebootArgs,
    ctx: *mut c_void,
) -> CStatus {
    let _ = ctx;
    code(picobootx_rp2350::reboot_prepare(&reboot_args(unsafe {
        &*args
    })))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn picoboot_default_reboot2_execute(
    args: *const CRebootArgs,
    ctx: *mut c_void,
) {
    let _ = ctx;
    picobootx_rp2350::reboot_execute(&reboot_args(unsafe { &*args }));
}

fn reboot_args(args: &CRebootArgs) -> Reboot {
    Reboot {
        flags: args.flags,
        delay_ms: args.delay_ms,
        p0: args.p0,
        p1: args.p1,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn picoboot_default_read_prepare(
    addr: u32,
    size: u32,
    ctx: *mut c_void,
) -> CStatus {
    let _ = ctx;
    code(picobootx_rp2350::read_prepare(addr, size))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn picoboot_default_read(
    addr: u32,
    buf: *mut u8,
    size: u32,
    ctx: *mut c_void,
) -> CStatus {
    let _ = ctx;
    let out = unsafe { out_slice(buf, size as usize) };
    code(unsafe { picobootx_rp2350::read(addr, out) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn picoboot_default_write_prepare(
    addr: u32,
    size: u32,
    is_flash: *mut bool,
    ctx: *mut c_void,
) -> CStatus {
    let _ = ctx;
    match picobootx_rp2350::write_prepare(addr, size) {
        Ok(target) => {
            unsafe { is_flash.write(target == Target::Flash) };
            Status::Ok as CStatus
        }
        Err(status) => status as CStatus,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn picoboot_default_write(
    addr: u32,
    buf: *const u8,
    len: u32,
    ctx: *mut c_void,
) -> CStatus {
    let _ = ctx;
    let data = unsafe { in_slice(buf, len as usize) };
    code(unsafe { picobootx_rp2350::write(addr, data) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn picoboot_default_flash_page_write(
    addr: u32,
    buf: *const u8,
    ctx: *mut c_void,
) -> CStatus {
    let _ = ctx;
    let page = unsafe { &*buf.cast::<[u8; FLASH_PAGE_SIZE]>() };
    code(picobootx_rp2350::flash_page_write(addr, page))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn picoboot_default_flash_erase_prepare(
    args: *const CAddrSizeArgs,
    ctx: *mut c_void,
) -> CStatus {
    let _ = ctx;
    let args = unsafe { &*args };
    code(picobootx_rp2350::flash_erase_prepare(args.addr, args.size))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn picoboot_default_flash_erase(
    args: *const CAddrSizeArgs,
    ctx: *mut c_void,
) -> CStatus {
    let _ = ctx;
    let args = unsafe { &*args };
    code(picobootx_rp2350::flash_erase(args.addr, args.size))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn picoboot_default_otp_read(
    row: u16,
    ecc: u8,
    buf: *mut u8,
    len: u32,
    ctx: *mut c_void,
) -> CStatus {
    let _ = ctx;
    let out = unsafe { out_slice(buf, len as usize) };
    code(picobootx_rp2350::otp_read(row, Ecc::from(ecc), out))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn picoboot_default_otp_write(
    row: u16,
    ecc: u8,
    buf: *const u8,
    len: u32,
    ctx: *mut c_void,
) -> CStatus {
    let _ = ctx;
    let data = unsafe { in_slice(buf, len as usize) };
    code(picobootx_rp2350::otp_write(row, Ecc::from(ecc), data))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn picoboot_default_get_info_sys(
    flag: u32,
    buf: *mut u8,
    buf_size: u32,
    bytes_written: *mut u32,
    ctx: *mut c_void,
) -> CStatus {
    let _ = ctx;
    let out = unsafe { out_slice(buf, buf_size as usize) };
    // picobootx.h has this report what it wrote.  The buffer is sized for the
    // one flag asked for and is filled or the call fails, so what it wrote on
    // success is the whole of it.
    let len = out.len() as u32;
    match picobootx_rp2350::get_info_sys(flag, out) {
        Ok(()) => {
            unsafe { bytes_written.write(len) };
            Status::Ok as CStatus
        }
        Err(status) => status as CStatus,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn picoboot_get_serial(buffer: *mut u16, max_len: usize) -> usize {
    let out = unsafe { out_slice(buffer, max_len) };
    // picobootx_impl.h reports every failure as a length of zero, which is what
    // this collapses the status back to.
    picobootx_rp2350::serial(out).unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn pb_status_from_bootrom(ret: c_int) -> CStatus {
    picobootx_rp2350::bootrom::status_from(ret) as CStatus
}

// c_char is signed on some targets and unsigned on others - i8 on x86_64
// Linux, u8 on aarch64 Linux - so this cast is required on the first and
// redundant on the second.  It is written for the target that needs it, and
// allowed on the target that does not, or the crate stops building with
// -D warnings on an Arm host.
#[allow(clippy::unnecessary_cast)]
#[unsafe(no_mangle)]
pub extern "C" fn picoboot_lookup_boot_fn(a: c_char, b: c_char) -> *mut c_void {
    picobootx_rp2350::bootrom::lookup(a as u8, b as u8)
        .cast_mut()
        .cast::<c_void>()
}
