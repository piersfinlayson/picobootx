// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! picobootx behind the C ABI its header describes, so the conformance suite
//! drives the Rust library through the same entry points as the C one.
//!
//! This is not a published crate and is not an example of how to use
//! picobootx.  An integrator writes `impl Ops`, not this.

#![no_std]
#![allow(clippy::missing_safety_doc)]

mod cabi;
mod defaults;
mod ops;
mod transport;

use core::ffi::{c_char, c_void};

use cabi::{CCommand, CControlRequest, CCustomOps, COps};
use cabi::{CONTROL_STAGE_DATA, CONTROL_STAGE_SETUP};
use picobootx::{Control, Endpoints, Picoboot, Recipient, Request, RequestType, Stage, State};

use ops::{CustomTable, OpsTable};
use transport::VendorTransport;

/// The state block, as the C sees it: a pointer to storage the caller owns.
///
/// The Rust value is written into that storage, which is why the harness asks
/// for its size and alignment rather than being told a constant.
struct FfiState {
    pb: Picoboot<'static, OpsTable, CustomTable>,
    ep_out: u8,
    ep_in: u8,
    // Where a control reply is handed to tinyusb from.  tinyusb keeps the
    // pointer across the data stage and may write through it, so it names
    // storage in the state block rather than a borrow of the library's.
    reply: [u8; picobootx::wire::STATUS_LEN],
}

// core is distributed compiled for unwinding, so its objects name the
// personality routine even where nothing can unwind.  The C binary this is
// linked into has no unwinder and never calls it — a definition is all the
// linker wants.
//
// Unreachable: nothing calls it.  Rust names this symbol for tidying up while
// a panic unwinds the stack, and a panic here stops dead instead.
// LCOV_UNREACHABLE_START
#[cfg(not(test))]
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}
// LCOV_UNREACHABLE_STOP

// Only for the archive.  A test target links std, which brings its own.
//
// Unreachable: it runs only if this shim has a bug.
// LCOV_UNREACHABLE_START
#[cfg(not(test))]
unsafe extern "C" {
    fn abort() -> !;
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // A panic here is a defect in this shim, not a condition to recover from.
    // abort ends the run and make reports it, where spinning would hang CI.
    unsafe { abort() }
}
// LCOV_UNREACHABLE_STOP

unsafe fn state<'a>(p: *mut c_void) -> &'a mut FfiState {
    unsafe { &mut *p.cast::<FfiState>() }
}

// ---------------------------------------------------------------------------
// picobootx.h
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn picoboot_init(
    state_block: *mut c_void,
    ops: *const COps,
    custom: *const CCustomOps,
    flash_write_buf: *mut u8,
    rhport: u8,
    ep_out: u8,
    ep_in: u8,
    ctx: *mut c_void,
) {
    let _ = rhport;
    let page = if flash_write_buf.is_null() {
        None
    } else {
        // The caller owns this for as long as the state block, which is what
        // picobootx.h asks of an integrator.
        Some(unsafe { &mut *flash_write_buf.cast::<[u8; 256]>() })
    };

    let value = FfiState {
        pb: Picoboot::new(
            OpsTable::new(ops, ctx),
            CustomTable::new(custom, ctx),
            page,
            Endpoints {
                out: ep_out,
                r#in: ep_in,
            },
        ),
        ep_out,
        ep_in,
        reply: [0; picobootx::wire::STATUS_LEN],
    };
    unsafe { state_block.cast::<FfiState>().write(value) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn picoboot_task(state_block: *mut c_void) {
    let s = unsafe { state(state_block) };
    let mut t = VendorTransport::new(s.ep_out, s.ep_in);
    s.pb.poll(&mut t);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn picoboot_tx_cb(state_block: *mut c_void, sent_bytes: u32) {
    // picobootx.h takes the count, and the library does not read it.
    let _ = sent_bytes;
    let s = unsafe { state(state_block) };
    let mut t = VendorTransport::new(s.ep_out, s.ep_in);
    s.pb.on_tx(&mut t);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn picoboot_rx_cb(state_block: *mut c_void, available_bytes: u32) {
    // picobootx.h takes the count, and the library reads it from the transport,
    // which is where this one came from.
    let _ = available_bytes;
    let s = unsafe { state(state_block) };
    let mut t = VendorTransport::new(s.ep_out, s.ep_in);
    s.pb.on_rx(&mut t);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn picoboot_control_xfer_cb(
    state_block: *mut c_void,
    rhport: u8,
    stage: u8,
    req: *const CControlRequest,
) -> bool {
    let s = unsafe { state(state_block) };
    let c = unsafe { &*req };

    let bm = c.bm_request_type;
    let request = Request {
        request_type: match (bm >> 5) & 0x3 {
            0 => RequestType::Standard,
            1 => RequestType::Class,
            2 => RequestType::Vendor,
            other => RequestType::Other(other),
        },
        recipient: match bm & 0x1f {
            0 => Recipient::Device,
            1 => Recipient::Interface,
            2 => Recipient::Endpoint,
            _ => Recipient::Other,
        },
        dir_in: bm & 0x80 != 0,
        request: c.b_request,
        value: c.w_value,
        index: c.w_index,
        length: c.w_length,
    };
    let stage_enum = match stage {
        CONTROL_STAGE_SETUP => Stage::Setup,
        CONTROL_STAGE_DATA => Stage::Data,
        _ => Stage::Ack,
    };

    let mut t = VendorTransport::new(s.ep_out, s.ep_in);
    let reply_len = match s.pb.on_control(&mut t, &request, stage_enum) {
        Control::NotHandled => return false,
        Control::Ack => None,
        Control::Reply(data) => {
            let n = core::cmp::min(data.len(), s.reply.len());
            let mut copy = [0u8; picobootx::wire::STATUS_LEN];
            copy[..n].copy_from_slice(&data[..n]);
            s.reply = copy;
            Some(n)
        }
    };

    if stage != CONTROL_STAGE_SETUP {
        return true;
    }
    match reply_len {
        None => unsafe { cabi::tud_control_status(rhport, req) },
        Some(n) => unsafe {
            cabi::tud_control_xfer(rhport, req, s.reply.as_mut_ptr().cast::<c_void>(), n as u16)
        },
    }
}

// ---------------------------------------------------------------------------
// test/src/pbt_lib.h
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn picobootx_ffi_state_size() -> usize {
    core::mem::size_of::<FfiState>()
}

#[unsafe(no_mangle)]
pub extern "C" fn picobootx_ffi_state_align() -> usize {
    core::mem::align_of::<FfiState>()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn picobootx_ffi_state_of(state_block: *const c_void) -> u8 {
    let s = unsafe { &*state_block.cast::<FfiState>() };
    s.pb.state() as u8
}

#[unsafe(no_mangle)]
pub extern "C" fn picobootx_ffi_state_name(state: u8) -> *const c_char {
    const NAMES: [&[u8]; 7] = [
        b"IDLE\0",
        b"DATA_OUT\0",
        b"DATA_IN\0",
        b"CUSTOM_IN\0",
        b"AWAIT_ZLP\0",
        b"AWAIT_ACK\0",
        b"STALLED\0",
    ];
    match NAMES.get(state as usize) {
        Some(n) => n.as_ptr().cast::<c_char>(),
        None => core::ptr::null(),
    }
}

/// What this library's own wire types measure, in the order `pbt_layout_t`
/// names, so the suite can check them against the header rather than against
/// themselves.
///
/// Nothing else would catch a `Status` that is not one byte, and that type is
/// the return of every operation crossing the boundary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn picobootx_ffi_layout(out: *mut u32, len: u32) -> u32 {
    use core::mem::{align_of, offset_of, size_of};
    let values: [u32; 15] = [
        size_of::<picobootx::Status>() as u32,
        size_of::<CCommand>() as u32,
        align_of::<CCommand>() as u32,
        offset_of!(CCommand, magic) as u32,
        offset_of!(CCommand, token) as u32,
        offset_of!(CCommand, cmd_id) as u32,
        offset_of!(CCommand, cmd_size) as u32,
        offset_of!(CCommand, transfer_len) as u32,
        offset_of!(CCommand, args) as u32,
        picobootx::wire::STATUS_LEN as u32,
        size_of::<COps>() as u32,
        offset_of!(COps, otp_write) as u32,
        size_of::<CCustomOps>() as u32,
        offset_of!(CCustomOps, fill) as u32,
        size_of::<CControlRequest>() as u32,
    ];
    let n = core::cmp::min(len as usize, values.len());
    for (i, v) in values.iter().take(n).enumerate() {
        unsafe { out.add(i).write(*v) };
    }
    values.len() as u32
}

// The command this shim hands to a C callback and the one the library hands to
// a Rust one are two declarations of the same 32 bytes: one length, and every
// field at one offset.  Their alignments differ and may - nothing reinterprets
// either as the other, and as_c copies field by field.
const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<CCommand>() == size_of::<picobootx::Command>());
    assert!(offset_of!(CCommand, magic) == offset_of!(picobootx::Command, magic));
    assert!(offset_of!(CCommand, token) == offset_of!(picobootx::Command, token));
    assert!(offset_of!(CCommand, cmd_id) == offset_of!(picobootx::Command, cmd_id));
    assert!(offset_of!(CCommand, cmd_size) == offset_of!(picobootx::Command, cmd_size));
    assert!(offset_of!(CCommand, transfer_len) == offset_of!(picobootx::Command, transfer_len));
    assert!(offset_of!(CCommand, args) == offset_of!(picobootx::Command, args));
};

// State is an enum in Rust and a plain integer across the boundary, so the two
// have to agree on the numbers.  Nothing else checks this.
const _: () = {
    assert!(State::Idle as u8 == 0);
    assert!(State::DataOut as u8 == 1);
    assert!(State::DataIn as u8 == 2);
    assert!(State::CustomIn as u8 == 3);
    assert!(State::AwaitZlp as u8 == 4);
    assert!(State::AwaitAck as u8 == 5);
    assert!(State::Stalled as u8 == 6);
};
