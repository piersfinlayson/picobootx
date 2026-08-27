// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! The C declarations this shim sits behind, mirrored from the headers.
//!
//! Layouts must match `include/picobootx.h` exactly, including that the suite
//! builds with `-fshort-enums`, so every status crossing the boundary is one
//! byte.  Nothing checks this at link time — `picobootx_ffi_layout` exists so
//! the suite can.

use core::ffi::c_void;

/// `pb_status_t`, one byte under `-fshort-enums`.
pub type CStatus = u8;

/// `picoboot_cmd_t`.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct CCommand {
    pub magic: u32,
    pub token: u32,
    pub cmd_id: u8,
    pub cmd_size: u8,
    pub reserved: u16,
    pub transfer_len: u32,
    pub args: [u8; 16],
}

/// `pb_exclusive_access_args_t`.
#[repr(C, packed)]
pub struct CExclusiveArgs {
    pub ea_type: u8,
}

/// `pb_addr_size_args_t`.
#[repr(C, packed)]
pub struct CAddrSizeArgs {
    pub addr: u32,
    pub size: u32,
}

/// `pb_reboot2_args_t`.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct CRebootArgs {
    pub flags: u32,
    pub delay_ms: u32,
    pub p0: u32,
    pub p1: u32,
}

type FnExclusive = unsafe extern "C" fn(*const CExclusiveArgs, *mut c_void) -> CStatus;
type FnVoidCtx = unsafe extern "C" fn(*mut c_void) -> CStatus;
type FnRebootPrepare = unsafe extern "C" fn(*const CRebootArgs, *mut c_void) -> CStatus;
type FnRebootExecute = unsafe extern "C" fn(*const CRebootArgs, *mut c_void);
/// `pb_info_type_t`, one byte under `-fshort-enums`.
pub type CInfoType = u8;

type FnGetInfoPrepare = unsafe extern "C" fn(CInfoType, u32, *mut u32, *mut c_void) -> CStatus;
type FnGetInfo =
    unsafe extern "C" fn(CInfoType, u32, u32, *mut u8, u32, *mut u32, *mut c_void) -> CStatus;
type FnReadPrepare = unsafe extern "C" fn(u32, u32, *mut c_void) -> CStatus;
type FnRead = unsafe extern "C" fn(u32, *mut u8, u32, *mut c_void) -> CStatus;
type FnOtpRead = unsafe extern "C" fn(u16, u8, *mut u8, u32, *mut c_void) -> CStatus;
type FnWritePrepare = unsafe extern "C" fn(u32, u32, *mut bool, *mut c_void) -> CStatus;
type FnFlashPageWrite = unsafe extern "C" fn(u32, *const u8, *mut c_void) -> CStatus;
type FnEraseArgs = unsafe extern "C" fn(*const CAddrSizeArgs, *mut c_void) -> CStatus;
type FnWrite = unsafe extern "C" fn(u32, *const u8, u32, *mut c_void) -> CStatus;
type FnOtpWrite = unsafe extern "C" fn(u16, u8, *const u8, u32, *mut c_void) -> CStatus;

/// `picoboot_ops_t`, in the order the header declares it.
#[repr(C)]
pub struct COps {
    pub exclusive_access: Option<FnExclusive>,
    pub exit_xip: Option<FnVoidCtx>,
    pub enter_xip: Option<FnVoidCtx>,
    pub reboot2_prepare: Option<FnRebootPrepare>,
    pub reboot2_execute: Option<FnRebootExecute>,
    pub get_info_prepare: Option<FnGetInfoPrepare>,
    pub get_info: Option<FnGetInfo>,
    pub read_prepare: Option<FnReadPrepare>,
    pub read: Option<FnRead>,
    pub otp_read: Option<FnOtpRead>,
    pub write_prepare: Option<FnWritePrepare>,
    pub flash_page_write: Option<FnFlashPageWrite>,
    pub flash_erase_prepare: Option<FnEraseArgs>,
    pub flash_erase: Option<FnEraseArgs>,
    pub write: Option<FnWrite>,
    pub otp_write: Option<FnOtpWrite>,
}

type FnDispatch =
    unsafe extern "C" fn(*const CCommand, *mut u8, u32, *mut u32, *mut c_void) -> CStatus;
type FnFill = unsafe extern "C" fn(
    *const CCommand,
    *mut u8,
    u32,
    *mut u32,
    *mut bool,
    *mut c_void,
) -> CStatus;

/// `picoboot_custom_ops_t`.
#[repr(C)]
pub struct CCustomOps {
    pub magic: u32,
    pub dispatch: Option<FnDispatch>,
    pub fill: Option<FnFill>,
}

/// `tusb_control_request_t`, the eight-byte SETUP packet.
#[repr(C, packed)]
pub struct CControlRequest {
    pub bm_request_type: u8,
    pub b_request: u8,
    pub w_value: u16,
    pub w_index: u16,
    pub w_length: u16,
}

// tinyusb's control stages.
pub const CONTROL_STAGE_SETUP: u8 = 1;
pub const CONTROL_STAGE_DATA: u8 = 2;

unsafe extern "C" {
    // The transport, which the harness or the tinyusb vendor driver supplies.
    pub fn picoboot_vendor_available() -> u32;
    pub fn picoboot_vendor_read(buffer: *mut c_void, bufsize: u32) -> u32;
    pub fn picoboot_vendor_read_clear();
    pub fn picoboot_vendor_write(buffer: *const c_void, bufsize: u32) -> u32;
    pub fn picoboot_vendor_write_available() -> u32;
    pub fn picoboot_vendor_write_flush() -> u32;
    pub fn picoboot_vendor_write_clear() -> bool;
    pub fn picoboot_vendor_send_zlp() -> bool;
    pub fn picoboot_vendor_is_endpoint_stalled(ep_addr: u8) -> bool;
    pub fn picoboot_vendor_stall_endpoint(ep_addr: u8);
    pub fn picoboot_vendor_unstall_endpoint(ep_addr: u8);

    // The two control-transfer entry points picobootx.c answers through.
    pub fn tud_control_xfer(
        rhport: u8,
        request: *const CControlRequest,
        buffer: *mut c_void,
        len: u16,
    ) -> bool;
    pub fn tud_control_status(rhport: u8, request: *const CControlRequest) -> bool;
}
