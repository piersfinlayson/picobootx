// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! A C `picoboot_ops_t` presented as an `impl Ops`.
//!
//! A null pointer in the C table means the device does not serve that command.
//! Rust says the same thing by leaving a method to its default, and where the C
//! checks a *pair* of pointers before acting — `read_prepare` with `read`, and
//! the rest — this refuses in the prepare, because that is what the trait's
//! contract asks of an integrator.

use core::ffi::c_void;

use picobootx::{Command, Custom, Ecc, Exclusive, Filled, Ops, Reboot, Result, Status, Target};

use crate::cabi::{
    CAddrSizeArgs, CCommand, CCustomOps, CExclusiveArgs, COps, CRebootArgs, CStatus,
};

fn status(code: CStatus) -> Result {
    match code {
        0 => Ok(()),
        other => Err(to_status(other)),
    }
}

fn to_status(code: CStatus) -> Status {
    match code {
        1 => Status::UnknownCmd,
        2 => Status::InvalidCmdLength,
        3 => Status::InvalidTransferLen,
        4 => Status::InvalidAddress,
        5 => Status::BadAlignment,
        6 => Status::InterleavedWrite,
        7 => Status::Rebooting,
        9 => Status::InvalidState,
        10 => Status::NotPermitted,
        11 => Status::InvalidArg,
        12 => Status::BufferTooSmall,
        13 => Status::PreconditionNotMet,
        14 => Status::ModifiedData,
        15 => Status::InvalidData,
        16 => Status::NotFound,
        17 => Status::UnsupportedMod,
        _ => Status::UnknownError,
    }
}

pub struct OpsTable {
    ops: *const COps,
    ctx: *mut c_void,
}

impl OpsTable {
    pub fn new(ops: *const COps, ctx: *mut c_void) -> Self {
        Self { ops, ctx }
    }

    fn t(&self) -> Option<&COps> {
        if self.ops.is_null() {
            // Unreachable by contract rather than by construction: nothing
            // here stops a NULL ops, but picobootx.h allows NULL only for
            // custom, and the C reads straight through ops without checking.
            // Every scenario is run against both libraries, so one passing
            // NULL would crash the C long before this line ran.
            // LCOV_UNREACHABLE_START
            None
            // LCOV_UNREACHABLE_STOP
        } else {
            Some(unsafe { &*self.ops })
        }
    }
}

impl Ops for OpsTable {
    fn exclusive_access(&mut self, mode: Exclusive) -> Result {
        match self.t().and_then(|t| t.exclusive_access) {
            None => Ok(()),
            Some(f) => {
                let args = CExclusiveArgs {
                    ea_type: u8::from(mode),
                };
                status(unsafe { f(&args, self.ctx) })
            }
        }
    }

    fn exit_xip(&mut self) -> Result {
        match self.t().and_then(|t| t.exit_xip) {
            None => Ok(()),
            Some(f) => status(unsafe { f(self.ctx) }),
        }
    }

    fn enter_xip(&mut self) -> Result {
        match self.t().and_then(|t| t.enter_xip) {
            None => Ok(()),
            Some(f) => status(unsafe { f(self.ctx) }),
        }
    }

    fn read_prepare(&mut self, addr: u32, size: u32) -> Result {
        let t = self.t().ok_or(Status::UnknownCmd)?;
        let (Some(prepare), Some(_)) = (t.read_prepare, t.read) else {
            return Err(Status::UnknownCmd);
        };
        status(unsafe { prepare(addr, size, self.ctx) })
    }

    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result {
        let f = self.t().and_then(|t| t.read).ok_or(Status::UnknownCmd)?;
        status(unsafe { f(addr, buf.as_mut_ptr(), buf.len() as u32, self.ctx) })
    }

    fn write_prepare(&mut self, addr: u32, size: u32) -> Result<Target> {
        let t = self.t().ok_or(Status::UnknownCmd)?;
        let prepare = t.write_prepare.ok_or(Status::UnknownCmd)?;
        let mut is_flash = false;
        status(unsafe { prepare(addr, size, &mut is_flash, self.ctx) })?;
        if is_flash {
            if t.flash_page_write.is_none() {
                return Err(Status::NotPermitted);
            }
            Ok(Target::Flash)
        } else {
            if t.write.is_none() {
                return Err(Status::UnknownCmd);
            }
            Ok(Target::Memory)
        }
    }

    fn write(&mut self, addr: u32, buf: &[u8]) -> Result {
        let f = self.t().and_then(|t| t.write).ok_or(Status::UnknownCmd)?;
        status(unsafe { f(addr, buf.as_ptr(), buf.len() as u32, self.ctx) })
    }

    fn flash_page_write(&mut self, addr: u32, page: &[u8; 256]) -> Result {
        let f = self
            .t()
            .and_then(|t| t.flash_page_write)
            .ok_or(Status::NotPermitted)?;
        status(unsafe { f(addr, page.as_ptr(), self.ctx) })
    }

    fn flash_erase_prepare(&mut self, addr: u32, size: u32) -> Result {
        let t = self.t().ok_or(Status::UnknownCmd)?;
        let (Some(prepare), Some(_)) = (t.flash_erase_prepare, t.flash_erase) else {
            return Err(Status::UnknownCmd);
        };
        let args = CAddrSizeArgs { addr, size };
        status(unsafe { prepare(&args, self.ctx) })
    }

    fn flash_erase(&mut self, addr: u32, size: u32) -> Result {
        let f = self
            .t()
            .and_then(|t| t.flash_erase)
            .ok_or(Status::UnknownCmd)?;
        let args = CAddrSizeArgs { addr, size };
        status(unsafe { f(&args, self.ctx) })
    }

    fn otp_read_prepare(&mut self, _row: u16, _count: u16, _ecc: Ecc) -> Result {
        if self.t().and_then(|t| t.otp_read).is_none() {
            return Err(Status::UnknownCmd);
        }
        Ok(())
    }

    fn otp_read(&mut self, row: u16, ecc: Ecc, buf: &mut [u8]) -> Result {
        let f = self
            .t()
            .and_then(|t| t.otp_read)
            .ok_or(Status::UnknownCmd)?;
        status(unsafe { f(row, ecc as u8, buf.as_mut_ptr(), buf.len() as u32, self.ctx) })
    }

    fn otp_write_prepare(&mut self, _row: u16, _count: u16, _ecc: Ecc) -> Result {
        if self.t().and_then(|t| t.otp_write).is_none() {
            return Err(Status::UnknownCmd);
        }
        Ok(())
    }

    fn otp_write(&mut self, row: u16, ecc: Ecc, buf: &[u8]) -> Result {
        let f = self
            .t()
            .and_then(|t| t.otp_write)
            .ok_or(Status::UnknownCmd)?;
        status(unsafe { f(row, ecc as u8, buf.as_ptr(), buf.len() as u32, self.ctx) })
    }

    fn get_info_sys_prepare(&mut self, _flags: u32) -> Result {
        if self.t().and_then(|t| t.get_info_sys).is_none() {
            return Err(Status::UnknownCmd);
        }
        Ok(())
    }

    fn get_info_sys(&mut self, flag: u32, buf: &mut [u8]) -> Result {
        let f = self
            .t()
            .and_then(|t| t.get_info_sys)
            .ok_or(Status::UnknownCmd)?;
        let mut written: u32 = 0;
        status(unsafe {
            f(
                flag,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut written,
                self.ctx,
            )
        })?;
        // The C callback reports what it wrote, and the buffer is sized for the
        // one flag it was asked for, so anything but a full buffer is an
        // integrator's callback disagreeing with the flag it answered.
        if written as usize != buf.len() {
            return Err(Status::UnknownError);
        }
        Ok(())
    }

    fn reboot_prepare(&mut self, args: &Reboot) -> Result {
        let f = self
            .t()
            .and_then(|t| t.reboot2_prepare)
            .ok_or(Status::UnknownCmd)?;
        let c = CRebootArgs {
            flags: args.flags,
            delay_ms: args.delay_ms,
            p0: args.p0,
            p1: args.p1,
        };
        status(unsafe { f(&c, self.ctx) })
    }

    fn reboot_execute(&mut self, args: &Reboot) {
        if let Some(f) = self.t().and_then(|t| t.reboot2_execute) {
            let c = CRebootArgs {
                flags: args.flags,
                delay_ms: args.delay_ms,
                p0: args.p0,
                p1: args.p1,
            };
            unsafe { f(&c, self.ctx) };
        }
    }
}

pub struct CustomTable {
    custom: *const CCustomOps,
    ctx: *mut c_void,
}

impl CustomTable {
    pub fn new(custom: *const CCustomOps, ctx: *mut c_void) -> Self {
        Self { custom, ctx }
    }

    fn t(&self) -> Option<&CCustomOps> {
        if self.custom.is_null() {
            None
        } else {
            Some(unsafe { &*self.custom })
        }
    }
}

fn as_c(cmd: &Command) -> CCommand {
    CCommand {
        magic: cmd.magic,
        token: cmd.token,
        cmd_id: cmd.cmd_id,
        cmd_size: cmd.cmd_size,
        reserved: cmd.reserved,
        transfer_len: cmd.transfer_len,
        args: cmd.args,
    }
}

impl Custom for CustomTable {
    fn magic(&self) -> Option<u32> {
        self.t().map(|t| t.magic)
    }

    fn dispatch(&mut self, cmd: &Command) -> Result {
        let t = self.t().ok_or(Status::UnknownCmd)?;
        let dispatch = t.dispatch.ok_or(Status::UnknownCmd)?;
        // A data-carrying command needs somewhere for the data to come from,
        // and the integrator has not supplied one, so refuse before dispatch
        // rather than partway through the transfer.
        if cmd.transfer_len != 0 && cmd.is_in() && t.fill.is_none() {
            return Err(Status::UnknownCmd);
        }
        let c = as_c(cmd);
        let mut written: u32 = 0;
        status(unsafe { dispatch(&c, core::ptr::null_mut(), 0, &mut written, self.ctx) })
    }

    fn fill(&mut self, cmd: &Command, buf: &mut [u8]) -> Result<Filled> {
        let f = self.t().and_then(|t| t.fill).ok_or(Status::UnknownCmd)?;
        let c = as_c(cmd);
        let mut written: u32 = 0;
        let mut done = false;
        status(unsafe {
            f(
                &c,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut written,
                &mut done,
                self.ctx,
            )
        })?;
        Ok(if done {
            Filled::Done(written as usize)
        } else if written > 0 {
            Filled::More(written as usize)
        } else {
            Filled::NoRoom
        })
    }
}
