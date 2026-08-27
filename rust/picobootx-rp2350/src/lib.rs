// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

#![no_std]
#![doc = include_str!("../README.md")]

// A build for the part is a build for its Arm core.  The bootrom is asked for
// the Arm secure entry in its table, and the erase sequence masks interrupts
// with cpsid i, so the RISC-V half of an RP2350 has neither the entry these ask
// for nor the instruction they use.  Serving picoboot from that core means an
// Ops of your own — picobootx itself is architecture-agnostic.
#[cfg(all(target_os = "none", not(target_arch = "arm")))]
compile_error!(
    "picobootx-rp2350's implementations are Arm-only: they ask the bootrom for \
     its Arm secure entries and mask interrupts with cpsid i"
);

pub mod bootrom;
mod chip;
mod defaults;
mod ops;

// The registers behind it are the part's own, so there is nothing to compile
// for a machine that is not one.  A USB stack that exposes its own halt
// control needs none of this.
#[cfg(target_os = "none")]
pub mod usb;

pub use defaults::{
    SERIAL_LEN, enter_xip, exclusive_access, exit_xip, flash_erase, flash_erase_prepare,
    flash_page_write, get_info, get_info_prepare, otp_read, otp_write, read, read_prepare,
    reboot_execute, reboot_prepare, serial, write, write_prepare,
};
pub use ops::Rp2350;

/// Where the bootrom answers from.
pub const ROM_BASE: u32 = 0x0000_0000;

/// How much of it there is — 32KB.
pub const ROM_SIZE: u32 = 0x0000_8000;

/// Where flash answers from, in execute-in-place.
pub const FLASH_BASE: u32 = 0x1000_0000;

/// The largest flash the part addresses — 32MB.
pub const FLASH_SIZE: u32 = 0x0200_0000;

/// Where SRAM answers from.
pub const SRAM_BASE: u32 = 0x2000_0000;

/// How much of it there is — 520KB.
pub const SRAM_SIZE: u32 = 0x0008_2000;
