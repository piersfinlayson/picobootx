// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! The default RP2350 implementations of what picobootx asks a device to do.
//!
//! Either use these, or write your own with these as a starting point.  They
//! are the whole of the porting problem: picobootx itself knows the protocol
//! and nothing about the part, and everything here that touches the part goes
//! through one place — see `chip`.
//!
//! Nothing below this reaches the chip through a peripheral access crate.  The
//! bootrom is read through raw pointers, so a routine the part does not publish
//! is a null the caller answers with [`picobootx::Status::NotFound`] rather than
//! a jump into nothing, and so the accesses have one place to be stood in for
//! when this is built for a machine that is not an RP2350.
//!
//! There are two ways in.  [`Rp2350`] is every one of these implementations as
//! a single `Ops`, for a device that serves the protocol on the part's own
//! terms throughout.  The free functions beside it are the same work a piece at
//! a time, so an `Ops` of your own can answer some commands its way and call
//! these for the rest.
//!
//! # Erasing flash needs `.ramfunc` placed in RAM
//!
//! An erase takes flash out of execute-in-place, so the part of the sequence
//! that runs while flash is unreadable is placed in the `.ramfunc` section.  A
//! section name places nothing on its own: the linker script decides where
//! `.ramfunc` lands, and the startup decides whether its bytes are carried
//! there.  A project missing either links without a warning, and what the erase
//! jumps into is a flash that has stopped answering or a RAM nothing filled.
//!
//! This crate ships the script that answers for it.  Add one flag beside the
//! one that reaches cortex-m-rt's script:
//!
//! ```text
//! # .cargo/config.toml
//! [target.thumbv8m.main-none-eabi]
//! rustflags = [
//!   "-C", "link-arg=-Tlink.x",
//!   "-C", "link-arg=-Tpicobootx.x",
//! ]
//! ```
//!
//! `picobootx.x` gives `.ramfunc` an address in RAM and a load address in
//! flash, and inserts it after cortex-m-rt's `.data`, so the copy the startup
//! already makes covers it.  With rust-lld, the default linker for the thumb
//! targets, that flag is the whole of it.
//!
//! ## Under GNU ld
//!
//! A project that links with `arm-none-eabi-gcc` or `arm-none-eabi-ld` cannot
//! use the flag.  GNU ld resolves `INSERT AFTER` only against the script it is
//! processing, so a `.data` defined by `link.x` is not visible to a
//! `picobootx.x` named by a second `-T`, and the link fails with
//! `.data not found for insert`.  Drop `-Tpicobootx.x` and put the same block
//! in your own `memory.x` — `link.x` does `INCLUDE memory.x`, which puts the
//! `INSERT` and the `.data` it names in one script:
//!
//! ```text
//! /* memory.x, after the MEMORY block */
//! SECTIONS
//! {
//!   .ramfunc : ALIGN(4)
//!   {
//!     . = ALIGN(4);
//!     *(.ramfunc .ramfunc.*);
//!     . = ALIGN(4);
//!   } > RAM AT>FLASH
//! } INSERT AFTER .data;
//! ```
//!
//! ## Or a script of your own
//!
//! A linker script of your own may place the section instead — give it an
//! address in SRAM and a load address in flash, and copy it before anything
//! erases flash.  A copy's length is a count of bytes, and a linker symbol
//! subtracted as a word type gives a count of words, which copies a quarter of
//! the section.
//!
//! Whichever of the three, [`flash_erase`] checks that the routine is resident
//! and that it holds what was linked, while flash still answers.  A build that
//! has not done both is refused with [`Status::PreconditionNotMet`], rather
//! than jumping into a bus that has stopped answering.
//!
//! [`Status::PreconditionNotMet`]: picobootx::Status::PreconditionNotMet

#![no_std]

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

pub use defaults::{
    enter_xip, exclusive_access, exit_xip, flash_erase, flash_erase_prepare, flash_page_write,
    get_info_sys, otp_read, otp_write, read, read_prepare, reboot_execute, reboot_prepare, serial,
    write, write_prepare,
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
