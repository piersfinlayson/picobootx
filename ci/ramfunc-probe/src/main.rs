// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! A program that links picobootx-rp2350's flash erase and does nothing else.
//!
//! It is never run.  The point is the ELF: `flash_erase` reaches
//! `erase_critical`, `erase_critical` is what `.ramfunc` holds, and a section
//! nothing reaches is a section the linker leaves out.  So the call is what
//! makes the check have something to look at.

#![no_std]
#![no_main]

use core::hint::black_box;
use core::panic::PanicInfo;

use cortex_m_rt::entry;

/// Initialised data, so `.data` has a size.
///
/// `.ramfunc` is loaded from flash immediately after `.data` and copied into
/// RAM by the same startup pass, so `ci/check-ramfunc.sh` compares the two
/// load addresses.  An empty `.data` makes that comparison hold whatever the
/// linker script does with the load region, which is a check that cannot
/// fail.  The value is written to from `main` because a static nothing reads
/// or writes is a static the linker drops.
static mut INITIALISED: [u32; 8] = [0xdead_beef; 8];

#[entry]
fn main() -> ! {
    // Through black_box, so nothing here can be folded away and take the
    // section with it.  The arguments are a flash sector, and the erase is
    // never reached on any part - this program is linked, not run.
    let addr = black_box(0x1000_0000u32);
    let size = black_box(0x0000_1000u32);
    black_box(picobootx_rp2350::flash_erase(addr, size)).ok();

    black_box(&raw mut INITIALISED);

    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
