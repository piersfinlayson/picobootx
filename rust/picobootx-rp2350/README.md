# picobootx-rp2350

What an RP2350 does when a picoboot host asks it something — the device
operations [`picobootx`] leaves to you, written for the part.

`no_std`, no allocator, and nothing under it but raw pointers: no
peripheral access crate, no HAL, no SDK.

Either use these, or write your own with these as a starting point. They are
the whole of the porting problem: `picobootx` knows the protocol and nothing
about the part, and everything that touches the part is here.

## Erasing flash needs `.ramfunc` placed in RAM

An erase takes flash out of execute-in-place, so the part of the sequence that
runs while flash is unreadable is placed in the `.ramfunc` section. A section
name places nothing on its own: the linker script decides where `.ramfunc`
lands, and the startup decides whether its bytes are carried there. A project
missing either links without a warning, and what the erase jumps into is a flash
that has stopped answering or a RAM nothing filled.

This crate ships the script that answers for it. Add one flag beside the one
that reaches cortex-m-rt's script:

```toml
# .cargo/config.toml
[target.thumbv8m.main-none-eabi]
rustflags = [
  "-C", "link-arg=-Tlink.x",
  "-C", "link-arg=-Tpicobootx.x",
]
```

`picobootx.x` gives `.ramfunc` an address in RAM and a load address in flash,
and inserts it after cortex-m-rt's `.data`, so the copy the startup already
makes covers it. With rust-lld, the default linker for the thumb targets, that
flag is the whole of it.

### Under GNU ld

A project that links with `arm-none-eabi-gcc` or `arm-none-eabi-ld` cannot use
the flag. GNU ld resolves `INSERT AFTER` only against the script it is
processing, so a `.data` defined by `link.x` is not visible to a `picobootx.x`
named by a second `-T`, and the link fails with `.data not found for insert`.
Drop `-Tpicobootx.x` and put the same block in your own `memory.x` — `link.x`
does `INCLUDE memory.x`, which puts the `INSERT` and the `.data` it names in one
script:

```text
/* memory.x, after the MEMORY block */
SECTIONS
{
  .ramfunc : ALIGN(4)
  {
    . = ALIGN(4);
    *(.ramfunc .ramfunc.*);
    . = ALIGN(4);
  } > RAM AT>FLASH
} INSERT AFTER .data;
```

### Or a script of your own

A linker script of your own may place the section instead — give it an address
in SRAM and a load address in flash, and copy it before anything erases flash. A
copy's length is a count of bytes, and a linker symbol subtracted as a word type
gives a count of words, which copies a quarter of the section.

Whichever of the three, `flash_erase` checks that the routine is resident and
that it holds what was linked, while flash still answers. A build that has not
done both is refused with `Status::PreconditionNotMet`, rather than jumping into
a bus that has stopped answering.

## Using it

Two ways in, and they are meant to be mixed.

`Rp2350` is the whole set as one `Ops`, for a device that serves the protocol on
the part's own terms throughout:

```rust,no_run
use picobootx::{Endpoints, Picoboot};
use picobootx_rp2350::Rp2350;

# let mut flash_page = [0u8; picobootx::wire::FLASH_PAGE_SIZE];
let mut pb = Picoboot::new(
    Rp2350,
    picobootx::NoCustom,
    Some(&mut flash_page),           // a 256-byte page buffer, for flash writes
    Endpoints { out: 0x03, r#in: 0x83 },
);
```

The free functions beside it are the same work a piece at a time, so an `Ops` of
your own can answer some commands its way and call these for the rest — a device
that keeps a host out of its own flash while still serving reads, say:

```rust,no_run
# use picobootx::{Ops, Result};
# struct MyDevice;
impl Ops for MyDevice {
    fn read_prepare(&mut self, addr: u32, size: u32) -> Result {
        picobootx_rp2350::read_prepare(addr, size)
    }

    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result {
        picobootx_rp2350::read_prepare(addr, buf.len() as u32)?;
        // SAFETY: the line above is what establishes the range.
        unsafe { picobootx_rp2350::read(addr, buf) }
    }
}
```

`read` and `write` are the two unsafe ones. Each serves a range its `_prepare`
accepted and checks nothing itself, which is what lets the library check a
transfer once and then move it a packet at a time. `Rp2350` runs the check
again, because a trait method anyone can call carries no such promise.

There is also `serial`, which is not an `Ops` method: it writes the part's
identifier as UTF-16 for a USB string descriptor.

## What it reaches

Everything the part offers arrives through its bootrom, looked up by
two-character code — reboot, OTP access, system information, and the flash erase
and program routines. `bootrom` publishes those lookups and the mapping from the
bootrom's error numbers to a picoboot status, for a device that wants to call
one directly.

A routine the part does not publish is a `None` the caller answers with
`Status::NotFound`, so a missing routine is a status a host reads back rather
than a jump through a null pointer.

The part of an erase that runs while flash is unreadable runs from RAM — see
the linker script above — and with interrupts masked. It reaches nothing outside
itself: the bootrom routines it needs are looked up before any of it starts and
handed to it as arguments.

## Which core

Arm. The bootrom entries these ask for are the Arm secure ones and the interrupt
mask is `cpsid i`, so a bare-metal build for the RP2350's RISC-V half is refused
at compile time. `picobootx` itself has no such tie.

## Building for a host

Every access to the chip goes through one module, and a target that is not
bare metal takes the other half of it: five `picobootx_host_test_*` functions
the program around the library supplies. Those are the same five names
`include/picobootx_impl.h` declares under `PICOBOOTX_HOST_TEST`, so picobootx's
conformance suite drives this crate and the C it was ported from through one
harness.

## Licence

MIT.

[`picobootx`]: https://crates.io/crates/picobootx
