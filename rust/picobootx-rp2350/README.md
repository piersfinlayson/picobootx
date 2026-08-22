# picobootx-rp2350

What an RP2350 does when a picoboot host asks it something — the device
operations [`picobootx`] leaves to you, written for the part.

`no_std`, no allocator, and nothing under it but raw pointers: no
peripheral access crate, no HAL, no SDK.

## Using it

Two ways in, and they are meant to be mixed.

`Rp2350` is the whole set as one `Ops`, for a device that serves the protocol on
the part's own terms throughout:

```rust,ignore
use picobootx::{Endpoints, Picoboot};
use picobootx_rp2350::Rp2350;

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

```rust,ignore
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

Erasing flash means taking flash out of execute-in-place, so the part of it that
runs while flash is unreadable is placed in RAM and runs with interrupts masked.
It reaches nothing outside itself: the bootrom routines it needs are looked up
before any of it starts and handed to it as arguments.

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
