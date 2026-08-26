# picobootx

The device side of the PICOBOOT protocol, so firmware that is **not** a
bootloader can be driven by [picotool] and every other picoboot host tool.

`no_std`, no allocator, and no dependencies. Nothing here assumes an RP2350, a
USB stack or an executor: what talks to the wire is a trait you implement, and
so is what the commands do.

## What it is for

PICOBOOT is how a host reads and writes an RP2040 or RP2350 in BOOTSEL mode.
This library lets an application speak it while it is running, so a device can
be inspected, reprogrammed and rebooted without being put into the bootloader
first — and can extend the protocol with commands of its own.

## Using it

Three pieces: what your device does, how bytes reach the wire, and a loop.

```rust,no_run
use picobootx::{Endpoints, Ops, Picoboot, Result, Status};

struct MyDevice;
# fn in_range(_addr: u32, _size: u32) -> bool { true }

// Every method has a default, so this is already a complete implementation —
// of a device that refuses everything. Write a method and that command starts
// working.
impl Ops for MyDevice {
    fn read_prepare(&mut self, addr: u32, size: u32) -> Result {
        if in_range(addr, size) { Ok(()) } else { Err(Status::InvalidAddress) }
    }

    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result {
        // ... fill buf from addr
        Ok(())
    }
}
```

A `_prepare` method promises the operation beside it. The library calls the
prepare before any data moves and takes its answer as "does this device serve
this command", so writing `read_prepare` and leaving `read` to its default is a
device that accepts a transfer it then abandons.

Then implement [`Transport`] over your USB stack's two bulk endpoints, and turn
the handle:

```rust,ignore
let mut pb = Picoboot::new(
    MyDevice,
    picobootx::NoCustom,
    Some(&mut flash_page),           // a 256-byte page buffer, for flash writes
    Endpoints { out: 0x03, r#in: 0x83 },
);

loop {
    usb.poll();
    pb.poll(&mut transport);
}
```

Tell it what the USB stack saw:

- [`Picoboot::on_rx`] when bytes arrive on the OUT endpoint
- [`Picoboot::on_tx`] when a transmission finishes
- [`Picoboot::on_control`] for a control request, whose answer you pass back to
  your stack

## Commands of your own

Give [`Custom`] a magic that is not [`wire::MAGIC`] and the command identifiers
are entirely yours, with no risk of colliding with PICOBOOT's now or later. A
command may complete with no data, or return as much as it likes to the host.

## Descriptors

picotool expects the picoboot interface to be class `0xFF`, subclass `0x00`,
protocol `0x00`, at interface 0 if the device has one interface or interface 1
if it has more, with `bMaxPacketSize0` of 64. Neither this library nor the
specification can enforce that, and picotool will not recognise a device that
gets it wrong.

## Companion crates

- `picobootx-rp2350` — the RP2350 operations, ready to use or to start from
- `picobootx-embassy` — the embassy-usb half, for a device on that stack

## Licence

MIT.

[picotool]: https://github.com/raspberrypi/picotool
