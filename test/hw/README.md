# The hardware test

`picobootx-embassy` serving picoboot on a real RP2350, driven by a real host.

The conformance suites answer what the protocol does.  They cannot answer what
a USB controller does — data toggles, halts, a host that waits for what it is
owed before it sends again.  This is for that, and it found a deadlock the
suites and a hundred per cent of line coverage did not.

It is an instrument, not an example.  [examples/embassy](../../examples/embassy)
is the thing to copy when building a device.

## The two halves

- **`device/`** — the firmware.  picobootx-embassy over `Rp2350` and no custom
  commands, plus two vendor control requests of its own.  It presents as
  `2e8a:000f`, product string `RP2350 picobootx hwtest`.
- **`host/`** — three binaries.  `picobootx-hw-test` runs the checks,
  `picobootx-hw-bootsel` puts the board back in BOOTSEL, and
  `picobootx-hw-diag` prints what the protocol and its queues are doing.

Each refuses any device that does not answer to that product string, so none of
them can touch a stock RP2350 in the bootloader, or anything else on the bus.

## Running it

Build both halves:

    make hw-device hw-host

The board is jumpered into BOOTSEL **once**, by hand, for the first flash:

    picotool load -x test/hw/device/target/thumbv8m.main-none-eabi/release/picobootx-hw-device -t elf

After that it puts itself back, over USB, and the jumper is never needed again:

    test/hw/host/target/release/picobootx-hw-bootsel

That request is answered on the control endpoint, so it works even when the
bulk endpoints are halted or wedged — which is exactly when a reflash is
wanted.

Then:

    test/hw/host/target/release/picobootx-hw-test

## What it checks

A refusal and the recovery after it, which is the sequence a wire is needed to
judge: the board serves a read, a read of a peripheral address is refused, the
device reports the refusal on the control endpoint, the host clears both halts
and sends `INTERFACE RESET`, and the next read is served.

Every read is tried twice, and one that fails first and succeeds second is
reported as a failure.  That is the shape of a lost transfer — losing exactly
one packet puts both ends back in step, so a retry works and the whole thing
reads as flakiness.

**Clear both halts.** `INTERFACE RESET` clears them device-side either way
(RP2350 datasheet 5.6.5.1), but a host that leaves its own OUT endpoint halted
loses the first transfer after recovery, and the loss looks exactly like a
device fault.

## CI

CI builds both halves and runs neither.  Running them needs a board.
