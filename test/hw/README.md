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

Checks are grouped, and a group name runs the groups whose name contains it,
the way `FILTER=` does in the conformance suite:

    test/hw/host/target/release/picobootx-hw-test abandoned

## What it checks

**`refusal`** — a refusal and the recovery after it, which is the sequence a
wire is needed to judge: the board serves a read, a read of a peripheral
address is refused, the device reports the refusal on the control endpoint and
reports both endpoints halted, the host clears both halts and sends
`INTERFACE RESET`, and the next read is served.

Every read is tried twice, and one that fails first and succeeds second is
reported as a failure.  That is the shape of a lost transfer — losing exactly
one packet puts both ends back in step, so a retry works and the whole thing
reads as flakiness.

**Clear both halts.** `INTERFACE RESET` clears them device-side either way
(RP2350 datasheet 5.6.5.1), but a host that leaves its own OUT endpoint halted
loses the first transfer after recovery, and the loss looks exactly like a
device fault.

**`abandoned`** — a host that stops part way through a command leaves a reply
armed on the controller, where the protocol's own queues cannot reach it.  The
board is asked for one address, the reply is left uncollected, `INTERFACE
RESET` is sent, and a different address is asked for.  The answer has to be the
second address's.  The RP2350 boot ROM takes the packet back on the same
request, and this is that claim asked of picobootx.

**`multi-packet`** — transfers longer than the 64 bytes a full-speed bulk
endpoint carries.  A packet is where a USB device's bookkeeping lives, so every
question about it starts at the second one: whether the data toggle alternates
across a long transfer, whether one that is an exact number of packets ends
without the host waiting for more, and whether one that is not ends on the short
packet.  Reads are checked against the same bytes taken four at a time, so a
long transfer is judged against the device's own answer rather than against what
this test expects the ROM to hold.  Writes go to a window the device nominates —
every address the RP2350 defaults accept is otherwise the test firmware's own
memory or the flash it runs from — and are read back and compared.

The conformance suites cannot ask any of it.  They hand the library a byte
queue, and a queue has no packets in it.

**`get-info`** — what the device says about itself, and what it does with a
request it cannot answer.  The values come from the boot ROM rather than from
picobootx, so what is asked is not whether they are right but whether the device
assembles them correctly: the reply is a word saying how many words follow and
then each flag's words in the protocol's order, and asking for two flags at once
has to give exactly what asking for each separately gave.  A flag the part does
not carry is counted as no words.  The transfer length is the host's to state,
so a length of nothing, one that is not a whole number of words, and one longer
than the reply can be are each refused, as is an information type the protocol
does not name.

Whether the values themselves are right is a question for the boot ROM, on the
same part, and not one this group can answer.

## How it talks to the board

**It speaks the whole protocol.** Every device-to-host transfer is followed by
the acknowledgement the protocol calls for.  A host that leaves it out parks the
device part way through a command, where it stays across the host process
exiting — neither end of a USB bus is reset by a program ending — so the next
run measures the last one.

**Every run starts and ends quiet.** `INTERFACE RESET`, and a check that the
device came back with both queues empty, neither endpoint halted and nothing
armed.  A run that leaves something behind has set the next one up to fail for a
reason that is not its own.

**A halt is cleared only where the device reports one.** `CLEAR_FEATURE` of an
endpoint halt resets the host's data toggle for that endpoint, so clearing a
halt that was never set desynchronises a device whose driver does not reset its
own, and the next transfer is silently lost.  Both real PICOBOOT hosts ask
first — picotool with `GET_STATUS`, picoboot-rs from its own record of what it
saw halt — so a test that cleared unconditionally would be measuring a host
nobody has.

## CI

CI builds both halves and runs neither.  Running them needs a board.
