# picobootx-embassy

Device-side [PICOBOOT](https://github.com/piersfinlayson/picobootx) for a
device whose USB stack is [embassy-usb](https://docs.embassy.dev/embassy-usb).
It answers `picotool`, [pico⚡flash](https://picoflash.org) and any other
picoboot host, alongside whatever else the device is doing.

`picobootx` itself is the protocol and knows nothing about a USB stack.  This
crate is the half that does: a task that drives the two bulk endpoints, a
`picobootx::Transport` over the queues that task fills, and an
`embassy_usb::Handler` that answers picoboot's control requests.

Written against **embassy-usb 0.6** and **embassy-usb-driver 0.2**.

## What a device supplies

Three things, and the first two are picobootx's rather than this crate's.

- **`picobootx::Ops`** — what the device does when a host asks it something.
  `picobootx-rp2350`'s `Rp2350` is every one of them for an RP2350.
- **`picobootx::Custom`** — commands of the device's own, if it has any.
  `picobootx::NoCustom` if it has none.
- **`EndpointControl`** — how the device halts one of its bulk endpoints, how
  it tells a packet the host has taken from one merely armed, and how it takes
  an armed one back.  embassy-usb keeps the halt control on
  `embassy_usb_driver::Bus`, which `UsbDevice` owns and does not lend out, and
  reports none of the rest, so this cannot come from the stack.  On an RP2350
  it is `Rp2350EndpointControl`, and on another part it is the device's to
  write.

## The `rp2350` feature

Off by default.  Turning it on brings in `picobootx-rp2350` and with it
`Rp2350EndpointControl`, which reaches the RP2350's own endpoint buffer control
words — the calls every embassy device on that part would otherwise write out
itself.

```toml
picobootx-embassy = { version = "0.1", features = ["rp2350"] }
```

The type is compiled only for a build for the part, since the registers behind
it exist nowhere else.

## Wiring it up

Allocate a vendor interface with two bulk endpoints, build a `PicobootClass`
over them, and run its task alongside the USB device's:

```ignore
let mut picoboot = PicobootClass::new(
    Rp2350,
    NoCustom,
    Some(&mut flash_page),
    Endpoints { out: 0x01, r#in: 0x81 },
    64,
    Rp2350EndpointControl,
);

let mut handler = picoboot.handler();
builder.handler(&mut handler);

let mut usb = builder.build();
join(usb.run(), picoboot.run(ep_out, ep_in)).await;
```

`examples/embassy` in the repository is a complete device built this way.

The two addresses and the packet size are given to `new` because the control
handler needs them and the host may reach it first.  `run` then takes all
three from the endpoints it is handed, since that is what the driver
allocated, so a value that disagrees is corrected rather than acted on.

## Reading what it is doing

`PicobootClass::diagnostics()` returns a `Diagnostics`: the protocol's state,
what each queue is holding, whether either endpoint is halted, and whether a
packet is armed and not yet taken.  Every field is read under one borrow, so
it is a picture of one moment rather than several.

It changes nothing.  A device answers it over a control request, a log or a
light — a control request being the useful one, since it is answerable while
the bulk endpoints are halted, which is when the answer is wanted.

## Three things worth knowing

**Both halves run on one executor.** The control handler and the driver task
each need the protocol and the queues, and they take turns through a
`RefCell`.  That makes a `PicobootClass` `!Sync`, so the compiler refuses to
put the two halves on separate executors rather than letting them race.

**A halt is recovered at `INTERFACE RESET`.** embassy-usb answers
`CLEAR_FEATURE(ENDPOINT_HALT)` itself and reports it to no handler, and a
driver is free to leave the endpoint's data toggle and receive buffer wherever
the halt left them.  The vendor `INTERFACE RESET` does reach a handler, and the
RP2350 datasheet (5.6.5.1) has it clear the halt on both bulk endpoints anyway,
so that is where `EndpointControl::resync` is called — for the endpoints
picoboot halted, and no others.  A host may send `CLEAR_FEATURE` first and need
not, and it also sends `INTERFACE RESET` to begin a session, where resyncing an
endpoint that never halted would put its toggle somewhere the host has not.

**An uncollected reply is taken back at `INTERFACE RESET` too.** A host that
stops part way through a command leaves a packet armed on the controller, and
the protocol's own queues are not where that packet is — emptying them reaches
everything except it.  Left there it is handed to whoever reads next, who gets
the previous session's answer to a question it never asked and is one command
behind from then on.  So `EndpointControl::retract` is called for the
device-to-host endpoint, which is what the RP2350 boot ROM does with the same
request.  It undoes the arming rather than resetting anything: arming a packet
advances the recorded data toggle, and a host that never saw that packet is
still waiting for its number.
