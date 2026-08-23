# picobootx embassy Example

A complete, bare-metal picobootx device for the RP2350, using
[embassy](https://embassy.dev) as the USB stack and async runtime.  It is the
reference for building picobootx with embassy, the way
[examples/tinyusb](../tinyusb) is the reference for building it with tinyusb.

It presents a single vendor interface serving the picoboot protocol on the
standard RP2350 vendor and product, `2e8a:000f`, so
[picotool](https://github.com/raspberrypi/picotool),
[pico⚡flash](https://picoflash.org) and
[Rust picoboot](https://docs.rs/picoboot/latest/picoboot/) drive it with no
arguments.  On top of the protocol it serves two commands of its own — one
that sets the LED and one that returns a name — which is what the `x` in
picobootx is for.

## Build

The `thumbv8m.main-none-eabi` target is required.  Install it if it is not
there:

```bash
rustup target add thumbv8m.main-none-eabi
```

From this directory:

```bash
cargo build --release
```

which writes

```text
target/thumbv8m.main-none-eabi/release/picobootx-embassy-example
```

The target and the two link flags come from
[.cargo/config.toml](.cargo/config.toml), and one of those flags is
picobootx's.  `-Tpicobootx.x` reaches the linker fragment `picobootx-rp2350`
ships, which places the flash erase's critical part in RAM.  Without it the
link succeeds without a word and an erase jumps into a flash that has stopped
answering — see the crate's own documentation for what a project with a linker
script of its own does instead.

## Run

The RP2350 needs the ELF as a UF2 or loaded over its own bootloader.  With the
board in BOOTSEL:

```bash
picotool load -x target/thumbv8m.main-none-eabi/release/picobootx-embassy-example
```

and once it is running, any picoboot host reaches it:

```bash
picotool info -a
```

## The LED

`Commands` drives GPIO 25, which is the LED on a Raspberry Pi Pico 2.  A board
that puts its LED somewhere else needs that one pin changed in
[src/main.rs](src/main.rs).
