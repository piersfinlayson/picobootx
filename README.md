# picobootx

picobootx is an open source device-side implementation of the PICOBOOT protocol, in C and in Rust.  The protocol and original device-side PICOBOOT implementation was developed by Raspberry Pi and is included in the RP2040 and RP2350 boot ROMs.

picobootx extends picoboot, hence the "x", by allowing:
- picoboot to be supported within a device's application code, not just the bootloader
- the picoboot protocol to be supported on devices other than the RP2040 and RP2350
- the specific firmware using picobootx to customise which picoboot commands are supported, and how 
- the protocol to be extended arbitrarily and, effectively, infinitely.

picobootx is compatible with picotool, Raspberry Pi's command line tool for flashing and managing RP2040 and RP2350 based devices in BOOTSEL mode.  However, picotool can _also_ manage any device running picobootx, which opens up management of the device by picotool when _not_ in BOOTSEL mode. 

picobootx also interoperates with third-party host tools that support picoboot, including:
- [pico⚡flash](https://picoflash.org) - A picoboot implementation that runs in a WebUSB capable browser, allowing you to drive the picoboot protocol from a web page.  No host software installation required, and works on macOS, Linux, Windows and Android using Chrome.
- [Rust picoboot](https://docs.rs/picoboot/latest/picoboot/) - A Rust library for implementing picoboot host tooling, which can be used to build custom host applications that interact with picoboot devices.

picobootx is used by [One ROM](https://onerom.org), the most flexible replacement ROM for your retro system, for live reprogramming and control of One ROM.  One ROM is from the same author as picobootx.

## The two implementations

Both speak the same protocol, and every conformance scenario runs against both, so the two agree rather than merely both passing.  Pick by what the firmware around them is written in.

- **C** — [src](src) and [include](include).  Vendored by `git clone` at a tag.  It comes pre-integrated with tinyusb, replacing tinyusb's own vendor device implementation.  [INTEGRATION.md](INTEGRATION.md) is its integration guide, and [examples/tinyusb](examples/tinyusb/README.md) a complete device.
- **Rust** — [rust](rust), three crates on crates.io.  `picobootx` is the protocol, knowing nothing about a part or a USB stack.  `picobootx-rp2350` is what an RP2350 does when a host asks it something.  `picobootx-embassy` is the embassy-usb half, and [examples/embassy](examples/embassy/README.md) a complete device built on it.

The two are versioned and released independently — [CHANGELOG.md](CHANGELOG.md) and [rust/CHANGELOG.md](rust/CHANGELOG.md), by way of [RELEASE.md](RELEASE.md).  A version number shared between them means nothing.

## Features

- Compatible with Raspberry Pi's picotool. 
- Compatible with third-party picoboot host tools, including [pico⚡flash](https://picoflash.org) and the [Rust picoboot crate](https://docs.rs/picoboot/latest/picoboot/).
- Extremely low resource usage, and no allocator.  In C the state block is yours to place statically or dynamically, with a choice of how much memory to give it, and in Rust the `Picoboot` value is yours to place the same way.  The 256-byte page buffer a flash write needs is optional in both.
- Flexible USB implementation allows other (non-vendor) interfaces to be exposed alongside picoboot.
- Allows the PICOBOOT protocol to be extended with custom commands following the overall PICOBOOT commands structure, using a custom magic value in the header.  The command ID space is yours entirely, and a custom command can either complete with no data phase, or return data of any length to the host.  (Host to device data phases for custom commands are not yet supported - see [Limitations](#limitations).)
- No dependency on Raspberry Pi's Pico SDK.
- Every line and every function of the C covered by the included conformance suite, and the Rust held to a per-file floor by the same run.

## Getting Started

**In C**, see [the integration guide](INTEGRATION.md) for how to integrate picobootx into your own project, and [the tinyusb example](examples/tinyusb/README.md) for a complete, working, bare-metal picobootx implementation using tinyusb and [pico-sdkless](https://github.com/piersfinlayson/pico-sdkless), which can be used as a reference for your own implementation.  `make example` builds it.

**In Rust**, add the crates you need and see their documentation on [docs.rs](https://docs.rs/picobootx) — `picobootx` for the protocol, `picobootx-rp2350` for the RP2350 operations, `picobootx-embassy` for a device on embassy-usb.  [The embassy example](examples/embassy/README.md) is the same device as the tinyusb one, built on [embassy](https://embassy.dev), and `make example-embassy` builds it.

## PICOBOOT Protocol

The PICOBOOT protocol is documented in the RP2040 and RP2350 datasheets.  picobootx follows the RP2350 datasheet, and does not currently fully implement RP2040 support.

## USB stack integration

picobootx comes pre-integrated with tinyusb, and is intended to replace tinyusb's default vendor device implementation as tinyusb's vendor device implementation has some limitations that make it unsuitable for picoboot protocol support, including:
- no support for stalling/unstalling endpoints
- no ability to send a ZLP (zero length packet) on demand as required by the protocol.

The heart of picobootx is intended to be USB stack agnostic and easy to port to other USB stacks (or even other physical layers).

The Rust picobootx in [rust](rust) is integrated with embassy-usb by the `picobootx-embassy` crate, which supplies the driver task, the transport and the control handler that embassy-usb asks a class for.  [examples/embassy](examples/embassy/README.md) is a whole device built on it, and [test/hw](test/hw/README.md) is the firmware and host driver that exercise it on a real board.

## Testing

Two conformance suites, a bridge that puts picobootx on a real USB bus for real
host tools, and the crates' own tests.  Everything compiles for the machine you
are on, so none of it needs a board:

```bash
make test
```

[TESTING.md](TESTING.md) is what each suite covers, how to run one on its own,
and how coverage is measured and gated.

## Limitations

Current limitations include:
- No explicit RP2040 support
- Only a single vendor interface is supported by the C tinyusb vendor implementation
- Custom commands cannot receive a host to device data payload.  A custom command with a non-zero transfer length and the direction bit clear is stalled with `PB_STATUS_UNKNOWN_CMD` in C, `Status::UnknownCmd` in Rust.  Device to host data is supported, via the optional `fill` callback in `picoboot_custom_ops_t` and `Custom::fill` respectively.

## License

picobootx is licensed under the MIT License.  See [LICENSE](LICENSE) for details.

## picotool/tinyusb Quirks

Some notable quirks were discovered in picotool and tinyusb during picobootx's development, which are documented here.  picobootx works around all of these quirks, providing a fully compatible implementation.

### picotool Specification Deficiencies

- picotool requests a dTransferLength of 256 bytes on GET_INFO command.  The spec states:

  "dTransferLength the size of data to be received. Note this must be a multiple of 4, and less than 256"

  This is a clear bug, either in picotool or the specification as 256 is not less than 256.

- picotool expects the picoboot vendor interface to be interface 0 (if the descriptor contains a single interface) or 1 (if the descriptor contains two interfaces).  The spec states:

  "Don’t rely on the interface number, because that is dependent on whether the device is currently exposing the Mass Storage Interface."

  It seems clear that picotool has assumed there will only be two interfaces, and it could be argued that picotool is strictly followed the spec, albeit unhelpfully.  However, it is hard to correlate what the spec says ("don't rely on the interface number") with its behaviour (relying on the interface number being 0 or 1).  If the interface will always be 0 or 1, the spec should say so, so other tools and implementations can rely on the same assumption.

- Even though, in a multi-interface configuration, picotool uses interface 1, it still insists the interface 0 has bInterfaceClass of 0xFF (vendor specific), bInterfaceSubClass of 0x00, and bInterfaceProtocol of 0x00, or it will not recognise the device as a RP2040/2350.

### tinyusb Wrinkles

- tinyusb appears not to provide any easy/proper/supported way for devices to stall/unstall their own endpoints.  tinyusb has been forked and picobootx builds against that fork.
