# picobootx

picobootx is an open source device-side implementation of the PICOBOOT protocol, written in C.  The protocol and original device-side PICOBOOT implementation was developed by Raspberry Pi and is included in the RP2040 and RP2350 boot ROMs.

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

## Features

- Compatible with Raspberry Pi's picotool. 
- Compatible with third-party picoboot host tools, including [pico⚡flash](https://picoflash.org) and the [Rust picoboot crate](https://docs.rs/picoboot/latest/picoboot/).
- Extremely low resource usage.  Memory for picoboot can be allocated either statically or dynamically, with a choice of how much memory to allocate.
- Flexible USB implementation allows other (non-vendor) interfaces to be exposed alongside picoboot.
- Allows the PICOBOOT protocol to be extended with custom commands following the overall PICOBOOT commands structure, using a custom magic value in the header.  The command ID space is yours entirely, and a custom command can either complete with no data phase, or return data of any length to the host.  (Host to device data phases for custom commands are not yet supported - see [Limitations](#limitations).)
- No dependency on Raspberry Pi's Pico SDK.
- 100% code coverage of the core function via included unit test suite.

## Getting Started

See [the integration guide](INTEGRATION.md) for how to integrate picobootx into your own project.

See [the tinyusb example](examples/tinyusb/README.md) for a complete, working, bare-metal picobootx implementation using tinyusb and [pico-sdkless](https://github.com/piersfinlayson/pico-sdkless), which can be used as a reference for your own implementation.

## PICOBOOT Protocol

The PICOBOOT protocol is documented in the RP2040 and RP2350 datasheets.  picobootx follows the RP2350 datasheet, and does not currently fully implement RP2040 support.

## USB stack integration

picobootx comes pre-integrated with tinyusb, and is intended to replace tinyusb's default vendor device implementation as tinyusb's vendor device implementation has some limitations that make it unsuitable for picoboot protocol support, including:
- no support for stalling/unstalling endpoints
- no ability to send a ZLP (zero length packet) on demand as required by the protocol.

The heart of picobootx should be USB stack agnostic, though and easy to port to other USB stacks (or even other physical layers).

## Testing

[test](test) holds a conformance suite covering command framing, the stall and
unstall protocol, packet boundaries, the device-to-host and host-to-device data
phases, custom commands, what a transport that refuses or truncates a transfer
gets, what an integrator's partial ops table does, how a bootrom routine that is
absent or refuses is reported, and the picotool accommodations described under
[picotool/tinyusb Quirks](#picotooltinyusb-quirks).

It compiles picobootx's core and its default implementations for the machine you
are on, with `PICOBOOTX_HOST_TEST` defined so the RP2350-specific parts of
[picobootx_impl.c](src/picobootx_impl.c) resolve to a model of the chip rather
than to hardware, and runs them against a stand-in for the USB transport.  The
code under test is the shipped code.  It needs a C compiler and make, and runs
on macOS and Linux:

```bash
make test
```

`make` on its own builds the suite without running it.  `make test
FILTER=stall` runs one suite.  `make test LOGGING=1` builds with picobootx's own
logging turned on.  `make test SANITIZE=1` builds under the address and
undefined behaviour sanitizers.

`make cov` runs the suite under coverage, reports how much of
[picobootx.c](src/picobootx.c) and [picobootx_impl.c](src/picobootx_impl.c) it
reached, and fails below every line and function of both.  Branches are reported
but not gated, since gcc and llvm-cov do not agree on what counts as one.  The
few arms the suite cannot reach are marked unreachable in the source with lcov
exclusion comments, each saying which invariant makes it so.  `make cov-html`
writes the same as a browsable report.  Both need lcov.
[picobootx_vendor.c](src/picobootx_vendor.c) is not in this build and so is not
in the figures — it is the tinyusb vendor driver the suite replaces with a
stand-in, and it is compiled by [examples/tinyusb](examples/tinyusb).

## Limitations

Current limitations include:
- No explicit RP2040 support
- Only a single vendor interface is supported by the vendor implementation
- Custom commands cannot receive a host to device data payload.  A custom command with a non-zero transfer length and the direction bit clear is stalled with `PB_STATUS_UNKNOWN_CMD`.  Device to host data is supported, via the optional `fill` callback in `picoboot_custom_ops_t`.

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
