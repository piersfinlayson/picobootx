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

[test](test) holds two conformance suites, and a bridge that puts picobootx on a
real USB bus so real picotool drives it.  All three compile picobootx for the
machine you are on, with `PICOBOOTX_HOST_TEST` defined so the RP2350-specific
parts of [picobootx_impl.c](src/picobootx_impl.c) resolve to a model of the chip
rather than to hardware.  The code under test is the shipped code.  The two
suites need a C compiler and make, and run on macOS and Linux:

```bash
make test
```

The **core** suite drives [picobootx.c](src/picobootx.c) and
[picobootx_impl.c](src/picobootx_impl.c) through a stand-in for the USB
transport.  It covers command framing, the stall and unstall protocol, packet
boundaries, the device-to-host and host-to-device data phases, custom commands,
what a transport that refuses or truncates a transfer gets, what an integrator's
partial ops table does, how a bootrom routine that is absent or refuses is
reported, and the picotool accommodations described under
[picotool/tinyusb Quirks](#picotooltinyusb-quirks).

The **usb** suite adds [picobootx_vendor.c](src/picobootx_vendor.c) and runs the
lot against real tinyusb, pinned to a commit and built for a machine with no USB
hardware.  A device controller and a model of a USB host stand in for the
silicon and the bus, so a scenario says what a host did — enumerate, issue a
control request, send a bulk packet — and asserts what the device did in reply.
This is the only way the vendor driver runs at all: it is a tinyusb class
driver, and nothing below usbd can call it.  Enumeration, endpoint claiming, the
descriptor content picotool insists on, and the driver's own stall, unstall and
acknowledgement handling live here.

The **usbip** bridge takes that same device — real tinyusb, the real vendor
driver, the library, the modelled chip — and puts it on the machine's own USB
bus, through the kernel's virtual host controller.  The bus is a socket on the
loopback interface and the device exists nowhere, so picotool enumerates it,
claims its interface and speaks PICOBOOT to it without knowing any of that.
Released picotool, unmodified:

```bash
make test-usbip
```

It reads the device, walks the modelled bootrom's table for `info -a`, loads a
program and reads it back byte for byte, loads a second over the first to show
the erase happened, erases a range and finds ones, and blows and reads an OTP
row.  Linux only, since `vhci-hcd` is a Linux driver, and the run
needs root — loading the module and handing it a socket are both privileged.
Building it does not, so only the run is handed to `sudo`.

`make` on its own builds both suites without running them.  `make test-core` and
`make test-usb` run one.  Inside [test](test), `make SUITE=usb` selects the
second suite, `FILTER=stall` runs the scenarios whose suite name contains a
string, `LOGGING=1` builds with picobootx's own logging turned on, and
`SANITIZE=1` builds under the address and undefined behaviour sanitizers.
`make usbip TRACE=1` runs the bridge with every transfer traced.

`make cov` runs both suites under coverage, merges what each reached, reports it
per file for all three sources of the library, and fails below every line and
function.  Branches are reported but not gated, since gcc and llvm-cov do not
agree on what counts as one.  The few arms neither suite can reach are marked
unreachable in the source with lcov exclusion comments, each saying which
invariant makes it so.  `make cov-html` writes the same as a browsable report.
Both need lcov.

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
