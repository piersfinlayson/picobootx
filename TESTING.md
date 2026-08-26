# Testing picobootx

[test](test) holds two conformance suites, and a bridge that puts picobootx on a
real USB bus so real host tools drive it.  All three compile picobootx for the
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
[picotool/tinyusb Quirks](README.md#picotooltinyusb-quirks).

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

[rust](rust) drives the same device with
[picoboot-rs](https://github.com/piersfinlayson/picoboot), the other
implementation of the PICOBOOT protocol:

```bash
make test-rust
```

Its checks mirror picotool's, so both host tools are held to the same claims.
The point is not the language — picotool reaches the kernel through libusb and
picoboot-rs through nusb, so a claim the two agree on is a claim about picobootx
rather than about either host.  It also reaches one thing picotool cannot: a
write asking an OTP bit to go back, which picotool refuses before it leaves the
host.  It needs a Rust toolchain, and nothing else in the tree refers to it.

The Rust crates carry tests of their own, which are not part of either suite:

```bash
make test-unit
```

The suites drive the Rust library through the C ABI, and that ABI hands every
operation over as a table of function pointers.  A table is either populated or
null, so nothing in the suites ever meets an `Ops` that left a method to its
default — which is the whole of the trait's "refuse by default" contract — and
nothing there holds an `Rp2350` as a Rust type either.  Those are the crates'
own tests, and they need a Rust toolchain.

`LIB=` chooses which picobootx is under test.  `LIB=c` is the C in
[src](src), and `LIB=rust` takes the protocol and the default RP2350
implementations from the Rust crates, leaving only the tinyusb vendor driver as
C.  Every scenario runs under both, and a defect one has and the other does not
shows up as a scenario that passes under one and fails under the other.

`make` on its own builds both suites without running them.  `make test-core` and
`make test-usb` run one.  Inside [test](test), `make SUITE=usb` selects the
second suite, `FILTER=stall` runs the scenarios whose suite name contains a
string, `LOGGING=1` builds with picobootx's own logging turned on, and
`SANITIZE=1` builds under the address and undefined behaviour sanitizers.
`make usbip TRACE=1` runs the bridge with every transfer traced.

`make cov` runs both suites under coverage, under both implementations, adds
the crates' own tests, and reports what they reached per file in one table —
the C's three sources and the Rust's eleven.  It gates twice.  The C fails below every line and every
function, and the few arms neither suite can reach are marked unreachable in the
source with lcov exclusion comments, each saying which invariant makes it so.
The Rust fails below the per-file floor in
[ci/coverage-baseline.txt](ci/coverage-baseline.txt), which `make cov-raise`
moves up and nothing moves down.  Branches are reported but not gated, since gcc
and llvm-cov do not agree on what counts as one.

`make cov-uncovered` lists the lines nothing reached, `make cov-html` writes the
C's figures as a browsable report.  Coverage needs lcov, and the Rust half needs
rustup's `llvm-tools` component for llvm-profdata and llvm-cov.
