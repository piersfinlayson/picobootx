# Changelog

picobootx follows [semantic versioning](https://semver.org).  Releases before
1.0.0 may change the API in a minor version.

`PICOBOOTX_VERSION_MAJOR`, `PICOBOOTX_VERSION_MINOR` and
`PICOBOOTX_VERSION_PATCH` in [picobootx_version.h](include/picobootx_version.h)
carry the same version, so an integrator can compile against more than one
release.

## Unreleased

- Added the Rust `picobootx-embassy`, which serves picoboot on a device whose
  USB stack is embassy-usb — a task driving the two bulk endpoints, a transport
  over the queues it fills, and an `embassy_usb::Handler` for picoboot's control
  requests.  [examples/embassy](examples/embassy) is a complete device built on
  it.  Its `rp2350` feature supplies `Rp2350Halt`, the halt control embassy-usb
  does not hand out, so a device on that part need not write it.
- `picobootx-rp2350` gained a `usb` module reaching the RP2350's endpoint
  buffer controls, for a USB stack that does not lend out its own halt control.
- The Rust `picobootx-rp2350` needs `-C link-arg=-Tpicobootx.x` beside
  `-Tlink.x` to place its flash erase routine in RAM.  Without it the routine
  linked into flash and stopped part way through an erase.
- [INTEGRATION.md](INTEGRATION.md) now says a C integrator's linker script and
  reset handler have to place and copy `.ramfunc`.
- `picoboot_default_get_info_sys` read past its own buffer for a request of 17
  to 19 bytes, reachable only by an integrator calling it directly.
- `picoboot_default_read_prepare`, `picoboot_default_write_prepare` and
  `picoboot_default_flash_erase_prepare` accepted a range that wrapped the
  address space.

## 0.2.0 - 2026-08-17

The first tagged release.  Everything up to this point — the picoboot state
machine, the tinyusb vendor device replacement, the default RP2350 command
implementations, flash erase and write support, and custom commands with a
device-to-host data phase — is what 0.2.0 contains.

- `GET_COMMAND_STATUS` now answers for a command that is still running, naming
  its identifier and token and reporting it as in progress.  It previously
  answered with the last command the host had acknowledged, which told a host
  diagnosing a transfer about a different command.
- Added a conformance suite in [test](test), which runs picobootx's core and its
  default implementations natively against a model of an RP2350 and a stand-in
  for the USB transport.  It needs a C compiler and make, and runs on macOS and
  Linux.  `make cov` gates on the suite reaching every line, function and branch
  of [picobootx.c](src/picobootx.c) and
  [picobootx_impl.c](src/picobootx_impl.c), bar the arms marked unreachable in
  the source.
- Added `PICOBOOTX_HOST_TEST` seams to
  [picobootx_impl.h](include/picobootx_impl.h), covering the bootrom table
  lookup, the QMI clock divisor, interrupt masking, placing a function in RAM,
  and device memory access.  A build for a device does not define
  `PICOBOOTX_HOST_TEST` and is unaffected.
- Added [picobootx_version.h](include/picobootx_version.h), which has no
  dependencies and can be included on its own.
- picobootx no longer includes `pico.h`.  The three QMI register constants it
  was included for are now declared in
  [picobootx_impl.h](include/picobootx_impl.h), so the library builds against
  tinyusb and the C standard library alone.  This was never a dependency on
  Raspberry Pi's Pico SDK, but it was an undeclared dependency on a header
  [picobootx.mk](picobootx.mk) does not provide.
