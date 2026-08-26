# Changelog — the Rust crates

This is the three crates in this directory.  The C library in [src](../src) and
[include](../include) carries its own version and its own changelog, in
[CHANGELOG.md](../CHANGELOG.md).

The three are versioned independently, so each has a section of its own here,
newest first within it.  They follow [semantic versioning](https://semver.org),
and before 1.0.0 a minor version may change the API.

`picobootx-rp2350` and `picobootx-embassy` both put `picobootx`'s own types in
their signatures, so a consumer holding two versions of `picobootx` gets types
that do not unify.  A `picobootx` release therefore moves both of them too.

[RELEASE.md](../RELEASE.md) is how a release is made.

## picobootx

### 0.1.0 - 2026-08-26

The device side of the PICOBOOT protocol, knowing nothing about a part, a USB
stack or an executor.

## picobootx-rp2350

### 0.1.0 - 2026-08-26

What an RP2350 does when a host asks it something, as the operations
`picobootx` leaves to a consumer.

## picobootx-embassy

### 0.1.0 - 2026-08-26

picobootx for a device whose USB stack is embassy-usb.
