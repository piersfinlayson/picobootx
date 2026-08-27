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

### Unreleased

`GET_INFO` answers did not match the RP2350 datasheet, so a host reading them as
specified read them wrong.  Fixing it replaced `Ops`'s `GET_INFO` methods with a
pair, which is not backwards compatible.

- `GET_INFO` for system information sends the flags word, and the leading count
  includes it.  Neither was sent before.
- A flag the device cannot answer is dropped, rather than the command being
  refused.
- `Ops` carries `get_info_prepare` and `get_info` in place of `get_info_sys`
  and `get_info_sys_prepare`.
- The partition table, UF2 target partition and UF2 download status can be
  served.  The partition table used to answer five hardcoded words.
- A device-to-host transfer no longer sends more bytes than the host asked for.
- `GET_INFO` is refused with `Status::BufferTooSmall` where the transfer length
  cannot hold the whole answer.
- An information type the library does not serve is refused with
  `Status::InvalidArg` rather than `Status::UnknownCmd`.
- `Info` names the four information types the protocol defines.
- `wire::GET_INFO_MAX_LEN` and `wire::INFO_MAX_ANSWER_WORDS` say how long a
  `GET_INFO` transfer and its answer may be.  `wire::INFO_MAX_WORDS` is gone.

### 0.1.0 - 2026-08-26

The device side of the PICOBOOT protocol, knowing nothing about a part, a USB
stack or an executor.

## picobootx-rp2350

### Unreleased

- `get_info_prepare` and `get_info` replace `get_info_sys`.  They answer system
  and partition table information by passing the ROM's routines through.
- They answer the UF2 target partition as nowhere, and refuse the UF2 download
  status.
- `Rp2350` serves `GET_INFO` for the partition table, through
  `get_partition_table_info`.

### 0.1.0 - 2026-08-26

## picobootx-embassy

### Unreleased

- Tracks `picobootx`'s `GET_INFO` operations change.  A device handing
  `PicobootClass::new` an `Ops` of its own writes the new pair.

### 0.1.0 - 2026-08-26

picobootx for a device whose USB stack is embassy-usb.
