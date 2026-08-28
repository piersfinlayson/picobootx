# Changelog — the C library

This is the C library in [src](src) and [include](include).  The Rust crates in
[rust](rust) carry their own versions and their own changelog, in
[rust/CHANGELOG.md](rust/CHANGELOG.md).

picobootx follows [semantic versioning](https://semver.org).  Releases before
1.0.0 may change the API in a minor version.

`PICOBOOTX_VERSION_MAJOR`, `PICOBOOTX_VERSION_MINOR` and
`PICOBOOTX_VERSION_PATCH` in [picobootx_version.h](include/picobootx_version.h)
carry the same version, so an integrator can compile against more than one
release.

## Unreleased

`PB_INFO_PARTITION` and `PB_INFO_UF2_TARGET` no longer read the partition table,
and system information is answered whole, so a device that has a partition table
or a small transmit FIFO serves those types itself.

- `picoboot_default_get_info_prepare` and `picoboot_default_get_info` use 32
  bytes of stack at most, where they each used 252.
- `PB_INFO_PARTITION` is answered with a constant — the flags asked for echoed
  back, no partitions, no partition table loaded, and all of flash
  unpartitioned and readable and writable by everyone.  A device with a real
  partition table must serve the type itself.
- `PB_INFO_UF2_TARGET` takes the two words behind its target from the same
  constant `PB_INFO_PARTITION` uses, so the unpartitioned space reads the same
  way whichever question a host asks.  It reads no partition table, and both
  types are answered on a part that publishes no bootrom routine.
- The buffer a data-in callback is handed is word aligned.
- `PICOBOOT_SYS_INFO_MAX_BYTES` is the longest system information answer, which
  `picoboot_default_get_info` produces in one call.  A
  `CFG_TUD_PICOBOOT_TX_BUFSIZE` smaller than it fails the build.
- `picoboot_ops_t.get_info` documents serving an answer in pieces from `ctx`,
  which the defaults cannot do.

## 0.3.0 - 2026-08-28

picobootx's `GET_INFO` answers did not match the RP2350 datasheet, so a host
reading them as specified read them wrong.  Fixing it replaced the operations
table's `GET_INFO` entry with a pair, which is not backwards compatible.

- `GET_INFO` for system information sends the flags word, and the leading count
  includes it.  Neither was sent before.
- A flag the device cannot answer is dropped, rather than the command being
  refused.
- `picoboot_ops_t` carries `get_info_prepare` and `get_info` in place of
  `get_info_sys`.
- The partition table, UF2 target partition and UF2 download status can be
  served.  The partition table used to answer five hardcoded words.
- `picoboot_default_get_info_prepare` and `picoboot_default_get_info` replace
  `picoboot_default_get_info_sys`.  They answer the UF2 target partition as
  nowhere and refuse the download status.
- A device-to-host transfer no longer sends more bytes than the host asked for.
- A data-in callback that declines the largest buffer the library hands over
  halts the command with `PB_STATUS_BUFFER_TOO_SMALL`, where the transfer
  previously went unfinished.
- `GET_INFO` is refused with `PB_STATUS_BUFFER_TOO_SMALL` where
  `dTransferLength` cannot hold the whole answer.
- An information type the library does not serve is refused with
  `PB_STATUS_INVALID_ARG` rather than `PB_STATUS_UNKNOWN_CMD`.
- `PICOBOOT_STATE_SIZE` is 80 bytes, four more than before.
- `PICOBOOT_GET_INFO_MAX_LEN` and `PICOBOOT_INFO_MAX_ANSWER_WORDS` say how long
  a `GET_INFO` transfer and its answer may be.
- `picoboot_default_read_prepare`, `picoboot_default_write_prepare` and
  `picoboot_default_flash_erase_prepare` accepted a range that wrapped the
  address space.
- [INTEGRATION.md](INTEGRATION.md) now says a C integrator's linker script and
  reset handler have to place and copy `.ramfunc`.

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
