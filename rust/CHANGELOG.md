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

### 0.3.0 - 2026-08-28

`Transport` gains a required associated const, so every implementor has to
declare its transmit buffer's size.  That is not backwards compatible.

- `Transport::TX_CAPACITY` is how many bytes the transmit FIFO holds.  It has
  no default, so an implementor cannot skip it.
- `Ops::MIN_TX_CAPACITY` is the room an `Ops` needs offered in a single call,
  defaulting to none.
- `Picoboot::poll` fails the build where the transport cannot hold what the
  operations answer whole, rather than leaving the transfer to make no
  progress.
- The buffer a data-in fill is handed is word aligned.
- `Ops::get_info` documents serving an answer in pieces from `&mut self`.

### 0.2.0 - 2026-08-28

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
- A data-in callback that declines the largest `buf` the library hands over
  halts the command with `Status::BufferTooSmall`, where the transfer
  previously went unfinished.

### 0.1.0 - 2026-08-26

The device side of the PICOBOOT protocol, knowing nothing about a part, a USB
stack or an executor.

## picobootx-rp2350

### 0.3.1 - 2026-08-30

- `flash_page_write` no longer refuses a page buffer outside SRAM.  Where that
  buffer lives is the caller's — the USB controller's RAM and the boot RAM are
  both legitimate and both were refused — and the requirement is documented
  instead.

### 0.3.0 - 2026-08-28

`Info::Partition` and `Info::Uf2Target` no longer read the partition table, and
system information is answered whole, so a device that has a partition table or
a small transmit FIFO serves those types itself.

- `get_info_prepare` and `get_info` use 32 bytes of stack at most, where they
  each used 252.
- `Info::Partition` is answered with a constant — the flags asked for echoed
  back, no partitions, no partition table loaded, and all of flash
  unpartitioned and readable and writable by everyone.  A device with a real
  partition table must serve the type itself.
- `SYS_INFO_MAX_BYTES` is the longest system information answer, which
  `get_info` produces in one call.  A device whose transmit FIFO holds less
  must serve `Info::Sys` itself.
- `Rp2350` declares `Ops::MIN_TX_CAPACITY`, so a transport too small for that
  answer fails the build.
- `Info::Uf2Target` takes the two words behind its target from the same constant
  `Info::Partition` uses, so the unpartitioned space reads the same way
  whichever question a host asks.  It reads no partition table, and both types
  are answered on a part that publishes no bootrom routine.

### 0.2.0 - 2026-08-28

- `get_info_prepare` and `get_info` replace `get_info_sys`.  They answer system
  and partition table information by passing the ROM's routines through.
- They answer the UF2 target partition as nowhere, and refuse the UF2 download
  status.
- `Rp2350` serves `GET_INFO` for the partition table, through
  `get_partition_table_info`.

### 0.1.0 - 2026-08-26

## picobootx-embassy

### 0.3.0 - 2026-08-28

- `Xport` declares `Transport::TX_CAPACITY`, which its transmit queue's 64
  bytes answer.

### 0.2.0 - 2026-08-28

- Tracks `picobootx`'s `GET_INFO` operations change.  A device handing
  `PicobootClass::new` an `Ops` of its own writes the new pair.

### 0.1.0 - 2026-08-26

picobootx for a device whose USB stack is embassy-usb.
