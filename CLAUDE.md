# picobootx — Claude Code project guide

picobootx is an open source, MIT-licensed, device-side implementation of the
PICOBOOT protocol, in C.  It is a standalone library that third parties embed.
[One ROM](https://onerom.org) is its most significant consumer, vendoring it by
`git clone` into `plugins/system/usb/picobootx`, so a change here reaches
shipped hardware.

## Working style (read first)

- Do it **right**, for the long term.  No hacks, no throwaway "make it pass"
  fixes.  If the clean solution is more work, that is the one we want.
- **Discuss the design before you code it.**  For anything beyond a trivial
  change, propose the design and wait.
- **Do not switch technical approach without asking.**  If you think a chosen
  path is wrong, stop and raise it rather than quietly re-architecting.
- **Do not assert from memory.**  Read the code before making claims about how
  it behaves.
- **A question is a question.**  Answer it.  Do not answer a question with a
  changed design.
- **Argue.**  Hold a position under push-back until you have new information,
  then concede by naming the thing that changed your mind.
- **Ask questions as free-form prose**, never as multiple choice.
- Hold the existing bar for comments and API documentation.  A comment states
  the contract, and must not date — no "currently", no "yet", no reference to
  work that has not landed.

## Writing

- **Never write a promise about the future into any file.**  Not a CHANGELOG, a
  README, a comment or a commit message.  No "comes later", no "for now", no "to
  be added in a future release".  A document says what is true today.  If you
  think something ought to follow, say so in chat and leave the file alone.
- **Never use a semicolon in prose or a comment.**  Two sentences, or a dash.
- **Banned words**, anywhere you write: "idempotent" (say what happens on a
  second run), "load-bearing" (say what depends on it and what breaks without
  it), "oracle" (name the thing that provides the answer).

## Git

- All commits are **GPG-signed**.  You do not have the passphrase, so you
  **cannot** commit — never run `git commit`.  Stage the change and hand over the
  exact command and message.
- **No `Co-Authored-By` trailer**, and no other AI attribution, anywhere in the
  history.
- Commit bodies are bullets, one line each, three or fewer, often none.
- Only commit when asked, only push when asked.

## Layout

- `include/` — the public headers.  `picobootx.h` is the API, `picobootx_impl.h`
  the default RP2350 implementations and the host-test seams,
  `picobootx_vendor.h` the transport, `picobootx_version.h` the version.
  `picobootx_private.h` is internal.
- `src/picobootx.c` — the protocol: framing, the state machine, the command
  table, custom command dispatch.
- `src/picobootx_impl.c` — the default RP2350 command implementations.  This is
  the whole of the porting problem, and everything in it that touches the chip
  goes through a seam.
- `src/picobootx_vendor.c` — the tinyusb vendor device driver, replacing
  tinyusb's stock one.
- `examples/tinyusb/` — a complete bare-metal example, and the only build that
  produces a binary for a device.  Its `tinyusb-repo` and `pico-sdkless-repo`
  are cloned, not committed.
- `test/` — the two conformance suites, and `test/usbip/`, the bridge that puts
  the device on a real USB bus for a host tool.  `test/tinyusb` is cloned at a
  pinned commit, not committed.
- `rust/` — the Rust picobootx.  `picobootx` is the library, `picobootx-rp2350`
  the default RP2350 implementations — the port of `src/picobootx_impl.c`, with
  its own copy of the host-test seam — and `picobootx-ffi` the C ABI
  `picobootx.h` describes, which is how the conformance suite drives them.
  `rust/interop` is a workspace of its own holding the picoboot-rs interop
  driver, which tracks picoboot-rs rather than pinning it and is reached only by
  `make test-rust`.  It is separate so the archive the suite links does not need
  the network to build.
- `picobootx.mk` — the source list and include path an integrator consumes.  A
  new source file or include directory belongs here too.

## The two boundaries

picobootx reaches the outside world in two places, and they are not alike.

- **The bulk endpoints** go through the `picoboot_vendor_*` API in
  `picobootx_vendor.h`.  `picobootx.c` uses nothing else for them, so the core
  really is transport-agnostic here.
- **The control endpoint** does not.  `picoboot_control_xfer_cb` takes a
  `tusb_control_request_t`, compares against tinyusb's request enumerations, and
  answers through `tud_control_xfer` and `tud_control_status`.  So `picobootx.c`
  includes `tusb.h`, and the core is tinyusb-typed on this path.  The suite works
  around it with a small stand-in in `test/shim/tusb.h`.  Anything that claims
  the core is USB-stack agnostic has to account for this.

## The host-test seam

The default implementations reach past the protocol to the chip: a bootrom table
at absolute address 0x16, a QMI register, the interrupt-enable bit, placing a
function in RAM, and reads and writes of arbitrary device addresses.  Both
implementations put each of the five behind a seam, and one harness answers
both, since the `picobootx_host_test_*` names are the same either side.

In C, `picobootx_impl.c` goes through a macro in `picobootx_impl.h`.

- Defining `PICOBOOTX_HOST_TEST` selects the host expansion, which calls a
  `picobootx_host_test_*` function the harness supplies.
- Leaving it undefined — which is **every build for a device** — expands to
  exactly the code that was there before the seam existed.  A seam that changes
  device codegen is a bug.  Check with
  `arm-none-eabi-objdump -d examples/tinyusb/build/picobootx.elf`.
- A new chip access needs a new seam.  Do not reach for `#ifdef` at the call
  site.

In Rust, `rust/picobootx-rp2350/src/chip.rs` holds both halves of all five, one
`#[cfg(target_os = "none")]` and one `#[cfg(not(...))]`, so a bare-metal target
reaches the chip and every other target reaches the harness.  Placing a function
in RAM is the one seam that is not a call: it is a `#[cfg_attr]` written at
`erase_critical` in `defaults.rs`.

- What the objdump check protects is that `erase_critical` really can run while
  flash is unreadable, which means it must reach nothing that is fetched from
  flash.  In Rust that is `.ramfunc` carrying **no `.rel.ramfunc`** — no
  outbound calls at all, with the bootrom routines arriving as arguments and
  called through a register.  Check with, from `rust`,
  `cargo build -p picobootx-rp2350 --target thumbv8m.main-none-eabi --release`
  and then `arm-none-eabi-readelf -S` on the rlib for the section, and
  `arm-none-eabi-objdump -r` on it for the absence of relocations against it.
- The default implementations are Arm-only — the bootrom entries they ask for
  are the Arm secure ones and the interrupt mask is `cpsid i` — so a bare-metal
  build for anything else is refused by a `compile_error!` rather than failing
  in the assembler.

## The conformance suite

From the repository root, which delegates to `test`:

    make                    # build both
    make test               # build and run both
    make test-core          # the core suite alone
    make test-usb           # the usb suite alone
    make test-usbip         # the usbip bridge, driven by picotool
    make test-rust          # the same bridge, driven by picoboot-rs
    make test LOGGING=1     # with picobootx's own logging
    make test SANITIZE=1    # under the address and undefined behaviour sanitizers
    make test LIB=rust      # against the Rust library rather than the C one
    make cov                # coverage of the library, listed per file and gated
    make cov-html           # the same, as a browsable report

The same targets work from `test` itself, where `run` stands in for `test` and
`SUITE=usb` selects the second suite.  `FILTER=` runs the scenarios whose suite
name contains a string.  A bare `make` builds without running in both places.

`LIB=` chooses which implementation of picobootx is under test.  `LIB=c` is the
C in `src/`.  `LIB=rust` takes both the protocol and the default RP2350
implementations from the Rust crates, linking the archive `rust/picobootx-ffi`
builds, and leaves only the tinyusb vendor driver in `src/picobootx_vendor.c` as
C.  Both pass every scenario, and the harness reaches the library only through
`test/src/pbt_lib.h`, which each implementation answers in its own
`pbt_lib_<lib>.c`.

Every scenario runs under both, which is what makes the two agree rather than
merely both pass.  A defect in one that the other does not have shows up as a
scenario that fails under one `LIB` and passes under the other, and that
asymmetry is the proof a new scenario bites.

There are two suites, and which one a scenario belongs in is decided by what it
needs to reach.  There is also a third build, `usbip`, which is a program rather
than a suite — see below.

**core** builds the protocol and the default implementations for the host —
`picobootx.c` and `picobootx_impl.c` under `LIB=c`, the Rust archive under
`LIB=rust`.  The harness supplies the wire (`test/src/pbt_wire.c`), the device
model (`test/src/pbt_device.c`), the callbacks and a sample custom command
implementation (`test/src/pbt_ops.c`).  Scenarios live in `test/suites/`.  There
is no tinyusb in this build at all, which is what keeps it quick to run and free
of a cloned dependency.

**usb** adds the shipped `picobootx_vendor.c` and links real tinyusb, pinned to a
commit and built with `CFG_TUSB_MCU = OPT_MCU_NONE`.  `test/usb/usbt_dcd.c` is
the device controller tinyusb has no port for, and `test/usb/usbt_host.c` models
the host that drives it.  Scenarios live in `test/usb/suites/` and speak in host
actions.  This is the only build that runs the vendor driver — it is a tinyusb
class driver, supplying `vendord_init`, `vendord_open`, `vendord_reset`,
`vendord_deinit` and `vendord_xfer_cb` in place of tinyusb's own, so nothing
below usbd can call it.

**usbip** is not a suite.  It is `test/usbip/`, a program that takes the usb
suite's device — the same controller, descriptors, application and chip model —
drops the model of a host, and hands the bus to the kernel's `vhci-hcd` instead,
so real picotool drives picobootx over a real USB bus.  The bus is a loopback
socket the program hands to the controller, which is why it attaches itself
rather than calling `usbip(8)`: the kernel looks the descriptor up in the writing
process's own table.  `test/usbip/picotool.sh` runs the picotool checks, and
`rust/interop` is a cargo package driving the same device with picoboot-rs — a
second implementation of the protocol over a second USB stack, nusb rather than
libusb.  `test/usbip/bridge.sh` is what both runners source to put the device on
the bus, and the makefile hands it the binary it built rather than the script
assembling a path, so a configuration cannot be driven by a stale bridge.
Linux only, and the runs need root.  Neither is part of `make test`.

Both suites share the runner in `test/src/pbt_main.c` and the recording and
assertions in `test/src/pbt_core.c`, and each names its own scenarios —
`test/src/pbt_suites.c` and `test/usb/usbt_suites.c`.  The usbip build links
`pbt_core.c` without the runner, which is why the two are apart.  The application
carrying picobootx is `test/usb/usbt_app.c`, shared by the usb suite and the
bridge, because there are two hosts and only one application.

tinyusb is compiled without picobootx's `-Werror`: its warnings are not this
repository's to fix, and patching a pinned dependency would be worse.

Rules that keep it worth having:

- **Test positively.**  A scenario that asserts "nothing changed" is not a test.
  Arm the state, apply the stimulus, and discriminate against a nearby wrong
  answer — show that the thing you refused is accepted when the one condition
  you changed is put back.
- **Assert order, not just occurrence.**  Everything observable is appended to
  one sequence log.  Use `pbt_before` and `pbt_nth` rather than only counting.
- **The device model is physical on purpose.**  Flash erases to 0xFF and programs
  by clearing bits, so a skipped erase shows up.  OTP only ever sets bits.  Do
  not soften either into a copy.
- **Mutation-check a new scenario.**  Break the library in the way the scenario
  is meant to catch, confirm it fails, and put the library back.  A scenario
  that has never failed has not been shown to test anything.
- An access the model cannot map **aborts** rather than returning something
  plausible.  That abort is a detection, not a harness bug.

## Coverage

`make cov` runs both suites, merges what each reached, and **fails below 100%**
of lines and functions.  What it measures depends on `LIB`, since it counts the
C the suites drive: `picobootx.c`, `picobootx_impl.c` and `picobootx_vendor.c`
under `LIB=c`, and `picobootx_vendor.c` alone under `LIB=rust`, where the other
two are the Rust archive's and carry no counters.  CI runs the `LIB=c` figure,
which is the one that covers the whole of the C.  It measures the `LOGGING=1`
build, because `command_to_str` is called only from a log statement and is
unreachable with logging off.  Branch counts are listed alongside and not gated — gcc and
llvm-cov disagree on what counts as a branch, so a branch gate would hold under
one compiler and fail under the other.

The remainder is marked in the library itself with `LCOV_EXCL_START` /
`LCOV_EXCL_STOP` pairs.  Every one of them is an
arm defending an invariant the state machine has already established — a
category the command table cannot hold, a callback a routed row cannot be
missing — and each carries a comment saying why it cannot be reached.

- **Any change that adds, removes or alters an `LCOV_EXCL` marker goes to Piers
  for review, without exception.**  Propose it and wait, the way a design change
  is proposed.
- An exclusion added to make the number work turns the figure into a lie.  If a
  branch is hard to reach, that is the signal to write the test — reaching for
  the marker is the wrong move, and reaching for it quietly is worse.
- The gate cuts both ways.  It fails on a new branch nothing reaches, and it
  fails when the only test reaching an existing branch is deleted.

`test/shim/tusb.h` reproduces tinyusb's declarations byte for byte and value for
value.  Anything added there must match tinyusb, or the suite pins behaviour the
device does not have.

## Versioning

- `include/picobootx_version.h` carries the version, and `CHANGELOG.md` has a
  section per release.  The release workflow refuses a tag that disagrees with
  either.
- Semantic versioning.  Before 1.0.0 a minor bump may change the API.
- Tags are `vX.Y.Z`.  Pushing one runs the release workflow, which builds, runs
  the suite, and creates the release from the CHANGELOG section.

## CI

`.github/workflows/build.yml` cross-builds the tinyusb example for Arm, runs the
suite on Linux under gcc and clang, on Linux under the sanitizers and with
`LOGGING=1`, and on macOS, measures the library's coverage on Linux, and drives
the usbip bridge with picotool built from a pinned release tag and with
picoboot-rs.  The coverage job
gates at 100% — see Coverage above.  All of it runs on GitHub-hosted runners and
needs no hardware.  Everything but the picotool job needs no privileges, no USB
and no kernel modules either — that one loads `vhci-hcd` and runs as root.

## Gotchas

- macOS ships **GNU Make 3.81**, which compares timestamps at one-second
  granularity.  Editing a source and rebuilding within the same second can leave
  a stale binary in place, and a test run will then measure the previous build.
  `make clean` between builds when a script is editing sources in a loop.
- The suite builds with `-fshort-enums`, because picobootx asserts its wire enums
  are one byte and that is the Arm embedded ABI's default rather than a host
  compiler's.
- `PICOBOOT_STATE_SIZE` describes the state block on a device, where a pointer is
  four bytes.  A 64-bit host build's block is larger, so the assertion checking
  the two agree is compiled only for device builds.
