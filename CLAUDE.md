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
- `examples/tinyusb/` — a complete bare-metal example in C, on tinyusb.  Its
  `tinyusb-repo` and `pico-sdkless-repo` are cloned, not committed.
  `make example` builds it.
- `examples/embassy/` — the same device in Rust, on embassy-usb through
  `picobootx-embassy`.  A workspace of its own, so it builds from its own
  directory, and its `.cargo/config.toml` carries the Arm target and the two
  link flags `picobootx-rp2350` asks a consumer for.  `make example-embassy`
  builds it.
- `test/` — the two conformance suites, and `test/usbip/`, the bridge that puts
  the device on a real USB bus for a host tool.  `test/tinyusb` is cloned at a
  pinned commit, not committed.
- `rust/` — the Rust picobootx.  `picobootx` is the library, `picobootx-rp2350`
  the default RP2350 implementations — the port of `src/picobootx_impl.c`, with
  its own copy of the host-test seam — and `picobootx-ffi` the C ABI
  `picobootx.h` describes, which is how the conformance suite drives them.
  `picobootx-embassy` is the embassy-usb half: the driver task, the transport
  and the control handler embassy-usb asks a class for, with `examples/embassy`
  a whole device built on it.
  `rust/interop` is a workspace of its own holding the picoboot-rs interop
  driver, which tracks picoboot-rs rather than pinning it and is reached only by
  `make test-rust`.  It is separate so the archive the suite links does not need
  the network to build.
- `ci/` — what the workflows call that is longer than a step.
  `coverage-report.sh` turns tracefiles into a table, a line list or a gate,
  `coverage-baseline.txt` holds the per-file floor each Rust source may not drop
  below, and `coverage-unmeasured.txt` names the sources that carry no
  executable line, each with the reason.  `check-ramfunc.sh` and
  `ramfunc-probe/` link `picobootx-rp2350` into a bare-metal binary and check
  where `.ramfunc` landed.
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
in RAM is the one seam that is not a call, and it is not one thing either.  It
is three:

- The `#[cfg_attr]` at `erase_critical` in `defaults.rs`, which names the
  `.ramfunc` section.  A name places nothing — the consumer's linker script
  decides where the section lands and the startup decides whether its bytes are
  carried there.
- `rust/picobootx-rp2350/picobootx.x`, the linker fragment that answers for it.
  It gives `.ramfunc` an address in RAM and a load address in flash and hooks
  itself on with `INSERT AFTER .data`, so cortex-m-rt's own `.data` copy carries
  it.  `build.rs` puts the fragment in `OUT_DIR` and the directory on the
  linker's search path, and the consumer adds one flag,
  `-C link-arg=-Tpicobootx.x`, beside `-Tlink.x`.  cargo does not carry a
  dependency's link arguments to the binary, which is why the flag is theirs.
  That flag is a rust-lld arrangement: GNU ld resolves `INSERT AFTER` only
  within the script it is processing, so a second `-T` fails the link with
  `.data not found for insert`, and the crate's documentation gives that
  consumer the same `SECTIONS` block to paste into their own `memory.x`, which
  `link.x` includes.
- The residency check in `flash_erase`, which reads back the routine's address
  and a marker word placed beside it while flash still answers, and refuses with
  `PRECONDITION_NOT_MET` rather than jumping into a bus that has stopped
  answering.

- What the objdump check protects is that `erase_critical` really can run while
  flash is unreadable, which means it must reach nothing that is fetched from
  flash.  In Rust that is `.ramfunc` carrying **no `.rel.ramfunc`** — no
  outbound calls at all, with the bootrom routines arriving as arguments and
  called through a register.  Check with, from `rust`,
  `cargo build -p picobootx-rp2350 --target thumbv8m.main-none-eabi --release`
  and then `arm-none-eabi-readelf -S` on the rlib for the section, and
  `arm-none-eabi-objdump -r` on it for the absence of relocations against it.
- Where the section ends up is a property of a **link**, and an rlib is not one.
  `ci/check-ramfunc.sh` builds `ci/ramfunc-probe`, a bare-metal binary whose
  only reason to exist is to call `flash_erase`, and reads `.ramfunc`'s
  addresses out of it: VMA in SRAM, LMA in flash, and `__edata` past the
  section's end, since the startup copy fills `__sdata..__edata` and a section
  outside that span is placed, loaded and never filled.  CI runs it, and it is
  what would have caught a fragment that places nothing.
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
    make test-unit          # the Rust crates' own tests
    make cov                # coverage of both languages, per file and gated
    make cov-raise          # raise the Rust floors to what cov measured
    make cov-uncovered      # the lines nothing reached
    make cov-html           # the C's figures, as a browsable report

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

`make cov` measures **both languages**, from the repository root.  It runs both
suites under `LIB=c` and again under `LIB=rust`, adds the crates' own tests, and
then prints one table over the C's three sources and the Rust's eleven and gates
twice.  Neither `LIB` on its own measures the library: the C only carries
counters where it is the implementation under test, and the Rust only where it
is.  Nor do the suites alone measure the Rust — see The crates' own tests below.

It measures the `LOGGING=1` build, because `command_to_str` is called only from
a log statement and is unreachable with logging off.  Branch counts are listed
alongside and not gated — gcc and llvm-cov disagree on what counts as a branch,
so a branch gate would hold under one compiler and fail under the other.

### How each half is measured

The C is gcov, read by lcov, exactly as before — `--coverage` on the whole
build, narrowed afterwards to `picobootx.c`, `picobootx_impl.c` and
`picobootx_vendor.c` so the harness exercising itself never counts towards what
the library reached.

The Rust is LLVM's own instrumentation: the archive is built with
`-C instrument-coverage` into a target directory of its own, the binaries write
one raw profile per process, and llvm-profdata and llvm-cov turn those into
lcov.  Three things that build have to keep, each of which would otherwise read
as coverage that was never measured:

- **A staticlib is linked without the profiler runtime**, so nothing in the
  archive defines the writer that turns the counters into a file.  On ELF
  nothing names `__llvm_profile_runtime` either, so the link succeeds, the
  binary carries its coverage map and no writer, and every run exits having
  written nothing.  `-Wl,-u,__llvm_profile_runtime` is what asks for it by name
  and pulls the definition in, and rustc's own `libprofiler_builtins-*.rlib`
  from the sysroot is what defines it — matched to the compiler that
  instrumented the code by construction.  Deleting that `-u` is silent, and
  reads as a suite that ran and reached nothing.  The symbol carries a leading
  underscore in Mach-O's table and none in ELF's, which is why
  `test/Makefile` picks the spelling by platform.
- **An archive member the linker leaves behind takes its coverage map with it**,
  so an untested function reads as one that does not exist rather than one
  nothing reached, and the total agrees.  `-force_load` on Mach-O and
  `--whole-archive` on ELF are what stop that.
- **llvm-profdata and llvm-cov come from the rustup sysroot**, not from PATH, so
  a system LLVM of some other vintage cannot answer instead.  `rustup component
  add llvm-tools` is what puts them there.

The raw profiles and gcov's counters are both **deleted** before a run rather
than left to accumulate.  gcov's runtime adds to what it finds, so a counter
file left in place would keep crediting a line the deleted test was the only
thing reaching — and the gate that exists to fail when a test goes would say
nothing.

### The crates' own tests

`make test-unit` runs them, and `make cov` runs them again under instrumentation
into `rust-unit.info`, which is one of the four tracefiles the report unions.
They live in `rust/picobootx/tests/`, `rust/picobootx-rp2350/tests/` and one
`#[cfg(test)]` module in `rust/picobootx/src/wire.rs`.

They exist because the conformance suite **structurally cannot** reach part of
the Rust.  The suite drives the library through the C ABI, which hands every
operation over as a `picoboot_ops_t` of function pointers — a table is either
populated or null, so nothing there ever meets an `Ops` that left a method to
its default, and the defaults are the whole of the trait's refuse-by-default
contract.  Nor does anything there hold an `Rp2350`: the shim builds its own
dispatch table out of the free functions.  Neither gap is a missing scenario,
and no scenario can close either.

What belongs where follows from that.  **A gap on the C ABI is a scenario**, in
`test/suites/`, so both implementations are held to it and the two agree rather
than merely both pass.  **A gap in Rust the C ABI cannot express is a crate
test.**  `picobootx-ffi` therefore has none: it is the C ABI, and the suite is
what drives that.

Two things that build has to keep:

- **The tests go in `tests/`, not in the measured sources.**  llvm-cov exports
  by file, so a `#[cfg(test)] mod tests` puts its own lines into that file's
  totals — always covered, so they pad the rate of the library lines beside
  them.  `wire.rs` carries one because `INFO_FLAGS` and `info_max_words` are
  private and a `const fn` evaluated at compile time is not reached at run time
  by anything else.  That file is at 100% of its library lines too, so nothing
  is hidden behind the padding, and that is the condition for putting a test
  module in a measured file at all.
- **A test binary brings its own profiler runtime**, unlike the archive, which
  is handed one by name.  The profiles are still checked for existence and for
  being non-empty before llvm-profdata is given them, because a build that
  wrote none reads exactly like a run that reached nothing.

`picobootx-rp2350`'s tests answer the five host-test seams themselves, as a
**recorder** and not as a model of a part: it says which seam was reached and
with what, and its bootrom publishes one routine so that a lookup which finds
something and a lookup which does not are both reachable.  The part's behaviour
is the suite's to test, against `test/src/pbt_device.c`, and it does.

### The two gates

**The C fails below 100%** of lines and functions.  The remainder is marked in
the library itself with `LCOV_UNREACHABLE_START` / `LCOV_UNREACHABLE_STOP`
pairs, which lcov fails on if a marked line turns out to have been reached
rather than dropping it quietly — the claim the comment makes is checked against
the counters.  Every one of them is an arm defending an invariant the state
machine has already established — a category the command table cannot hold, a
callback a routed row cannot be missing — and each carries a comment saying why
it cannot be reached.

A region covers the arm's body, from inside the opening brace.  The line
carrying the condition is evaluated on every call, so a marker placed above the
`if` claims a line that runs, and the capture fails naming it.

- **Any change that adds, removes or alters an unreachability marker goes to
  Piers for review, without exception.**  Propose it and wait, the way a design
  change is proposed.
- An exclusion added to make the number work turns the figure into a lie.  If a
  branch is hard to reach, that is the signal to write the test — reaching for
  the marker is the wrong move, and reaching for it quietly is worse.
- The gate cuts both ways.  It fails on a new branch nothing reaches, and it
  fails when the only test reaching an existing branch is deleted.

**The Rust fails below a per-file floor**, held in `ci/coverage-baseline.txt`.
`ci/coverage-report.sh --check` is the gate and `--raise` moves floors **up**,
never down — lowering one is a hand edit and the commit says why.  The floors
belong to the whole set of runs, so `--check` refuses unless the four the
floors are built from are present, and `--raise` refuses tracefile arguments
altogether: it rewrites every floor, and a subset would rewrite floors it never
measured.

Four ways a file can fail the check, because a gate that can report a false
green is worth nothing:

- `NEW` — measured, with no floor.  A new source cannot arrive untested.
- `DROP` — below its floor.
- `GONE` — a floor with no measured file behind it.  A lost `--whole-archive`,
  a module removed by a `cfg`, a crate dropped from the measured set and a path
  filter that stopped matching all look like this, and every one of them would
  otherwise leave the gate passing over what was left.
- `UNMEASURED` — a source in the tree that reached no tracefile at all.  Which
  files reach llvm-cov and lcov is decided by hand-kept lists in `test/Makefile`,
  so a new crate is measured by nothing and has no floor to be missing either.
  The check walks `src/*.c` and every `.rs` under a crate's `src/` in `rust/`
  and requires each to be in the measured set or named, with its reason, in
  `ci/coverage-unmeasured.txt`.  An entry there that names a file which has gone
  — or one that turns out to be measured after all — fails as `STALE`.

`make cov` empties `test/build/coverage` before it captures, so every tracefile
the report reads was written by that run.  Without that, a `make -C test cov
LIB=c` on its own leaves the previous run's `rust.info` in place and both the
report and the check take it as current.

The C's three files carry a floor of 100.0 in the same file.  That is the same
gate said twice, deliberately: the exact one in `test/Makefile` catches a lost
line whatever the file's size, and the floor says in writing where the C stands.

**The floors are CI's figures.**  A different machine measures differently, and
a floor raised from one is not a floor another can meet.  Raise them from the
coverage job's own output.

The Rust marks its unreachable lines too, with the same marker and under the
same rule: **any change that adds, removes or alters one goes to Piers for
review**, and an exclusion added to make a number work turns the figure into a
lie, here as in the C.

Nothing on the Rust's side has honoured it by the time the tracefile exists.
lcov reads the C's source as it captures, so a C tracefile has never held the
marked lines.  llvm-cov reads the coverage map out of the binary and never opens
the source, and rustc's own `#[coverage(off)]` is a nightly feature that takes a
whole function rather than a line.  So `test/Makefile` runs `lcov --filter region`
over `rust.info` and `rust-unit.info` afterwards, which reads each source and
drops the marked lines.  lcov filters a file only when it recognises the
extension as C, Perl, Python or Java, so `COV_RUST_FILTER` names `rs` in
`c_file_extensions` — without that the filter is skipped and says nothing.

The device-only half of `picobootx-rp2350` — the `#[cfg(target_os = "none")]`
side of `chip.rs`, the `compile_error!` guard in its `lib.rs`, the `.ramfunc`
attribute at `erase_critical`, and the residency check that guards it, its
marker word and the call to it in `flash_erase` — needs no marker at all: `cfg`
removes it before codegen on a host build, so it never enters the denominator.
That is also why a floor cannot speak for that code, and why
`ci/check-ramfunc.sh` exists.

`make cov-uncovered` lists the lines nothing reached, which is where a floor
below 100 comes from.  `make cov-html` writes the C's figures as a browsable
report.

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

`.github/workflows/build.yml` cross-builds both examples for Arm and links
`ci/ramfunc-probe` to check where `.ramfunc` landed, runs the
suite on Linux under gcc and clang, on Linux under the sanitizers and with
`LOGGING=1`, and on macOS, measures both languages' coverage on Linux, and
drives the usbip bridge with picotool built from a pinned release tag and with
picoboot-rs.  It formats and lints four cargo workspaces — `rust`,
`rust/interop`, `examples/embassy` and `ci/ramfunc-probe` — because `--all` and
`--workspace` reach only the members of the one they are asked in, so a
workspace left unnamed there is checked by nobody.  The coverage job holds the
C at 100% and the Rust to its floors —
see Coverage above — and writes the figures to the run summary page, so the
numbers are readable by anyone who can see the repository rather than only by
someone with an account who opens the log.  All of it runs on GitHub-hosted
runners and needs no hardware.  Everything but the picotool job needs no privileges, no USB
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
