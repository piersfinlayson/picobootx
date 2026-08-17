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
  compiles `picobootx_vendor.c`.  Its `tinyusb-repo` and `pico-sdkless-repo`
  are cloned, not committed.
- `test/` — the conformance suite.
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

`picobootx_impl.c` reaches past the protocol to the chip: a bootrom table at
absolute address 0x16, a QMI register, the interrupt-enable bit, placing a
function in RAM, and reads and writes of arbitrary device addresses.  Each goes
through a macro in `picobootx_impl.h`.

- Defining `PICOBOOTX_HOST_TEST` selects the host expansion, which calls a
  `picobootx_host_test_*` function the harness supplies.
- Leaving it undefined — which is **every build for a device** — expands to
  exactly the code that was there before the seam existed.  A seam that changes
  device codegen is a bug.  Check with
  `arm-none-eabi-objdump -d examples/tinyusb/build/picobootx.elf`.
- A new chip access needs a new seam.  Do not reach for `#ifdef` at the call
  site.

## The conformance suite

From the repository root, which delegates to `test`:

    make                    # build
    make test               # build and run
    make test FILTER=stall  # one suite
    make test LOGGING=1     # with picobootx's own logging
    make test SANITIZE=1    # under the address and undefined behaviour sanitizers
    make cov                # coverage of the library, listed per file and gated
    make cov-html           # the same, as a browsable report

The same targets work from `test` itself, where `run` stands in for `test`.  A
bare `make` builds without running in both places.

It compiles the shipped `picobootx.c` and `picobootx_impl.c` for the host.  The
harness supplies the wire (`test/src/pbt_wire.c`), the device model
(`test/src/pbt_device.c`), the callbacks and a sample custom command
implementation (`test/src/pbt_ops.c`).  Scenarios live in `test/suites/`.

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

`make cov` measures `picobootx.c` and `picobootx_impl.c` and **fails below 100%**
of lines and functions.  CI runs it.  It measures the `LOGGING=1` build, because
`command_to_str` is called only from a log statement and is unreachable with
logging off.  Branch counts are listed alongside and not gated — gcc and
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
`LOGGING=1`, and on macOS, and measures the library's coverage on Linux.  The
coverage job gates at 100% — see Coverage above.  All of it runs on
GitHub-hosted runners, needing no privileges, no USB and no kernel modules.

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
