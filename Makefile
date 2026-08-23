# Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
#
# MIT License

# picobootx's entry points.
#
# picobootx has no build of its own — it is source that an integrating project
# compiles alongside its own, which is what picobootx.mk exists for.  What can be
# built here is the conformance suite in test and the two worked examples in
# examples, and these targets reach all three from the repository root so none
# has to be found first.
#
# Variables named on the command line reach the sub-make unchanged, so
# `make cov CC=gcc`, `make test FILTER=stall`, `make test LOGGING=1` and
# `make test SANITIZE=1` all do what the same invocation does in test.

TEST_DIR            := test
RUST_DIR            := rust
INTEROP_DIR         := $(RUST_DIR)/interop
PROBE_DIR           := ci/ramfunc-probe
EXAMPLE_DIR         := examples/tinyusb
EXAMPLE_EMBASSY_DIR := examples/embassy
HW_DEVICE_DIR       := test/hw/device
HW_HOST_DIR         := test/hw/host

# Where the sub-make writes its tracefiles, and what ci/coverage-report.sh
# reads.  Named here as well because cov empties it — see there.
COV_DIR     := $(TEST_DIR)/build/coverage

# The example clones this alongside itself.  Its presence is what says the
# example has been built here — see clean-example.
EXAMPLE_TINYUSB_DIR := tinyusb-repo

.PHONY: all test test-core test-usb test-usbip test-rust test-unit build cov \
        cov-html cov-raise cov-uncovered clean clean-test clean-example \
        clean-example-embassy clean-rust example example-embassy \
        hw-device hw-host clean-hw

all: build

# cargo clean in one workspace, named by $(1).  A tree that has not built it has
# nothing to remove, and must not be made to install a toolchain to find that
# out.
define cargo-clean
if [ -d $(1)/target ]; then \
    (cd $(1) && cargo clean); \
else \
    echo "$(1) has not been built, nothing to clean"; \
fi
endef

# Build both suites without running them.
build:
	@$(MAKE) -C $(TEST_DIR) build
	@$(MAKE) -C $(TEST_DIR) SUITE=usb build

# Build and run both suites.  core drives picobootx through a stand-in for the
# USB transport, usb drives it through real tinyusb and a model of a host, and
# only the second reaches the vendor driver.  test-usbip is not among them: it
# needs Linux and root, and neither suite needs either.
test: test-core test-usb

test-core:
	@$(MAKE) -C $(TEST_DIR) run

test-usb:
	@$(MAKE) -C $(TEST_DIR) SUITE=usb run

# Put the usb suite's device on this machine's own USB bus, through the kernel's
# virtual host controller, and drive it with real picotool.  Linux only, and the
# run needs root — building it does not, so only the run is handed to sudo.
test-usbip:
	@$(MAKE) -C $(TEST_DIR) usbip

# The Rust crates' own tests.  The conformance suite drives the Rust library
# through the C ABI, which hands every operation over as a table of function
# pointers — so it never meets an Ops that left a method to its default, and
# never holds an Rp2350 as a Rust type.  Those are the crates' own tests, and
# this is what runs them.  Needs cargo, which is why it is not part of
# `make test`: the suites build and run with nothing but a C compiler and make.
test-unit:
	@command -v cargo >/dev/null || \
	    (echo "cargo is not on PATH, and this target needs it" && exit 1)
	@$(MAKE) -C $(TEST_DIR) test-unit

# The same device, driven by picoboot-rs instead of picotool — a second
# implementation of the protocol, over a second USB stack.  Needs Linux, root
# and a network, so it is its own target and is not reached by anything above.
test-rust:
	@command -v cargo >/dev/null || \
	    (echo "cargo is not on PATH, and this target needs it" && exit 1)
	@$(MAKE) -C $(TEST_DIR) usbip-build
	@# Everything else this depends on is held still by Cargo.lock, so a run
	@# reports what picoboot-rs did and not what some other crate released.
	@# picoboot-rs itself is taken fresh, which is the whole point of it.
	cd $(INTEROP_DIR) && cargo update -p picoboot && cargo build --release
	sudo $(INTEROP_DIR)/interop.sh $(if $(filter 1,$(TRACE)),-v)

# Both suites under coverage, under both implementations, merged.  Every line
# of both languages is measured by this one target: the C only carries counters
# where it is the library under test, and the Rust only where it is, so a run
# under one LIB alone measures half the library and cannot say so.
#
# Three gates, and each has to hold.  test/Makefile's own gate wants every line
# and every function of the C, under each LIB in turn.  ci/coverage-report.sh
# --check wants every file at or above the floor in ci/coverage-baseline.txt,
# which is where the Rust is held.
cov:
	@# Emptied first, so every tracefile the report reads was written by this
	@# run.  A LIB= run of its own writes one of the three and leaves the
	@# others where they are, and both the report and the check would take
	@# those as current.  With the directory cleared, what is missing is
	@# missing, and the check says so.
	rm -rf $(COV_DIR)
	@$(MAKE) -C $(TEST_DIR) cov LIB=c
	@$(MAKE) -C $(TEST_DIR) cov LIB=rust
	@# And the Rust the suites structurally cannot reach, since they drive the
	@# library through the C ABI - see test-unit.
	@$(MAKE) -C $(TEST_DIR) cov-unit
	@echo
	@ci/coverage-report.sh
	@echo
	@ci/coverage-report.sh --check

# Raise the floors to what the last `make cov` measured.  Up only — a floor
# that has to come down is a hand edit, and the commit says why.
cov-raise:
	@ci/coverage-report.sh --raise

# The lines nothing reached, which is where a floor that is not 100 comes from.
cov-uncovered:
	@ci/coverage-report.sh --uncovered $(FILE)

cov-html:
	@$(MAKE) -C $(TEST_DIR) cov-html

# Every build output.  Neither clean removes a cloned repository — the tinyusb
# example's distclean does that, from its own directory.
clean: clean-test clean-rust clean-example clean-example-embassy clean-hw

clean-test:
	@$(MAKE) -C $(TEST_DIR) clean

# The library, the interop driver and the RAM function probe.  Each is a
# workspace of its own, so each is asked separately.
clean-rust:
	@$(call cargo-clean,$(RUST_DIR))
	@$(call cargo-clean,$(INTEROP_DIR))
	@$(call cargo-clean,$(PROBE_DIR))

# The example's Makefile includes tinyusb.mk and pico-sdkless's common.mk, which
# arrive with the repositories it clones as it is parsed.  So it cannot be
# reached at all until they are there, and asking it to clean on a fresh
# checkout would fetch three repositories to delete a directory that does not
# exist.  Nothing to clean is not a failure, so say so and carry on.
clean-example:
	@if [ -d $(EXAMPLE_DIR)/$(EXAMPLE_TINYUSB_DIR) ]; then \
	    $(MAKE) -C $(EXAMPLE_DIR) clean; \
	else \
	    echo "$(EXAMPLE_DIR) has not been built, nothing to clean"; \
	fi

clean-example-embassy:
	@$(call cargo-clean,$(EXAMPLE_EMBASSY_DIR))

# The tinyusb example, a bare-metal picobootx device for the RP2350 in C.  Needs
# an arm-none-eabi toolchain, and clones what it builds against.
example:
	@$(MAKE) -C $(EXAMPLE_DIR)

# The embassy example, the same device in Rust.  A workspace of its own, so it
# is built from its own directory rather than from rust, and the Arm target and
# the two link flags come from its .cargo/config.toml.
example-embassy:
	@command -v cargo >/dev/null || \
	    (echo "cargo is not on PATH, and this target needs it" && exit 1)
	cd $(EXAMPLE_EMBASSY_DIR) && cargo build --release

# The hardware test's two halves.  Built here and by CI, run by neither: both
# want a board on the end of a USB cable.  See test/hw/README.md.
hw-device:
	@command -v cargo >/dev/null || \
	    (echo "cargo is not on PATH, and this target needs it" && exit 1)
	cd $(HW_DEVICE_DIR) && cargo build --release

hw-host:
	@command -v cargo >/dev/null || \
	    (echo "cargo is not on PATH, and this target needs it" && exit 1)
	cd $(HW_HOST_DIR) && cargo build --release

clean-hw:
	@$(call cargo-clean,$(HW_DEVICE_DIR))
	@$(call cargo-clean,$(HW_HOST_DIR))
