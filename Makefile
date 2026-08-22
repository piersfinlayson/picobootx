# Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
#
# MIT License

# picobootx's entry points.
#
# picobootx has no build of its own — it is source that an integrating project
# compiles alongside its own, which is what picobootx.mk exists for.  What can be
# built here is the conformance suite in test and the worked example in
# examples/tinyusb, and these targets reach both from the repository root so
# neither has to be found first.
#
# Variables named on the command line reach the sub-make unchanged, so
# `make cov CC=gcc`, `make test FILTER=stall`, `make test LOGGING=1` and
# `make test SANITIZE=1` all do what the same invocation does in test.

TEST_DIR    := test
RUST_DIR    := rust
INTEROP_DIR := $(RUST_DIR)/interop
EXAMPLE_DIR := examples/tinyusb

# The example clones this alongside itself.  Its presence is what says the
# example has been built here — see clean-example.
EXAMPLE_TINYUSB_DIR := tinyusb-repo

.PHONY: all test test-core test-usb test-usbip test-rust build cov cov-html \
        clean clean-test clean-example clean-rust example

all: build

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

# Run both under coverage, merged.  cov gates, cov-html writes a browsable
# report.
cov:
	@$(MAKE) -C $(TEST_DIR) cov

cov-html:
	@$(MAKE) -C $(TEST_DIR) cov-html

# Both build outputs.  Neither clean removes a cloned repository — the example's
# distclean does that, from its own directory.
clean: clean-test clean-rust clean-example

clean-test:
	@$(MAKE) -C $(TEST_DIR) clean

# A tree that has built neither the library nor the interop driver has nothing
# to clean, and must not be made to install a toolchain to find that out.  The
# two are separate workspaces, so each is asked separately.
clean-rust:
	@for d in $(RUST_DIR) $(INTEROP_DIR); do \
	    if [ -d $$d/target ]; then \
	        (cd $$d && cargo clean); \
	    else \
	        echo "$$d has not been built, nothing to clean"; \
	    fi; \
	done

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

# The worked example, a bare-metal picobootx device for the RP2350.  Needs an
# arm-none-eabi toolchain, and clones what it builds against.
example:
	@$(MAKE) -C $(EXAMPLE_DIR)
