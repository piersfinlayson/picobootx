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
EXAMPLE_DIR := examples/tinyusb

# The example clones this alongside itself.  Its presence is what says the
# example has been built here — see clean-example.
EXAMPLE_TINYUSB_DIR := tinyusb-repo

.PHONY: all test build cov cov-html clean clean-test clean-example example

all: build

# Build the conformance suite without running it.
build:
	@$(MAKE) -C $(TEST_DIR) build

# Build and run it.
test:
	@$(MAKE) -C $(TEST_DIR) run

# Run it under coverage.  cov gates, cov-html writes a browsable report.
cov:
	@$(MAKE) -C $(TEST_DIR) cov

cov-html:
	@$(MAKE) -C $(TEST_DIR) cov-html

# Both build outputs.  Neither clean removes a cloned repository — the example's
# distclean does that, from its own directory.
clean: clean-test clean-example

clean-test:
	@$(MAKE) -C $(TEST_DIR) clean

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
