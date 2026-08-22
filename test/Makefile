# Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
#
# MIT License

# picobootx's conformance suite.
#
# Builds picobootx's core and its default implementations for this machine, with
# PICOBOOTX_HOST_TEST defined so the seams in picobootx_impl.h resolve to the
# harness rather than to RP2350 hardware, and links them against the harness's
# own transport and device model.
#
# No USB, no kernel modules, no privileges, and nothing beyond a C compiler and
# make.  It builds and runs on macOS and on Linux, with either clang or gcc.
#
#   make             build and run
#   make build       build only
#   make run         run, building first if needed
#   make FILTER=zlp  run only the suites whose name contains this
#   make LOGGING=1   build with picobootx's own logging turned on
#   make SANITIZE=1  build with the address and undefined behaviour sanitizers
#   make LIB=c|rust  which implementation of picobootx is under test
#   make cov         run under coverage, list what the library reached, and
#                    fail if it is not all of it
#   make cov-html    the same, as a browsable report
#   make usbip       put the device on this machine's USB bus and drive it with
#                    picotool.  Linux only, and the run needs root
#   make usbip TRACE=1  the same, with the bridge tracing every transfer
#   make clean
#
# Coverage needs lcov, and a gcov that reads the counters the compiler wrote.
# gcc's own gcov does, and is the default.  clang writes profiles only
# llvm-cov reads, so build coverage with clang by naming its reader:
#
#   make cov CC=clang GCOV="llvm-cov gcov"
#
# The gate covers lines and functions, and holds under either compiler.  Branch
# counts are listed for information and not gated: llvm-cov's gcov emulation
# counts branches gcc does not — among them some attributed to a function's
# closing brace, which nothing can take — so a branch gate would pass under one
# compiler and fail under the other.

CC      ?= cc
OPT     ?= -O1 -g

# Which suite is being built.
#
#   core  picobootx's core and default implementations, against the harness's
#         own stand-in for the USB transport.  No tinyusb.
#   usb   the same, plus picobootx_vendor.c, against real tinyusb driven by a
#         host device controller and a model of a USB host.  This is the only
#         way to reach the vendor driver, since it is a tinyusb class driver and
#         nothing below usbd can call it.
#   usbip the usb suite's device, without the model of a host and without any
#         scenarios, put on the machine's own USB bus through vhci-hcd so a real
#         host tool drives it.  A program rather than a suite.  Linux only, and
#         it needs root.
#
# All three compile picobootx.c and picobootx_impl.c, with different headers and
# different flags, so each keeps its own object directory.
SUITE ?= core

# Names the file answering src/pbt_lib.h, which is where the harness asks the
# few things picobootx.h does not tell it about the library in front of it.
LIB ?= c
ifeq ($(filter $(LIB),c rust),)
$(error LIB=$(LIB) is not a library this makefile knows.  LIB=c selects the C implementation in ../src, LIB=rust the Rust one in ../rust)
endif

# Each configuration keeps its own object directory.  They differ only in
# compiler flags, which make cannot see, so sharing one directory would leave
# whichever configuration was built first in place.
BUILD_VARIANT := $(SUITE)
ifeq ($(LOGGING),1)
BUILD_VARIANT := $(BUILD_VARIANT)-logging
endif
ifeq ($(SANITIZE),1)
BUILD_VARIANT := $(BUILD_VARIANT)-sanitize
endif
ifeq ($(COVERAGE),1)
BUILD_VARIANT := $(BUILD_VARIANT)-coverage
endif
ifeq ($(LIB),rust)
BUILD_VARIANT := $(BUILD_VARIANT)-rust
endif

BUILD   ?= build/$(BUILD_VARIANT)

ROOT    := ..

# Where the usbip bridge this configuration builds ends up.  The scripts that
# put it on the bus are handed this rather than assembling it themselves, so a
# configuration that lands somewhere else cannot be driven by a stale one.
BRIDGE  := build/usbip$(if $(filter rust,$(LIB)),-rust)/picobootx-usbip

# The Rust library is an archive cargo builds.  It carries the protocol only:
# the default RP2350 implementations beside it are still the C ones.
ifeq ($(LIB),rust)
RUST_DIR := $(ROOT)/rust
RUST_A   := $(RUST_DIR)/target/release/libpicobootx_ffi.a
endif

# ---------------------------------------------------------------------------
# tinyusb, for the usb suite
#
# Pinned to a commit rather than a tag, because the fork carries none.  A commit
# cannot be reached by clone --branch, so the repository is created empty and
# the one commit fetched into it — which also brings nothing else.
#
# Remove the tinyusb/ directory after changing this, so it is re-fetched.  The
# example clones the same fork at whatever HEAD is, deliberately: this pin is so
# a suite that gates CI cannot go red because the fork moved.
# ---------------------------------------------------------------------------

TINYUSB_DIR    := tinyusb
TINYUSB_COMMIT := 8e4f5c1d269976d6c56660782a441a1d780845f0
TINYUSB_URL    := https://github.com/piersfinlayson/tinyusb.git

ifneq ($(filter usb usbip,$(SUITE)),)
# Fetched here, while the makefile is being read, rather than as a target.  The
# tinyusb sources are found through VPATH, and make resolves VPATH as it builds
# its dependency graph — before it would run any target.  A rule that fetched
# them would therefore be too late on a fresh checkout, where make stops with
# "no rule to make target" instead.  Only this suite needs tinyusb, so the core
# suite still builds with nothing but a compiler and make.
$(shell [ -d $(TINYUSB_DIR) ] || ( \
	git init -q $(TINYUSB_DIR) && \
	git -C $(TINYUSB_DIR) remote add origin $(TINYUSB_URL) && \
	git -C $(TINYUSB_DIR) fetch -q --depth 1 origin $(TINYUSB_COMMIT) && \
	git -C $(TINYUSB_DIR) checkout -q FETCH_HEAD ))

INCLUDES := -Iusb -I$(TINYUSB_DIR)/src -I$(TINYUSB_DIR)/src/common \
            -I$(TINYUSB_DIR)/src/device -I$(ROOT)/include -Isrc
ifeq ($(SUITE),usbip)
TARGET   := $(BUILD)/picobootx-usbip
INCLUDES += -Iusbip
else
TARGET   := $(BUILD)/picobootx-usb-test
endif
else
TARGET   := $(BUILD)/picobootx-test
INCLUDES := -Ishim -I$(ROOT)/include -Isrc
endif

CFLAGS := $(OPT) -std=c11 -Wall -Wextra -Werror

# picobootx asserts that its wire enums are one byte, which is the Arm embedded
# ABI's default and not a host compiler's.  Building the host test with short
# enums keeps the layouts the library checks the same as the device's, rather
# than relaxing the checks to suit the host.
CFLAGS += -fshort-enums

CFLAGS += -DPICOBOOTX_HOST_TEST=1
CFLAGS += $(INCLUDES)

ifeq ($(LOGGING),1)
CFLAGS += -DPICOBOOT_LOGGING=1
endif

ifeq ($(SANITIZE),1)
SAN_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer
CFLAGS  += $(SAN_FLAGS)
LDFLAGS += $(SAN_FLAGS)
endif

ifeq ($(COVERAGE),1)
# Counters are emitted for the whole build and filtered down to the library
# afterwards, so the harness's own coverage never flatters the library's.
CFLAGS  += --coverage
LDFLAGS += --coverage
endif

# Rebuild when a header changes.  Without this a change to tusb_config.h leaves
# every object that read it stale, and the build silently disagrees with itself.
CFLAGS += -MMD -MP

CFLAGS  += $(EXTRA_CFLAGS)
LDFLAGS += $(EXTRA_LDFLAGS)

# What tinyusb is compiled with: the same flags, without the warning policy
# picobootx holds itself to.
TINYUSB_CFLAGS := $(filter-out -Werror,$(CFLAGS)) -Wno-unused-parameter

ifneq ($(filter usb usbip,$(SUITE)),)

# picobootx_vendor.c joins the library here.  It defines vendord_init, _open,
# _reset, _deinit and _xfer_cb — tinyusb's own vendor class driver hooks — so it
# stands in for class/vendor/vendor_device.c, which is why that file is not
# among the tinyusb sources below.
LIB_SRC := \
	$(if $(filter c,$(LIB)),$(ROOT)/src/picobootx.c) \
	$(ROOT)/src/picobootx_impl.c \
	$(ROOT)/src/picobootx_vendor.c

TINYUSB_SRC := \
	$(TINYUSB_DIR)/src/tusb.c \
	$(TINYUSB_DIR)/src/common/tusb_fifo.c \
	$(TINYUSB_DIR)/src/device/usbd.c \
	$(TINYUSB_DIR)/src/device/usbd_control.c

# The device both of these build is the same one, and it is everything but the
# host: the controller, the descriptors, the application carrying picobootx, and
# the model underneath.  What differs is who drives it.
DEVICE_SRC := \
	src/pbt_core.c \
	src/pbt_device.c \
	src/pbt_lib_$(LIB).c \
	src/pbt_ops.c \
	usb/usbt_dcd.c \
	usb/usbt_app.c \
	usb/usbt_descriptors.c

ifeq ($(SUITE),usbip)

# The bridge: no scenarios, no runner, and no host inside the process.  The host
# is the machine's own kernel, reaching the same device through vhci-hcd.
HARNESS_SRC := $(DEVICE_SRC)

SUITE_SRC := \
	usbip/usbipt_main.c \
	usbip/usbipt_device.c \
	usbip/usbipt_vhci.c \
	usbip/usbipt_urb.c

# The bridge is sockets, poll and sysfs, none of which a strict C11 declares.
CFLAGS += -D_DEFAULT_SOURCE

# The whole flash window picobootx admits, rather than the part's worth the
# suites model.  See PBT_FLASH_MODELLED in src/pbt.h.
CFLAGS += -DPBT_FLASH_MODELLED=RP2350_FLASH_SIZE

else

HARNESS_SRC := \
	$(DEVICE_SRC) \
	src/pbt_main.c \
	usb/usbt_suites.c \
	usb/usbt_host.c

SUITE_SRC := \
	usb/suites/enumeration.c \
	usb/suites/vendor.c

endif

SRC := $(LIB_SRC) $(HARNESS_SRC) $(SUITE_SRC)
VPATH := $(ROOT)/src:src:usb:usb/suites:usbip:$(TINYUSB_DIR)/src:$(TINYUSB_DIR)/src/common:$(TINYUSB_DIR)/src/device

else

# The library under test.  picobootx_vendor.c is deliberately absent: it is the
# tinyusb vendor driver, and the harness supplies its own implementation of the
# picoboot_vendor_* API it provides.  The usb suite covers it.
LIB_SRC := \
	$(if $(filter c,$(LIB)),$(ROOT)/src/picobootx.c) \
	$(ROOT)/src/picobootx_impl.c

HARNESS_SRC := \
	src/pbt_core.c \
	src/pbt_lib_$(LIB).c \
	src/pbt_main.c \
	src/pbt_flow.c \
	src/pbt_suites.c \
	src/pbt_device.c \
	src/pbt_wire.c \
	src/pbt_ops.c

SUITE_SRC := \
	suites/framing.c \
	suites/stall.c \
	suites/zlp.c \
	suites/data_in.c \
	suites/data_out.c \
	suites/custom.c \
	suites/transport.c \
	suites/ops.c \
	suites/bootrom.c \
	suites/quirks.c

SRC := $(LIB_SRC) $(HARNESS_SRC) $(SUITE_SRC)
VPATH := $(ROOT)/src:src:suites

endif

# tinyusb's objects are kept apart because they are compiled on different
# terms — see TINYUSB_CFLAGS.
OBJ    := $(patsubst %.c,$(BUILD)/%.o,$(notdir $(SRC)))
TU_OBJ := $(patsubst %.c,$(BUILD)/tu/%.o,$(notdir $(TINYUSB_SRC)))

# ---------------------------------------------------------------------------
# Coverage
#
# The whole build carries counters, harness and suites included, because the
# flag applies to a compilation and not to a file.  The report is then narrowed
# to LIB_SRC, so the harness exercising itself never counts towards what the
# library reached.
#
# picobootx_vendor.c is not in LIB_SRC and so is absent from the data rather
# than reported as nothing reached.  It is the tinyusb vendor driver this suite
# replaces, and it is compiled by examples/tinyusb.
#
# Everything the suite cannot reach is marked in the library with an
# LCOV_EXCL_START / LCOV_EXCL_STOP pair or an LCOV_EXCL_BR_LINE comment, and
# every one of those is an arm defending an invariant the state machine has
# already established.  cov gates on the result being complete, so a new branch
# nothing reaches fails the build, and so does removing a test that was the only
# thing reaching an existing one.
# ---------------------------------------------------------------------------

# The reader for the counters the compiler wrote.  See the note at the top.
GCOV ?= gcov

# Error classes lcov raises about the counters themselves rather than about
# coverage.  llvm-cov's gcov emulation reports branch data lcov judges
# inconsistent, and reports function extents lcov's version checks reject, and
# neither says anything about what the suites reached.  gcc raises neither, so
# accepting them costs the measured configuration nothing and lets the same
# command work under either compiler.
COV_IGNORE := --ignore-errors inconsistent,unsupported,corrupt

# Coverage measures the logging build.  command_to_str is called only from a
# log statement, so with logging off it is compiled and never reached, and a
# figure counting it as missed would be measuring the build rather than the
# suite.  cov-capture therefore re-enters make with both flags set, and the
# directory it reads is named for both — whatever the flags of the invocation
# it was reached from.
# Coverage measures the logging build of both suites, merged.  command_to_str
# is called only from a log statement, so with logging off it is compiled and
# never reached, and a figure counting it as missed would be measuring the build
# rather than the suite.  cov-capture therefore re-enters make with both flags
# set, once per suite, and reads the directories those runs wrote — whatever the
# flags of the invocation it was reached from.
COV_SUFFIX := -logging
ifeq ($(SANITIZE),1)
COV_SUFFIX := $(COV_SUFFIX)-sanitize
endif
COV_SUFFIX := $(COV_SUFFIX)-coverage
ifeq ($(LIB),rust)
COV_SUFFIX := $(COV_SUFFIX)-rust
endif

COV_CORE := build/core$(COV_SUFFIX)
COV_USB  := build/usb$(COV_SUFFIX)
COV_DIR  := build/coverage

COV_ALL  := $(COV_DIR)/all.info
COV_INFO := $(COV_DIR)/picobootx.info
COV_HTML := $(COV_DIR)/html

# Every source file of the library, whichever suite reaches it.  Named here
# rather than taken from LIB_SRC, because LIB_SRC is whatever the current
# invocation is building and the gate is about the library as a whole:
# picobootx_vendor.c is only in the usb suite's build, and a gate that forgot it
# when invoked from the core suite would pass while measuring two files out of
# three.
COV_LIB_SRC := \
	$(if $(filter c,$(LIB)),$(ROOT)/src/picobootx.c) \
	$(ROOT)/src/picobootx_impl.c \
	$(ROOT)/src/picobootx_vendor.c

# The library files as lcov patterns rather than as paths, since lcov records
# whatever absolute path the compiler saw.  Quoted, so the shell hands the
# wildcard to lcov rather than trying to expand it here.
COV_PATTERN := $(patsubst $(ROOT)/%,'*/%',$(COV_LIB_SRC))

.PHONY: all build run clean cov cov-capture cov-html usb usb-build \
        usbip usbip-build

all: build

build: $(TARGET)

run: $(TARGET)
	./$(TARGET) $(FILTER)

# The usb suite, from a core-suite invocation.  Re-enters make rather than
# duplicating the rules, so both suites are built and run the same way.
usb:
	@$(MAKE) SUITE=usb run

usb-build:
	@$(MAKE) SUITE=usb build

# The usbip bridge, driven by picotool.  Linux only.  Building it needs no more
# than the suites do, and running it needs root — loading vhci-hcd and handing it
# a socket are both privileged — so only the run is handed to sudo, and the
# objects stay yours.
usbip: usbip-build
	sudo PBT_BRIDGE=$(abspath $(BRIDGE)) ./usbip/picotool.sh \
	    $(if $(filter 1,$(TRACE)),-v)

usbip-build:
	@$(MAKE) SUITE=usbip build
	@echo $(abspath $(BRIDGE)) > build/usbip-bridge-path

$(TARGET): $(OBJ) $(TU_OBJ) $(RUST_A)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $^

ifeq ($(LIB),rust)
.PHONY: $(RUST_A)
$(RUST_A):
	@cd $(RUST_DIR) && cargo build --release -p picobootx-ffi
endif

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

# tinyusb is vendored, so it is not held to picobootx's warning policy.  Its
# own warnings are not this repository's to fix, and patching them would be a
# change to a pinned dependency.
$(BUILD)/tu/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(TINYUSB_CFLAGS) -c -o $@ $<

cov-capture:
	$(MAKE) SUITE=core COVERAGE=1 LOGGING=1 run
	$(MAKE) SUITE=usb  COVERAGE=1 LOGGING=1 run
	@mkdir -p $(COV_DIR)
	lcov --version
	@# lcov runs the reader as a single executable, so one that needs an
	@# argument of its own — llvm-cov's gcov mode — reaches it through this.
	@printf '#!/bin/sh\nexec %s "$$@"\n' '$(GCOV)' > $(COV_DIR)/gcov-tool
	@chmod +x $(COV_DIR)/gcov-tool
	lcov --gcov-tool $(COV_DIR)/gcov-tool --capture --directory $(COV_CORE) \
	     --output-file $(COV_DIR)/core.info --rc branch_coverage=1 $(COV_IGNORE)
	lcov --gcov-tool $(COV_DIR)/gcov-tool --capture --directory $(COV_USB) \
	     --output-file $(COV_DIR)/usb.info --rc branch_coverage=1 $(COV_IGNORE)
	@# Merged, so a line one suite reaches counts however the other fares.  The
	@# two share picobootx.c and picobootx_impl.c, and only the usb suite
	@# compiles picobootx_vendor.c at all.
	lcov --add-tracefile $(COV_DIR)/core.info --add-tracefile $(COV_DIR)/usb.info \
	     --output-file $(COV_ALL) --rc branch_coverage=1 $(COV_IGNORE)
	lcov --extract $(COV_ALL) $(COV_PATTERN) \
	     --output-file $(COV_INFO) --rc branch_coverage=1 $(COV_IGNORE)
	@test -s $(COV_INFO) || \
	    (echo "no coverage data for $(COV_LIB_SRC)" && exit 1)

cov: cov-capture
	lcov --list $(COV_INFO) --rc branch_coverage=1 $(COV_IGNORE)
	@# The gate.  Every line and function of the library the suite is expected
	@# to reach, with the rest marked unreachable in the source.  Branches are
	@# listed but not gated, as epio does it: gcc and llvm-cov disagree on what
	@# counts as a branch, so gating them would fail under one compiler and pass
	@# under the other.  The file count is checked too, so a library file
	@# dropping out of the report cannot pass as everything left being complete.
	@lcov --list $(COV_INFO) --rc branch_coverage=1 $(COV_IGNORE) | awk -F'|' '\
	    /\.c[ \t]*\|/ { \
	        rows++; \
	        for (i = 2; i <= 3; i++) { \
	            if ($$i !~ /100%/) { \
	                print "not fully covered: " $$0; bad = 1; \
	            } \
	        } \
	    } \
	    END { \
	        if (rows != $(words $(COV_LIB_SRC))) { \
	            print "expected $(words $(COV_LIB_SRC)) files in the report, found " rows+0; \
	            bad = 1; \
	        } \
	        exit (bad ? 1 : 0); \
	    }'

cov-html: cov-capture
	genhtml $(COV_INFO) --output-directory $(COV_HTML) --rc branch_coverage=1 $(COV_IGNORE)
	@echo "coverage report at $(COV_HTML)/index.html"

clean:
	rm -rf build

-include $(OBJ:.o=.d) $(TU_OBJ:.o=.d)
