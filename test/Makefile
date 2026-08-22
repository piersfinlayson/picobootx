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
#   make cov         run under coverage, list what this LIB's library reached,
#                    and fail if the C is not all of it
#   make cov-html    the same, as a browsable report
#   make usbip       put the device on this machine's USB bus and drive it with
#                    picotool.  Linux only, and the run needs root
#   make usbip TRACE=1  the same, with the bridge tracing every transfer
#   make clean
#
# `make cov` here measures one LIB, which is half the library.  The whole of it
# is `make cov` from the repository root, which runs this under both and reports
# the two together — see the Coverage section of CLAUDE.md.
#
# Coverage needs lcov, and a gcov that reads the counters the compiler wrote.
# gcc's own gcov does, and is the default.  clang writes profiles only
# llvm-cov reads, so build coverage with clang by naming its reader:
#
#   make cov CC=clang GCOV="llvm-cov gcov"
#
# Under LIB=rust it also needs rustup's llvm-tools component, which carries the
# llvm-profdata and llvm-cov that read what -C instrument-coverage wrote.
#
# The C gate covers lines and functions, and holds under either compiler.
# Branch counts are listed for information and not gated: llvm-cov's gcov
# emulation counts branches gcc does not — among them some attributed to a
# function's closing brace, which nothing can take — so a branch gate would pass
# under one compiler and fail under the other.

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
# All three build the same library, with different headers and different flags,
# so each keeps its own object directory.
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

# The Rust library is an archive cargo builds.  It carries the protocol and the
# default RP2350 implementations, so nothing in ../src is compiled for it but
# the tinyusb vendor driver.
#
# Under coverage the archive is a different build of the same crates — it
# carries LLVM's counters — so it is built into a target directory of its own.
# Sharing one would mean every switch between `make test LIB=rust` and
# `make cov LIB=rust` rebuilt the workspace.
#
# rustc's own toolchain supplies the tools that read what it wrote: the
# profiler runtime the archive needs at link time, and llvm-profdata and
# llvm-cov afterwards.  Taken from the sysroot rather than from PATH, so a
# system LLVM of some other vintage cannot answer instead.
ifeq ($(LIB),rust)
RUST_DIR    := $(ROOT)/rust
RUST_TARGET := target$(if $(filter 1,$(COVERAGE)),/coverage)
RUST_A      := $(RUST_DIR)/$(RUST_TARGET)/release/libpicobootx_ffi.a
RUST_LINK   := $(RUST_A)

RUST_SYSROOT  := $(shell rustc --print sysroot)
RUST_HOST     := $(shell rustc -vV | sed -n 's/^host: //p')
RUST_LIBDIR   := $(RUST_SYSROOT)/lib/rustlib/$(RUST_HOST)/lib
LLVM_BIN      := $(RUST_SYSROOT)/lib/rustlib/$(RUST_HOST)/bin
LLVM_PROFDATA ?= $(LLVM_BIN)/llvm-profdata
LLVM_COV      ?= $(LLVM_BIN)/llvm-cov

ifeq ($(COVERAGE),1)
RUSTFLAGS_COV := -C instrument-coverage

# A staticlib is linked without the profiler runtime — the crate is dropped on
# the way in — so nothing in the archive defines the writer that turns the
# counters into a file.  rustc's own copy defines it, and taking it from the
# sysroot means it is the version that instrumented the code by construction.
PROFILER_RLIB := $(wildcard $(RUST_LIBDIR)/libprofiler_builtins-*.rlib)

# Asking for __llvm_profile_runtime by name is what pulls that copy in.  On
# Mach-O the archive names it and the linker would fetch it anyway.  On ELF
# nothing names it: the link succeeds, the binary carries its coverage map and
# no writer, and every run exits having written nothing.  That is why it is
# asked for here rather than left to the reference — the failure it prevents is
# silent, and reads as a suite that ran and reached nothing.
#
# The symbol carries a leading underscore in Mach-O's table and none in ELF's.
ifeq ($(shell uname -s),Darwin)
PROFILE_RUNTIME_SYM := ___llvm_profile_runtime
else
PROFILE_RUNTIME_SYM := __llvm_profile_runtime
endif

# Every member of the archive, whether or not the link needs it.  An archive
# member the linker leaves behind carries its coverage map out of the binary
# with it, and llvm-cov reads the binary — so an untested function would read
# as one that does not exist rather than as one nothing reached, and the total
# would say so too.
ifeq ($(shell uname -s),Darwin)
RUST_LINK := -Wl,-force_load,$(abspath $(RUST_A))
else
RUST_LINK := -Wl,--whole-archive $(RUST_A) -Wl,--no-whole-archive
endif
RUST_LINK := -Wl,-u,$(PROFILE_RUNTIME_SYM) $(RUST_LINK) $(PROFILER_RLIB)
endif
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
	$(if $(filter c,$(LIB)),$(ROOT)/src/picobootx.c $(ROOT)/src/picobootx_impl.c) \
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
	$(if $(filter c,$(LIB)),$(ROOT)/src/picobootx.c $(ROOT)/src/picobootx_impl.c)

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
#
# Under LIB=rust the Rust library is measured alongside, by LLVM's own
# instrumentation rather than by gcov, and written to its own tracefile for
# ci/coverage-report.sh to gate against ci/coverage-baseline.txt.  Nothing is
# gated here on it: the floors belong to the whole set of runs, and this
# makefile only ever performs one of them.
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

# One tracefile per LIB, because each measures a different library and the
# top-level cov runs both.  A single name would leave whichever ran second in
# place, and the report would describe half of what was measured.
COV_ALL  := $(COV_DIR)/all-$(LIB).info
COV_INFO := $(COV_DIR)/picobootx-$(LIB).info
COV_HTML := $(COV_DIR)/html-$(LIB)

# The Rust library's own counters.  LLVM writes one raw profile per process,
# llvm-profdata turns the set into one indexed profile, and llvm-cov reads that
# against the binaries the counters came out of.
COV_PROFRAW  := $(COV_DIR)/profraw
COV_PROFDATA := $(COV_DIR)/rust.profdata
COV_RUST     := $(COV_DIR)/rust.info

# The Rust sources the report is narrowed to.  picobootx is the protocol,
# picobootx-rp2350 the default implementations, and picobootx-ffi the C ABI in
# front of both — the only thing that drives the library's public API from C, so
# a line of it nothing reaches is an API path nothing reaches.  rust/interop is
# absent because it is a separate workspace and is not linked here at all.
#
# Absolute, because llvm-cov matches them against the paths rustc recorded and
# those are absolute.
COV_RUST_SRC := \
	$(abspath $(ROOT)/rust/picobootx/src) \
	$(abspath $(ROOT)/rust/picobootx-rp2350/src) \
	$(abspath $(ROOT)/rust/picobootx-ffi/src)

# %p, so the two suites — and a re-run of either — each write their own raw
# profile.  Without it the last process to exit replaces what the others
# recorded.
ifeq ($(LIB)$(COVERAGE),rust1)
COV_RUN_ENV := LLVM_PROFILE_FILE=$(abspath $(COV_PROFRAW))/%p.profraw
endif

# Every source file of the library, whichever suite reaches it.  Named here
# rather than taken from LIB_SRC, because LIB_SRC is whatever the current
# invocation is building and the gate is about the library as a whole:
# picobootx_vendor.c is only in the usb suite's build, and a gate that forgot it
# when invoked from the core suite would pass while measuring two files out of
# three.
#
# Under LIB=rust the only C left is picobootx_vendor.c, and that is all this
# measures: the protocol and the default implementations are then the Rust
# archive's, which carries no gcov counters.
COV_LIB_SRC := \
	$(if $(filter c,$(LIB)),$(ROOT)/src/picobootx.c $(ROOT)/src/picobootx_impl.c) \
	$(ROOT)/src/picobootx_vendor.c

# The library files as lcov patterns rather than as paths, since lcov records
# whatever absolute path the compiler saw.  Quoted, so the shell hands the
# wildcard to lcov rather than trying to expand it here.
COV_PATTERN := $(patsubst $(ROOT)/%,'*/%',$(COV_LIB_SRC))

.PHONY: all build run clean cov cov-capture cov-capture-rust cov-html \
        usb usb-build usbip usbip-build

all: build

build: $(TARGET)

run: $(TARGET)
	$(COV_RUN_ENV) ./$(TARGET) $(FILTER)

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

# The archive reaches the link through RUST_LINK rather than through $^, since
# under coverage it is named to the linker with flags around it rather than as
# an ordinary input.
$(TARGET): $(OBJ) $(TU_OBJ) $(RUST_A)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(TU_OBJ) $(RUST_LINK)

ifeq ($(LIB),rust)
.PHONY: $(RUST_A)
# RUSTFLAGS reaches a build script as well as the library, so under coverage
# the build scripts are instrumented too and each writes a profile as it exits.
# cargo runs them with the package directory as their working directory, so
# without somewhere to put it that profile lands in the source tree - and if it
# landed among the suites' profiles instead, a build script's counters would be
# merged into the library's figures.  Neither is wanted, so it goes to a
# directory of its own under build.
$(RUST_A):
	@cd $(RUST_DIR) && CARGO_TARGET_DIR=$(RUST_TARGET) \
	    LLVM_PROFILE_FILE=$(abspath $(COV_DIR))/build-scripts/%p.profraw \
	    RUSTFLAGS="$(RUSTFLAGS_COV)" cargo build --release -p picobootx-ffi
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
	@mkdir -p $(COV_DIR)
	@# gcov's counters are deleted rather than left in place, because the
	@# runtime adds to what it finds.  A counter file from the run before keeps
	@# crediting a line the deleted test was the only thing reaching — so the
	@# gate that exists to fail when a test goes would say nothing.
	find $(COV_CORE) $(COV_USB) -name '*.gcda' -delete 2>/dev/null || true
ifeq ($(LIB),rust)
	@# The same for LLVM's raw profiles, which llvm-profdata merges as a union.
	rm -rf $(COV_PROFRAW)
	@mkdir -p $(COV_PROFRAW)
endif
	$(MAKE) SUITE=core COVERAGE=1 LOGGING=1 run
	$(MAKE) SUITE=usb  COVERAGE=1 LOGGING=1 run
	lcov --version
	@# lcov runs the reader as a single executable, so one that needs an
	@# argument of its own — llvm-cov's gcov mode — reaches it through this.
	@printf '#!/bin/sh\nexec %s "$$@"\n' '$(GCOV)' > $(COV_DIR)/gcov-tool
	@chmod +x $(COV_DIR)/gcov-tool
	lcov --gcov-tool $(COV_DIR)/gcov-tool --capture --directory $(COV_CORE) \
	     --output-file $(COV_DIR)/core-$(LIB).info --rc branch_coverage=1 $(COV_IGNORE)
	lcov --gcov-tool $(COV_DIR)/gcov-tool --capture --directory $(COV_USB) \
	     --output-file $(COV_DIR)/usb-$(LIB).info --rc branch_coverage=1 $(COV_IGNORE)
	@# Merged, so a line one suite reaches counts however the other fares.  The
	@# two share whichever of the library's C files this LIB builds, and only
	@# the usb suite compiles picobootx_vendor.c at all.
	lcov --add-tracefile $(COV_DIR)/core-$(LIB).info \
	     --add-tracefile $(COV_DIR)/usb-$(LIB).info \
	     --output-file $(COV_ALL) --rc branch_coverage=1 $(COV_IGNORE)
	lcov --extract $(COV_ALL) $(COV_PATTERN) \
	     --output-file $(COV_INFO) --rc branch_coverage=1 $(COV_IGNORE)
	@test -s $(COV_INFO) || \
	    (echo "no coverage data for $(COV_LIB_SRC)" && exit 1)
	@# Paths as ci/coverage-report.sh and ci/coverage-baseline.txt name them:
	@# from the repository root.  lcov records whatever absolute path the
	@# compiler saw, which is where the tree happens to be checked out.
	@sed -i.bak 's#^SF:$(abspath $(ROOT))/#SF:#' $(COV_INFO) && rm -f $(COV_INFO).bak
ifeq ($(LIB),rust)
	@$(MAKE) COVERAGE=1 cov-capture-rust
endif

# The Rust library's half.  Only under LIB=rust: with LIB=c there is no Rust in
# the binary at all.
#
# One indexed profile from every process that ran, then one tracefile per
# binary.  llvm-cov reads a binary's coverage map against a profile, and takes
# one binary, so each is asked in turn.  The profile is the merge of both runs
# before either export, so both exports carry both suites' counts and the two
# tracefiles come out the same as each other whenever the binaries carry the
# same instrumented functions - which they do, since both link the whole
# archive.  ci/coverage-report.sh unions them, so a binary that one day carries
# only part of the library still contributes what it has.
cov-capture-rust:
	@ls $(COV_PROFRAW)/*.profraw >/dev/null 2>&1 || \
	    (echo "no raw profiles in $(COV_PROFRAW) — the runs wrote none" && exit 1)
	@# A raw profile of zero bytes is one the writer never got to.  llvm-profdata
	@# merges it without complaint and the figures then describe a run that did
	@# not happen, so this is checked here rather than trusted.
	@# Braces, not a subshell: `|| (… && exit 1)` inside a loop exits the
	@# subshell alone, so the loop carries on and the recipe's status is
	@# whatever the last iteration returned.
	@for f in $(COV_PROFRAW)/*.profraw; do \
	    test -s $$f || { echo "$$f is empty — the run did not write its profile" >&2; exit 1; }; \
	done
	$(LLVM_PROFDATA) merge -sparse -o $(COV_PROFDATA) $(COV_PROFRAW)/*.profraw
	@rm -f $(COV_RUST)
	@for pair in core:$(COV_CORE)/picobootx-test usb:$(COV_USB)/picobootx-usb-test; do \
	    name=$${pair%%:*}; bin=$${pair#*:}; \
	    $(LLVM_COV) export --format=lcov --instr-profile $(COV_PROFDATA) \
	        $$bin $(COV_RUST_SRC) > $(COV_DIR)/rust-$$name.info || exit 1; \
	done
	@# Same normalisation as the C's, for the same reason.
	@sed -e 's#^SF:$(abspath $(ROOT))/#SF:#' \
	     $(COV_DIR)/rust-core.info $(COV_DIR)/rust-usb.info > $(COV_RUST)
	@test -s $(COV_RUST) || \
	    (echo "no coverage data for $(COV_RUST_SRC)" && exit 1)

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

# From the repository root, because the tracefile names its files from there and
# genhtml has to find the source to quote it.
cov-html: cov-capture
	cd $(ROOT) && genhtml $(abspath $(COV_INFO)) \
	    --output-directory $(abspath $(COV_HTML)) --rc branch_coverage=1 $(COV_IGNORE)
	@echo "coverage report at $(COV_HTML)/index.html"

clean:
	rm -rf build

-include $(OBJ:.o=.d) $(TU_OBJ:.o=.d)
