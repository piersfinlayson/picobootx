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
#   make cov         run under coverage, list what the library reached, and
#                    fail if it is not all of it
#   make cov-html    the same, as a browsable report
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

# Each configuration keeps its own object directory.  They differ only in
# compiler flags, which make cannot see, so sharing one directory would leave
# whichever configuration was built first in place.
BUILD_VARIANT := base
ifeq ($(LOGGING),1)
BUILD_VARIANT := $(BUILD_VARIANT)-logging
endif
ifeq ($(SANITIZE),1)
BUILD_VARIANT := $(BUILD_VARIANT)-sanitize
endif
ifeq ($(COVERAGE),1)
BUILD_VARIANT := $(BUILD_VARIANT)-coverage
endif

BUILD   ?= build/$(BUILD_VARIANT)
TARGET  := $(BUILD)/picobootx-test

ROOT    := ..

INCLUDES := -Ishim -I$(ROOT)/include -Isrc

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

CFLAGS  += $(EXTRA_CFLAGS)
LDFLAGS += $(EXTRA_LDFLAGS)

# The library under test.  picobootx_vendor.c is deliberately absent: it is the
# tinyusb vendor driver, and the harness supplies its own implementation of the
# picoboot_vendor_* API it provides.
LIB_SRC := \
	$(ROOT)/src/picobootx.c \
	$(ROOT)/src/picobootx_impl.c

HARNESS_SRC := \
	src/pbt_core.c \
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
OBJ := $(patsubst %.c,$(BUILD)/%.o,$(notdir $(SRC)))

VPATH := $(ROOT)/src:src:suites

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

# Coverage measures the logging build.  command_to_str is called only from a
# log statement, so with logging off it is compiled and never reached, and a
# figure counting it as missed would be measuring the build rather than the
# suite.  cov-capture therefore re-enters make with both flags set, and the
# directory it reads is named for both — whatever the flags of the invocation
# it was reached from.
COV_VARIANT := base-logging
ifeq ($(SANITIZE),1)
COV_VARIANT := $(COV_VARIANT)-sanitize
endif
COV_BUILD := build/$(COV_VARIANT)-coverage

COV_ALL  := $(COV_BUILD)/all.info
COV_INFO := $(COV_BUILD)/picobootx.info
COV_HTML := $(COV_BUILD)/html

# The library files as lcov patterns rather than as paths, since lcov records
# whatever absolute path the compiler saw.  Quoted, so the shell hands the
# wildcard to lcov rather than trying to expand it here.
COV_PATTERN := $(patsubst $(ROOT)/%,'*/%',$(LIB_SRC))

.PHONY: all build run clean cov cov-capture cov-html

all: build

build: $(TARGET)

run: $(TARGET)
	./$(TARGET) $(FILTER)

$(TARGET): $(OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $^

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

cov-capture:
	$(MAKE) COVERAGE=1 LOGGING=1 run
	lcov --version
	@# lcov runs the reader as a single executable, so one that needs an
	@# argument of its own — llvm-cov's gcov mode — reaches it through this.
	@printf '#!/bin/sh\nexec %s "$$@"\n' '$(GCOV)' > $(COV_BUILD)/gcov-tool
	@chmod +x $(COV_BUILD)/gcov-tool
	lcov --gcov-tool $(COV_BUILD)/gcov-tool --capture --directory $(COV_BUILD) \
	     --output-file $(COV_ALL) --rc branch_coverage=1
	lcov --extract $(COV_ALL) $(COV_PATTERN) \
	     --output-file $(COV_INFO) --rc branch_coverage=1
	@test -s $(COV_INFO) || \
	    (echo "no coverage data for $(LIB_SRC)" && exit 1)

cov: cov-capture
	lcov --list $(COV_INFO) --rc branch_coverage=1
	@# The gate.  Every line and function of the library the suite is expected
	@# to reach, with the rest marked unreachable in the source.  Branches are
	@# listed but not gated, as epio does it: gcc and llvm-cov disagree on what
	@# counts as a branch, so gating them would fail under one compiler and pass
	@# under the other.  The file count is checked too, so a library file
	@# dropping out of the report cannot pass as everything left being complete.
	@lcov --list $(COV_INFO) --rc branch_coverage=1 | awk -F'|' '\
	    /\.c[ \t]*\|/ { \
	        rows++; \
	        for (i = 2; i <= 3; i++) { \
	            if ($$i !~ /100%/) { \
	                print "not fully covered: " $$0; bad = 1; \
	            } \
	        } \
	    } \
	    END { \
	        if (rows != $(words $(LIB_SRC))) { \
	            print "expected $(words $(LIB_SRC)) files in the report, found " rows+0; \
	            bad = 1; \
	        } \
	        exit (bad ? 1 : 0); \
	    }'

cov-html: cov-capture
	genhtml $(COV_INFO) --output-directory $(COV_HTML) --rc branch_coverage=1
	@echo "coverage report at $(COV_HTML)/index.html"

clean:
	rm -rf build
