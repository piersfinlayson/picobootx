# Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
#
# MIT License

# The C half of picobootx's hardware test.
#
# The same arrangement as examples/tinyusb - tinyusb as the USB stack,
# pico-sdkless as the RP2350 support library, both cloned beside this Makefile.
# What it builds is an instrument rather than an example, so it stops at an ELF:
# the board is flashed with picotool, and nothing here needs a UF2.
#
# Usage:
#   make all
#   make clean
#   make distclean

# If the arm-none-eabi toolchain is not in the PATH, set TOOLCHAIN to the
# directory containing it
TOOLCHAIN ?=
CC      := $(if $(TOOLCHAIN),$(TOOLCHAIN)/arm-none-eabi-gcc,arm-none-eabi-gcc)
OBJCOPY := $(if $(TOOLCHAIN),$(TOOLCHAIN)/arm-none-eabi-objcopy,arm-none-eabi-objcopy)
OBJDUMP := $(if $(TOOLCHAIN),$(TOOLCHAIN)/arm-none-eabi-objdump,arm-none-eabi-objdump)

# Bring in tinyusb, at the commit ../../../tinyusb.mk names.  The usb
# conformance suite compiles the same commit, which is what lets a finding on a
# board and a scenario in the suite be about the same library.
TINYUSB_DIR   := tinyusb-repo
include ../../../tinyusb.mk
$(shell $(call tinyusb-fetch,$(TINYUSB_DIR)))
TINYUSB_SRC_C := $(patsubst %,$(TINYUSB_DIR)/%,$(TINYUSB_SRC_C))
TINYUSB_INCLUDE_DIRS := $(patsubst %,$(TINYUSB_DIR)/%,$(TINYUSB_INCLUDE_DIRS))

# Bring in pico-sdkless
PICO_SDKLESS_DIR := pico-sdkless-repo
$(shell [ -d $(PICO_SDKLESS_DIR) ] || git clone https://github.com/piersfinlayson/pico-sdkless.git $(PICO_SDKLESS_DIR))
PICO_SDKLESS_COMMON_DIR := $(PICO_SDKLESS_DIR)/examples/common
include $(PICO_SDKLESS_COMMON_DIR)/common.mk
PICO_SDKLESS_COMMON_SRC := $(patsubst %,$(PICO_SDKLESS_COMMON_DIR)/%,$(COMMON_SRC))
PICO_SDKLESS_COMMON_LD := $(patsubst %,$(PICO_SDKLESS_COMMON_DIR)/%,$(COMMON_LD))

# Bring in picobootx
include ../../../picobootx.mk
PICOBOOTX_SRC_C := $(patsubst %,../../../%,$(PICOBOOTX_SRC_C))
PICOBOOTX_INCLUDE_DIRS := $(patsubst %,../../../%,$(PICOBOOTX_INCLUDE_DIRS))

FLASH_BASE := 0x10000000

# Where the host is told it may erase and program, and how much of it there is.
# It has to be flash this firmware is not made of, and pico-sdkless's linker
# script offers the linker all 2048K of the part - so unlike the embassy half,
# which hands its linker only the flash below the window, this is enforced after
# the link by checking the image never reaches the window.  See check-window.
FLASH_WINDOW := 0x10100000

BUILD_DIR := build
BIN_PREFIX := picobootx-hw-device-tinyusb
ELF := $(BUILD_DIR)/$(BIN_PREFIX).elf
BIN := $(BUILD_DIR)/$(BIN_PREFIX).bin

DEVICE_SRC := src/main.c src/usb_descriptors.c

CFLAGS := -mcpu=cortex-m33 -mthumb -mfloat-abi=hard -mfpu=fpv5-sp-d16 \
          -O2 -Wall -Wextra -Werror \
          -ffunction-sections -fdata-sections \
          -MMD -MP -Iinclude -I../../../include -I$(PICO_SDKLESS_DIR)/include \
          -fno-builtin -nostdlib \
          $(addprefix -I,$(TINYUSB_INCLUDE_DIRS))

LDFLAGS := -nostdlib \
           -T $(PICO_SDKLESS_COMMON_LD) \
           -Wl,--fatal-warnings \
           -Wl,--no-warn-rwx-segments \
           -Wl,-Map=$(BUILD_DIR)/$(BIN_PREFIX).map

DEVICE_OBJ := $(patsubst %.c,$(BUILD_DIR)/%.o,$(DEVICE_SRC))
PICO_SDKLESS_COMMON_OBJ := $(patsubst $(PICO_SDKLESS_COMMON_DIR)/%.c,$(BUILD_DIR)/common/%.o,$(PICO_SDKLESS_COMMON_SRC))
TINYUSB_OBJ := $(patsubst %.c,$(BUILD_DIR)/%.o,$(TINYUSB_SRC_C))
PICOBOOTX_OBJ := $(patsubst ../../../%.c,$(BUILD_DIR)/picobootx/%.o,$(PICOBOOTX_SRC_C))
ALL_OBJ     := $(DEVICE_OBJ) $(PICO_SDKLESS_COMMON_OBJ) $(TINYUSB_OBJ) $(PICOBOOTX_OBJ)

.PHONY: all check-window clean distclean

all: check-window

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/common/%.o: $(PICO_SDKLESS_COMMON_DIR)/%.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/picobootx/%.o: ../../../%.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

$(ELF): $(ALL_OBJ) $(PICO_SDKLESS_DIR)/include/pico.h $(PICO_SDKLESS_COMMON_LD)
	@echo "Linking..."
	@$(CC) $(CFLAGS) $(LDFLAGS) $(ALL_OBJ) -o $@

$(BIN): $(ELF)
	@echo "Converting ELF to binary..."
	@$(OBJCOPY) -O binary $< $@
	@$(OBJDUMP) -s -j .vector_table $(ELF) > $(BUILD_DIR)/$(BIN_PREFIX).dis
	@$(OBJDUMP) -s -j .boot_block $(ELF) >> $(BUILD_DIR)/$(BIN_PREFIX).dis
	@$(OBJDUMP) -d -S $(ELF) >> $(BUILD_DIR)/$(BIN_PREFIX).dis

# The flash the host erases has to be flash this firmware is not made of, and
# the linker was given the whole part.  The binary is the image as it is loaded,
# from FLASH_BASE up with the gaps padded, so its size is where the firmware
# ends - and a firmware that reached the window would be erasing itself.
check-window: $(BIN)
	@size=$$(wc -c < $(BIN) | tr -d ' '); \
	limit=$$(($(FLASH_WINDOW) - $(FLASH_BASE))); \
	if [ $$size -gt $$limit ]; then \
	    echo "$(BIN) is $$size bytes, which reaches the flash window at $(FLASH_WINDOW)" >&2; \
	    echo "The host erases that window, so the firmware must end below it." >&2; \
	    exit 1; \
	fi; \
	echo "Image is $$size bytes, below the flash window at $(FLASH_WINDOW)"

$(BUILD_DIR):
	@mkdir -p $@

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)

distclean: clean
	@echo "Removing cloned repositories..."
	@rm -rf $(TINYUSB_DIR) $(PICO_SDKLESS_DIR)

-include $(ALL_OBJ:.o=.d)
