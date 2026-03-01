# Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
#
# MIT License

# Makefile for building the picobootx tinyusb example
#
# Uses tinyusb as the USB stack and pico-sdkless as the RP2350 support library
#
# Automaticaly clones tinyusb and pico-sdkless
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

# Bring in tinyusb
TINYUSB_DIR   := tinyusb-repo
$(shell [ -d $(TINYUSB_DIR) ] || git clone https://github.com/piersfinlayson/tinyusb.git $(TINYUSB_DIR))
include tinyusb.mk
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
include ../../picobootx.mk
PICOBOOTX_SRC_C := $(patsubst %,../../%,$(PICOBOOTX_SRC_C))
PICOBOOTX_INCLUDE_DIRS := $(patsubst %,../../%,$(PICOBOOTX_INCLUDE_DIRS))

# RP2350 ARM (non-secure) family ID
RP2350_FAMILY_ID := 0xe48bff59
FLASH_BASE       := 0x10000000

BUILD_DIR := build
BIN_PREFIX := picobootx
ELF := $(BUILD_DIR)/$(BIN_PREFIX).elf
BIN := $(BUILD_DIR)/$(BIN_PREFIX).bin

TOOLSDIR := tools
UF2CONV := $(TOOLSDIR)/uf2conv.py
UF2     := $(BUILD_DIR)/$(BIN_PREFIX).uf2

EXAMPLE_SRC := src/main.c src/usb_descriptors.c

CFLAGS := -mcpu=cortex-m33 -mthumb -mfloat-abi=hard -mfpu=fpv5-sp-d16 \
          -O2 -Wall -Wextra -Werror \
          -ffunction-sections -fdata-sections \
          -MMD -MP -Iinclude -I../../include -I$(PICO_SDKLESS_DIR)/include \
          -fno-builtin -nostdlib \
          $(addprefix -I,$(TINYUSB_INCLUDE_DIRS))

LDFLAGS := -nostdlib \
           -T $(PICO_SDKLESS_COMMON_LD) \
           -Wl,--fatal-warnings \
           -Wl,-Map=$(BUILD_DIR)/$(BIN_PREFIX).map

EXAMPLE_OBJ := $(patsubst %.c,$(BUILD_DIR)/%.o,$(EXAMPLE_SRC))
PICO_SDKLESS_COMMON_OBJ := $(patsubst $(PICO_SDKLESS_COMMON_DIR)/%.c,$(BUILD_DIR)/common/%.o,$(PICO_SDKLESS_COMMON_SRC))
TINYUSB_OBJ := $(patsubst %.c,$(BUILD_DIR)/%.o,$(TINYUSB_SRC_C))
PICOBOOTX_OBJ := $(patsubst ../../%.c,$(BUILD_DIR)/picobootx/%.o,$(PICOBOOTX_SRC_C))
ALL_OBJ     := $(EXAMPLE_OBJ) $(PICO_SDKLESS_COMMON_OBJ) $(TINYUSB_OBJ) $(PICOBOOTX_OBJ)

.PHONY: all clean distclean

all: $(UF2)

$(UF2CONV):
	@mkdir -p $(TOOLSDIR)
	@echo "Downloading uf2conv.py..."
	@curl -sL https://raw.githubusercontent.com/microsoft/uf2/master/utils/uf2conv.py -o $@
	@curl -sL https://raw.githubusercontent.com/microsoft/uf2/master/utils/uf2families.json -o tools/uf2families.json
	@chmod +x $@

$(UF2): $(BIN) $(UF2CONV)
	@echo "Converting binary to UF2..."
	@python3 $(UF2CONV) --base $(FLASH_BASE) --family $(RP2350_FAMILY_ID) --output $@ $<

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/common/%.o: $(PICO_SDKLESS_COMMON_DIR)/%.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/picobootx/%.o: ../../%.c | $(BUILD_DIR)
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

$(BUILD_DIR):
	@mkdir -p $@

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)

toolsclean:
	@echo "Cleaning downloaded tools..."
	@rm -rf $(TOOLSDIR)

distclean: clean
	@echo "Removing cloned repositories..."
	@rm -rf $(TINYUSB_DIR)

-include $(ALL_OBJ:.o=.d)