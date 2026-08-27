// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// Default picobootx protocol implementations.
//
// Either use these or write your own using these as a starting point.

#include "picobootx_private.h"
#include "picobootx_impl.h"

// Error codes returned by ROM functions
#define BOOTROM_ERROR_TIMEOUT                   (-1)    // Unused in RP2350
#define BOOTROM_ERROR_GENERIC                   (-2)    // Unused in RP2350
#define BOOTROM_ERROR_NO_DATA                   (-3)    // Unused in RP2350
#define BOOTROM_ERROR_NOT_PERMITTED             (-4)
#define BOOTROM_ERROR_INVALID_ARG               (-5)
#define BOOTROM_ERROR_IO                        (-6)    // Unused in RP2350
#define BOOTROM_ERROR_BADAUTH                   (-7)    // Unused in RP2350
#define BOOTROM_ERROR_CONNECT_FAILED            (-8)    // Unused in RP2350
#define BOOTROM_ERROR_INSUFFICIENT_RESOURCES    (-9)    // get_uf2_target_partition
                                                        // returns it for a work area
                                                        // too small
#define BOOTROM_ERROR_INVALID_ADDRESS           (-10)
#define BOOTROM_ERROR_BAD_ALIGNMENT             (-11)
#define BOOTROM_ERROR_INVALID_STATE             (-12)
#define BOOTROM_ERROR_BUFFER_TOO_SMALL          (-13)
#define BOOTROM_ERROR_PRECONDITION_NOT_MET      (-14)
#define BOOTROM_ERROR_MODIFIED_DATA             (-15)
#define BOOTROM_ERROR_INVALID_DATA              (-16)
#define BOOTROM_ERROR_NOT_FOUND                 (-17)
#define BOOTROM_ERROR_UNSUPPORTED_MODIFICATION  (-18)
#define BOOTROM_ERROR_LOCK_REQUIRED             (-19)

// OTP access flags used by otp_access_fn_t
#define OTP_ACCESS_FLAG_WRITE 0x00010000u
#define OTP_ACCESS_FLAG_ECC   0x00020000u

// Whether addr through addr + size lies inside the region at base.
//
// The end is taken in 64 bits, so a range that would wrap the address space is
// outside every region rather than inside whichever one its wrapped end lands
// in.
static bool pb_range_within(
    uint32_t addr,
    uint32_t size,
    uint32_t base,
    uint32_t len
) {
    uint64_t end = (uint64_t)addr + (uint64_t)size;
    return addr >= base && end <= (uint64_t)base + (uint64_t)len;
}

pb_status_t pb_status_from_bootrom(int ret) {
    switch (ret) {
        case 0:                                    return PB_STATUS_OK;
        case BOOTROM_ERROR_NOT_PERMITTED:          return PB_STATUS_NOT_PERMITTED;
        case BOOTROM_ERROR_INVALID_ARG:            return PB_STATUS_INVALID_ARG;
        case BOOTROM_ERROR_INVALID_ADDRESS:        return PB_STATUS_INVALID_ADDRESS;
        case BOOTROM_ERROR_BAD_ALIGNMENT:          return PB_STATUS_BAD_ALIGNMENT;
        case BOOTROM_ERROR_INVALID_STATE:          return PB_STATUS_INVALID_STATE;
        case BOOTROM_ERROR_BUFFER_TOO_SMALL:       return PB_STATUS_BUFFER_TOO_SMALL;
        case BOOTROM_ERROR_PRECONDITION_NOT_MET:   return PB_STATUS_PRECONDITION_NOT_MET;
        case BOOTROM_ERROR_MODIFIED_DATA:          return PB_STATUS_MODIFIED_DATA;
        case BOOTROM_ERROR_INVALID_DATA:           return PB_STATUS_INVALID_DATA;
        case BOOTROM_ERROR_NOT_FOUND:              return PB_STATUS_NOT_FOUND;
        case BOOTROM_ERROR_UNSUPPORTED_MODIFICATION: return PB_STATUS_UNSUPPORTED_MOD;
        default:                                   return PB_STATUS_UNKNOWN_ERROR;
    }
}

void *picoboot_lookup_boot_fn(char a, char b) {
    uint32_t code = (uint32_t)((uint8_t)b << 8) | (uint8_t)a;
    return PICOBOOTX_BOOTROM_LOOKUP(code, RP2350_ROM_TABLE_FLAG_FUNC_ARM_SEC);
}

typedef int (*reboot_fn_t)(uint32_t flags, uint32_t delay_ms, uint32_t p0, uint32_t p1);
static reboot_fn_t pb_lookup_reboot_fn(void) {
    reboot_fn_t reboot = (reboot_fn_t)picoboot_lookup_boot_fn('R', 'B');
    return reboot;
}

typedef int (*get_sys_info_fn_t)(uint32_t *out_buffer, uint32_t out_buffer_word_size, uint32_t flags);
static get_sys_info_fn_t pb_lookup_get_sys_info_fn(void) {
    get_sys_info_fn_t get_sys_info = (get_sys_info_fn_t)picoboot_lookup_boot_fn('G', 'S');
    return get_sys_info;
}

typedef int (*get_partition_table_info_fn_t)(uint32_t *out_buffer, uint32_t out_buffer_word_size, uint32_t flags_and_partition);
static get_partition_table_info_fn_t pb_lookup_get_partition_table_info_fn(void) {
    return (get_partition_table_info_fn_t)picoboot_lookup_boot_fn('G', 'P');
}

typedef int (*otp_access_fn_t)(uint8_t *buf, uint32_t buf_len, uint32_t row_and_flags);
otp_access_fn_t pb_lookup_otp_access_fn(void) {
    return (otp_access_fn_t)picoboot_lookup_boot_fn('O', 'A');
}

typedef void (*flash_range_erase_fn_t)(uint32_t flash_offs, size_t count, uint32_t block_size, uint8_t block_cmd);
static flash_range_erase_fn_t pb_lookup_flash_range_erase_fn(void) {
    return (flash_range_erase_fn_t)picoboot_lookup_boot_fn('R', 'E');
}

typedef void (*flash_range_program_fn_t)(uint32_t flash_offs, const uint8_t *data, size_t count);
static flash_range_program_fn_t pb_lookup_flash_range_program_fn(void) {
    return (flash_range_program_fn_t)picoboot_lookup_boot_fn('R', 'P');
}

typedef void (*connect_internal_flash_fn_t)(void);
static connect_internal_flash_fn_t pb_lookup_connect_internal_flash_fn(void) {
    return (connect_internal_flash_fn_t)picoboot_lookup_boot_fn('I', 'F');
}

typedef void (*flash_exit_xip_fn_t)(void);
static flash_exit_xip_fn_t pb_lookup_flash_exit_xip_fn(void) {
    return (flash_exit_xip_fn_t)picoboot_lookup_boot_fn('E', 'X');
}

typedef void (*flash_flush_cache_fn_t)(void);
static flash_flush_cache_fn_t pb_lookup_flash_flush_cache_fn(void) {
    return (flash_flush_cache_fn_t)picoboot_lookup_boot_fn('F', 'C');
}

typedef void (*flash_select_xip_read_mode_fn_t)(uint8_t mode, uint8_t clkdiv);
static flash_select_xip_read_mode_fn_t pb_lookup_flash_select_xip_read_mode_fn(void) {
    return (flash_select_xip_read_mode_fn_t)picoboot_lookup_boot_fn('X', 'M');
}

size_t picoboot_get_serial(uint16_t *buffer, size_t max_len) {
    if (max_len < 17) {
        ERR("Serial buffer too small: %zu code units", max_len);
        return 0;
    }

    otp_access_fn_t otp_access = pb_lookup_otp_access_fn();
    if (otp_access == NULL) {
        ERR("Unable to find OTP access function in ROM - cannot read serial");
        return 0;
    }

    uint8_t chipid[8];
    int rc = otp_access(chipid, sizeof(chipid), OTP_ACCESS_FLAG_ECC | 0x000);
    if (rc != 0) {
        ERR("Failed to read chip ID from OTP: %d", rc);
        return 0;
    }

    uint16_t words[4];
    for (int i = 0; i < 4; i++) {
        words[i] = (uint16_t)chipid[i * 2] | ((uint16_t)chipid[i * 2 + 1] << 8);
    }

    // Format as UTF-16LE hex string, MSW first
    static const char hex[] = "0123456789ABCDEF";
    size_t pos = 0;
    for (int w = 3; w >= 0; w--) {
        for (int nibble = 3; nibble >= 0; nibble--) {
            buffer[pos++] = (uint16_t)hex[(words[w] >> (nibble * 4)) & 0xf];
        }
    }
    buffer[pos] = 0;

    return pos;
}

pb_status_t picoboot_default_exclusive_access(const pb_exclusive_access_args_t *args, void *ctx) {
    (void)args;
    (void)ctx;

    pb_status_t st = PB_STATUS_OK;
    switch (args->ea_type) {
        case PB_EA_NOT_EXCL:
        case PB_EA_EXCL:
        case PB_EA_EXCL_AND_EJECT:
            break;

        default:
            st = PB_STATUS_INVALID_ARG;
            break;
    }

    return st;
}

pb_status_t picoboot_default_exit_xip(void *ctx) {
    (void)ctx;
    return PB_STATUS_OK;
}

pb_status_t picoboot_default_enter_xip(void *ctx) {
    (void)ctx;
    return PB_STATUS_OK;
}

pb_status_t picoboot_default_reboot2_prepare(const pb_reboot2_args_t *args, void *ctx) {
    (void)ctx;
    (void)args;

    reboot_fn_t reboot = pb_lookup_reboot_fn();
    if (reboot == NULL) {
        ERR("Unable to find reboot function in ROM - cannot prepare for reboot");
        return PB_STATUS_NOT_FOUND;
    }

    return PB_STATUS_OK;
}

void picoboot_default_reboot2_execute(const pb_reboot2_args_t *args, void *ctx) {
    (void)args;
    (void)ctx;

    // This should not fail as it as we checked for it in prepare
    reboot_fn_t reboot = pb_lookup_reboot_fn();
    if (reboot == NULL) {
        ERR("Unable to find reboot function in ROM - cannot prepare for reboot");
        return;
    }

    uint32_t flags  = args->flags;
    uint32_t delay_ms = args->delay_ms;
    uint32_t p0 = args->p0;
    uint32_t p1 = args->p1;

    reboot(flags, delay_ms, p0, p1);
}

pb_status_t picoboot_default_read_prepare(
    uint32_t addr, 
    uint32_t size, 
    void *ctx
) {
    (void)ctx;

    // Validate entire range lies within a single valid region.  A range
    // spanning two of them is refused, since the gap between them is not
    // memory.
    bool valid =
        pb_range_within(addr, size, RP2350_ROM_BASE,   RP2350_ROM_SIZE)   ||
        pb_range_within(addr, size, RP2350_FLASH_BASE, RP2350_FLASH_SIZE) ||
        pb_range_within(addr, size, RP2350_SRAM_BASE,  RP2350_SRAM_SIZE);

    if (!valid) {
        LOG("Invalid read request: addr=0x%08x size=%u", addr, size);
        return PB_STATUS_INVALID_ARG;
    }

    return PB_STATUS_OK;
}

pb_status_t picoboot_default_read(uint32_t addr, uint8_t *buf, uint32_t len, void *ctx) {
    (void)ctx;

    // Don't validate here as it will have been done in picoboot_read_validate

    const void *src = PICOBOOTX_DEV_PTR(addr, len);

    if ((addr % 4 == 0) && (len == 4)) {
        // Aligned word read - can just read directly into the buffer
        *(uint32_t *)buf = *(const uint32_t *)src;
        return PB_STATUS_OK;
    }

    // Otherwise memcpy
    memcpy(buf, src, len);
    return PB_STATUS_OK;
}

pb_status_t picoboot_default_write_prepare(
    uint32_t addr,
    uint32_t size,
    bool *is_flash,
    void *ctx
) {
    (void)ctx;

    bool is_sram =
        pb_range_within(addr, size, RP2350_SRAM_BASE, RP2350_SRAM_SIZE);
    bool is_flash_region =
        pb_range_within(addr, size, RP2350_FLASH_BASE, RP2350_FLASH_SIZE);

    if (!is_sram && !is_flash_region) {
        LOG("Invalid write request: addr=0x%08x size=%u", addr, size);
        return PB_STATUS_INVALID_ARG;
    }

    if (is_flash_region && (addr % 256u) != 0u) {
        LOG("Unaligned flash write: addr=0x%08x", addr);
        return PB_STATUS_BAD_ALIGNMENT;
    }

    *is_flash = is_flash_region;
    return PB_STATUS_OK;
}

pb_status_t picoboot_default_write(
    uint32_t addr,
    const uint8_t *buf,
    uint32_t len,
    void *ctx
) {
    (void)ctx;
    memcpy(PICOBOOTX_DEV_PTR(addr, len), buf, len);
    return PB_STATUS_OK;
}

pb_status_t picoboot_default_flash_page_write(
    uint32_t addr,
    const uint8_t *buf,
    void *ctx
) {
    (void)ctx;

    flash_range_program_fn_t flash_range_program = pb_lookup_flash_range_program_fn();
    if (flash_range_program == NULL) {
        ERR("Unable to find flash_range_program in ROM");
        return PB_STATUS_NOT_FOUND;
    }

    uint32_t flash_offs = addr - RP2350_FLASH_BASE;
    flash_range_program(flash_offs, buf, 256u);
    return PB_STATUS_OK;
}

pb_status_t picoboot_default_flash_erase_prepare(
    const pb_addr_size_args_t *args,
    void *ctx
) {
    (void)ctx;

    if (!pb_range_within(args->addr, args->size,
                         RP2350_FLASH_BASE, RP2350_FLASH_SIZE)) {
        ERR("flash_erase_prepare: address out of range: addr=0x%08x size=%u", args->addr, args->size);
        return PB_STATUS_INVALID_ADDRESS;
    }

    if ((args->addr % FLASH_SECTOR_SIZE) != 0u || (args->size % FLASH_SECTOR_SIZE) != 0u) {
        ERR("flash_erase_prepare: addr/size not sector-aligned: addr=0x%08x size=%u", args->addr, args->size);
        return PB_STATUS_BAD_ALIGNMENT;
    }

    return PB_STATUS_OK;
}

// This function MUST run from RAM, as it disables flash access while erasing.
// It also disables interrupts (which are also serviced from flash) for the
// duration of the erase.
static void PICOBOOTX_RAMFUNC flash_erase_critical(
    flash_exit_xip_fn_t exit_xip,
    flash_range_erase_fn_t range_erase,
    flash_flush_cache_fn_t flush_cache,
    flash_select_xip_read_mode_fn_t select_xip,
    uint32_t flash_offs,
    uint32_t size,
    uint8_t clkdiv
) {
    // Disable interrupts
    PICOBOOTX_IRQ_DISABLE();

    // Exit XIP mode before erasing so that the RP2350 enters QSPI serial
    // command mode (required for erases).  This has the impact of preventing
    // access to flash from code. 
    exit_xip();

    // Erase the appropriate set of sectors.  The bootrom flash erase function
    // figures out if it can do a bulk erase or needs to do multiple sector
    // erases - which is why we pass in the command for doing larger erases in
    // case it can use it.
    range_erase(flash_offs, size, FLASH_BLOCK_SIZE, FLASH_BLOCK_ERASE_CMD);
    
    // Re-enable XIP mode so firmware can re-access flash.
    select_xip(3, clkdiv);

    // Flush the flash cache to ensure the pre-erased data isn't returned on
    // subsequent reads.
    flush_cache();

    // Re-enable interrupts
    PICOBOOTX_IRQ_ENABLE();
}

pb_status_t picoboot_default_flash_erase(
    const pb_addr_size_args_t *args,
    void *ctx
) {
    (void)ctx;

    connect_internal_flash_fn_t connect_internal_flash = pb_lookup_connect_internal_flash_fn();
    if (connect_internal_flash == NULL) {
        ERR("Unable to find connect_internal_flash in ROM");
        return PB_STATUS_NOT_FOUND;
    }

    flash_exit_xip_fn_t flash_exit_xip = pb_lookup_flash_exit_xip_fn();
    if (flash_exit_xip == NULL) {
        ERR("Unable to find flash_exit_xip in ROM");
        return PB_STATUS_NOT_FOUND;
    }

    flash_range_erase_fn_t flash_range_erase = pb_lookup_flash_range_erase_fn();
    if (flash_range_erase == NULL) {
        ERR("Unable to find flash_range_erase in ROM");
        return PB_STATUS_NOT_FOUND;
    }

    flash_flush_cache_fn_t flash_flush_cache = pb_lookup_flash_flush_cache_fn();
    if (flash_flush_cache == NULL) {
        ERR("Unable to find flash_flush_cache in ROM");
        return PB_STATUS_NOT_FOUND;
    }

    flash_select_xip_read_mode_fn_t flash_select_xip_read_mode = pb_lookup_flash_select_xip_read_mode_fn();
    if (flash_select_xip_read_mode == NULL) {
        ERR("Unable to find flash_select_xip_read_mode in ROM");
        return PB_STATUS_NOT_FOUND;
    }

    DEBUG("erase flash: addr=0x%08x size=%u", args->addr, args->size);
    connect_internal_flash();

    // Restore XIP mode using the clock divisor currently configured in QMI,
    // which reflects whatever was set up by the firmware's own QMI setup.
    // Mode 3 (EBh quad-IO) is the fastest; if this causes issues try mode 2
    // (BBh dual-IO), mode 1 (0Bh serial), or mode 0 (03h serial, slowest/most
    // compatible). Alternatively, the bootrom saves the discovered mode into
    // boot RAM as an XIP setup function which could be called here instead,
    // restoring exactly what the bootrom found during flash scanning.
    uint8_t clkdiv = PICOBOOTX_XIP_CLKDIV();
    DEBUG("Will be restoring flash XIP mode 3 with clkdiv %u", clkdiv);

    uint32_t flash_offs = args->addr - RP2350_FLASH_BASE;
    flash_erase_critical(
        flash_exit_xip,
        flash_range_erase,
        flash_flush_cache,
        flash_select_xip_read_mode,
        flash_offs,
        args->size,
        clkdiv
    );

    DEBUG("flash erase completed");

    return PB_STATUS_OK;
}

// PT_INFO, in get_partition_table_info's flags_and_partition (RP2350 datasheet
// 5.4.8.16).  Its answer is the flags word, a word of partition counts, and two
// words describing the unpartitioned space.
#define PB_PT_INFO_FLAG   0x0001u
#define PB_PT_INFO_WORDS  4u

// Word 0 of a UF2 target answer, saying the family goes nowhere (RP2350
// datasheet 5.6.4.11).
#define PB_UF2_TARGET_NONE 0xffffffffu

// Where a UF2 of some family would be downloaded to.
//
// Nowhere.  A UF2 is dragged onto a mass storage drive, as it is onto the one
// BOOTSEL mode presents.  picobootx presents none and is told of none, so there
// is nowhere for it to name, whatever family was asked about — which is why this
// ignores the family.  A device that does present such a drive answers this
// itself rather than taking this default.
//
// The two words beside the target describe the unpartitioned space, and
// get_partition_table_info reports them.  The datasheet marks them meaningful
// only where the target is not -1, so an answer without them is still a whole
// answer, and the target alone is sent where that routine did not give them.
static pb_status_t pb_rom_uf2_target(
    uint32_t *scratch,
    uint32_t  scratch_words,
    uint32_t *filled
) {
    get_partition_table_info_fn_t get_partition_table_info =
        pb_lookup_get_partition_table_info_fn();
    if (get_partition_table_info == NULL) {
        ERR("Unable to find get_partition_table_info in ROM");
        return PB_STATUS_NOT_FOUND;
    }

    int ret = get_partition_table_info(scratch, scratch_words, PB_PT_INFO_FLAG);
    if (ret < 0) {
        ERR("get_partition_table_info refused PT_INFO: %d", ret);
        return pb_status_from_bootrom(ret);
    }

    if ((uint32_t)ret >= PB_PT_INFO_WORDS) {
        // Drop the flags word and the partition counts, keeping the two the
        // answer carries.
        scratch[1] = scratch[2];
        scratch[2] = scratch[3];
        *filled = 3u;
    } else {
        *filled = 1u;
    }
    scratch[0] = PB_UF2_TARGET_NONE;
    return PB_STATUS_OK;
}

// The answer to one information request, in scratch the caller owns.
//
// Both routines this wraps have the same shape and the same contract as picoboot
// itself (RP2350 datasheet 5.4.8.16 and 5.4.8.17): they fill a word buffer,
// putting the subset of the flags asked for that they answered in its first
// word, and return how many words they wrote.  So the answer is passed straight
// through, and a flag this part cannot answer is dropped by the ROM rather than
// by anything here.
static pb_status_t pb_rom_info(
    pb_info_type_t type,
    uint32_t       param0,
    uint32_t      *scratch,
    uint32_t       scratch_words,
    uint32_t      *filled
) {
    int ret;
    switch (type) {
        case PB_INFO_SYS: {
            get_sys_info_fn_t get_sys_info = pb_lookup_get_sys_info_fn();
            if (get_sys_info == NULL) {
                ERR("Unable to find get_sys_info in ROM");
                return PB_STATUS_NOT_FOUND;
            }
            ret = get_sys_info(scratch, scratch_words, param0);
            break;
        }
        case PB_INFO_PARTITION: {
            get_partition_table_info_fn_t get_partition_table_info =
                pb_lookup_get_partition_table_info_fn();
            if (get_partition_table_info == NULL) {
                ERR("Unable to find get_partition_table_info in ROM");
                return PB_STATUS_NOT_FOUND;
            }
            ret = get_partition_table_info(scratch, scratch_words, param0);
            break;
        }
        case PB_INFO_UF2_TARGET:
            return pb_rom_uf2_target(scratch, scratch_words, filled);
        default:
            // PB_INFO_UF2_STATUS reports a download in progress over the drive
            // BOOTSEL mode presents, and this port has none to report on.
            return PB_STATUS_INVALID_ARG;
    }
    if (ret < 0) {
        ERR("ROM refused information type 0x%02x: %d", type, ret);
        return pb_status_from_bootrom(ret);
    }
    *filled = (uint32_t)ret;
    return PB_STATUS_OK;
}

pb_status_t picoboot_default_get_info_prepare(
    pb_info_type_t  type,
    uint32_t        param0,
    uint32_t       *words,
    void           *ctx
) {
    (void)ctx;
    uint32_t scratch[PICOBOOT_INFO_MAX_ANSWER_WORDS];
    return pb_rom_info(type, param0, scratch,
                       PICOBOOT_INFO_MAX_ANSWER_WORDS, words);
}

pb_status_t picoboot_default_get_info(
    pb_info_type_t  type,
    uint32_t        param0,
    uint32_t        at_word,
    uint8_t        *buf,
    uint32_t        max_len,
    uint32_t       *bytes_written,
    void           *ctx
) {
    (void)ctx;

    // The ROM fills from the start of the answer every time and takes no
    // offset, so the whole of it is produced again and the window copied out.
    // That leaves this pair with no state between calls, and the ROM guards the
    // repeat itself: get_partition_table_info hashes the partition table when it
    // loads it and returns INVALID_STATE if it has changed since, and every
    // system information flag reads a value fixed for the life of the boot.
    uint32_t scratch[PICOBOOT_INFO_MAX_ANSWER_WORDS];
    uint32_t filled = 0u;
    pb_status_t st = pb_rom_info(type, param0, scratch,
                                 PICOBOOT_INFO_MAX_ANSWER_WORDS, &filled);
    if (st != PB_STATUS_OK) {
        return st;
    }

    // Whole words only.  The library offers a whole number of them, so this
    // matters to a caller reaching the default directly.  A length that is not
    // a whole number of words has the remainder left alone rather than filled
    // with part of a word.
    *bytes_written = 0u;
    if (at_word < filled) {
        uint32_t left = (filled - at_word) * (uint32_t)sizeof(uint32_t);
        uint32_t room = max_len & ~(uint32_t)(sizeof(uint32_t) - 1u);
        *bytes_written = left < room ? left : room;
        memcpy(buf, &scratch[at_word], *bytes_written);
    }
    return PB_STATUS_OK;
}

pb_status_t picoboot_default_otp_read(
    uint16_t row,
    uint8_t ecc,
    uint8_t *buf,
    uint32_t len,
    void *ctx
) {
    (void)ctx;

    uint8_t row_size = ecc ? 2u : 4u;
    if (len % row_size != 0) {
        ERR("OTP write length %u is not a multiple of row size %u", len, row_size);
        return PB_STATUS_INVALID_ARG;
    }

    otp_access_fn_t otb_access = pb_lookup_otp_access_fn();
    if (otb_access == NULL) {
        ERR("Unable to find OTP access function in ROM");
        return PB_STATUS_NOT_FOUND;
    }

    uint32_t access_row = row;
    if (ecc) {
        access_row |= OTP_ACCESS_FLAG_ECC;
    }
    int ret = otb_access(buf, len, access_row);
    if (ret < 0) {
        ERR("OTP read failed at row %u: %d", row, ret);
        return pb_status_from_bootrom(ret);
    }
    return PB_STATUS_OK;
}

pb_status_t picoboot_default_otp_write(
    uint16_t row,
    uint8_t ecc,
    const uint8_t *buf,
    uint32_t len,
    void *ctx
) {
    (void)ctx;

    uint8_t row_size = ecc ? 2u : 4u;
    if (len % row_size != 0u) {
        ERR("OTP write length %u is not a multiple of row size %u", len, row_size);
        return PB_STATUS_INVALID_ARG;
    }

    otp_access_fn_t otp_access = pb_lookup_otp_access_fn();
    if (otp_access == NULL) {
        ERR("Unable to find OTP access function in ROM");
        return PB_STATUS_NOT_FOUND;
    }

    uint32_t access_row = row;
    access_row |= OTP_ACCESS_FLAG_WRITE;
    if (ecc) {
        access_row |= OTP_ACCESS_FLAG_ECC;
    }

    int ret = otp_access((uint8_t *)buf, len, access_row);
    if (ret < 0) {
        ERR("OTP write failed at row %u: %d", row, ret);
        return pb_status_from_bootrom(ret);
    }
    return PB_STATUS_OK;
}
