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
#define BOOTROM_ERROR_INSUFFICIENT_RESOURCES    (-9)    // Unused in RP2350
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

#if 0
// Currnently unused
typedef int (*get_partition_table_info_fn_t)(uint32_t *out_buffer, uint32_t out_buffer_word_size, uint32_t flags_and_partition);
static get_partition_table_info_fn_t pb_lookup_get_partition_table_info_fn(void) {
    return (get_partition_table_info_fn_t)picoboot_lookup_boot_fn('G', 'P');
}
#endif

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

pb_status_t picoboot_default_get_info_sys(
    uint32_t  flag,
    uint8_t  *buf,
    uint32_t  buf_size,
    uint32_t *bytes_written,
    void     *ctx
) {
    (void)ctx;

    get_sys_info_fn_t get_sys_info = pb_lookup_get_sys_info_fn();
    if (get_sys_info == NULL) {
        ERR("Unable to find get_sys_info in ROM");
        return PB_STATUS_NOT_FOUND;
    }

    // Judged in bytes, not in words: the whole of buf is filled from the words
    // after the leading one, so a size that is a whole number of words and a
    // part of another would read past the end of tmp.
    if (buf_size > PB_INFO_MAX_WORDS * sizeof(uint32_t)) {
        ERR("Buffer too large for get_info_sys: %u bytes", buf_size);
        return PB_STATUS_UNKNOWN_ERROR;
    }
    uint32_t wc = buf_size / sizeof(uint32_t);
    uint32_t tmp[PB_INFO_MAX_WORDS + 1];

    int ret = get_sys_info(tmp, wc + 1, flag);
    if (ret < 0) {
        ERR("get_sys_info failed: %d", ret);
        return pb_status_from_bootrom(ret);
    }

    if (!(tmp[0] & flag)) {
        ERR("get_sys_info: flag 0x%08x not supported", flag);
        return PB_STATUS_INVALID_ARG;
    }

    memcpy(buf, &tmp[1], buf_size);
    *bytes_written = buf_size;
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
