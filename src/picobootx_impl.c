// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// Default picobootx protocol implementations.
//
// Either use these or write your own using these as a starting point.

#include "picobootx_private.h"

void *picoboot_lookup_boot_fn(char a, char b) {
    // Get the ROM table lookup function - RP2350
    typedef void *(*rom_table_lookup_fn)(uint32_t code, uint32_t mask);
#define ROM_TABLE_LOOKUP_ADDR 0x00000016
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
    rom_table_lookup_fn rom_table_lookup = 
        (rom_table_lookup_fn)(uintptr_t)*(uint16_t*)(ROM_TABLE_LOOKUP_ADDR);
#pragma GCC diagnostic pop

    uint32_t code = (b << 8) | a;
#define ROM_TABLE_FLAG_FUNC_ARM_SEC 0x0004
    void *fn = rom_table_lookup(code, ROM_TABLE_FLAG_FUNC_ARM_SEC);
    return fn;
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
    int rc = otp_access(chipid, sizeof(chipid), 0x00020000 | 0x000);
    if (rc != 0) {
        ERR("Failed to read chip ID from OTP: %d", rc);
        return 0;
    }

    uint16_t words[4];
    for (int i = 0; i < 4; i++) {
        words[i] = (uint16_t)chipid[i * 2] | ((uint16_t)chipid[i * 2 + 1] << 8);
    }

    // Format as UTF-16LE hex string, MSW first
    static const char hex[] = "0123456789abcdef";
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

// RP2350 memory regions
#define RP2350_ROM_BASE    0x00000000u
#define RP2350_ROM_SIZE    0x00008000u  // 32KB
#define RP2350_FLASH_BASE  0x10000000u
#define RP2350_FLASH_SIZE  0x02000000u  // 32MB
#define RP2350_SRAM_BASE   0x20000000u
#define RP2350_SRAM_SIZE   0x00082000u  // 520KB

pb_status_t picoboot_default_validate_read(
    uint32_t addr, 
    uint32_t size, 
    void *ctx
) {
    (void)ctx;

    // Validate entire range lies within a single valid region.
    // GCC dislikes >= ROM_BASE as it's 0, so always true
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
    bool valid =
        (addr >= RP2350_ROM_BASE   && (addr + size) <= (RP2350_ROM_BASE   + RP2350_ROM_SIZE))   ||
        (addr >= RP2350_FLASH_BASE && (addr + size) <= (RP2350_FLASH_BASE + RP2350_FLASH_SIZE)) ||
        (addr >= RP2350_SRAM_BASE  && (addr + size) <= (RP2350_SRAM_BASE  + RP2350_SRAM_SIZE));
#pragma GCC diagnostic pop

    if (!valid) {
        LOG("Invalid read request: addr=0x%08x size=%u", addr, size);
        return PB_STATUS_INVALID_ARG;
    }

    return PB_STATUS_OK;
}

pb_status_t picoboot_default_read(uint32_t addr, uint8_t *buf, uint32_t len, void *ctx) {
    (void)ctx;

    // Don't validate here as it will have been done in picoboot_read_validate

    if ((addr % 4 == 0) && (len == 4)) {
        // Aligned word read - can just read directly into the buffer
        *(uint32_t *)buf = *(const uint32_t *)addr;
        return PB_STATUS_OK;
    }

    // Otherwise memcpy
    memcpy(buf, (const void *)addr, len);
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

    uint32_t wc = buf_size / sizeof(uint32_t);
    if (wc > PB_INFO_MAX_WORDS) {
        ERR("Buffer too large for get_info_sys: %u bytes", buf_size);
        return PB_STATUS_UNKNOWN_ERROR;
    }
    uint32_t tmp[PB_INFO_MAX_WORDS + 1];

    int ret = get_sys_info(tmp, wc + 1, flag);
    if (ret < 0) {
        ERR("get_sys_info failed: %d", ret);
        return PB_STATUS_NOT_FOUND;
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
        access_row |= 0x20000u;
    }
    int ret = otb_access(buf, len, access_row);
    if (ret < 0) {
        ERR("OTP access failed: %d", ret);
        return PB_STATUS_UNKNOWN_ERROR;
    }
    return PB_STATUS_OK;
}
