// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// Default picobootx protocol implementations.

#if !defined(PICOBOOTX_IMPL_H)
#define PICOBOOTX_IMPL_H

// RP2350 memory regions
#define RP2350_ROM_BASE    0x00000000u
#define RP2350_ROM_SIZE    0x00008000u  // 32KB
#define RP2350_FLASH_BASE  0x10000000u
#define RP2350_FLASH_SIZE  0x02000000u  // 32MB
#define RP2350_SRAM_BASE   0x20000000u
#define RP2350_SRAM_SIZE   0x00082000u  // 520KB

#define FLASH_BLOCK_ERASE_CMD 0xd8u

// Helper to take return codes from boot ROM functions and convert to
// pb_status_t
pb_status_t pb_status_from_bootrom(int ret);

// Lookup RP2350 bootrom functions
void *picoboot_lookup_boot_fn(char a, char b);

// Returns PB_STATUS_OK for all EXCLUSIVE_ACCESS types, or PB_STATUS_INVALID_ARG
// for unknown types.
pb_status_t picoboot_default_exclusive_access(
    const pb_exclusive_access_args_t *args, 
    void *ctx
);

// Returns PB_STATUS_OK.
pb_status_t picoboot_default_exit_xip(void *ctx);

// Returns PB_STATUS_OK.
pb_status_t picoboot_default_enter_xip(void *ctx);

// Returns PB_STATUS_OK.  Does not check arguments or reboot.
pb_status_t picoboot_default_reboot2_prepare(
    const pb_reboot2_args_t *args, 
    void *ctx
);

// Reboots into BOOTSEL using the provided arguments.
void picoboot_default_reboot2_execute(
    const pb_reboot2_args_t *args, 
    void *ctx
);

// Validates standard set of addresses for an RP2350
pb_status_t picoboot_default_read_prepare(
    uint32_t addr, 
    uint32_t size, 
    void *ctx
);

// Reads data from the specified address. Does not perform any validation.
pb_status_t picoboot_default_read(
    uint32_t addr, 
    uint8_t *buf, 
    uint32_t size, 
    void *ctx
);

// Validates write is to a supported address for an RP2350 
pb_status_t picoboot_default_write_prepare(
    uint32_t addr,
    uint32_t size,
    bool *is_flash,
    void *ctx
);

// Writes data to the specified address.  Does not perform any validation.
pb_status_t picoboot_default_write(
    uint32_t addr,
    const uint8_t *buf,
    uint32_t len,
    void *ctx
);

// Writes a 256-byte page to flash at the specified address.
// Does not perform any validation.
pb_status_t picoboot_default_flash_page_write(
    uint32_t addr,
    const uint8_t *buf,
    void *ctx
);

// Validates flash erase parameters for an RP2350
pb_status_t picoboot_default_flash_erase_prepare(
    const pb_addr_size_args_t *args,
    void *ctx
);

// Performs flash erase.  Does not perform any validation.
pb_status_t picoboot_default_flash_erase(
    const pb_addr_size_args_t *args,
    void *ctx
);

// Reads OTP data as specified.
pb_status_t picoboot_default_otp_read(
    uint16_t row,
    uint8_t ecc,
    uint8_t *buf,
    uint32_t len,
    void *ctx
);

// Writes OTP data as specified.
// len is the length of the buffer in bytes
pb_status_t picoboot_default_otp_write(
    uint16_t row,
    uint8_t ecc,
    const uint8_t *buf,
    uint32_t len,
    void *ctx
);

// Retrieves system information using the ROM's get_sys_info function
pb_status_t picoboot_default_get_info_sys(
    uint32_t  flag,
    uint8_t  *buf,
    uint32_t  buf_size,
    uint32_t *bytes_written,
    void     *ctx
);

// Retrieve the device's serial number, as UTF-16, for inclusion in a USB
// descriptor.
size_t picoboot_get_serial(uint16_t *buffer, size_t max_len);

#endif // PICOBOOTX_IMPL_H
