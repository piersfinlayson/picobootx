// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// Default picobootx protocol implementations.

#if !defined(PICOBOOTX_IMPL_H)
#define PICOBOOTX_IMPL_H

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
pb_status_t picoboot_default_validate_read(
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

// Reads OTP data as specified.  Does not perform any validation.
pb_status_t picoboot_default_otp_read(
    uint16_t row,
    uint8_t ecc,
    uint8_t *buf,
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

// Reads OTP rows as specified.
// len is the length of the buffer in bytes
pb_status_t picoboot_default_otp_write(
    uint16_t row,
    uint8_t ecc,
    uint8_t *buf,
    uint32_t len,
    void *ctx
);

// Retrieve the device's serial number, as UTF-16, for inclusion in a USB
// descriptor.
size_t picoboot_get_serial(uint16_t *buffer, size_t max_len);

#endif // PICOBOOTX_IMPL_H
