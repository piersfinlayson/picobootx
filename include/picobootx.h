// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

#ifndef PICOBOOT_H
#define PICOBOOT_H

#include <stdint.h>
#include <stdbool.h>
#include "tusb.h"

// tusb.h must be included before this header.

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// tinyusb configuration checkes
//
// This section consists of static asserts to verify the tinyusb configuration
// is correctly configured for use as a picoboot backend.
//
// Items which cannot be asserted:
// - The picoboot interface must be Class 0xFF, SubClass 0x00, Protocol, 0x00
// - If you have a single interface, the picoboot interface must be interface
//   0.
// - If you have multiple interfaces, the picoboot interface must be interface
//   1.  Strictly, this is not required by the spec, but is required by the
//   current picotool implementation.  If you require a pair of CDC
//   interfaces, it is recommended you add a dummy/unused/other interface as
//   interface 0, then picoboot as interface 1, then CDC as interfaces 2/3.
// ---------------------------------------------------------------------------
_Static_assert(CFG_TUD_ENDPOINT0_SIZE == 64, "The picoboot protocol requires bMaxPacketSize0 of 64 in the device descriptor");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#define PICOBOOT_MAGIC          0x431fd10bu
#define PICOBOOT_CMD_LEN        32u
#define PICOBOOT_ARGS_LEN       16u
#define PICOBOOT_STATUS_LEN     16u
#define PICOBOOT_DIR_IN         0x80u   // bit 7 of cmd_id set = host reads data

// Size of pb_state_block_t in bytes. Use this to allocate storage without
// needing to include picoboot_private.h. Verified by _Static_assert in
// picoboot_private.h.
#define PICOBOOT_STATE_SIZE     76u

// ---------------------------------------------------------------------------
// GET_INFO info types
// ---------------------------------------------------------------------------

typedef enum {
    PB_INFO_SYS              = 0x01,
    PB_INFO_PARTITION        = 0x02,
    PB_INFO_UF2_TARGET       = 0x03,
    PB_INFO_UF2_STATUS       = 0x04,
} pb_info_type_t;
_Static_assert(sizeof(pb_info_type_t) == 1, "pb_get_info_args_t size mismatch");

// ---------------------------------------------------------------------------
// EXCLUSIVE_ACCESS types
// ---------------------------------------------------------------------------

typedef enum {
    PB_EA_NOT_EXCL          = 0x00,
    PB_EA_EXCL              = 0x01,
    PB_EA_EXCL_AND_EJECT    = 0x02,
} pb_ea_type_t;
_Static_assert(sizeof(pb_ea_type_t) == 1, "pb_ea_type_t size mismatch");

// ---------------------------------------------------------------------------
// Status codes (returned via GET_COMMAND_STATUS control request)
// ---------------------------------------------------------------------------

typedef enum {
    PB_STATUS_OK                   = 0,
    PB_STATUS_UNKNOWN_CMD          = 1,
    PB_STATUS_INVALID_CMD_LENGTH   = 2,
    PB_STATUS_INVALID_TRANSFER_LEN = 3,
    PB_STATUS_INVALID_ADDRESS      = 4,
    PB_STATUS_BAD_ALIGNMENT        = 5,
    PB_STATUS_INTERLEAVED_WRITE    = 6,
    PB_STATUS_REBOOTING            = 7,
    PB_STATUS_UNKNOWN_ERROR        = 8,
    PB_STATUS_INVALID_STATE        = 9,
    PB_STATUS_NOT_PERMITTED        = 10,
    PB_STATUS_INVALID_ARG          = 11,
    PB_STATUS_BUFFER_TOO_SMALL     = 12,
    PB_STATUS_PRECONDITION_NOT_MET = 13,
    PB_STATUS_MODIFIED_DATA        = 14,
    PB_STATUS_INVALID_DATA         = 15,
    PB_STATUS_NOT_FOUND            = 16,
    PB_STATUS_UNSUPPORTED_MOD      = 17,
} pb_status_t;
_Static_assert(sizeof(pb_status_t) == 1, "pb_status_t size mismatch");

// ---------------------------------------------------------------------------
// Wire structs
// ---------------------------------------------------------------------------

// Full 32-byte command packet received on BULK_OUT
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t token;
    uint8_t  cmd_id;
    uint8_t  cmd_size;
    uint16_t reserved;
    uint32_t transfer_len;
    uint8_t  args[PICOBOOT_ARGS_LEN];
} picoboot_cmd_t;

// 16-byte status packet returned via GET_COMMAND_STATUS control request
typedef struct __attribute__((packed)) {
    uint32_t token;
    uint32_t status_code;
    uint8_t  cmd_id;
    uint8_t  in_progress;
    uint8_t  reserved[6];
} picoboot_status_t;

// ---------------------------------------------------------------------------
// Args structs — overlaid onto picoboot_cmd_t.args
// ---------------------------------------------------------------------------

typedef struct __attribute__((packed)) {
    pb_ea_type_t ea_type;
} pb_exclusive_access_args_t;

typedef struct __attribute__((packed)) {
    uint32_t addr;
    uint32_t size;
} pb_addr_size_args_t;   // shared by READ, WRITE, FLASH_ERASE

typedef struct __attribute__((packed)) {
    uint32_t flags;
    uint32_t delay_ms;
    uint32_t p0;
    uint32_t p1;
} pb_reboot2_args_t;

typedef struct __attribute__((packed)) {
    uint8_t  info_type;   // pb_info_type_t
    uint8_t  reserved[3];
    uint32_t param0;      // flags for INFO_SYS; flags_and_partition for PARTITION;
                          // family_id for UF2_TARGET
} pb_get_info_args_t;

typedef struct __attribute__((packed)) {
    uint16_t row;
    uint16_t row_count;
    uint8_t  ecc;         // 0=raw (32 bits/row), 1=ECC (16 bits/row)
} pb_otp_args_t;          // shared by OTP_READ and OTP_WRITE

// ---------------------------------------------------------------------------
// Callback interfaces
// ---------------------------------------------------------------------------

typedef struct {
    // Management functions
    pb_status_t (*exclusive_access)(const pb_exclusive_access_args_t *args, void *ctx);
    pb_status_t (*exit_xip)(void *ctx);
    pb_status_t (*enter_xip)(void *ctx);
    pb_status_t (*reboot2_prepare)(const pb_reboot2_args_t *args, void *ctx);
    void (*reboot2_execute)(const pb_reboot2_args_t *args, void *ctx);
    pb_status_t (*get_info_sys)(
        uint32_t flags,
        uint8_t *buf,
        uint32_t buf_len,
        uint32_t *bytes_written,
        void *ctx
    );

    // Read functions
    pb_status_t (*validate_read)(uint32_t addr, uint32_t size, void *ctx);
    pb_status_t (*read)(
        uint32_t addr,
        uint8_t *buf,
        uint32_t len,
        void *ctx
    );
    pb_status_t (*otp_read)(
        uint16_t row,
        uint8_t ecc,
        uint8_t *buf,
        uint32_t len,
        void *ctx
    );

    // Flash erase
    pb_status_t (*flash_erase)(const pb_addr_size_args_t *args, void *ctx);

    // Write functions.  Only supported if picoboot is initialised with a flash_write_buf.
    pb_status_t (*write)(uint32_t addr, const uint8_t *buf, uint32_t len, void *ctx);
    pb_status_t (*otp_write)(const pb_otp_args_t *args, const uint8_t *buf, uint32_t len, void *ctx);
} picoboot_ops_t;

// Custom / extended command dispatch (alternative magic value).  Not yet supported
typedef struct {
    uint32_t    magic;
    pb_status_t (*dispatch)(
        const picoboot_cmd_t *cmd,
        uint8_t *buf,
        uint32_t buf_len,
        uint32_t *bytes_written,
        void *ctx
    );
} picoboot_custom_ops_t;

// ---------------------------------------------------------------------------
// State block — integrator allocates, library owns contents
// ---------------------------------------------------------------------------

// Opaque to integrators. Allocate PICOBOOT_STATE_SIZE bytes with at least
// 4-byte alignment.
//
// Example static allocation:
//   static uint32_t picoboot_state_buf[PICOBOOT_STATE_SIZE / 4];
//   #define picoboot_state ((pb_state_block_t *)picoboot_state_buf)
typedef struct pb_state_block pb_state_block_t;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Initialise the library.
//   state           : caller-allocated state block (PICOBOOT_STATE_SIZE bytes,
//                     4-byte aligned)
//   ops             : standard PICOBOOT command callbacks
//   custom          : extended magic dispatch; may be NULL
//   flash_write_buf : 256-byte, 4-byte-aligned buffer for write accumulation;
//                     NULL disables WRITE and OTP_WRITE (PB_STATUS_NOT_PERMITTED)
//   rhport          : TinyUSB root hub port (0 on RP2350)
//   ep_out          : BULK OUT endpoint address
//   ep_in           : BULK IN endpoint address
//   ctx             : passed verbatim to all callbacks
void picoboot_init(pb_state_block_t            *state,
                   const picoboot_ops_t        *ops,
                   const picoboot_custom_ops_t *custom,
                   uint8_t                     *flash_write_buf,
                   uint8_t                      rhport,
                   uint8_t                      ep_out,
                   uint8_t                      ep_in,
                   void                        *ctx);

// Call from your main loop / plugin task alongside tud_task().
void picoboot_task(pb_state_block_t *state);

// Wire into tud_vendor_control_xfer_cb() — return its result directly.
bool picoboot_control_xfer_cb(pb_state_block_t             *state,
                               uint8_t                       rhport,
                               uint8_t                       stage,
                               tusb_control_request_t const *req);

// Call from your app_picoboot_tx_cb().
void picoboot_tx_cb(pb_state_block_t *state, uint32_t sent_bytes);

// Call from your app_picoboot_rx_cb().
void picoboot_rx_cb(pb_state_block_t *state, uint32_t count);

// Helper to retrieve a unique 16 character serial number from the RP2350
size_t picoboot_get_serial(uint16_t *buffer, size_t buf_size);

#ifdef __cplusplus
}
#endif

#endif // PICOBOOT_H