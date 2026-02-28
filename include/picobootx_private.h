// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

#ifndef PICOBOOTX_PRIVATE_H
#define PICOBOOTX_PRIVATE_H

#include <stddef.h>
#include "picobootx.h"

#ifdef __cplusplus
extern "C" {
#endif

// Logging macros
#if defined(PICOBOOT_LOGGING) && (PICOBOOT_LOGGING == 1)
#if !defined(DEBUG)
extern void picoboot_debug(const char *msg, ...);
#define DEBUG picoboot_debug
#endif // DEBUG
#if !defined(LOG)
extern void picoboot_log(const char *msg, ...);
#define LOG picoboot_log
#endif // LOG
#if !defined(ERROR)
extern void picoboot_error(const char *msg, ...);
#define ERR picoboot_error
#endif // ERROR
#else // !PICOBOOT_LOGGING
#if !defined(DEBUG)
#define DEBUG(...) do {} while(0)
#endif // DEBUG
#if !defined(LOG)
#define LOG(...) do {} while(0)
#endif // LOG
#if !defined(ERROR)
#define ERR(...) do {} while(0)
#endif // ERROR
#endif // PICOBOOT_LOGGING

//
// GET_INFO flag table and helpers
//

// None of the entries below can have a value greater than PB_INFO_MAX_WORDS
#define PB_INFO_MAX_WORDS 4
#define PB_INFO_FLAG_TABLE \
    X(0x0001u, 3u, CHIP_INFO)      \
    X(0x0002u, 1u, CRITICAL)       \
    X(0x0004u, 1u, CPU_INFO)       \
    X(0x0008u, 1u, FLASH_DEV_INFO) \
    X(0x0010u, 4u, BOOT_RANDOM)    \
    X(0x0040u, 4u, BOOT_INFO)

// ---------------------------------------------------------------------------
// Command IDs — internal to the library
// ---------------------------------------------------------------------------

typedef enum {
    PB_CMD_EXCLUSIVE_ACCESS = 0x01,
    PB_CMD_REBOOT           = 0x02,   // RP2040 only, stub on RP2350
    PB_CMD_FLASH_ERASE      = 0x03,
    PB_CMD_WRITE            = 0x05,
    PB_CMD_EXIT_XIP         = 0x06,   // no-op on RP2350
    PB_CMD_ENTER_XIP        = 0x07,   // no-op on RP2350
    PB_CMD_EXEC             = 0x08,   // not supported on RP2350 bootrom; repurposed here
    PB_CMD_VECTORIZE_FLASH  = 0x09,   // not supported on RP2350
    PB_CMD_REBOOT2          = 0x0a,
    PB_CMD_OTP_WRITE        = 0x0d,
    PB_CMD_READ             = 0x84,   // bit 7 set: IN direction
    PB_CMD_GET_INFO         = 0x8b,   // bit 7 set: IN direction
    PB_CMD_OTP_READ         = 0x8c,   // bit 7 set: IN direction
} pb_cmd_id_t;

// ---------------------------------------------------------------------------
// Control request codes
// ---------------------------------------------------------------------------

#define PICOBOOT_BREQUEST_INTERFACE_RESET  0x41u
#define PICOBOOT_BREQUEST_GET_CMD_STATUS   0x42u

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

typedef enum {
    PB_STATE_IDLE,        // waiting for a 32-byte command on BULK_OUT
    PB_STATE_DATA_OUT,    // accumulating host->device data (WRITE, OTP_WRITE)
    PB_STATE_DATA_IN,     // streaming device->host data (READ, GET_INFO, OTP_READ)
    PB_STATE_AWAIT_ZLP,   // ZLP sent on IN; waiting for tx completion callback
                          // before taking any post-command action (e.g. REBOOT2)
    PB_STATE_AWAIT_ACK,   // IN data transfer complete; waiting for host's
                          // completion packet on OUT (IN-direction commands only)
    PB_STATE_STALLED,     // bulk endpoints stalled; awaiting GET_COMMAND_STATUS
} pb_state_t;
extern const char *pb_state_to_str[];

// ---------------------------------------------------------------------------
// Per-command in-progress state (union — only one active at a time)
// ---------------------------------------------------------------------------

typedef struct {
    uint32_t addr;               // current read address
    uint32_t remaining;          // bytes left to send
} pb_in_read_t;

typedef struct {
    uint32_t remaining_flags;    // bitmask of requested flags not yet sent
    uint32_t transfer_remaining; // bytes still owed to host
    bool     header_sent;        // true once the leading count word has been sent
} pb_in_get_info_t;

typedef struct {
    uint16_t current_row;        // next row to read
    uint16_t rows_remaining;     // rows not yet sent
    uint8_t  ecc;                // 0=raw (4 bytes/row), 1=ECC (2 bytes/row)
    uint32_t transfer_remaining; // bytes still owed to host
} pb_in_otp_read_t;

typedef struct {
    uint32_t received;           // bytes accumulated so far
    uint32_t expected;           // total bytes expected from host
} pb_out_write_t;

// ---------------------------------------------------------------------------
// State block definition
// ---------------------------------------------------------------------------

struct pb_state_block {
    // Configuration — set once at init, never modified
    const picoboot_ops_t        *ops;             // 4 bytes
    const picoboot_custom_ops_t *custom;          // 4 bytes
    uint8_t                     *flash_write_buf; // 4 bytes; NULL = WRITE disabled
    void                        *ctx;             // 4 bytes

    // State machine
    pb_state_t                   state;           // 4 bytes (enum)

    // Minimal last-command state for GET_COMMAND_STATUS
    uint32_t                     token;           // 4 bytes
    uint8_t                      rhport;          // 1 byte
    uint8_t                      ep_out;          // 1 byte
    uint8_t                      ep_in;           // 1 byte
    uint8_t                      cmd_id;          // 1 byte (completes word)

    // Args persisted for post-ZLP action (REBOOT2 only)
    pb_reboot2_args_t            reboot2_args;    // 16 bytes

    // Status returned by GET_COMMAND_STATUS
    picoboot_status_t            status;          // 16 bytes (packed struct)

    // Per-command transfer state — only one active at a time
    union {
        pb_in_read_t     read;     //  8 bytes
        pb_in_get_info_t get_info; // 12 bytes (largest)
        pb_in_otp_read_t otp_read; // 12 bytes
        pb_out_write_t   write;    //  8 bytes
    } xfer;                        // 12 bytes

    // ZLP buffer: usbd_edpt_xfer requires a non-NULL pointer even for
    // zero-length transfers on some hardware. 1 byte, owned by state block.
    uint8_t                      zlp_buf[1];      // 1 byte (+3 padding = 4)
};                                                // total: 76 bytes on 32-bit ARM

// Verify PICOBOOT_STATE_SIZE matches the actual struct size.
// If this fires, update PICOBOOT_STATE_SIZE in picoboot.h.
_Static_assert(sizeof(struct pb_state_block) == PICOBOOT_STATE_SIZE,
               "PICOBOOT_STATE_SIZE in picoboot.h does not match sizeof(pb_state_block)");

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

static inline bool pb_cmd_is_in(uint8_t cmd_id) {
    return (cmd_id & PICOBOOT_DIR_IN) != 0u;
}

void pb_set_status(pb_state_block_t *s, pb_status_t code, bool in_progress);
void pb_stall(pb_state_block_t *s, pb_status_t code);
void pb_send_zlp(pb_state_block_t *s);

#ifdef __cplusplus
}
#endif

#endif // PICOBOOTX_PRIVATE_H