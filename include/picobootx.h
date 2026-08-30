// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

#ifndef PICOBOOT_H
#define PICOBOOT_H

#include <stdint.h>
#include <stdbool.h>
#include "picobootx_version.h"
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
#define PICOBOOT_STATE_SIZE    80u

#define FLASH_SECTOR_SIZE      4096u
#define FLASH_PAGE_SIZE        256u
#define FLASH_BLOCK_SIZE       65536u

// The longest data phase GET_INFO accepts, in bytes.  The protocol requires
// dTransferLength to be a multiple of four (RP2350 datasheet 5.6.4.11), and a
// longer one is refused with PB_STATUS_INVALID_TRANSFER_LEN.
#define PICOBOOT_GET_INFO_MAX_LEN 256u

// The most words a GET_INFO answer can be: the longest transfer, less the count
// word the library puts in front of the answer.  An answer longer than this
// halts the command with PB_STATUS_UNKNOWN_ERROR.
#define PICOBOOT_INFO_MAX_ANSWER_WORDS \
    ((PICOBOOT_GET_INFO_MAX_LEN / 4u) - 1u)

// ---------------------------------------------------------------------------
// GET_INFO info types
//
// Every type's reply is one shape: a word saying how many significant words
// follow, then those words, then zeroes to fill dTransferLength (RP2350
// datasheet 5.6.4.11).  The count word and the padding are the library's.
// Everything between them is the device's answer, and its shape is the type's
// business rather than the library's:
//
//   PB_INFO_SYS         the answer get_sys_info produces (5.4.8.17) — a first
//                       word carrying the subset of dParam0 the device
//                       answered, then the data for each of those flags in
//                       flag order.
//   PB_INFO_PARTITION   the answer get_partition_table_info produces
//                       (5.4.8.16), in the same shape, from
//                       dParam0 as flags_and_partition.
//   PB_INFO_UF2_TARGET  the words 5.6.4.11 defines for it, from dParam0 as a
//                       UF2 family id.  No leading flags word.
//   PB_INFO_UF2_STATUS  the words 5.6.4.11 defines for it.  No leading flags
//                       word, and no parameter.
//
// A device says which types it serves by refusing the rest from
// picoboot_ops_t.get_info_prepare, with PB_STATUS_INVALID_ARG.  A type outside
// this enumeration never reaches it — the library refuses that itself, with the
// same status.
//
// What the RP2350 defaults in picobootx_impl.h answer, and what an integrator
// writes for the rest:
//
//   PB_INFO_SYS         Served.  picoboot_default_get_info passes get_sys_info
//                       through, so the flags this part cannot answer are
//                       dropped by the ROM and the rest are still served.
//   PB_INFO_PARTITION   Served as a constant — no partitions, no partition
//                       table loaded, and all of flash unpartitioned and
//                       readable and writable by everyone, which is what every
//                       RP2350 without a partition table looks like.
//                       picobootx does not read a partition table, and a
//                       device that has one answers this type itself.
//   PB_INFO_UF2_TARGET  Served, as nowhere.  A UF2 reaches a device by being
//                       dragged onto a mass storage drive, and picobootx has
//                       none and is told of none, so it has nowhere to name.
//                       The answer is three words — a target of -1, then the
//                       two PB_INFO_PARTITION gives for the unpartitioned
//                       space, so the same region reads the same way whichever
//                       question a host asks.  A device that does present such
//                       a drive answers this itself.
//   PB_INFO_UF2_STATUS  Not served — refused with PB_STATUS_INVALID_ARG.  It
//                       reports a UF2 download in progress over the USB drive
//                       the bootrom presents in BOOTSEL mode, and picobootx has
//                       no equivalent of that drive, so there is no download for
//                       it to report on.  An integrator whose device has one
//                       answers it from that.
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
// Command categories
//
// Defines the protocol mechanics of a command: how it is validated, what
// state transition follows dispatch, and how the state machine handles it.
// USB IN/OUT direction is from the host's perspective.
// ---------------------------------------------------------------------------

typedef enum {
    PB_CAT_ACTION_SYNC,     // synchronous: call op, it returns, send ack
                            // (exclusive_access, exit_xip, enter_xip)
    PB_CAT_ACTION_ASYNC,    // async: call op to initiate, completion signalled
                            // via callback (flash_erase)
    PB_CAT_ACTION_DEFERRED, // send ack first, execute after ack clears
                            // (reboot2)
    PB_CAT_DATA_IN,         // device->host data transfer
                            // (read, get_info, otp_read)
    PB_CAT_DATA_OUT,        // host->device data transfer
                            // (write, otp_write)
    PB_CAT_UNSUPPORTED,     // known but rejected on this platform
} pb_cmd_category_t;

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

    // GET_INFO.  Both are needed: with either NULL, GET_INFO returns
    // PB_STATUS_UNKNOWN_CMD, which is a device that does not serve it at all.
    // A device that serves some types and not others refuses the rest from
    // get_info_prepare with PB_STATUS_INVALID_ARG.
    //
    // get_info_prepare writes to *words how many words the answer to this
    // request will be, before any of it goes.  That is the count word the
    // library puts in front of the answer, and it is also what the library
    // judges dTransferLength against: a transfer too short for the answer the
    // device says it will give is refused with PB_STATUS_BUFFER_TOO_SMALL.
    // Reporting more than PICOBOOT_INFO_MAX_ANSWER_WORDS halts the command with
    // PB_STATUS_UNKNOWN_ERROR.  Reporting none is a valid answer, and sends a
    // count of zero.
    //
    // get_info produces the answer, from at_word onwards, over as many calls as
    // it takes.  type and param0 are handed back every time, so the callback
    // needs to keep nothing between calls.  Write at most max_len bytes, always
    // a whole number of words, and set *bytes_written to what was written:
    //
    //   *bytes_written > 0   data produced, more may follow
    //   *bytes_written == 0  not enough room for the next piece, call again
    //                        later with more
    //
    // max_len is never more than the answer has left to give, so the last call
    // offers exactly the bytes still owed.  Writing more than max_len, or a
    // count that is not a whole number of words, halts the command with
    // PB_STATUS_UNKNOWN_ERROR and none of those bytes reaches the host.
    //
    // buf is word aligned, so a producer that writes words can write them
    // straight into it rather than into a buffer of its own.  The RP2350 ROM
    // information routines write words, and the defaults do exactly that.
    //
    // A decline has to be one a later call can satisfy.  The largest buffer
    // this ever hands over is 64 bytes, so a fill declining that much is asking
    // for room that does not exist, and the command is stalled with
    // PB_STATUS_BUFFER_TOO_SMALL rather than called again.  The buffer is also
    // no larger than the transmit FIFO has room for, so a callback that can
    // only answer whole needs a FIFO that holds a whole answer.
    //
    // ctx is the pointer given to picoboot_init, handed back untouched on every
    // call.  A callback that wants to produce its answer once and hand out the
    // window at_word names keeps it there — the library keeps no cursor and no
    // buffer on the callback's behalf, and this is the whole of what a callback
    // needs to serve an answer in pieces.  The defaults in picobootx_impl.h have
    // no context of their own, which is why they answer system information
    // whole.
    //
    // The library halts the command on a non-PB_STATUS_OK return from either,
    // with that status, and the host reads it back with GET_COMMAND_STATUS.
    pb_status_t (*get_info_prepare)(
        pb_info_type_t type,
        uint32_t param0,
        uint32_t *words,
        void *ctx
    );
    pb_status_t (*get_info)(
        pb_info_type_t type,
        uint32_t param0,
        uint32_t at_word,
        uint8_t *buf,
        uint32_t max_len,
        uint32_t *bytes_written,
        void *ctx
    );

    // Read functions
    pb_status_t (*read_prepare)(uint32_t addr, uint32_t size, void *ctx);
    pb_status_t (*read)(
        uint32_t addr,
        uint8_t *buf,
        uint32_t len,
        void *ctx
    );
    // otp_read_prepare is offered the whole request — the first row, how many
    // rows, and which view they are addressed through — before any of it is
    // read, so a device that keeps a host out of a range refuses the range
    // rather than the packets that reach it.  NULL means the device serves
    // OTP_READ and does not restrict ranges, which is what every device
    // written before this callback existed does.
    //
    // otp_read is what OTP_READ needs, and the command returns
    // PB_STATUS_UNKNOWN_CMD without it whatever otp_read_prepare says.
    pb_status_t (*otp_read_prepare)(
        uint16_t row,
        uint16_t row_count,
        uint8_t ecc,
        void *ctx
    );
    pb_status_t (*otp_read)(
        uint16_t row,
        uint8_t ecc,
        uint8_t *buf,
        uint32_t len,
        void *ctx
    );

    // Write functions. write_prepare required for WRITE command.
    // flash_page_write required if flash writes are to be supported;
    // flash_write_buf must also be non-NULL.
    pb_status_t (*write_prepare)(
        uint32_t addr,
        uint32_t size,
        bool *is_flash,
        void *ctx
    );
    pb_status_t (*flash_page_write)(
        uint32_t addr,
        const uint8_t *buf,
        void *ctx
    );

    // Flash erase
    pb_status_t (*flash_erase_prepare)(const pb_addr_size_args_t *args, void *ctx);
    pb_status_t (*flash_erase)(const pb_addr_size_args_t *args, void *ctx);

    // write serves a WRITE that write_prepare reported is not flash, and
    // otp_write serves OTP_WRITE.  Each is the only thing its command needs,
    // and the command returns PB_STATUS_UNKNOWN_CMD without it.  Neither
    // consults flash_write_buf — that buffer accumulates a whole 256-byte flash
    // page out of 64-byte USB packets, and neither a memory write nor a 2- or
    // 4-byte OTP row has anything to accumulate.
    pb_status_t (*write)(
        uint32_t addr, 
        const uint8_t *buf, 
        uint32_t len, 
        void *ctx
    );
    // otp_write_prepare is otp_read_prepare's counterpart, and matters more:
    // without it a device refusing a range only refuses the packet that
    // reaches it, and the rows before that one have already been blown.
    pb_status_t (*otp_write_prepare)(
        uint16_t row,
        uint16_t row_count,
        uint8_t ecc,
        void *ctx
    );
    pb_status_t (*otp_write)(
        uint16_t row,
        uint8_t ecc,
        const uint8_t *buf,
        uint32_t len,
        void *ctx
    );
} picoboot_ops_t;

// Custom / extended command dispatch (alternative magic value).
//
// A command whose magic matches this struct's magic is handed to dispatch
// instead of being resolved through the standard PICOBOOT command table.
// Routing depends on the command's transfer_len and direction bit:
//
//   transfer_len == 0
//       dispatch is called once and, if it returns PB_STATUS_OK, the library
//       acknowledges the command with a ZLP.  No data phase.
//
//   transfer_len > 0 and PICOBOOT_DIR_IN set in cmd_id (device -> host)
//       dispatch is called once to validate and prepare, then fill is called
//       repeatedly until it reports the transfer complete.  If fill is NULL
//       the command is stalled with PB_STATUS_UNKNOWN_CMD.
//
//   transfer_len > 0 and PICOBOOT_DIR_IN clear (host -> device)
//       Not supported: the command is stalled with PB_STATUS_UNKNOWN_CMD.
//
// A non-PB_STATUS_OK return from either callback stalls the command with that
// status, which the host retrieves via GET_COMMAND_STATUS.
//
// transfer_len is the whole of what the device may send, and an answer that
// does not fit it belongs to dispatch to refuse, with
// PB_STATUS_BUFFER_TOO_SMALL.  A transfer that reaches fill with an answer too
// large for it is refused there instead, with the same status and once part of
// the answer may already have gone to the host.
typedef struct {
    uint32_t    magic;

    // Called once per custom command.  buf is NULL and buf_len 0, because a
    // custom command has no host -> device data phase, and bytes_written is
    // ignored.  For a data-IN command this is the place to validate the args
    // and set up whatever state fill will need.
    pb_status_t (*dispatch)(
        const picoboot_cmd_t *cmd,
        uint8_t *buf,
        uint32_t buf_len,
        uint32_t *bytes_written,
        void *ctx
    );

    // Optional; NULL means custom data-IN commands are unsupported.
    //
    // Produces the device -> host payload for a custom command, in as many
    // calls as it likes.  cmd is the originating command, preserved by the
    // library for the duration of the transfer.  Write at most max_len bytes
    // to buf and set *bytes_written accordingly:
    //
    //   *done = true                       : transfer complete (any bytes
    //                                        written on this call are sent)
    //   *done = false, *bytes_written > 0  : data produced, more may follow
    //   *done = false, *bytes_written == 0 : not enough space for the next
    //                                        item, call again later
    //
    // max_len is never more than the transfer has left to send, so the last
    // call of a transfer offers exactly the bytes still owed to the host.
    // Reporting more than max_len stalls the command with
    // PB_STATUS_UNKNOWN_ERROR, and none of those bytes reaches the host.
    //
    // A decline has to be one a later call can satisfy.  The largest buffer
    // this ever hands over is 64 bytes, so a fill declining that much is asking
    // for room that does not exist, and the command is stalled with
    // PB_STATUS_BUFFER_TOO_SMALL rather than called again.
    //
    // The callee tracks its own position between calls, in its own ctx — the
    // library keeps no per-transfer cursor on its behalf.
    pb_status_t (*fill)(
        const picoboot_cmd_t *cmd,
        uint8_t *buf,
        uint32_t max_len,
        uint32_t *bytes_written,
        bool *done,
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
//   flash_write_buf : 256-byte, 4-byte-aligned buffer used to accumulate a
//                     flash page.  NULL disables WRITE to flash, which then
//                     returns PB_STATUS_NOT_PERMITTED once write_prepare has
//                     reported the destination is flash.  WRITE to memory and
//                     OTP_WRITE do not use it and are unaffected.
//
//                     It is read by the boot ROM after flash has been taken
//                     out of execute-in-place, so it must be somewhere that
//                     still answers then.  Anywhere but flash itself, and any
//                     PSRAM, which answer through the same interface.  Which
//                     of a device's memory that leaves is yours, and picobootx
//                     does not check it.
//   rhport          : TinyUSB root hub port (0 on RP2350)
//   ep_out          : BULK OUT endpoint address
//   ep_in           : BULK IN endpoint address
//   ctx             : passed verbatim to all callbacks
void picoboot_init(
    pb_state_block_t *state,
    const picoboot_ops_t *ops,
    const picoboot_custom_ops_t *custom,
    uint8_t *flash_write_buf,
    uint8_t rhport,
    uint8_t ep_out,
    uint8_t ep_in,
    void *ctx
);

// Call from your main loop / plugin task alongside tud_task().
void picoboot_task(pb_state_block_t *state);

// Wire into tud_vendor_control_xfer_cb() — return its result directly.
bool picoboot_control_xfer_cb(
    pb_state_block_t *state,
    uint8_t rhport,
    uint8_t stage,
    tusb_control_request_t const *req
);

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