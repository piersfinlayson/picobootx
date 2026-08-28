// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// Default picobootx protocol implementations.
//
// Either use these or write your own using these as a starting point.

#include "picobootx_private.h"
#include "picobootx_impl.h"
#include "picobootx_vendor.h"

// picoboot_default_get_info produces a system information answer whole, in one
// call, so the room the library can offer it has to reach the longest such
// answer.  That room is bounded by the transmit FIFO, and a FIFO too small for
// the answer never offers enough.  The default declines every call, the
// transfer makes no progress, and the host waits on a reply that never comes.
//
// Failing the build says so where an integrator sizing the FIFO down would
// otherwise meet it on the wire.  An integrator who needs a smaller FIFO than
// this writes get_info themselves and serves the answer in pieces — see
// picoboot_default_get_info in picobootx_impl.h.
_Static_assert(CFG_TUD_PICOBOOT_TX_BUFSIZE >= PICOBOOT_SYS_INFO_MAX_BYTES,
               "CFG_TUD_PICOBOOT_TX_BUFSIZE cannot hold the longest system "
               "information answer, which picoboot_default_get_info produces "
               "in a single call");

// The pump's own buffer caps the room too, so an answer larger than it holds
// would never be offered enough however large the transmit FIFO is.
_Static_assert(PB_DATA_IN_BUF_SIZE >= PICOBOOT_SYS_INFO_MAX_BYTES,
               "the longest system information answer is larger than the room "
               "the library ever offers a fill in one call");

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

// The rest of the partition table flags (RP2350 datasheet 5.4.8.16).  The first
// four ask for a field of a partition rather than of the table.  SINGLE narrows
// those four to the one partition named in the top byte of flags_and_partition.
#define PB_PT_LOCATION_AND_FLAGS 0x0010u
#define PB_PT_ID                 0x0020u
#define PB_PT_FAMILY_IDS         0x0040u
#define PB_PT_NAME               0x0080u
#define PB_PT_SINGLE             0x8000u

// The flags this default answers.  A flag outside the set is dropped from the
// answer, as get_partition_table_info drops one the part cannot answer.
//
// SINGLE is answered like the rest.  The boot ROM echoes it whenever it is
// asked for, including on its own with nothing to answer, and narrowing to one
// partition is honoured by a device with none.  Masking with this also drops the
// partition number, which the boot ROM leaves out of the answered-flags word
// too.  Asked about partition 3 with 0x03008030 it answers 0x8030.
#define PB_PT_ANSWERED_FLAGS                                    \
    (PB_PT_INFO_FLAG | PB_PT_LOCATION_AND_FLAGS | PB_PT_ID |    \
     PB_PT_FAMILY_IDS | PB_PT_NAME | PB_PT_SINGLE)

// The unpartitioned space of an RP2350 with no partition table, in the two
// words PT_INFO carries for it (RP2350 datasheet 5.9.4.2, table 473).
//
// The first is where it is and who may touch it — first sector 0 and last
// sector 8191, which is every bit of the 13-bit field and the largest range it
// can express, with all six permissions set — secure, non-secure and NS boot may
// each read and write.  All of flash, unpartitioned, open to everyone, which is
// what having no partition table means and is the same on every RP2350.
//
// The second is those same six permissions with every UF2 family bit clear.  A
// family bit says a UF2 of that family would be accepted, and a UF2 reaches a
// device by being dragged onto a mass storage drive.  The bootrom sets four of
// them because BOOTSEL mode presents such a drive.  A device running picobootx
// is running its application and presents none, so it accepts no family, and
// the RP2040 family was never this part's.
#define PB_UNPARTITIONED_LOCATION 0xffffe000u
#define PB_UNPARTITIONED_FLAGS    0xfc000000u

// Word 0 of a UF2 target answer, saying the family goes nowhere (RP2350
// datasheet 5.6.4.11).
#define PB_UF2_TARGET_NONE 0xffffffffu

// The words of an answer from at_word on, copied into the caller's buffer.
//
// Whole words only.  The library offers a whole number of them, so this matters
// to a caller reaching a default directly.  A room that is not a whole number of
// words has the remainder left alone rather than filled with part of a word.
static void pb_copy_answer(
    const uint32_t *answer,
    uint32_t        filled,
    uint32_t        at_word,
    uint8_t        *buf,
    uint32_t        room,
    uint32_t       *bytes_written
) {
    *bytes_written = 0u;
    if (at_word >= filled) {
        return;
    }
    uint32_t left = (filled - at_word) * (uint32_t)sizeof(uint32_t);
    *bytes_written = left < room ? left : room;
    memcpy(buf, &answer[at_word], *bytes_written);
}

// How many words this part's system information answer will be, without
// producing any of it.
//
// get_sys_info answers a single flag as the flags word followed by that flag's
// data, so a probe of one flag returns one more word than the flag contributes,
// and one word for a flag the part does not answer.  Summing the contributions
// over the flags asked for gives the length of the answer to all of them, with
// the ROM saying how long each is — so a flag a future part adds is counted
// here with no change to this.
//
// tmp holds one flag's data at a time.  The widest flag the datasheet defines
// is four words.
static pb_status_t pb_sys_info_words(uint32_t param0, uint32_t *words) {
    get_sys_info_fn_t get_sys_info = pb_lookup_get_sys_info_fn();
    if (get_sys_info == NULL) {
        ERR("Unable to find get_sys_info in ROM");
        return PB_STATUS_NOT_FOUND;
    }

    uint32_t tmp[8];
    uint32_t total = 1u;  // the flags word, which every answer carries

    for (unsigned bit = 0u; bit < 32u; bit++) {
        uint32_t flag = 1u << bit;
        if ((param0 & flag) == 0u) {
            continue;
        }
        int ret = get_sys_info(tmp, (uint32_t)(sizeof(tmp) / sizeof(tmp[0])),
                               flag);
        if (ret < 0) {
            ERR("get_sys_info refused flag 0x%08x: %d", flag, ret);
            return pb_status_from_bootrom(ret);
        }
        if (ret > 1) {
            total += (uint32_t)ret - 1u;
        }
    }

    *words = total;
    return PB_STATUS_OK;
}

// The system information answer, written where the caller asked for it.
//
// The ROM produces the whole answer or none of it, and takes no offset, so this
// serves it in one call from its first word and needs no buffer of its own.  buf
// is word aligned, which is what the library promises a fill and what lets the
// ROM write through it.
//
// Room too small for the whole answer is declined rather than refused.  Nothing
// is written, and the caller offers more next time.  So the transmit FIFO has to
// reach the size of an answer — see picoboot_default_get_info in
// picobootx_impl.h for what a FIFO that does not means.
static pb_status_t pb_sys_info_fill(
    uint32_t  param0,
    uint32_t  at_word,
    uint8_t  *buf,
    uint32_t  room,
    uint32_t *bytes_written
) {
    *bytes_written = 0u;

    // The answer goes in one call, so there is no later window to serve.
    if (at_word != 0u) {
        return PB_STATUS_OK;
    }

    get_sys_info_fn_t get_sys_info = pb_lookup_get_sys_info_fn();
    if (get_sys_info == NULL) {
        ERR("Unable to find get_sys_info in ROM");
        return PB_STATUS_NOT_FOUND;
    }

    int ret = get_sys_info((uint32_t *)(void *)buf,
                           room / (uint32_t)sizeof(uint32_t), param0);
    if (ret == BOOTROM_ERROR_BUFFER_TOO_SMALL) {
        LOG("get_sys_info declined %u bytes of room", room);
        return PB_STATUS_OK;
    }
    if (ret < 0) {
        ERR("get_sys_info refused flags 0x%08x: %d", param0, ret);
        return pb_status_from_bootrom(ret);
    }

    *bytes_written = (uint32_t)ret * (uint32_t)sizeof(uint32_t);
    return PB_STATUS_OK;
}

// The partition table answer, in answer, and how many words it is.
//
// A constant.  picobootx does not read a partition table, so this says the one
// thing true of every RP2350 without one — no partitions, no table loaded, and
// all of flash unpartitioned and open to everyone.  A device that does have a
// partition table answers PB_INFO_PARTITION itself rather than taking this
// default.
//
// A per-partition field — location and flags, id, family ids, name — contributes
// no words, there being no partitions, and the flags word still names it as
// answered.  answer holds PB_PT_INFO_WORDS words.
static uint32_t pb_partition_answer(uint32_t param0, uint32_t *answer) {
    answer[0] = param0 & PB_PT_ANSWERED_FLAGS;
    if ((param0 & PB_PT_INFO_FLAG) == 0u) {
        return 1u;
    }
    answer[1] = 0u;  // no partitions, and no partition table loaded
    answer[2] = PB_UNPARTITIONED_LOCATION;
    answer[3] = PB_UNPARTITIONED_FLAGS;
    return PB_PT_INFO_WORDS;
}

// Where a UF2 of some family would be downloaded to, in three words.
//
// Nowhere.  A UF2 is dragged onto a mass storage drive, as it is onto the one
// BOOTSEL mode presents.  picobootx presents none and is told of none, so there
// is nowhere for it to name, whatever family was asked about — which is why this
// ignores the family.  A device that does present such a drive answers this
// itself rather than taking this default.
//
// The two words behind the target are the unpartitioned space, and they are the
// two PB_INFO_PARTITION reports for it.  5.6.4.11 makes them the target
// partition's own location "if the partition number is not -1", and it is -1, so
// they describe a download that cannot happen — which leaves agreeing with what
// this device says about that region when asked directly as the one thing they
// can usefully do.  Reading them from the ROM instead made the same region come
// back two ways, differing in the accept-family bits this device has no drive to
// accept a family onto.
//
// All three go, short of anything to say with the last two — picotool checks
// the reply is three words before it reads the first.
#define PB_UF2_TARGET_WORDS 3u

static void pb_uf2_target_answer(uint32_t *answer) {
    answer[0] = PB_UF2_TARGET_NONE;
    answer[1] = PB_UNPARTITIONED_LOCATION;
    answer[2] = PB_UNPARTITIONED_FLAGS;
}

pb_status_t picoboot_default_get_info_prepare(
    pb_info_type_t  type,
    uint32_t        param0,
    uint32_t       *words,
    void           *ctx
) {
    (void)ctx;

    switch (type) {
        case PB_INFO_SYS:
            return pb_sys_info_words(param0, words);
        case PB_INFO_PARTITION: {
            uint32_t answer[PB_PT_INFO_WORDS];
            *words = pb_partition_answer(param0, answer);
            return PB_STATUS_OK;
        }
        case PB_INFO_UF2_TARGET:
            *words = PB_UF2_TARGET_WORDS;
            return PB_STATUS_OK;
        default:
            // PB_INFO_UF2_STATUS reports a download in progress over the drive
            // BOOTSEL mode presents, and this port has none to report on.
            return PB_STATUS_INVALID_ARG;
    }
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

    // Whole words only.  The library offers a whole number of them, so this
    // matters to a caller reaching the default directly.
    uint32_t room = max_len & ~(uint32_t)(sizeof(uint32_t) - 1u);
    *bytes_written = 0u;

    // Only system information comes from the ROM, and it is not held between
    // calls.  The routine takes no offset, so what it produces is produced
    // again, and the ROM guards the repeat itself — every system information
    // flag reads a value fixed for the life of the boot.  The other two types
    // are constants, so a repeat is the same arithmetic twice.
    switch (type) {
        case PB_INFO_SYS:
            return pb_sys_info_fill(param0, at_word, buf, room, bytes_written);
        case PB_INFO_PARTITION: {
            uint32_t answer[PB_PT_INFO_WORDS];
            uint32_t filled = pb_partition_answer(param0, answer);
            pb_copy_answer(answer, filled, at_word, buf, room, bytes_written);
            return PB_STATUS_OK;
        }
        case PB_INFO_UF2_TARGET: {
            uint32_t answer[PB_UF2_TARGET_WORDS];
            pb_uf2_target_answer(answer);
            pb_copy_answer(answer, PB_UF2_TARGET_WORDS, at_word, buf, room,
                           bytes_written);
            return PB_STATUS_OK;
        }
        default:
            return PB_STATUS_INVALID_ARG;
    }
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
