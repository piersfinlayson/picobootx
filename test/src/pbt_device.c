// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// The device picobootx's default implementations think they are running on.
//
// picobootx_impl.c reaches past the picoboot protocol to the chip underneath it
// — a bootrom function table, a QMI register, the interrupt-enable bit, and
// reads and writes of arbitrary device addresses.  Each of those goes through a
// PICOBOOTX_HOST_TEST seam, and each seam lands here.
//
// The model is deliberately physical rather than convenient.  Flash erases to
// 0xFF and programs by clearing bits, so a program the device issued without
// erasing first leaves evidence.  OTP only ever sets bits, so a row written
// twice does not read back as the second write.  Getting those the easy way
// round — a plain copy — would make a whole class of sequencing mistake
// invisible, which is the opposite of what a model is for.
//
// Every call is recorded in the sequence log, with its arguments, so a scenario
// can assert how the device asked and in what order.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pbt.h"

// Bootrom error codes.  picobootx_impl.c maps these to pb_status_t values, and
// the model returns them so that mapping is exercised rather than bypassed.
#define PBT_BOOTROM_ERROR_INVALID_ARG      (-5)
#define PBT_BOOTROM_ERROR_BUFFER_TOO_SMALL (-13)

// OTP access flags, as picobootx_impl.c passes them.
#define PBT_OTP_FLAG_WRITE 0x00010000u
#define PBT_OTP_FLAG_ECC   0x00020000u

// ---------------------------------------------------------------------------
// Modelled memory
// ---------------------------------------------------------------------------

static uint8_t  s_rom[PBT_ROM_MODELLED];
static uint8_t  s_flash[PBT_FLASH_MODELLED];
static uint8_t  s_sram[PBT_SRAM_MODELLED];
static uint32_t s_otp[PBT_OTP_ROWS];

uint8_t  *pbt_rom(void)   { return s_rom; }
uint8_t  *pbt_flash(void) { return s_flash; }
uint8_t  *pbt_sram(void)  { return s_sram; }
uint32_t *pbt_otp(void)   { return s_otp; }

// ---------------------------------------------------------------------------
// Modelled chip state
// ---------------------------------------------------------------------------

static bool     s_irq_disabled;
static bool     s_xip_active;
static uint8_t  s_xip_clkdiv;
static uint32_t s_sys_info_supported;

// Two-character codes the lookup has been told to answer NULL for.
#define PBT_WITHHOLD_MAX 8
static uint32_t s_withheld[PBT_WITHHOLD_MAX];
static unsigned s_withheld_count;

// The bootrom error code the OTP access refuses with, or zero when it answers
// normally.  A part refuses a read whose ECC cannot be corrected and a write to
// a row that is locked, and picobootx has to turn that refusal into a status
// rather than treat the buffer as filled.
static int s_otp_rc;

void pbt_otp_fail(int rc) { s_otp_rc = rc; }

bool pbt_irq_disabled(void) { return s_irq_disabled; }
bool pbt_xip_active(void)   { return s_xip_active; }

void pbt_set_xip_clkdiv(uint8_t clkdiv) { s_xip_clkdiv = clkdiv; }

void pbt_set_sys_info_supported(uint32_t mask) { s_sys_info_supported = mask; }

// Packs a two-character bootrom code the way picoboot_lookup_boot_fn does.
#define PBT_ROM_CODE(a, b) ((uint32_t)((uint8_t)(b) << 8) | (uint8_t)(a))

void pbt_bootrom_withhold(char a, char b) {
    if (s_withheld_count >= PBT_WITHHOLD_MAX) {
        fprintf(stderr, "pbt: too many withheld bootrom codes\n");
        abort();
    }
    s_withheld[s_withheld_count++] = PBT_ROM_CODE(a, b);
}

// ---------------------------------------------------------------------------
// What says which part this is
//
// A host reading the low ROM finds three halfwords that identify the bootrom:
// the characters 'M' and 'u', a word saying which family and revision, and a
// pointer to the function table.  picotool reads them before it does anything
// else, and a device whose ROM does not carry them is one it will not issue an
// RP2350 command to, however the descriptors identify it.
//
// The table carries the entries a host asks for and stops.  It is not a part's
// table: picobootx reaches every bootrom routine through the lookup seam rather
// than by walking this, so nothing in the library depends on what is here, and a
// faithful one would be work in exchange for nothing.  An entry is a tag, a
// flags word, and one halfword per flag set, and a zero tag ends the walk.
//
// One entry earns its place.  picotool reads the bootrom's revision for
// `info -a`, and a walk that found nothing fails the whole command.
// ---------------------------------------------------------------------------

#define PBT_BOOTROM_MAGIC_OFFS  0x10u
#define PBT_BOOTROM_TABLE_OFFS  0x18u
#define PBT_BOOTROM_GITREV_OFFS 0x20u

// 'M', 'u', then the family — 2 for RP2350 — and the revision, which a host
// masks off.
static const uint8_t k_bootrom_magic[4] = { 'M', 'u', 0x02u, 0x03u };

// The entry says its value is data rather than a routine to call, which is what
// picotool asks for when it looks the revision up.
#define PBT_ROM_TABLE_FLAG_DATA 0x0040u

// What the modelled bootrom answers when asked which revision it is.  Not any
// released part's, so a host reporting it is plainly reporting this model.
#define PBT_BOOTROM_GITREV 0xB007C0DEu

static void pbt_rom_put16(uint32_t offs, uint16_t value) {
    s_rom[offs]     = (uint8_t)(value & 0xFFu);
    s_rom[offs + 1] = (uint8_t)(value >> 8);
}

// The divisor the model reports unless a scenario chooses another.  Non-zero
// and not one of the values a mistake would produce by accident, so a scenario
// asserting that the erase sequence carried it through cannot pass on a stray
// zero.
#define PBT_DEFAULT_XIP_CLKDIV 7u

// ---------------------------------------------------------------------------
// get_sys_info  (RP2350 datasheet 5.4.8.17)
//
// The flags and their word counts are the datasheet's, held here rather than
// taken from the library: the library knows nothing about individual flags, so
// a table read out of it would be reading the answer off the thing under test.
//
// The information returned is chosen by the flags parameter, and "the first
// word in the returned buffer, is the (sub)set of those flags that the API
// supports".  So the routine answers whole: that flags word, then "words of
// data for each present flag in order".  A flag the chip cannot answer is
// absent from the flags word and contributes no data — it is not a reason to
// refuse the call.
// ---------------------------------------------------------------------------

typedef struct {
    uint32_t    flag;
    uint8_t     words;
    const char *name;
} pbt_info_entry_t;

// 0x0020 NONCE is defined by 5.4.8.17 as "not supported", so it is here as a
// flag a host may ask for, carrying no data, and outside the set the model
// answers.  That is the flag a real part drops.
static const pbt_info_entry_t k_info[] = {
    { PBT_SYS_CHIP_INFO,      3u, "CHIP_INFO" },
    { PBT_SYS_CRITICAL,       1u, "CRITICAL" },
    { PBT_SYS_CPU_INFO,       1u, "CPU_INFO" },
    { PBT_SYS_FLASH_DEV_INFO, 1u, "FLASH_DEV_INFO" },
    { PBT_SYS_BOOT_RANDOM,    4u, "BOOT_RANDOM" },
    { PBT_SYS_NONCE,          0u, "NONCE" },
    { PBT_SYS_BOOT_INFO,      4u, "BOOT_INFO" },
};

#define PBT_INFO_COUNT (sizeof(k_info) / sizeof(k_info[0]))

unsigned pbt_sys_flag_count(void) { return (unsigned)PBT_INFO_COUNT; }

uint32_t pbt_sys_flag_at(unsigned index) {
    return index < PBT_INFO_COUNT ? k_info[index].flag : 0u;
}

const char *pbt_sys_flag_name(uint32_t flag) {
    for (unsigned i = 0; i < PBT_INFO_COUNT; i++) {
        if (k_info[i].flag == flag) {
            return k_info[i].name;
        }
    }
    return "unnamed";
}

uint32_t pbt_sys_info_words(uint32_t flags) {
    uint32_t words = 0u;
    for (unsigned i = 0; i < PBT_INFO_COUNT; i++) {
        if ((flags & k_info[i].flag) != 0u) {
            words += k_info[i].words;
        }
    }
    return words;
}

uint32_t pbt_sys_info_word(uint32_t flag) {
    // Distinct per flag and unlikely to arise any other way, so a scenario can
    // say which flag's data it is looking at rather than only how much of it
    // came back.
    return 0x51000000u | flag;
}

// ---------------------------------------------------------------------------
// get_partition_table_info  (RP2350 datasheet 5.4.8.16)
//
// Same shape as get_sys_info: a flags word carrying the supported subset of the
// request, then data per flag.  "With the exception of PT_INFO, all the flags
// select 'per partition' information, so each field is returned in flag order
// for one partition after the next", so the partitions are the outer loop and
// the flags the inner one.  SINGLE_PARTITION narrows that to one partition,
// named in the top eight bits of flags_and_partition, and carries no data of
// its own.
// ---------------------------------------------------------------------------

// How many words each per-partition flag carries for one partition.
#define PBT_PART_LOC_FLAGS_WORDS 2u
#define PBT_PART_ID_WORDS        2u

// PT_INFO's three words.
#define PBT_PART_PT_INFO_WORDS 3u

static unsigned s_partition_count;
static uint32_t s_partition_supported;

void pbt_set_partitions(unsigned count) {
    if (count > PBT_PARTITION_MAX) {
        fprintf(stderr, "pbt: %u partitions asked for, the model holds %u\n",
                count, PBT_PARTITION_MAX);
        abort();
    }
    s_partition_count = count;
}

void pbt_set_partition_supported(uint32_t mask) {
    s_partition_supported = mask;
}

unsigned pbt_partition_count(void) { return s_partition_count; }

uint32_t pbt_partition_word(unsigned index, uint32_t flag) {
    // Distinct per partition and per flag, so a scenario can say whose data it
    // is looking at and in what order it arrived.
    return 0x52000000u | ((uint32_t)index << 16) | flag;
}

// The bootrom error the modelled routines refuse with, or zero when they answer
// normally, and how many calls they answer before they start refusing.
static int      s_sys_info_rc;
static unsigned s_sys_info_ok_calls;
static int      s_partition_rc;
static unsigned s_partition_ok_calls;

void pbt_sys_info_fail(int rc)  { pbt_sys_info_fail_after(0u, rc); }
void pbt_partition_fail(int rc) { pbt_partition_fail_after(0u, rc); }

void pbt_sys_info_fail_after(unsigned calls, int rc) {
    s_sys_info_ok_calls = calls;
    s_sys_info_rc       = rc;
}

void pbt_partition_fail_after(unsigned calls, int rc) {
    s_partition_ok_calls = calls;
    s_partition_rc       = rc;
}

// Whether this call is one the routine has been told to refuse.  A part told to
// answer the first calls counts them down and refuses from then on.
static bool pbt_refuses_now(int rc, unsigned *ok_calls) {
    if (rc == 0) {
        return false;
    }
    if (*ok_calls > 0u) {
        (*ok_calls)--;
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

void pbt_device_reset(void) {
    // Flash starts erased, as a blank part does.  SRAM and ROM start at a
    // recognisable pattern rather than zero, so a read that returned zeros
    // because nothing happened is distinguishable from one that returned data.
    memset(s_flash, 0xFF, sizeof(s_flash));
    for (uint32_t i = 0; i < sizeof(s_sram); i++) {
        s_sram[i] = (uint8_t)(0xA0u + (i & 0x0Fu));
    }
    for (uint32_t i = 0; i < sizeof(s_rom); i++) {
        s_rom[i] = (uint8_t)(0x50u + (i & 0x0Fu));
    }
    memcpy(s_rom + PBT_BOOTROM_MAGIC_OFFS, k_bootrom_magic,
           sizeof(k_bootrom_magic));
    pbt_rom_put16(PBT_BOOTROM_MAGIC_OFFS + 4, PBT_BOOTROM_TABLE_OFFS);

    // The revision entry, then the zero tag that ends the walk.  A tag is the
    // two characters that name it, low byte first, as a bootrom code is
    // everywhere else.
    pbt_rom_put16(PBT_BOOTROM_TABLE_OFFS + 0, (uint16_t)PBT_ROM_CODE('G', 'R'));
    pbt_rom_put16(PBT_BOOTROM_TABLE_OFFS + 2, PBT_ROM_TABLE_FLAG_DATA);
    pbt_rom_put16(PBT_BOOTROM_TABLE_OFFS + 4, PBT_BOOTROM_GITREV_OFFS);
    pbt_rom_put16(PBT_BOOTROM_TABLE_OFFS + 6, 0);

    pbt_rom_put16(PBT_BOOTROM_GITREV_OFFS + 0,
                  (uint16_t)(PBT_BOOTROM_GITREV & 0xFFFFu));
    pbt_rom_put16(PBT_BOOTROM_GITREV_OFFS + 2,
                  (uint16_t)(PBT_BOOTROM_GITREV >> 16));

    memset(s_otp, 0, sizeof(s_otp));

    s_irq_disabled        = false;
    s_xip_active          = true;
    s_xip_clkdiv          = PBT_DEFAULT_XIP_CLKDIV;
    s_sys_info_supported  = PBT_SYS_SERVED;
    s_partition_supported = PBT_PART_SERVED;

    // A part with no partition table, which is what the measured RP2350 the
    // partition expectations come from had.  A scenario that wants per-partition
    // data asks for partitions.
    s_partition_count     = 0;

    s_withheld_count      = 0;
    s_otp_rc              = 0;
    s_sys_info_rc         = 0;
    s_sys_info_ok_calls   = 0;
    s_partition_rc        = 0;
    s_partition_ok_calls  = 0;
}

// ---------------------------------------------------------------------------
// Seam: device address to host pointer
// ---------------------------------------------------------------------------

void *picobootx_host_test_dev_ptr(uint32_t addr, uint32_t len) {
    if (addr >= RP2350_SRAM_BASE &&
        (uint64_t)addr + len <= (uint64_t)RP2350_SRAM_BASE + PBT_SRAM_MODELLED) {
        return s_sram + (addr - RP2350_SRAM_BASE);
    }
    if (addr >= RP2350_FLASH_BASE &&
        (uint64_t)addr + len <= (uint64_t)RP2350_FLASH_BASE + PBT_FLASH_MODELLED) {
        return s_flash + (addr - RP2350_FLASH_BASE);
    }
    if ((uint64_t)addr + len <= (uint64_t)RP2350_ROM_BASE + PBT_ROM_MODELLED) {
        return s_rom + (addr - RP2350_ROM_BASE);
    }

    // Reaching here means the range passed the library's own validation and
    // still has nowhere to land.  That is a mistake in the scenario or in the
    // validation, and either way the process must not go on to dereference it.
    fprintf(stderr,
            "pbt: no mapping for device address 0x%08x len %u.  The model "
            "covers ROM, the low %u bytes of flash, and SRAM.\n",
            addr, len, PBT_FLASH_MODELLED);
    abort();
}

// ---------------------------------------------------------------------------
// Seam: XIP clock divisor
// ---------------------------------------------------------------------------

uint8_t picobootx_host_test_xip_clkdiv(void) {
    // Recorded so a scenario can require that it was read before XIP was taken
    // down, which is the whole reason the erase sequence reads it at all.
    pbt_log("xip_clkdiv_read", s_xip_clkdiv, 0, 0, 0);
    return s_xip_clkdiv;
}

// ---------------------------------------------------------------------------
// Seam: interrupt masking
// ---------------------------------------------------------------------------

void picobootx_host_test_irq_disable(void) {
    pbt_log("irq_disable", 0, 0, 0, 0);
    s_irq_disabled = true;
}

void picobootx_host_test_irq_enable(void) {
    pbt_log("irq_enable", 0, 0, 0, 0);
    s_irq_disabled = false;
}

// ---------------------------------------------------------------------------
// The bootrom
// ---------------------------------------------------------------------------

static int pbt_rom_reboot(uint32_t flags, uint32_t delay_ms, uint32_t p0,
                          uint32_t p1) {
    pbt_log("rom_reboot", flags, delay_ms, p0, p1);
    return 0;
}

static int pbt_rom_get_sys_info(uint32_t *out, uint32_t out_words,
                                uint32_t flags) {
    pbt_log("rom_get_sys_info", flags, out_words, 0, 0);

    if (pbt_refuses_now(s_sys_info_rc, &s_sys_info_ok_calls)) {
        // Refused before anything is written, so a scenario can tell a refusal
        // apart from a partial answer.
        return s_sys_info_rc;
    }

    // The subset the chip answers.  A flag outside it — NONCE, or one no
    // version of the routine defines — is dropped here, and the host learns
    // that from this word rather than from a refusal.
    const uint32_t answered = flags & s_sys_info_supported;

    uint32_t words = 1u;
    for (unsigned i = 0; i < PBT_INFO_COUNT; i++) {
        if ((answered & k_info[i].flag) != 0u) {
            words += k_info[i].words;
        }
    }
    if (out_words < words) {
        return PBT_BOOTROM_ERROR_BUFFER_TOO_SMALL;
    }

    out[0] = answered;
    uint32_t at = 1u;
    for (unsigned i = 0; i < PBT_INFO_COUNT; i++) {
        if ((answered & k_info[i].flag) == 0u) {
            continue;
        }
        for (uint8_t w = 0; w < k_info[i].words; w++) {
            out[at++] = pbt_sys_info_word(k_info[i].flag) + w;
        }
    }
    return (int)words;
}

static int pbt_rom_get_partition_table_info(uint32_t *out, uint32_t out_words,
                                            uint32_t flags_and_partition) {
    pbt_log("rom_get_partition_table_info", flags_and_partition, out_words, 0,
            0);

    if (pbt_refuses_now(s_partition_rc, &s_partition_ok_calls)) {
        return s_partition_rc;
    }

    const uint32_t answered = flags_and_partition & s_partition_supported;
    const bool     single   = (answered & PBT_PART_SINGLE) != 0u;
    const unsigned chosen   = (flags_and_partition >> 24) & 0xFFu;

    // Which partitions the per-partition flags speak for.  SINGLE_PARTITION
    // names one, and a number the table does not hold speaks for none.
    unsigned first = 0u;
    unsigned last  = s_partition_count;   // exclusive
    if (single) {
        first = chosen;
        last  = (chosen < s_partition_count) ? chosen + 1u : chosen;
    }

    uint32_t per_partition = 0u;
    if ((answered & PBT_PART_LOC_FLAGS) != 0u) {
        per_partition += PBT_PART_LOC_FLAGS_WORDS;
    }
    if ((answered & PBT_PART_ID) != 0u) {
        per_partition += PBT_PART_ID_WORDS;
    }

    uint32_t words = 1u;
    if ((answered & PBT_PART_PT_INFO) != 0u) {
        words += PBT_PART_PT_INFO_WORDS;
    }
    words += per_partition * (last - first);

    if (out_words < words) {
        return PBT_BOOTROM_ERROR_BUFFER_TOO_SMALL;
    }

    out[0] = answered;
    uint32_t at = 1u;
    if ((answered & PBT_PART_PT_INFO) != 0u) {
        // 5.4.8.16: the partition count in the low eight bits and whether a
        // partition table is present in bit 8, then the two words 5.9.4.2
        // describes for unpartitioned space.
        out[at++] = (uint32_t)s_partition_count |
                    (s_partition_count != 0u ? 0x100u : 0u);
        out[at++] = PBT_PT_UNPARTITIONED_LOCATION;
        out[at++] = PBT_PT_UNPARTITIONED_FLAGS;
    }
    for (unsigned p = first; p < last; p++) {
        if ((answered & PBT_PART_LOC_FLAGS) != 0u) {
            for (uint32_t w = 0; w < PBT_PART_LOC_FLAGS_WORDS; w++) {
                out[at++] = pbt_partition_word(p, PBT_PART_LOC_FLAGS) + w;
            }
        }
        if ((answered & PBT_PART_ID) != 0u) {
            for (uint32_t w = 0; w < PBT_PART_ID_WORDS; w++) {
                out[at++] = pbt_partition_word(p, PBT_PART_ID) + w;
            }
        }
    }
    return (int)words;
}

static int pbt_rom_otp_access(uint8_t *buf, uint32_t buf_len,
                              uint32_t row_and_flags) {
    bool     write    = (row_and_flags & PBT_OTP_FLAG_WRITE) != 0u;
    bool     ecc      = (row_and_flags & PBT_OTP_FLAG_ECC) != 0u;
    uint32_t row      = row_and_flags & 0xFFFFu;
    uint32_t row_size = ecc ? 2u : 4u;

    pbt_log("rom_otp_access", row, buf_len, ecc ? 1u : 0u, write ? 1u : 0u);

    if (s_otp_rc != 0) {
        // Refused before anything is read or blown, so a scenario can tell a
        // refusal apart from a partial access.
        return s_otp_rc;
    }

    if (buf_len % row_size != 0u) {
        return PBT_BOOTROM_ERROR_INVALID_ARG;
    }
    uint32_t rows = buf_len / row_size;
    if (row + rows > PBT_OTP_ROWS) {
        return PBT_BOOTROM_ERROR_INVALID_ARG;
    }

    for (uint32_t i = 0; i < rows; i++) {
        uint32_t *cell = &s_otp[row + i];
        uint8_t  *slot = buf + (i * row_size);
        if (write) {
            // OTP fuses only ever go from clear to set, so a write ORs.  A row
            // written twice therefore reads back as the union, and a scenario
            // that expected the second write to replace the first sees it.
            uint32_t value = ecc
                ? ((uint32_t)slot[0] | ((uint32_t)slot[1] << 8))
                : ((uint32_t)slot[0] | ((uint32_t)slot[1] << 8) |
                   ((uint32_t)slot[2] << 16) | ((uint32_t)slot[3] << 24));
            *cell |= value;
        } else {
            slot[0] = (uint8_t)(*cell & 0xFFu);
            slot[1] = (uint8_t)((*cell >> 8) & 0xFFu);
            if (!ecc) {
                slot[2] = (uint8_t)((*cell >> 16) & 0xFFu);
                slot[3] = (uint8_t)((*cell >> 24) & 0xFFu);
            }
        }
    }
    return 0;
}

static void pbt_rom_connect_internal_flash(void) {
    pbt_log("rom_connect_internal_flash", 0, 0, 0, 0);
}

static void pbt_rom_flash_exit_xip(void) {
    pbt_log("rom_flash_exit_xip", 0, 0, 0, 0);
    s_xip_active = false;
}

static void pbt_rom_flash_range_erase(uint32_t offs, size_t count,
                                      uint32_t block_size, uint8_t block_cmd) {
    pbt_log("rom_flash_range_erase", offs, (uint32_t)count, block_size,
            block_cmd);

    // Flash cannot be erased while it is answering execute-in-place reads.  An
    // erase issued with XIP still up is recorded and does nothing, so the
    // scenario sees unerased flash rather than a silently successful erase.
    if (s_xip_active) {
        pbt_log("rom_flash_erase_while_xip", offs, (uint32_t)count, 0, 0);
        return;
    }
    if (offs + count > PBT_FLASH_MODELLED) {
        pbt_log("rom_flash_erase_out_of_model", offs, (uint32_t)count, 0, 0);
        return;
    }
    memset(s_flash + offs, 0xFF, count);
}

static void pbt_rom_flash_flush_cache(void) {
    pbt_log("rom_flash_flush_cache", 0, 0, 0, 0);
}

static void pbt_rom_flash_select_xip_read_mode(uint8_t mode, uint8_t clkdiv) {
    pbt_log("rom_flash_select_xip_read_mode", mode, clkdiv, 0, 0);
    s_xip_active = true;
}

static void pbt_rom_flash_range_program(uint32_t offs, const uint8_t *data,
                                        size_t count) {
    pbt_log("rom_flash_range_program", offs, (uint32_t)count, 0, 0);

    // Flash cannot be programmed while it is answering execute-in-place reads,
    // for the same reason it cannot be erased.  A program issued with XIP still
    // up is recorded and does nothing, so the scenario sees flash that did not
    // change rather than a silently successful write.
    if (s_xip_active) {
        pbt_log("rom_flash_program_while_xip", offs, (uint32_t)count, 0, 0);
        return;
    }
    if (offs + count > PBT_FLASH_MODELLED) {
        pbt_log("rom_flash_program_out_of_model", offs, (uint32_t)count, 0, 0);
        return;
    }
    // Programming can only clear bits.  Modelling that rather than copying is
    // what makes a page the device programmed without erasing first come back
    // as the AND of the two, instead of looking like a clean write.
    for (size_t i = 0; i < count; i++) {
        s_flash[offs + i] &= data[i];
    }
}

// ---------------------------------------------------------------------------
// Seam: bootrom lookup
// ---------------------------------------------------------------------------

void *picobootx_host_test_bootrom_lookup(uint32_t code, uint32_t mask) {
    pbt_log("bootrom_lookup", code, mask, 0, 0);

    for (unsigned i = 0; i < s_withheld_count; i++) {
        if (s_withheld[i] == code) {
            return NULL;
        }
    }

    switch (code) {
        case PBT_ROM_CODE('R', 'B'): return (void *)pbt_rom_reboot;
        case PBT_ROM_CODE('G', 'S'): return (void *)pbt_rom_get_sys_info;
        case PBT_ROM_CODE('G', 'P'): return (void *)pbt_rom_get_partition_table_info;
        case PBT_ROM_CODE('O', 'A'): return (void *)pbt_rom_otp_access;
        case PBT_ROM_CODE('R', 'E'): return (void *)pbt_rom_flash_range_erase;
        case PBT_ROM_CODE('R', 'P'): return (void *)pbt_rom_flash_range_program;
        case PBT_ROM_CODE('I', 'F'): return (void *)pbt_rom_connect_internal_flash;
        case PBT_ROM_CODE('E', 'X'): return (void *)pbt_rom_flash_exit_xip;
        case PBT_ROM_CODE('F', 'C'): return (void *)pbt_rom_flash_flush_cache;
        case PBT_ROM_CODE('X', 'M'): return (void *)pbt_rom_flash_select_xip_read_mode;
        default:                     return NULL;
    }
}
