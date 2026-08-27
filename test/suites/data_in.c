// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// Device-to-host transfers: READ, GET_INFO and OTP_READ.

#include <string.h>

#include "pbt.h"

// Reads a 32-bit word out of the payload the device sent.
static uint32_t payload_word(uint32_t index) {
    uint32_t word = 0;
    if ((index + 1u) * 4u <= pbt_payload_len()) {
        memcpy(&word, pbt_payload() + (index * 4u), sizeof(word));
    }
    return word;
}

// Whether the device sent a word at this index at all.  payload_word answers
// zero for a word that is not there, so a scenario expecting a zero word has to
// say first that the word was sent — otherwise a response that stopped short
// satisfies it.
static bool payload_has_word(uint32_t index) {
    return (index + 1u) * 4u <= pbt_payload_len();
}

// ---------------------------------------------------------------------------
// What a GET_INFO reply looks like
//
// 5.6.4.11: "The fist word returned indicates the number of significant words
// of data that follow. A full 'transfer length' is always returned, padding
// with zeroes as necessary."  That count word and that padding are the
// library's.  Everything between them is what the device answered, and its
// shape belongs to the type rather than to the library.
//
// Two of the four types carry a flags word in front of their data, because the
// bootrom routines behind them do.  5.4.8.17 and 5.4.8.16 both say "the first
// word in the returned buffer, is the (sub)set of those flags that the API
// supports", and both then return "words of data for each present flag in
// order".  So for INFO_SYS and PARTITION a host reads the first data word at
// payload word 2, and the flags word is one of the significant words the count
// counts.  5.6.4.11 gives the two UF2 types their words directly and puts no
// such word in front of either, so there the first data word is payload word 1.
//
// A flag the device cannot answer is dropped from that flags word rather than
// refusing the command.  5.4.8.17 tells a host to "always check this value
// before interpreting the buffer", which is advice worth giving only if a
// request naming a flag nobody serves is still answered for the flags beside
// it.  NONCE is the flag 5.4.8.17 itself marks "not supported", so it is the
// one every RP2350 drops.
//
// Where dTransferLength cannot hold the whole reply the command is refused with
// BUFFER_TOO_SMALL, Table 471's "The provided buffer was too small to hold the
// result".  README.md records why that reading was chosen, and get_sys_info's
// own out_buffer_word_size and BOOTROM_ERROR_BUFFER_TOO_SMALL point the same
// way.
//
// The flags themselves are in pbt.h, alongside the modelled part that answers
// them.
// ---------------------------------------------------------------------------

// Where the count and the flags word leave the first data word.
#define SYS_FIRST_DATA_WORD 2u

static void scenario_read_returns_device_memory(void) {
    pbt_begin();
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_READ, 0x08u, 32u);
    pbt_args_addr_size(&cmd, RP2350_SRAM_BASE, 32u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);

    PBT_CHECK_EQ(pbt_payload_len(), 32u);
    PBT_CHECK_EQ(memcmp(pbt_payload(), pbt_sram(), 32u), 0);
    PBT_CHECK_EQ(pbt_count("op_read_prepare"), 1);
    PBT_CHECK(pbt_before("op_read_prepare", "op_read"));
}

static void scenario_read_is_correct_aligned_and_unaligned(void) {
    pbt_begin();
    pbt_start();

    // A four-byte read from a four-byte boundary takes the word path.  The same
    // read one byte along takes the copy path.  Both have to produce the bytes
    // that are actually there.
    picoboot_cmd_t aligned = pbt_cmd(PB_CMD_READ, 0x08u, 4u);
    pbt_args_addr_size(&aligned, RP2350_SRAM_BASE + 16u, 4u);
    PBT_CHECK_STATUS(pbt_run_cmd(&aligned), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_payload_len(), 4u);
    PBT_CHECK_EQ(memcmp(pbt_payload(), pbt_sram() + 16u, 4u), 0);

    pbt_begin();
    pbt_start();

    picoboot_cmd_t unaligned = pbt_cmd(PB_CMD_READ, 0x08u, 4u);
    pbt_args_addr_size(&unaligned, RP2350_SRAM_BASE + 17u, 4u);
    PBT_CHECK_STATUS(pbt_run_cmd(&unaligned), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_payload_len(), 4u);
    PBT_CHECK_EQ(memcmp(pbt_payload(), pbt_sram() + 17u, 4u), 0);

    // The model gives neighbouring bytes different values, so the two reads
    // above cannot both pass by returning the same thing.
    PBT_CHECK(pbt_sram()[16] != pbt_sram()[17]);
}

static void scenario_read_covers_flash_and_rom(void) {
    // All three regions picoboot_default_read_prepare admits are readable, not
    // just the one most reads go to.
    const struct {
        const char *name;
        uint32_t    base;
    } regions[] = {
        { "rom",   RP2350_ROM_BASE },
        { "flash", RP2350_FLASH_BASE },
        { "sram",  RP2350_SRAM_BASE },
    };

    for (unsigned i = 0; i < sizeof(regions) / sizeof(regions[0]); i++) {
        pbt_begin();
        pbt_start();

        // Put something in the region that is unique to it, so a read that
        // silently came from somewhere else does not match.
        uint8_t *model = regions[i].base == RP2350_ROM_BASE   ? pbt_rom()
                       : regions[i].base == RP2350_FLASH_BASE ? pbt_flash()
                                                              : pbt_sram();
        for (unsigned j = 0; j < 16u; j++) {
            model[j] = (uint8_t)(0x10u * (i + 1u) + j);
        }

        picoboot_cmd_t cmd = pbt_cmd(PB_CMD_READ, 0x08u, 16u);
        pbt_args_addr_size(&cmd, regions[i].base, 16u);

        pb_status_t got = pbt_run_cmd(&cmd);
        if (got != PB_STATUS_OK) {
            pbt_fail(__FILE__, __LINE__, "%s read: %s", regions[i].name,
                     pbt_status_name((int)got));
            continue;
        }
        if (memcmp(pbt_payload(), model, 16u) != 0) {
            pbt_fail(__FILE__, __LINE__, "%s read returned the wrong bytes",
                     regions[i].name);
        }
    }
}

static void scenario_read_outside_every_region_is_refused(void) {
    pbt_begin();
    pbt_start();

    // Between flash and SRAM, so it is inside no region rather than merely past
    // the end of one.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_READ, 0x08u, 16u);
    pbt_args_addr_size(&cmd, 0x30000000u, 16u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_INVALID_ARG);

    // Refused before any memory was touched, which is the point of validating
    // the whole range up front.
    PBT_CHECK_EQ(pbt_count("op_read"), 0);
    PBT_CHECK_EQ(pbt_packet_count(), 0u);
}

static void scenario_read_running_off_the_end_is_refused(void) {
    // Each region's last bytes, read with a length that carries the request past
    // the end of it.  A check that only looked at the start address would let
    // any of these through, and a check that only knew about one region would
    // let the other two through.
    //
    // inside is an address the read is expected to succeed at.  For ROM and
    // SRAM that is the region's own last 64 bytes.  The model covers only the
    // low 256KB of the 32MB flash, so flash's is its base instead — the point of
    // the second read is that a read of the same shape is accepted, not where in
    // the region it lands.
    const struct {
        const char *name;
        uint32_t    end;
        uint32_t    inside;
    } regions[] = {
        { "rom",   RP2350_ROM_BASE   + RP2350_ROM_SIZE,
          RP2350_ROM_BASE   + RP2350_ROM_SIZE   - 64u },
        { "flash", RP2350_FLASH_BASE + RP2350_FLASH_SIZE, RP2350_FLASH_BASE },
        { "sram",  RP2350_SRAM_BASE  + RP2350_SRAM_SIZE,
          RP2350_SRAM_BASE  + RP2350_SRAM_SIZE  - 64u },
    };

    for (unsigned i = 0; i < sizeof(regions) / sizeof(regions[0]); i++) {
        pbt_begin();
        pbt_start();

        picoboot_cmd_t cmd = pbt_cmd(PB_CMD_READ, 0x08u, 64u);
        pbt_args_addr_size(&cmd, regions[i].end - 32u, 64u);

        pb_status_t got = pbt_run_cmd(&cmd);
        if (got != PB_STATUS_INVALID_ARG) {
            pbt_fail(__FILE__, __LINE__, "%s overrun: expected INVALID_ARG, "
                     "got %s", regions[i].name, pbt_status_name((int)got));
        }
        if (pbt_count("op_read") != 0) {
            pbt_fail(__FILE__, __LINE__, "%s overrun: the read was issued anyway",
                     regions[i].name);
        }

        // The same length wholly inside the region is fine, so what was refused
        // was the overrun and not the address or the length.
        pbt_recover();
        picoboot_cmd_t inside = pbt_cmd(PB_CMD_READ, 0x08u, 64u);
        pbt_args_addr_size(&inside, regions[i].inside, 64u);
        pb_status_t ok = pbt_run_cmd(&inside);
        if (ok != PB_STATUS_OK) {
            pbt_fail(__FILE__, __LINE__, "%s read wholly inside the region: %s",
                     regions[i].name, pbt_status_name((int)ok));
        }
    }
}

static void scenario_read_without_its_callbacks_is_refused(void) {
    // Two different pieces are needed, and either one missing refuses the
    // command rather than calling through a null pointer.
    pbt_begin();
    pbt_ops.read = NULL;
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_READ, 0x08u, 16u);
    pbt_args_addr_size(&cmd, RP2350_SRAM_BASE, 16u);
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_UNKNOWN_CMD);
    PBT_CHECK_EQ(pbt_count("op_read_prepare"), 0);

    pbt_begin();
    pbt_ops.read_prepare = NULL;
    pbt_start();

    picoboot_cmd_t again = pbt_cmd(PB_CMD_READ, 0x08u, 16u);
    pbt_args_addr_size(&again, RP2350_SRAM_BASE, 16u);
    PBT_CHECK_STATUS(pbt_run_cmd(&again), PB_STATUS_UNKNOWN_CMD);
    PBT_CHECK_EQ(pbt_count("op_read"), 0);
}

// A read callback that serves one call and then refuses, for showing what
// happens when a device discovers partway through a transfer that it cannot
// produce the rest.  The default implementation never fails, so an integrator's
// that does has to be written here.
#define READ_REFUSAL_STATUS PB_STATUS_INVALID_DATA

static uint32_t s_reads_before_refusal;

static pb_status_t op_read_then_refuse(uint32_t addr, uint8_t *buf,
                                       uint32_t len, void *ctx) {
    pbt_log("op_read", addr, len, 0, 0);
    if (s_reads_before_refusal == 0u) {
        return READ_REFUSAL_STATUS;
    }
    s_reads_before_refusal--;
    return picoboot_default_read(addr, buf, len, ctx);
}

static void scenario_a_read_that_fails_partway_stalls(void) {
    pbt_begin();
    s_reads_before_refusal = 1u;
    pbt_ops.read = op_read_then_refuse;
    pbt_start();

    // Two endpoints' worth, so the first call succeeds and its data is on the
    // wire before the second refuses.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_READ, 0x08u, 128u);
    pbt_args_addr_size(&cmd, RP2350_SRAM_BASE, 128u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), READ_REFUSAL_STATUS);

    PBT_CHECK_EQ(pbt_count("op_read"), 2);
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_STALLED);

    // The host is left holding the packet it already had, and the halt is what
    // tells it no more is coming.  A device that returned silently here would
    // leave the host waiting for the rest of a transfer that had been abandoned.
    PBT_CHECK_EQ(pbt_packet_count(), 1u);
    PBT_CHECK_EQ(pbt_payload_len(), 64u);
    PBT_CHECK_EQ(memcmp(pbt_payload(), pbt_sram(), 64u), 0);

    picoboot_status_t status;
    PBT_REQUIRE(pbt_ctrl_get_status(&status));
    PBT_CHECK_EQ(status.token, cmd.token);
    PBT_CHECK_EQ(status.in_progress, 0u);

    // The same read with a callback that does not refuse delivers both packets,
    // so what stopped it was the refusal.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t again = pbt_cmd(PB_CMD_READ, 0x08u, 128u);
    pbt_args_addr_size(&again, RP2350_SRAM_BASE, 128u);
    PBT_CHECK_STATUS(pbt_run_cmd(&again), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_packet_count(), 2u);
    PBT_CHECK_EQ(pbt_payload_len(), 128u);
}

static void scenario_get_info_sys_sends_a_count_flags_then_the_data(void) {
    pbt_begin();
    pbt_start();

    // Two flags, carrying three words and one word respectively.
    const uint32_t chip_info = PBT_SYS_CHIP_INFO;
    const uint32_t cpu_info  = PBT_SYS_CPU_INFO;

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 64u);
    pbt_args_get_info(&cmd, PB_INFO_SYS, chip_info | cpu_info);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 64u);

    // The leading word counts the significant words after it: the flags word
    // and the four words of data.
    PBT_CHECK_EQ(payload_word(0), 5u);

    // Then get_sys_info's own first word, the requested flags the device
    // answered.
    PBT_CHECK_EQ(payload_word(1), chip_info | cpu_info);

    // Then each answered flag's data, lowest flag first.
    PBT_CHECK_EQ(payload_word(2), pbt_sys_info_word(chip_info) + 0u);
    PBT_CHECK_EQ(payload_word(3), pbt_sys_info_word(chip_info) + 1u);
    PBT_CHECK_EQ(payload_word(4), pbt_sys_info_word(chip_info) + 2u);
    PBT_CHECK_EQ(payload_word(5), pbt_sys_info_word(cpu_info) + 0u);

    // And the rest of the transfer the host asked for is padded, not left
    // holding whatever was in the buffer.
    for (uint32_t i = 6; i < 16u; i++) {
        PBT_CHECK(payload_has_word(i));
        PBT_CHECK_EQ(payload_word(i), 0u);
    }

    // The device was asked how long the answer would be before any of it went,
    // once, and said five words — the count the host was then sent.
    PBT_CHECK_EQ(pbt_count("op_get_info_prepare"), 1);
    PBT_REQUIRE(pbt_nth("op_get_info_prepare", 0) != NULL);
    PBT_CHECK_EQ(pbt_nth("op_get_info_prepare", 0)->a0, PB_INFO_SYS);
    PBT_CHECK_EQ(pbt_nth("op_get_info_prepare", 0)->a1, chip_info | cpu_info);
    PBT_CHECK_EQ(pbt_nth("op_get_info_prepare", 0)->a2, 5u);
    PBT_CHECK(pbt_before("op_get_info_prepare", "op_get_info"));

    // The whole answer came from the device, in one request rather than one per
    // flag, and it started at the beginning of it.
    PBT_CHECK(pbt_count("op_get_info") >= 1);
    PBT_REQUIRE(pbt_nth("op_get_info", 0) != NULL);
    PBT_CHECK_EQ(pbt_nth("op_get_info", 0)->a0, PB_INFO_SYS);
    PBT_CHECK_EQ(pbt_nth("op_get_info", 0)->a1, chip_info | cpu_info);
    PBT_CHECK_EQ(pbt_nth("op_get_info", 0)->a2, 0u);
}

static void scenario_get_info_sys_word_count_per_flag(void) {
    // Each flag alone, in a transfer that holds the count, the flags word and
    // exactly the words 5.4.8.17 gives that flag.  A response one word longer
    // or shorter than the specification says does not fit this transfer.
    //
    // NONCE is in here too.  5.4.8.17 gives it no words at all, so its answer
    // is the count and an empty flags word, and it is served like any other.
    for (unsigned i = 0; i < pbt_sys_flag_count(); i++) {
        const uint32_t flag   = pbt_sys_flag_at(i);
        const char    *name   = pbt_sys_flag_name(flag);
        const uint32_t served = flag & PBT_SYS_SERVED;
        const uint32_t words  = pbt_sys_info_words(served);

        pbt_begin();
        pbt_start();

        picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u,
                                     (SYS_FIRST_DATA_WORD + words) * 4u);
        pbt_args_get_info(&cmd, PB_INFO_SYS, flag);

        pb_status_t got = pbt_run_cmd(&cmd);
        if (got != PB_STATUS_OK) {
            pbt_fail(__FILE__, __LINE__, "%s: %s", name,
                     pbt_status_name((int)got));
            continue;
        }
        if (payload_word(0) != 1u + words) {
            pbt_fail(__FILE__, __LINE__, "%s: count %u, expected %u", name,
                     payload_word(0), 1u + words);
        }
        if (!payload_has_word(1u) || payload_word(1) != served) {
            pbt_fail(__FILE__, __LINE__, "%s: flags word 0x%08x, expected "
                     "0x%08x", name, payload_word(1), served);
        }
        for (uint32_t w = 0; w < words; w++) {
            uint32_t expected = pbt_sys_info_word(flag) + w;
            if (payload_word(SYS_FIRST_DATA_WORD + w) != expected) {
                pbt_fail(__FILE__, __LINE__, "%s: data word %u is 0x%08x, "
                         "expected 0x%08x", name, w,
                         payload_word(SYS_FIRST_DATA_WORD + w), expected);
            }
        }
    }
}

static void scenario_get_info_sys_answers_every_flag_in_order(void) {
    pbt_begin();
    pbt_start();

    // Every flag 5.4.8.17 names, in a transfer sized to the answer exactly:
    // fifteen significant words behind the count, which is sixty-four bytes.
    // Nothing is padded, so a word missing from the answer cannot hide behind
    // the padding rule.
    PBT_REQUIRE(pbt_sys_info_words(PBT_SYS_SERVED) == PBT_SYS_SERVED_WORDS);

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 64u);
    pbt_args_get_info(&cmd, PB_INFO_SYS, PBT_SYS_ALL);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 64u);

    PBT_CHECK_EQ(payload_word(0), 1u + PBT_SYS_SERVED_WORDS);

    // NONCE was asked for and is not here, and every other flag is.
    PBT_CHECK_EQ(payload_word(1), PBT_SYS_SERVED);
    PBT_CHECK_EQ(payload_word(1) & PBT_SYS_NONCE, 0u);

    // The data runs in ascending flag order, so where a flag's data starts is
    // decided by how many words the flags below it carry.  A response that
    // ordered the flags any other way puts the wrong value at each of these,
    // and one that left room for NONCE shifts everything above it.
    uint32_t at = SYS_FIRST_DATA_WORD;
    for (unsigned i = 0; i < pbt_sys_flag_count(); i++) {
        const uint32_t flag = pbt_sys_flag_at(i);
        if ((PBT_SYS_SERVED & flag) == 0u) {
            continue;
        }
        for (uint32_t w = 0; w < pbt_sys_info_words(flag); w++) {
            uint32_t expected = pbt_sys_info_word(flag) + w;
            if (payload_word(at) != expected) {
                pbt_fail(__FILE__, __LINE__, "word %u: expected %s data word "
                         "%u (0x%08x), got 0x%08x", at, pbt_sys_flag_name(flag),
                         w, expected, payload_word(at));
            }
            at++;
        }
    }

    // The answer ends where the transfer does.
    PBT_CHECK_EQ(at * 4u, pbt_payload_len());
}

static void scenario_get_info_sys_drops_a_flag_the_chip_will_not_answer(void) {
    // The flag is dropped from the flags word, and the flags beside it are
    // served in full.  5.4.8.17 defines NONCE and says of it only "not
    // supported", so a request naming it is a request naming a flag no part
    // answers.
    pbt_begin();
    pbt_start();

    // NONCE on its own.  Nothing to answer, so the flags word is empty and it
    // is the only significant word — and the command is served, not refused.
    picoboot_cmd_t alone = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 32u);
    pbt_args_get_info(&alone, PB_INFO_SYS, PBT_SYS_NONCE);

    PBT_CHECK_STATUS(pbt_run_cmd(&alone), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 32u);
    PBT_CHECK_EQ(payload_word(0), 1u);
    PBT_CHECK(payload_has_word(1u));
    PBT_CHECK_EQ(payload_word(1), 0u);

    // NONCE beside a flag the part does answer.  The answer is CHIP_INFO's,
    // whole, and NONCE is absent from the flags word.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t beside = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 32u);
    pbt_args_get_info(&beside, PB_INFO_SYS, PBT_SYS_CHIP_INFO | PBT_SYS_NONCE);

    PBT_CHECK_STATUS(pbt_run_cmd(&beside), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 32u);
    PBT_CHECK_EQ(payload_word(0), 4u);
    PBT_CHECK_EQ(payload_word(1), PBT_SYS_CHIP_INFO);
    for (uint32_t w = 0; w < 3u; w++) {
        PBT_CHECK_EQ(payload_word(SYS_FIRST_DATA_WORD + w),
                     pbt_sys_info_word(PBT_SYS_CHIP_INFO) + w);
    }
    for (uint32_t i = 5u; i < 8u; i++) {
        PBT_CHECK(payload_has_word(i));
        PBT_CHECK_EQ(payload_word(i), 0u);
    }

    // Twenty bytes is that answer and no padding.  The transfer is sized to
    // what the device will answer rather than to what was asked for, and it is
    // served: the dropped flag makes no claim on the buffer.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t exact = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&exact, PB_INFO_SYS, PBT_SYS_CHIP_INFO | PBT_SYS_NONCE);

    PBT_CHECK_STATUS(pbt_run_cmd(&exact), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_payload_len(), 20u);
    PBT_CHECK_EQ(payload_word(0), 4u);
    PBT_CHECK_EQ(payload_word(1), PBT_SYS_CHIP_INFO);
    PBT_CHECK_EQ(payload_word(4), pbt_sys_info_word(PBT_SYS_CHIP_INFO) + 2u);

    // And a flag this particular part will not answer, which NONCE cannot show
    // because no part answers it.  CPU_INFO is dropped when the part does not
    // serve it and served when it does, with nothing else about the request
    // changed.
    pbt_begin();
    pbt_set_sys_info_supported(PBT_SYS_CRITICAL);
    pbt_start();
    picoboot_cmd_t withheld = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 16u);
    pbt_args_get_info(&withheld, PB_INFO_SYS,
                      PBT_SYS_CRITICAL | PBT_SYS_CPU_INFO);
    PBT_CHECK_STATUS(pbt_run_cmd(&withheld), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 16u);
    PBT_CHECK_EQ(payload_word(0), 2u);
    PBT_CHECK_EQ(payload_word(1), PBT_SYS_CRITICAL);
    PBT_CHECK_EQ(payload_word(2), pbt_sys_info_word(PBT_SYS_CRITICAL));
    PBT_CHECK(payload_has_word(3u));
    PBT_CHECK_EQ(payload_word(3), 0u);

    pbt_begin();
    pbt_start();
    picoboot_cmd_t served = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 16u);
    pbt_args_get_info(&served, PB_INFO_SYS,
                      PBT_SYS_CRITICAL | PBT_SYS_CPU_INFO);
    PBT_CHECK_STATUS(pbt_run_cmd(&served), PB_STATUS_OK);
    PBT_CHECK_EQ(payload_word(0), 3u);
    PBT_CHECK_EQ(payload_word(1), PBT_SYS_CRITICAL | PBT_SYS_CPU_INFO);
    PBT_CHECK_EQ(payload_word(2), pbt_sys_info_word(PBT_SYS_CRITICAL));
    PBT_CHECK_EQ(payload_word(3), pbt_sys_info_word(PBT_SYS_CPU_INFO));
}

static void scenario_get_info_sys_answers_under_an_unserved_high_flag(void) {
    // A request naming a flag the device does not serve, above every flag it
    // does, in a transfer sized to the answer and no further.
    //
    // The device writes the last word it owes with a bit it was asked about
    // still outstanding, and there is nothing further it could write for it.
    // The transfer holds the two header words and the served flags' data
    // exactly, so no padding stands between the end of the answer and the end
    // of the transfer.
    //
    // 0x0080 and 0x0100 are above every flag 5.4.8.17 names, so no device
    // answers either.
    const struct {
        const char *what;
        uint32_t    served;    // what the device answers, ascending by flag
        uint32_t    unserved;  // above every flag the device serves
    } variants[] = {
        { "CPU_INFO",              PBT_SYS_CPU_INFO,                  0x0080u },
        { "CRITICAL and BOOT_INFO",
          PBT_SYS_CRITICAL | PBT_SYS_BOOT_INFO,                       0x0100u },
    };

    for (unsigned v = 0; v < sizeof(variants) / sizeof(variants[0]); v++) {
        const uint32_t words    = pbt_sys_info_words(variants[v].served);
        const uint32_t transfer = (SYS_FIRST_DATA_WORD + words) * 4u;

        pbt_begin();
        pbt_start();

        picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, transfer);
        pbt_args_get_info(&cmd, PB_INFO_SYS,
                          variants[v].served | variants[v].unserved);

        // Served, not refused.  A flag nobody answers is reported through the
        // flags word, and a request carrying one is still a request for the
        // flags beside it.
        pb_status_t got = pbt_run_cmd(&cmd);
        if (got != PB_STATUS_OK) {
            pbt_fail(__FILE__, __LINE__, "%s under 0x%04x: expected %s, got %s",
                     variants[v].what, variants[v].unserved,
                     pbt_status_name((int)PB_STATUS_OK),
                     pbt_status_name((int)got));
            continue;
        }

        if (pbt_payload_len() != transfer) {
            pbt_fail(__FILE__, __LINE__, "%s under 0x%04x: %u bytes for a "
                     "transfer of %u", variants[v].what, variants[v].unserved,
                     pbt_payload_len(), transfer);
            continue;
        }
        if (payload_word(0) != 1u + words) {
            pbt_fail(__FILE__, __LINE__, "%s under 0x%04x: count %u, expected "
                     "%u", variants[v].what, variants[v].unserved,
                     payload_word(0), 1u + words);
        }
        if (payload_word(1) != variants[v].served) {
            pbt_fail(__FILE__, __LINE__, "%s under 0x%04x: flags word "
                     "0x%08x, expected 0x%08x", variants[v].what,
                     variants[v].unserved, payload_word(1),
                     variants[v].served);
        }

        // The data runs to the last word of the transfer, so the answer fills
        // it rather than being followed by padding that would hide a word.
        uint32_t at = SYS_FIRST_DATA_WORD;
        for (unsigned i = 0; i < pbt_sys_flag_count(); i++) {
            const uint32_t flag = pbt_sys_flag_at(i);
            if ((variants[v].served & flag) == 0u) {
                continue;
            }
            for (uint32_t w = 0; w < pbt_sys_info_words(flag); w++) {
                uint32_t expected = pbt_sys_info_word(flag) + w;
                if (payload_word(at) != expected) {
                    pbt_fail(__FILE__, __LINE__, "%s under 0x%04x: word %u is "
                             "0x%08x, expected %s data word %u (0x%08x)",
                             variants[v].what, variants[v].unserved, at,
                             payload_word(at), pbt_sys_flag_name(flag), w,
                             expected);
                }
                at++;
            }
        }
        if (at * 4u != transfer) {
            pbt_fail(__FILE__, __LINE__, "%s under 0x%04x: the answer ends at "
                     "byte %u of a %u-byte transfer", variants[v].what,
                     variants[v].unserved, at * 4u, transfer);
        }

        // One word short of that same answer is refused, so serving the case
        // above was the transfer holding it and not the device serving
        // whatever it is asked for.  The unserved flag is no reason to hand
        // back less than was asked about.
        pbt_begin();
        pbt_start();

        picoboot_cmd_t tight = pbt_cmd(PB_CMD_GET_INFO, 0x10u, transfer - 4u);
        pbt_args_get_info(&tight, PB_INFO_SYS,
                          variants[v].served | variants[v].unserved);

        pb_status_t refused = pbt_run_cmd(&tight);
        if (refused != PB_STATUS_BUFFER_TOO_SMALL) {
            pbt_fail(__FILE__, __LINE__, "%s under 0x%04x in %u bytes: "
                     "expected %s, got %s", variants[v].what,
                     variants[v].unserved, transfer - 4u,
                     pbt_status_name((int)PB_STATUS_BUFFER_TOO_SMALL),
                     pbt_status_name((int)refused));
        }
        if (pbt_payload_len() != 0u || pbt_packet_count() != 0u) {
            pbt_fail(__FILE__, __LINE__, "%s under 0x%04x in %u bytes: %u "
                     "bytes in %u packets went out", variants[v].what,
                     variants[v].unserved, transfer - 4u, pbt_payload_len(),
                     pbt_packet_count());
        }
    }
}

static void scenario_get_info_sys_refuses_a_transfer_too_short(void) {
    // CHIP_INFO is three words of data, so the whole reply is the count, the
    // flags word and those three: twenty bytes.  Sixteen holds a word less than
    // that and eight a whole flag less, and neither is served.
    //
    // BUFFER_TOO_SMALL is the reason Table 471 gives for a buffer too small to
    // hold the result, and it is what get_sys_info itself reports for an
    // out_buffer_word_size that will not take the answer.  Sending part of the
    // response instead would leave the host holding a prefix it has no way to
    // measure.
    const struct {
        uint32_t    transfer;
        pb_status_t expected;
        uint32_t    payload;
    } cases[] = {
        { 20u, PB_STATUS_OK,               20u },
        { 16u, PB_STATUS_BUFFER_TOO_SMALL,  0u },
        {  8u, PB_STATUS_BUFFER_TOO_SMALL,  0u },
    };

    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        pbt_begin();
        pbt_start();

        picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u,
                                     cases[i].transfer);
        pbt_args_get_info(&cmd, PB_INFO_SYS, PBT_SYS_CHIP_INFO);

        pb_status_t got = pbt_run_cmd(&cmd);
        if (got != cases[i].expected) {
            pbt_fail(__FILE__, __LINE__, "CHIP_INFO in %u: expected %s, got %s",
                     cases[i].transfer, pbt_status_name((int)cases[i].expected),
                     pbt_status_name((int)got));
        }
        if (pbt_payload_len() != cases[i].payload) {
            pbt_fail(__FILE__, __LINE__, "CHIP_INFO in %u: %u bytes of "
                     "payload, expected %u", cases[i].transfer,
                     pbt_payload_len(), cases[i].payload);
        }
        if (cases[i].expected != PB_STATUS_OK) {
            // Refused whole, and the endpoints halted so the host looks the
            // reason up rather than reading a prefix.
            if (pbt_packet_count() != 0u) {
                pbt_fail(__FILE__, __LINE__, "CHIP_INFO in %u: %u packets went "
                         "out", cases[i].transfer, pbt_packet_count());
            }
            if (pbt_cur_state() != PB_STATE_STALLED) {
                pbt_fail(__FILE__, __LINE__, "CHIP_INFO in %u: state %s",
                         cases[i].transfer,
                         pbt_state_name(pbt_cur_state()));
            }
        }
    }

    // Two flags, and the same boundary one word further out: twenty-four bytes
    // holds CHIP_INFO and CPU_INFO exactly and twenty does not.  So the refusal
    // tracks the answer's length rather than sitting at a fixed size.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t tight = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&tight, PB_INFO_SYS,
                      PBT_SYS_CHIP_INFO | PBT_SYS_CPU_INFO);
    PBT_CHECK_STATUS(pbt_run_cmd(&tight), PB_STATUS_BUFFER_TOO_SMALL);

    pbt_begin();
    pbt_start();
    picoboot_cmd_t roomy = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 24u);
    pbt_args_get_info(&roomy, PB_INFO_SYS,
                      PBT_SYS_CHIP_INFO | PBT_SYS_CPU_INFO);
    PBT_CHECK_STATUS(pbt_run_cmd(&roomy), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_payload_len(), 24u);
    PBT_CHECK_EQ(payload_word(0), 5u);
    PBT_CHECK_EQ(payload_word(1), PBT_SYS_CHIP_INFO | PBT_SYS_CPU_INFO);
    PBT_CHECK_EQ(payload_word(5), pbt_sys_info_word(PBT_SYS_CPU_INFO));
}

// The data-in commands the harness can drive, for the property that none of
// them puts more on the wire than it was asked for.
typedef enum {
    DATA_IN_READ,
    DATA_IN_OTP_READ,
    DATA_IN_INFO_SYS,
    DATA_IN_INFO_PARTITION,
    DATA_IN_CUSTOM,
} data_in_kind_t;

static picoboot_cmd_t data_in_cmd(data_in_kind_t kind, uint32_t param,
                                  uint32_t transfer) {
    switch (kind) {
        case DATA_IN_READ: {
            picoboot_cmd_t cmd = pbt_cmd(PB_CMD_READ, 0x08u, transfer);
            pbt_args_addr_size(&cmd, RP2350_SRAM_BASE, transfer);
            return cmd;
        }
        case DATA_IN_OTP_READ: {
            picoboot_cmd_t cmd = pbt_cmd(PB_CMD_OTP_READ, 0x05u, transfer);
            pbt_args_otp(&cmd, 0u, (uint16_t)(transfer / 4u), 0u);
            return cmd;
        }
        case DATA_IN_INFO_PARTITION: {
            picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, transfer);
            pbt_args_get_info(&cmd, PB_INFO_PARTITION, param);
            return cmd;
        }
        case DATA_IN_CUSTOM:
            return pbt_custom_cmd((uint8_t)param, 0x00u, transfer);
        case DATA_IN_INFO_SYS:
        default: {
            picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, transfer);
            pbt_args_get_info(&cmd, PB_INFO_SYS, param);
            return cmd;
        }
    }
}

static void scenario_no_data_in_command_overruns_its_transfer(void) {
    // 5.6.4: "if dTransferLength is non-zero, then that many bytes are
    // transferred over the bulk pipe and the command is completed with an empty
    // packet in the opposite direction."  That many bytes, and no more.  A host
    // reads dTransferLength and then reads the completion, so anything beyond
    // the length it asked for arrives where it is looking for the empty packet.
    //
    // Each case is a data-in command whose answer is longer than the transfer
    // it was given, or one of the same shape whose answer fits.  Whatever the
    // command decides to do about the shortfall, what reaches the host is
    // bounded by what the host asked for.
    const struct {
        const char    *what;
        data_in_kind_t kind;
        uint32_t       param;
        uint32_t       transfer;
        pb_status_t    expected;
        uint32_t       payload;
    } cases[] = {
        // Both of these derive their length from their own arguments and
        // insist the two agree, so they are here as the commands that have
        // never had a shortfall to get wrong.
        { "READ of 32", DATA_IN_READ, 0u, 32u, PB_STATUS_OK, 32u },
        { "OTP_READ of four rows", DATA_IN_OTP_READ, 0u, 16u, PB_STATUS_OK,
          16u },

        // CHIP_INFO is twenty bytes of response.  Eight and twelve cannot hold
        // it and twenty exactly can.
        { "SYS CHIP_INFO in 8", DATA_IN_INFO_SYS, PBT_SYS_CHIP_INFO, 8u,
          PB_STATUS_BUFFER_TOO_SMALL, 0u },
        { "SYS CHIP_INFO in 12", DATA_IN_INFO_SYS, PBT_SYS_CHIP_INFO, 12u,
          PB_STATUS_BUFFER_TOO_SMALL, 0u },
        { "SYS CHIP_INFO in 20", DATA_IN_INFO_SYS, PBT_SYS_CHIP_INFO, 20u,
          PB_STATUS_OK, 20u },

        // BOOT_INFO is twenty-four, so eight bytes falls short by a whole
        // flag rather than by part of one.
        { "SYS BOOT_INFO in 8", DATA_IN_INFO_SYS, PBT_SYS_BOOT_INFO, 8u,
          PB_STATUS_BUFFER_TOO_SMALL, 0u },

        // PT_INFO is twenty bytes of response — the count, the flags word and
        // its three.  Eight falls short by two words and sixteen by one.
        { "PARTITION PT_INFO in 8", DATA_IN_INFO_PARTITION, PBT_PART_PT_INFO,
          8u, PB_STATUS_BUFFER_TOO_SMALL, 0u },
        { "PARTITION PT_INFO in 16", DATA_IN_INFO_PARTITION, PBT_PART_PT_INFO,
          16u, PB_STATUS_BUFFER_TOO_SMALL, 0u },
        { "PARTITION PT_INFO in 20", DATA_IN_INFO_PARTITION, PBT_PART_PT_INFO,
          20u, PB_STATUS_OK, 20u },

        // An integrator's fill producing items it cannot split, in a transfer
        // that is not a whole number of them.
        { "custom items in 32", DATA_IN_CUSTOM, PBT_CUSTOM_CMD_ITEMS, 32u,
          PB_STATUS_BUFFER_TOO_SMALL, 0u },
        { "custom items in 56", DATA_IN_CUSTOM, PBT_CUSTOM_CMD_ITEMS, 56u,
          PB_STATUS_BUFFER_TOO_SMALL, 0u },
        { "custom items in 48", DATA_IN_CUSTOM, PBT_CUSTOM_CMD_ITEMS, 48u,
          PB_STATUS_OK, 48u },

        // A fill that produces whatever it is given room for has no shortfall
        // to meet, at a length that is not a whole number of packets.
        { "custom bytes in 70", DATA_IN_CUSTOM, PBT_CUSTOM_CMD_COUNT, 70u,
          PB_STATUS_OK, 70u },
    };

    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        pbt_begin();
        pbt_use_custom = true;
        pbt_start();

        picoboot_cmd_t cmd = data_in_cmd(cases[i].kind, cases[i].param,
                                         cases[i].transfer);
        pb_status_t got = pbt_run_cmd(&cmd);

        // The property, checked for every case whatever it answered.
        if (pbt_payload_len() > cases[i].transfer) {
            pbt_fail(__FILE__, __LINE__, "%s: %u bytes went to a host that "
                     "asked for %u", cases[i].what, pbt_payload_len(),
                     cases[i].transfer);
        }
        if (got != cases[i].expected) {
            pbt_fail(__FILE__, __LINE__, "%s: expected %s, got %s",
                     cases[i].what, pbt_status_name((int)cases[i].expected),
                     pbt_status_name((int)got));
        }
        if (pbt_payload_len() != cases[i].payload) {
            pbt_fail(__FILE__, __LINE__, "%s: %u bytes of payload, expected %u",
                     cases[i].what, pbt_payload_len(), cases[i].payload);
        }
    }
}

static void scenario_get_info_sys_with_no_flags_sends_an_empty_flags_word(void) {
    pbt_begin();
    pbt_start();

    // A request for no flags is still a get_sys_info buffer, and that buffer
    // always starts with the flags word.  So one significant word follows the
    // count, and it is zero: nothing was asked for and nothing was answered.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 12u);
    pbt_args_get_info(&cmd, PB_INFO_SYS, 0u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);

    // The whole transfer length comes back, padded, as it does for a request
    // that had something to say.
    PBT_CHECK_EQ(pbt_payload_len(), 12u);
    PBT_CHECK_EQ(payload_word(0), 1u);
    PBT_CHECK(payload_has_word(1u));
    PBT_CHECK_EQ(payload_word(1), 0u);
    PBT_CHECK(payload_has_word(2u));
    PBT_CHECK_EQ(payload_word(2), 0u);
    PBT_CHECK_EQ(pbt_packet_count(), 1u);

    // One flag in a transfer of the same length fills it, so the count of one
    // above was the empty request and not the length.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t one = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 12u);
    pbt_args_get_info(&one, PB_INFO_SYS, PBT_SYS_CPU_INFO);
    PBT_CHECK_STATUS(pbt_run_cmd(&one), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_payload_len(), 12u);
    PBT_CHECK_EQ(payload_word(0), 2u);
    PBT_CHECK_EQ(payload_word(1), PBT_SYS_CPU_INFO);
    PBT_CHECK_EQ(payload_word(2), pbt_sys_info_word(PBT_SYS_CPU_INFO));
}

static void scenario_get_info_sys_no_flags_in_a_header_sized_transfer(void) {
    pbt_begin();
    pbt_start();

    // A request for no flags at all, in a transfer holding the count and the
    // flags word and nothing else.  5.6.4.11's padding rule has nothing to pad,
    // so every byte a host reads here is part of the response itself.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 8u);
    pbt_args_get_info(&cmd, PB_INFO_SYS, 0u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_payload_len(), 8u);

    // One significant word follows the count, and it is the flags word: nothing
    // was asked for, so nothing was answered.
    PBT_CHECK_EQ(payload_word(0), 1u);
    PBT_CHECK(payload_has_word(1u));
    PBT_CHECK_EQ(payload_word(1), 0u);

    // The count word plus the words it counts is the whole payload, which is
    // what says the eight bytes are those two words rather than a shorter
    // answer with padding behind it.
    PBT_CHECK_EQ((1u + payload_word(0)) * 4u, pbt_payload_len());

    PBT_CHECK_EQ(pbt_packet_count(), 1u);

    // Four bytes holds the count and not the flags word, so even a request that
    // asks for nothing has an eight-byte answer and is refused below it.  That
    // is the same boundary every other INFO_SYS request is held to.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t tight = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 4u);
    pbt_args_get_info(&tight, PB_INFO_SYS, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&tight), PB_STATUS_BUFFER_TOO_SMALL);
    PBT_CHECK_EQ(pbt_payload_len(), 0u);
    PBT_CHECK_EQ(pbt_packet_count(), 0u);
}

static void scenario_get_info_sys_with_only_unserved_flags(void) {
    pbt_begin();
    pbt_start();

    // What a request naming no flags answers, kept so the answer to a request
    // naming only flags nobody serves can be held against it byte for byte.
    picoboot_cmd_t none = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 8u);
    pbt_args_get_info(&none, PB_INFO_SYS, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&none), PB_STATUS_OK);

    uint8_t  empty[8];
    uint32_t empty_len = pbt_payload_len();
    memset(empty, 0xAA, sizeof(empty));
    if (empty_len <= sizeof(empty)) {
        memcpy(empty, pbt_payload(), empty_len);
    }

    pbt_begin();
    pbt_start();

    // NONCE is defined and unsupported, and 0x0080 is above every flag 5.4.8.17
    // names.  Between them they are the whole of the request and none of it can
    // be answered.  The flags word is the subset supported, and here that
    // subset is empty.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 8u);
    pbt_args_get_info(&cmd, PB_INFO_SYS, PBT_SYS_NONCE | 0x0080u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_payload_len(), 8u);
    PBT_CHECK_EQ(payload_word(0), 1u);
    PBT_CHECK(payload_has_word(1u));
    PBT_CHECK_EQ(payload_word(1), 0u);
    PBT_CHECK_EQ((1u + payload_word(0)) * 4u, pbt_payload_len());

    // And the same bytes as asking for nothing at all.
    PBT_CHECK_EQ(pbt_payload_len(), empty_len);
    if (pbt_payload_len() == empty_len && empty_len <= sizeof(empty)) {
        PBT_CHECK_EQ(memcmp(empty, pbt_payload(), empty_len), 0);
    }

    // Four bytes cannot hold that answer either, so a request nobody can serve
    // is held to the same eight-byte minimum as one that is served.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t tight = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 4u);
    pbt_args_get_info(&tight, PB_INFO_SYS, PBT_SYS_NONCE | 0x0080u);
    PBT_CHECK_STATUS(pbt_run_cmd(&tight), PB_STATUS_BUFFER_TOO_SMALL);
    PBT_CHECK_EQ(pbt_payload_len(), 0u);
    PBT_CHECK_EQ(pbt_packet_count(), 0u);
}

// A device with nothing to say about the request.  picobootx.h: "Reporting none
// is a valid answer, and sends a count of zero."  The two default
// implementations never report none — a get_sys_info or
// get_partition_table_info buffer always starts with its flags word — so this
// is a device an integrator writes.
static pb_status_t op_prepare_no_words(pb_info_type_t type, uint32_t param0,
                                       uint32_t *words, void *ctx) {
    (void)ctx;
    *words = 0u;
    pbt_log("op_get_info_prepare", type, param0, *words, PB_STATUS_OK);
    return PB_STATUS_OK;
}

static void scenario_get_info_answers_nothing_in_one_word(void) {
    pbt_begin();
    pbt_ops.get_info_prepare = op_prepare_no_words;
    pbt_start();

    // 5.6.4.11: "The fist word returned indicates the number of significant
    // words of data that follow."  None follow, so the count is zero and the
    // reply is that one word.  Four bytes holds it exactly, and the padding
    // rule has nothing to pad.
    //
    // The fill is left as the default, which would go to the chip and produce a
    // flag's worth of data if it were asked.  So a reply longer than four bytes
    // here is not a rounding error, it is the library asking for an answer the
    // device said it did not have.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 4u);
    pbt_args_get_info(&cmd, PB_INFO_SYS, PBT_SYS_CHIP_INFO);

    // Driven a step at a time rather than through pbt_run_cmd, so the state
    // between the data phase and the completion is visible.
    pbt_host_send_cmd(&cmd);
    pbt_pump();

    // 5.6.4: "the command is completed with an empty packet in the opposite
    // direction."  The device has sent its one word and is waiting for that
    // packet, which is what says it finished rather than stopped.
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_AWAIT_ACK);
    PBT_CHECK_EQ(pbt_payload_len(), 4u);
    pbt_host_ack();
    pbt_pump();

    picoboot_status_t st;
    PBT_REQUIRE(pbt_ctrl_get_status(&st));
    PBT_CHECK_STATUS((pb_status_t)st.status_code, PB_STATUS_OK);
    PBT_CHECK_EQ(st.in_progress, 0u);
    PBT_CHECK_EQ(pbt_payload_len(), 4u);
    PBT_CHECK(payload_has_word(0u));
    PBT_CHECK_EQ(payload_word(0), 0u);

    // One word and no more.  payload_word answers zero for a word that is not
    // there, so the count being zero says nothing on its own — that the reply
    // stops after it is what says the answer was empty rather than absent.
    PBT_CHECK(!payload_has_word(1u));
    PBT_CHECK_EQ(pbt_packet_count(), 1u);

    // The device was asked how long its answer would be, said none, and was
    // never asked to produce any of it.
    PBT_CHECK_EQ(pbt_count("op_get_info_prepare"), 1);
    PBT_REQUIRE(pbt_nth("op_get_info_prepare", 0) != NULL);
    PBT_CHECK_EQ(pbt_nth("op_get_info_prepare", 0)->a2, 0u);
    PBT_CHECK_EQ(pbt_count("op_get_info"), 0);

    // And back to idle with both endpoints running, ready for the next
    // command, so a device that answers nothing leaves nothing behind.
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_IDLE);
    PBT_CHECK(!pbt_ep_stalled(PBT_EP_IN));
    PBT_CHECK(!pbt_ep_stalled(PBT_EP_OUT));

    // The same empty answer in a longer transfer is padded, so the four bytes
    // above were the transfer length and not a device that stops early.
    pbt_begin();
    pbt_ops.get_info_prepare = op_prepare_no_words;
    pbt_start();
    picoboot_cmd_t roomy = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 16u);
    pbt_args_get_info(&roomy, PB_INFO_SYS, PBT_SYS_CHIP_INFO);
    PBT_CHECK_STATUS(pbt_run_cmd(&roomy), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_payload_len(), 16u);
    PBT_CHECK_EQ(payload_word(0), 0u);
    for (uint32_t i = 1u; i < 4u; i++) {
        PBT_CHECK(payload_has_word(i));
        PBT_CHECK_EQ(payload_word(i), 0u);
    }
    PBT_CHECK_EQ(pbt_count("op_get_info"), 0);

    // A device with one word to say does not fit that four-byte transfer, so
    // four bytes was accepted because the answer was empty and not because four
    // is a length GET_INFO always takes.  The same request, the same length,
    // one word of difference.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t one = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 4u);
    pbt_args_get_info(&one, PB_INFO_SYS, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&one), PB_STATUS_BUFFER_TOO_SMALL);
    PBT_CHECK_EQ(pbt_packet_count(), 0u);
}

// ---------------------------------------------------------------------------
// Callbacks that do not keep to the contract
//
// picobootx.h states what get_info_prepare and get_info may do, and what the
// library does with one that goes past it.  Each of these is an integrator's
// callback breaking one clause, and the request they are given is one the
// default implementations answer, so putting the default back is what shows the
// refusal was the callback's doing.
// ---------------------------------------------------------------------------

// "Reporting more than PICOBOOT_INFO_MAX_ANSWER_WORDS halts the command with
// PB_STATUS_UNKNOWN_ERROR."
static pb_status_t op_prepare_too_many_words(pb_info_type_t type,
                                             uint32_t param0, uint32_t *words,
                                             void *ctx) {
    (void)type;
    (void)param0;
    (void)ctx;
    *words = PICOBOOT_INFO_MAX_ANSWER_WORDS + 1u;
    pbt_log("op_get_info_prepare", type, param0, *words, PB_STATUS_OK);
    return PB_STATUS_OK;
}

// The same, one word inside the limit, so the refusal above can be shown to be
// the word count and not the callback being the harness's.
static pb_status_t op_prepare_the_most_words(pb_info_type_t type,
                                             uint32_t param0, uint32_t *words,
                                             void *ctx) {
    (void)type;
    (void)param0;
    (void)ctx;
    *words = PICOBOOT_INFO_MAX_ANSWER_WORDS;
    pbt_log("op_get_info_prepare", type, param0, *words, PB_STATUS_OK);
    return PB_STATUS_OK;
}

// Fills what it was offered and says so, so the pair above can be driven to
// completion.  The words are recognisable, and different from every other
// value the harness produces.
static pb_status_t op_get_info_counting(pb_info_type_t type, uint32_t param0,
                                        uint32_t at_word, uint8_t *buf,
                                        uint32_t max_len,
                                        uint32_t *bytes_written, void *ctx) {
    (void)param0;
    (void)ctx;
    pbt_log("op_get_info", type, param0, at_word, max_len);

    uint32_t words = max_len / 4u;
    for (uint32_t i = 0; i < words; i++) {
        uint32_t value = 0x53000000u | (at_word + i);
        memcpy(buf + (i * 4u), &value, sizeof(value));
    }
    *bytes_written = words * 4u;
    return PB_STATUS_OK;
}

// "Writing more than max_len ... halts the command with
// PB_STATUS_UNKNOWN_ERROR and none of those bytes reaches the host."  It writes
// only what it was given room for: a callback that really wrote past the buffer
// would be corrupting the library's memory, which no library can defend
// against.  The number it reports is the only thing that can be checked.
static pb_status_t op_get_info_overstating(pb_info_type_t type, uint32_t param0,
                                           uint32_t at_word, uint8_t *buf,
                                           uint32_t max_len,
                                           uint32_t *bytes_written, void *ctx) {
    pb_status_t st = op_get_info_counting(type, param0, at_word, buf, max_len,
                                          bytes_written, ctx);
    *bytes_written = max_len + 4u;
    return st;
}

// "... or a count that is not a whole number of words, halts the command with
// PB_STATUS_UNKNOWN_ERROR".
static pb_status_t op_get_info_part_word(pb_info_type_t type, uint32_t param0,
                                         uint32_t at_word, uint8_t *buf,
                                         uint32_t max_len,
                                         uint32_t *bytes_written, void *ctx) {
    pb_status_t st = op_get_info_counting(type, param0, at_word, buf, max_len,
                                          bytes_written, ctx);
    *bytes_written = max_len - 1u;
    return st;
}

// A prepare that refuses the request outright, with a status no other path in
// the suite produces, so a scenario asserting it cannot pass by coincidence.
#define REFUSE_PREPARE_STATUS PB_STATUS_INVALID_DATA
#define REFUSE_FILL_STATUS    PB_STATUS_NOT_PERMITTED

static pb_status_t op_prepare_refusing(pb_info_type_t type, uint32_t param0,
                                       uint32_t *words, void *ctx) {
    (void)words;
    (void)ctx;
    pbt_log("op_get_info_prepare", type, param0, 0u, REFUSE_PREPARE_STATUS);
    return REFUSE_PREPARE_STATUS;
}

static pb_status_t op_get_info_refusing(pb_info_type_t type, uint32_t param0,
                                        uint32_t at_word, uint8_t *buf,
                                        uint32_t max_len,
                                        uint32_t *bytes_written, void *ctx) {
    (void)buf;
    (void)bytes_written;
    (void)ctx;
    pbt_log("op_get_info", type, param0, at_word, max_len);
    return REFUSE_FILL_STATUS;
}

static void scenario_get_info_prepare_reporting_too_many_words_is_refused(void) {
    pbt_begin();
    pbt_ops.get_info_prepare = op_prepare_too_many_words;
    pbt_ops.get_info         = op_get_info_counting;
    pbt_start();

    // The transfer is the longest GET_INFO takes, so what is refused is the
    // count the callback reported and not the room the host offered.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u,
                                 PICOBOOT_GET_INFO_MAX_LEN);
    pbt_args_get_info(&cmd, PB_INFO_SYS, PBT_SYS_CPU_INFO);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_UNKNOWN_ERROR);
    PBT_CHECK_EQ(pbt_count("op_get_info_prepare"), 1);

    // Refused before anything was produced, so the host is not handed the
    // beginning of an answer that has no end.
    PBT_CHECK_EQ(pbt_count("op_get_info"), 0);
    PBT_CHECK_EQ(pbt_packet_count(), 0u);
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_STALLED);

    // One word fewer is the most an answer may be, and it is served — so what
    // was refused was the word past the limit.
    pbt_begin();
    pbt_ops.get_info_prepare = op_prepare_the_most_words;
    pbt_ops.get_info         = op_get_info_counting;
    pbt_start();
    picoboot_cmd_t most = pbt_cmd(PB_CMD_GET_INFO, 0x10u,
                                  PICOBOOT_GET_INFO_MAX_LEN);
    pbt_args_get_info(&most, PB_INFO_SYS, PBT_SYS_CPU_INFO);
    PBT_CHECK_STATUS(pbt_run_cmd(&most), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_payload_len(), PICOBOOT_GET_INFO_MAX_LEN);
    PBT_CHECK_EQ(payload_word(0), PICOBOOT_INFO_MAX_ANSWER_WORDS);
    PBT_CHECK_EQ(payload_word(1), 0x53000000u);
    PBT_CHECK_EQ(payload_word(PICOBOOT_INFO_MAX_ANSWER_WORDS),
                 0x53000000u | (PICOBOOT_INFO_MAX_ANSWER_WORDS - 1u));
}

static void scenario_a_get_info_that_fills_the_wrong_amount_is_refused(void) {
    const struct {
        const char *what;
        pb_status_t (*fill)(pb_info_type_t, uint32_t, uint32_t, uint8_t *,
                            uint32_t, uint32_t *, void *);
    } cases[] = {
        { "more than it was offered", op_get_info_overstating },
        { "a part word",              op_get_info_part_word },
    };

    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        pbt_begin();
        pbt_ops.get_info = cases[i].fill;
        pbt_start();

        // Twenty bytes is the whole of a CHIP_INFO response, so the callback is
        // reached with the whole of the answer to produce.
        picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
        pbt_args_get_info(&cmd, PB_INFO_SYS, PBT_SYS_CHIP_INFO);

        pb_status_t got = pbt_run_cmd(&cmd);
        if (got != PB_STATUS_UNKNOWN_ERROR) {
            pbt_fail(__FILE__, __LINE__, "%s: expected %s, got %s",
                     cases[i].what,
                     pbt_status_name((int)PB_STATUS_UNKNOWN_ERROR),
                     pbt_status_name((int)got));
        }
        if (pbt_count("op_get_info") < 1) {
            pbt_fail(__FILE__, __LINE__, "%s: the callback was never reached",
                     cases[i].what);
        }
        // The leading count had been produced and is discarded with the rest,
        // so the host is not handed the beginning of an answer that has no end.
        if (pbt_packet_count() != 0u) {
            pbt_fail(__FILE__, __LINE__, "%s: %u packets went to the host",
                     cases[i].what, pbt_packet_count());
        }
        if (pbt_cur_state() != PB_STATE_STALLED) {
            pbt_fail(__FILE__, __LINE__, "%s: state %s", cases[i].what,
                     pbt_state_name(pbt_cur_state()));
        }
    }

    // The same request against a callback that fills what it says it filled is
    // answered, so what was refused was the disagreement.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t again = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&again, PB_INFO_SYS, PBT_SYS_CHIP_INFO);
    PBT_CHECK_STATUS(pbt_run_cmd(&again), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_payload_len(), 20u);
    PBT_CHECK_EQ(payload_word(0), 4u);
    PBT_CHECK_EQ(payload_word(1), PBT_SYS_CHIP_INFO);
}

static void scenario_a_get_info_callback_that_refuses_carries_its_status(void) {
    // picobootx.h: "The library halts the command on a non-PB_STATUS_OK return
    // from either, with that status, and the host reads it back with
    // GET_COMMAND_STATUS."
    pbt_begin();
    pbt_ops.get_info_prepare = op_prepare_refusing;
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&cmd, PB_INFO_SYS, PBT_SYS_CHIP_INFO);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), REFUSE_PREPARE_STATUS);
    PBT_CHECK_EQ(pbt_count("op_get_info_prepare"), 1);

    // A prepare that refused is never asked to produce anything.
    PBT_CHECK_EQ(pbt_count("op_get_info"), 0);
    PBT_CHECK_EQ(pbt_packet_count(), 0u);

    // A refusal from the other half is reported as itself too, which is what
    // says the status is the callback's and not a fixed one for GET_INFO.
    pbt_begin();
    pbt_ops.get_info = op_get_info_refusing;
    pbt_start();
    picoboot_cmd_t fill = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&fill, PB_INFO_SYS, PBT_SYS_CHIP_INFO);
    PBT_CHECK_STATUS(pbt_run_cmd(&fill), REFUSE_FILL_STATUS);
    PBT_CHECK_EQ(pbt_count("op_get_info_prepare"), 1);
    PBT_CHECK_EQ(pbt_count("op_get_info"), 1);
    PBT_CHECK_EQ(pbt_packet_count(), 0u);

    // With both defaults back the same request is served.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t good = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&good, PB_INFO_SYS, PBT_SYS_CHIP_INFO);
    PBT_CHECK_STATUS(pbt_run_cmd(&good), PB_STATUS_OK);
}

// ---------------------------------------------------------------------------
// PARTITION
// ---------------------------------------------------------------------------

static void scenario_get_info_partition_sends_a_count_flags_then_the_data(void) {
    // The words a part with no partition table answers with.  PT_INFO's first
    // word carries the partition count in its low eight bits and whether a
    // table is present in bit 8, so an empty table is zero, and the two words
    // after it are unpartitioned space's, which 5.4.8.16's note fixes at a base
    // of 0 and a size of 0x2000 sectors.
    const struct {
        const char *what;
        uint32_t    param0;
        uint32_t    transfer;
        uint32_t    count;      // the leading word
        uint32_t    flags;      // the flags word
        uint32_t    words[3];   // the data behind it
        uint32_t    data_words;
    } cases[] = {
        { "PT_INFO, LOCATION_AND_FLAGS and PARTITION_ID",
          PBT_PART_PT_INFO | PBT_PART_LOC_FLAGS | PBT_PART_ID, 64u,
          4u, 0x0031u,
          { 0u, PBT_PT_UNPARTITIONED_LOCATION, PBT_PT_UNPARTITIONED_FLAGS },
          3u },

        // PT_INFO alone answers the same three words, so the two per-partition
        // flags above contributed none of them.
        { "PT_INFO alone", PBT_PART_PT_INFO, 32u,
          4u, PBT_PART_PT_INFO,
          { 0u, PBT_PT_UNPARTITIONED_LOCATION, PBT_PT_UNPARTITIONED_FLAGS },
          3u },

        // A per-partition flag on its own against a table with no partitions.
        // The flag is supported, so it is in the flags word, and there is no
        // partition for it to speak about, so it brings no data — the flags
        // word is the whole of the answer.
        { "LOCATION_AND_FLAGS alone", PBT_PART_LOC_FLAGS, 32u,
          1u, PBT_PART_LOC_FLAGS, { 0u, 0u, 0u }, 0u },

        // No flags at all is still a get_partition_table_info buffer, and that
        // buffer starts with the flags word.
        { "no flags", 0u, 32u, 1u, 0u, { 0u, 0u, 0u }, 0u },
    };

    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        pbt_begin();
        pbt_start();

        picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u,
                                     cases[i].transfer);
        pbt_args_get_info(&cmd, PB_INFO_PARTITION, cases[i].param0);

        pb_status_t got = pbt_run_cmd(&cmd);
        if (got != PB_STATUS_OK) {
            pbt_fail(__FILE__, __LINE__, "%s: %s", cases[i].what,
                     pbt_status_name((int)got));
            continue;
        }
        if (pbt_payload_len() != cases[i].transfer) {
            pbt_fail(__FILE__, __LINE__, "%s: %u bytes for a transfer of %u",
                     cases[i].what, pbt_payload_len(), cases[i].transfer);
            continue;
        }
        if (payload_word(0) != cases[i].count) {
            pbt_fail(__FILE__, __LINE__, "%s: count %u, expected %u",
                     cases[i].what, payload_word(0), cases[i].count);
        }
        if (!payload_has_word(1u) || payload_word(1) != cases[i].flags) {
            pbt_fail(__FILE__, __LINE__, "%s: flags word 0x%08x, expected "
                     "0x%08x", cases[i].what, payload_word(1),
                     cases[i].flags);
        }
        for (uint32_t w = 0; w < cases[i].data_words; w++) {
            if (payload_word(SYS_FIRST_DATA_WORD + w) != cases[i].words[w]) {
                pbt_fail(__FILE__, __LINE__, "%s: data word %u is 0x%08x, "
                         "expected 0x%08x", cases[i].what, w,
                         payload_word(SYS_FIRST_DATA_WORD + w),
                         cases[i].words[w]);
            }
        }

        // Everything past the answer is the padding rule's, and it is there
        // rather than the transfer having stopped short.
        for (uint32_t w = 1u + cases[i].count; w * 4u < cases[i].transfer; w++) {
            if (!payload_has_word(w)) {
                pbt_fail(__FILE__, __LINE__, "%s: no word %u in a %u-byte "
                         "transfer", cases[i].what, w, cases[i].transfer);
                break;
            }
            if (payload_word(w) != 0u) {
                pbt_fail(__FILE__, __LINE__, "%s: padding word %u is 0x%08x",
                         cases[i].what, w, payload_word(w));
            }
        }

        // The partition type goes to its own callback, and it is the same pair
        // every other type goes through.
        if (pbt_count("op_get_info_prepare") != 1) {
            pbt_fail(__FILE__, __LINE__, "%s: %d prepare calls", cases[i].what,
                     pbt_count("op_get_info_prepare"));
        }
    }
}

static void scenario_get_info_partition_answers_each_partition_in_turn(void) {
    // 5.4.8.16: "With the exception of PT_INFO, all the flags select 'per
    // partition' information, so each field is returned in flag order for one
    // partition after the next."  So the partitions are the outer run and the
    // flags the inner one, and a device that grouped by flag instead puts a
    // different value at every position but the first.
    pbt_begin();
    pbt_set_partitions(3u);
    pbt_start();

    const uint32_t param0 = PBT_PART_PT_INFO | PBT_PART_LOC_FLAGS |
                            PBT_PART_ID;

    // Three words for PT_INFO, then four per partition.
    const uint32_t data_words = 3u + (3u * 4u);
    const uint32_t transfer   = (SYS_FIRST_DATA_WORD + data_words) * 4u;

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, transfer);
    pbt_args_get_info(&cmd, PB_INFO_PARTITION, param0);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == transfer);

    PBT_CHECK_EQ(payload_word(0), 1u + data_words);
    PBT_CHECK_EQ(payload_word(1), param0);

    // PT_INFO now reports three partitions and a table present.
    PBT_CHECK_EQ(payload_word(2), 3u | 0x100u);
    PBT_CHECK_EQ(payload_word(3), PBT_PT_UNPARTITIONED_LOCATION);
    PBT_CHECK_EQ(payload_word(4), PBT_PT_UNPARTITIONED_FLAGS);

    uint32_t at = 5u;
    for (unsigned p = 0; p < 3u; p++) {
        for (uint32_t w = 0; w < 2u; w++) {
            uint32_t expected = pbt_partition_word(p, PBT_PART_LOC_FLAGS) + w;
            if (payload_word(at) != expected) {
                pbt_fail(__FILE__, __LINE__, "word %u: expected partition %u "
                         "location word %u (0x%08x), got 0x%08x", at, p, w,
                         expected, payload_word(at));
            }
            at++;
        }
        for (uint32_t w = 0; w < 2u; w++) {
            uint32_t expected = pbt_partition_word(p, PBT_PART_ID) + w;
            if (payload_word(at) != expected) {
                pbt_fail(__FILE__, __LINE__, "word %u: expected partition %u "
                         "id word %u (0x%08x), got 0x%08x", at, p, w, expected,
                         payload_word(at));
            }
            at++;
        }
    }
    PBT_CHECK_EQ(at * 4u, transfer);

    // 5.4.8.16: "The special SINGLE_PARTITION flag indicates that data for only
    // a single partition is required ... the partition number is stored in the
    // top 8 bits of flags_and_partition."  So the same request narrowed to
    // partition 1 answers that partition's four words and nobody else's.
    pbt_begin();
    pbt_set_partitions(3u);
    pbt_start();

    const uint32_t single = PBT_PART_LOC_FLAGS | PBT_PART_ID |
                            PBT_PART_SINGLE | (1u << 24);
    picoboot_cmd_t one = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 24u);
    pbt_args_get_info(&one, PB_INFO_PARTITION, single);

    PBT_CHECK_STATUS(pbt_run_cmd(&one), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 24u);
    PBT_CHECK_EQ(payload_word(0), 5u);
    PBT_CHECK_EQ(payload_word(1),
                 PBT_PART_LOC_FLAGS | PBT_PART_ID | PBT_PART_SINGLE);
    PBT_CHECK_EQ(payload_word(2), pbt_partition_word(1u, PBT_PART_LOC_FLAGS));
    PBT_CHECK_EQ(payload_word(3),
                 pbt_partition_word(1u, PBT_PART_LOC_FLAGS) + 1u);
    PBT_CHECK_EQ(payload_word(4), pbt_partition_word(1u, PBT_PART_ID));
    PBT_CHECK_EQ(payload_word(5), pbt_partition_word(1u, PBT_PART_ID) + 1u);
}

static void scenario_get_info_partition_drops_a_flag_it_does_not_answer(void) {
    // The same rule as INFO_SYS's flags word, on the routine 5.4.8.16
    // describes: "the first word in the returned buffer, is the (sub)set of
    // those flags that the API supports".  0x0200 is outside the flags that
    // section defines, so no part answers it.
    pbt_begin();
    pbt_set_partitions(1u);
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&cmd, PB_INFO_PARTITION,
                      PBT_PART_LOC_FLAGS | 0x0200u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 20u);
    PBT_CHECK_EQ(payload_word(0), 3u);
    PBT_CHECK_EQ(payload_word(1), PBT_PART_LOC_FLAGS);
    PBT_CHECK_EQ(payload_word(2), pbt_partition_word(0u, PBT_PART_LOC_FLAGS));
    PBT_CHECK_EQ(payload_word(3),
                 pbt_partition_word(0u, PBT_PART_LOC_FLAGS) + 1u);
    PBT_CHECK(payload_has_word(4u));
    PBT_CHECK_EQ(payload_word(4), 0u);

    // A flag the part does answer, in place of the one it does not, brings its
    // data with it — so what kept 0x0200 out was the part not answering it.
    pbt_begin();
    pbt_set_partitions(1u);
    pbt_start();
    picoboot_cmd_t both = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 28u);
    pbt_args_get_info(&both, PB_INFO_PARTITION,
                      PBT_PART_LOC_FLAGS | PBT_PART_ID);
    PBT_CHECK_STATUS(pbt_run_cmd(&both), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 28u);
    PBT_CHECK_EQ(payload_word(0), 5u);
    PBT_CHECK_EQ(payload_word(1), PBT_PART_LOC_FLAGS | PBT_PART_ID);
    PBT_CHECK_EQ(payload_word(4), pbt_partition_word(0u, PBT_PART_ID));

    // And a flag this particular part does not answer, which a part with a
    // newer routine would.  It is the same request as the one just served, with
    // only what the part supports changed, so PARTITION_ID's two words go and
    // nothing else moves.
    pbt_begin();
    pbt_set_partitions(1u);
    pbt_set_partition_supported(PBT_PART_PT_INFO | PBT_PART_LOC_FLAGS);
    pbt_start();
    picoboot_cmd_t withheld = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 28u);
    pbt_args_get_info(&withheld, PB_INFO_PARTITION,
                      PBT_PART_LOC_FLAGS | PBT_PART_ID);
    PBT_CHECK_STATUS(pbt_run_cmd(&withheld), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 28u);
    PBT_CHECK_EQ(payload_word(0), 3u);
    PBT_CHECK_EQ(payload_word(1), PBT_PART_LOC_FLAGS);
    PBT_CHECK_EQ(payload_word(2), pbt_partition_word(0u, PBT_PART_LOC_FLAGS));
    PBT_CHECK_EQ(payload_word(3),
                 pbt_partition_word(0u, PBT_PART_LOC_FLAGS) + 1u);
    PBT_CHECK(payload_has_word(4u));
    PBT_CHECK_EQ(payload_word(4), 0u);
}

// ---------------------------------------------------------------------------
// UF2_TARGET, as the RP2350 defaults answer it
//
// picobootx.h: "Served, as nowhere.  A UF2 reaches a device by being dragged
// onto a mass storage drive, and picobootx has none and is told of none, so it
// has nowhere to name.  The answer is a target of -1 with the unpartitioned
// space beside it, which get_partition_table_info reports."
//
// 5.6.4.11 gives the words: "Word 0 : Target partition number", of which "-1 :
// if there is nowhere to download the family", and words 1 and 2 the target
// partition's own two words "if the partition number is not -1".  So the target
// is the whole of the answer's meaning here, and the two words behind it are
// what the partition table reports for unpartitioned space.
//
// 5.5.3's rule about where an rp2350-arm-s family lands describes the bootrom's
// drive.  The default names no drive at all, so no family id can change the
// answer, and that is asserted by comparing the answers to different families
// rather than by asserting one of them twice.
// ---------------------------------------------------------------------------

static void scenario_get_info_uf2_target_has_nowhere_to_put_a_family(void) {
    pbt_begin();
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 32u);
    pbt_args_get_info(&cmd, PB_INFO_UF2_TARGET, 0u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 32u);

    // Three significant words behind the count, and no flags word: 5.6.4.11
    // defines these words directly, so the first of them is payload word 1.
    PBT_CHECK_EQ(payload_word(0), 3u);
    PBT_CHECK_EQ(payload_word(1), 0xFFFFFFFFu);
    PBT_CHECK_EQ(payload_word(2), PBT_PT_UNPARTITIONED_LOCATION);
    PBT_CHECK_EQ(payload_word(3), PBT_PT_UNPARTITIONED_FLAGS);

    // Then the padding rule, and it is there rather than the transfer having
    // stopped short.
    for (uint32_t i = 4u; i < 8u; i++) {
        PBT_CHECK(payload_has_word(i));
        PBT_CHECK_EQ(payload_word(i), 0u);
    }

    PBT_CHECK_EQ(pbt_count("op_get_info_prepare"), 1);
    PBT_REQUIRE(pbt_nth("op_get_info_prepare", 0) != NULL);
    PBT_CHECK_EQ(pbt_nth("op_get_info_prepare", 0)->a2, 3u);
    PBT_CHECK_EQ(pbt_nth("op_get_info_prepare", 0)->a0, PB_INFO_UF2_TARGET);

    // The answer came from the partition table, which is where picobootx.h says
    // the two words beside the target come from.
    PBT_CHECK(pbt_count("rom_get_partition_table_info") >= 1);
    PBT_CHECK_EQ(pbt_count("rom_get_sys_info"), 0);

    // Keep those bytes, to hold the other families' answers against.
    uint8_t  first[32];
    uint32_t first_len = pbt_payload_len();
    memset(first, 0xAAu, sizeof(first));
    if (first_len <= sizeof(first)) {
        memcpy(first, pbt_payload(), first_len);
    }

    // Every family gets the same answer, because none of them has anywhere to
    // go.  0xe48bff59 is the rp2350-arm-s family, the one whose destination
    // 5.5.3 fixes on the bootrom's drive, so a device that consulted the family
    // at all would answer this one differently from the rest.
    const struct {
        const char *what;
        uint32_t    family;
    } families[] = {
        { "rp2350-arm-s", 0xE48BFF59u },
        { "rp2350-riscv", 0xE48BFF5Au },
        { "no family at all", 0xFFFFFFFFu },
        { "a family nobody defines", 0xDEADBEEFu },
    };

    for (unsigned i = 0; i < sizeof(families) / sizeof(families[0]); i++) {
        pbt_begin();
        pbt_start();

        picoboot_cmd_t other = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 32u);
        pbt_args_get_info(&other, PB_INFO_UF2_TARGET, families[i].family);

        pb_status_t got = pbt_run_cmd(&other);
        if (got != PB_STATUS_OK) {
            pbt_fail(__FILE__, __LINE__, "%s (0x%08x): %s", families[i].what,
                     families[i].family, pbt_status_name((int)got));
            continue;
        }
        if (pbt_payload_len() != first_len) {
            pbt_fail(__FILE__, __LINE__, "%s (0x%08x): %u bytes, family 0 gave "
                     "%u", families[i].what, families[i].family,
                     pbt_payload_len(), first_len);
            continue;
        }
        if (memcmp(first, pbt_payload(), first_len) != 0) {
            pbt_fail(__FILE__, __LINE__, "%s (0x%08x): a different answer from "
                     "family 0 — target 0x%08x against 0x%08x",
                     families[i].what, families[i].family, payload_word(1),
                     0xFFFFFFFFu);
        }

        // The family did reach the device, so what makes the answers identical
        // is the device ignoring it and not the library dropping it.
        const pbt_event_t *prepare = pbt_nth("op_get_info_prepare", 0);
        if (prepare == NULL || prepare->a1 != families[i].family) {
            pbt_fail(__FILE__, __LINE__, "%s (0x%08x): the device was handed "
                     "0x%08x", families[i].what, families[i].family,
                     prepare == NULL ? 0u : prepare->a1);
        }
    }

    // The two words behind the target are the ones the partition-table question
    // reports for unpartitioned space, so they are that table's answer rather
    // than a pair of constants written out twice.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t table = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&table, PB_INFO_PARTITION, PBT_PART_PT_INFO);
    PBT_CHECK_STATUS(pbt_run_cmd(&table), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 20u);
    PBT_CHECK_EQ(payload_word(3), PBT_PT_UNPARTITIONED_LOCATION);
    PBT_CHECK_EQ(payload_word(4), PBT_PT_UNPARTITIONED_FLAGS);

    // Sixteen bytes is that answer exactly and twelve is a word short of it, so
    // the transfer is judged against the three words the device said it would
    // give.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t exact = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 16u);
    pbt_args_get_info(&exact, PB_INFO_UF2_TARGET, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&exact), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_payload_len(), 16u);
    PBT_CHECK_EQ(payload_word(3), PBT_PT_UNPARTITIONED_FLAGS);

    pbt_begin();
    pbt_start();
    picoboot_cmd_t tight = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 12u);
    pbt_args_get_info(&tight, PB_INFO_UF2_TARGET, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&tight), PB_STATUS_BUFFER_TOO_SMALL);
    PBT_CHECK_EQ(pbt_packet_count(), 0u);
}

static void scenario_get_info_uf2_target_alone_when_the_table_says_less(void) {
    // Where the partition table reports fewer than the four words the target
    // question draws its second and third words from, the target goes out on
    // its own.  That is still a whole answer: 5.6.4.11 makes words 1 and 2
    // meaningful only "if the partition number is not -1", and it is -1.
    //
    // A part answers short when it does not serve PT_INFO, which is the flag
    // carrying unpartitioned space's two words.  5.4.8.16 has the routine reply
    // with "the (sub)set of those flags that the API supports", so a part that
    // does not support it answers the flags word and nothing else.
    pbt_begin();
    pbt_set_partition_supported(PBT_PART_LOC_FLAGS | PBT_PART_ID);
    pbt_start();

    // Eight bytes is the count and one word, so nothing here is padding and a
    // word that did not arrive cannot hide behind the padding rule.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 8u);
    pbt_args_get_info(&cmd, PB_INFO_UF2_TARGET, 0u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 8u);
    PBT_CHECK_EQ(payload_word(0), 1u);
    PBT_CHECK_EQ(payload_word(1), 0xFFFFFFFFu);

    // One word, and the reply stops there.
    PBT_CHECK(!payload_has_word(2u));
    PBT_CHECK_EQ((1u + payload_word(0)) * 4u, pbt_payload_len());

    // The device said one word before any of it went, which is what the host
    // was sent as the count.
    PBT_REQUIRE(pbt_nth("op_get_info_prepare", 0) != NULL);
    PBT_CHECK_EQ(pbt_nth("op_get_info_prepare", 0)->a2, 1u);

    // Sixteen bytes of transfer pads the rest rather than finding two more
    // words to send.
    pbt_begin();
    pbt_set_partition_supported(PBT_PART_LOC_FLAGS | PBT_PART_ID);
    pbt_start();
    picoboot_cmd_t roomy = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 16u);
    pbt_args_get_info(&roomy, PB_INFO_UF2_TARGET, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&roomy), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 16u);
    PBT_CHECK_EQ(payload_word(0), 1u);
    PBT_CHECK_EQ(payload_word(1), 0xFFFFFFFFu);
    for (uint32_t i = 2u; i < 4u; i++) {
        PBT_CHECK(payload_has_word(i));
        PBT_CHECK_EQ(payload_word(i), 0u);
    }

    // With PT_INFO supported again the same request answers three words, so
    // what shortened the answer was the table and not the request.  One
    // condition changed, and the two words come back.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t full = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 16u);
    pbt_args_get_info(&full, PB_INFO_UF2_TARGET, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&full), PB_STATUS_OK);
    PBT_CHECK_EQ(payload_word(0), 3u);
    PBT_CHECK_EQ(payload_word(1), 0xFFFFFFFFu);
    PBT_CHECK_EQ(payload_word(2), PBT_PT_UNPARTITIONED_LOCATION);
    PBT_CHECK_EQ(payload_word(3), PBT_PT_UNPARTITIONED_FLAGS);

    // Eight bytes does not hold that three-word answer, so the short transfer
    // above was accepted because the answer was short and not because eight is
    // a length UF2_TARGET always takes.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t narrow = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 8u);
    pbt_args_get_info(&narrow, PB_INFO_UF2_TARGET, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&narrow), PB_STATUS_BUFFER_TOO_SMALL);
    PBT_CHECK_EQ(pbt_packet_count(), 0u);
}

// ---------------------------------------------------------------------------
// The types a device does and does not serve
// ---------------------------------------------------------------------------

static void scenario_get_info_refuses_a_type_outside_the_four(void) {
    // Table 471 gives UNKNOWN_CMD as "the ID of the command was unrecognised"
    // and INVALID_ARG as "Argument is outside of range of supported values".
    // GET_INFO is a recognised command whatever bType it carries, so a bType
    // outside the four 5.6.4.11 defines is the argument being out of range.  A
    // host told UNKNOWN_CMD would conclude the device has no GET_INFO at all.
    const uint8_t types[] = {
        0x00u,   // below every defined type
        0x05u,   // one past the highest
        0x7Fu,   // well above
        0xFFu,
    };

    for (unsigned i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        pbt_begin();
        pbt_start();

        picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 16u);
        pbt_args_get_info(&cmd, types[i], 0u);

        pb_status_t got = pbt_run_cmd(&cmd);
        if (got != PB_STATUS_INVALID_ARG) {
            pbt_fail(__FILE__, __LINE__, "bType 0x%02x: expected %s, got %s",
                     types[i], pbt_status_name((int)PB_STATUS_INVALID_ARG),
                     pbt_status_name((int)got));
        }

        // picobootx.h: "A type outside this enumeration never reaches it — the
        // library refuses that itself".  So no callback ran, and a device
        // cannot be handed a type it has no case for.
        if (pbt_count("op_get_info_prepare") != 0) {
            pbt_fail(__FILE__, __LINE__, "bType 0x%02x: %d prepare calls",
                     types[i], pbt_count("op_get_info_prepare"));
        }
        if (pbt_packet_count() != 0u) {
            pbt_fail(__FILE__, __LINE__,
                     "bType 0x%02x: %u packets went to the host", types[i],
                     pbt_packet_count());
        }
    }

    // A type inside the four, in a command of the same shape, reaches the
    // device — so what was refused was the type being outside the enumeration.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t sys = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 16u);
    pbt_args_get_info(&sys, PB_INFO_SYS, PBT_SYS_CPU_INFO);
    PBT_CHECK_STATUS(pbt_run_cmd(&sys), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_count("op_get_info_prepare"), 1);
}

static void scenario_get_info_refuses_a_type_the_device_does_not_serve(void) {
    // picobootx.h: "A device says which types it serves by refusing the rest
    // from picoboot_ops_t.get_info_prepare, with PB_STATUS_INVALID_ARG."
    //
    // UF2_STATUS is the one type the defaults refuse.  picobootx.h: it "reports
    // a UF2 download in progress over the USB drive the bootrom presents in
    // BOOTSEL mode, and picobootx has no equivalent of that drive, so there is
    // no download for it to report on."  A device serving picobootx is running
    // its own application, so there is nothing to report and no honest answer
    // to give — which is different from UF2_TARGET, where "nowhere" is itself
    // the honest answer.
    //
    // The refusal comes from the callback rather than from the library, which
    // is what the prepare call in the log says.
    const uint8_t types[] = { PB_INFO_UF2_STATUS };

    for (unsigned i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        pbt_begin();
        pbt_start();

        picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 16u);
        pbt_args_get_info(&cmd, types[i], 0u);

        pb_status_t got = pbt_run_cmd(&cmd);
        if (got != PB_STATUS_INVALID_ARG) {
            pbt_fail(__FILE__, __LINE__, "bType 0x%02x: expected %s, got %s",
                     types[i], pbt_status_name((int)PB_STATUS_INVALID_ARG),
                     pbt_status_name((int)got));
        }
        if (pbt_count("op_get_info_prepare") != 1) {
            pbt_fail(__FILE__, __LINE__, "bType 0x%02x: %d prepare calls, "
                     "expected the device to be asked once", types[i],
                     pbt_count("op_get_info_prepare"));
        }
        if (pbt_count("op_get_info") != 0) {
            pbt_fail(__FILE__, __LINE__, "bType 0x%02x: the device was asked "
                     "to produce an answer it had refused", types[i]);
        }
        if (pbt_packet_count() != 0u) {
            pbt_fail(__FILE__, __LINE__,
                     "bType 0x%02x: %u packets went to the host", types[i],
                     pbt_packet_count());
        }
    }
}

static void scenario_get_info_serves_the_uf2_types_a_device_answers(void) {
    // 5.6.4.11 gives UF2_TARGET's words directly — the target partition number,
    // then that partition's two words — and puts no flags word in front of
    // them.  The count word and the padding are still the library's.
    pbt_begin();
    pbt_ops.get_info_prepare = pbt_uf2_get_info_prepare;
    pbt_ops.get_info         = pbt_uf2_get_info;
    pbt_start();

    picoboot_cmd_t target = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 32u);
    pbt_args_get_info(&target, PB_INFO_UF2_TARGET, PBT_UF2_FAMILY(0));

    PBT_CHECK_STATUS(pbt_run_cmd(&target), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 32u);
    PBT_CHECK_EQ(payload_word(0), PBT_UF2_TARGET_WORDS);

    // The first data word is payload word 1, not word 2: there is no flags word
    // to step over.  With no partition table the family has nowhere to go, so
    // it is 5.6.4.11's -1 followed by unpartitioned space's two words.
    PBT_CHECK_EQ(payload_word(1), PBT_UF2_TARGET_NOWHERE);
    PBT_CHECK_EQ(payload_word(2), PBT_PT_UNPARTITIONED_LOCATION);
    PBT_CHECK_EQ(payload_word(3), PBT_PT_UNPARTITIONED_FLAGS);
    for (uint32_t i = 4u; i < 8u; i++) {
        PBT_CHECK(payload_has_word(i));
        PBT_CHECK_EQ(payload_word(i), 0u);
    }
    PBT_CHECK_EQ(pbt_count("op_get_info_prepare"), 1);
    PBT_REQUIRE(pbt_nth("op_get_info_prepare", 0) != NULL);
    PBT_CHECK_EQ(pbt_nth("op_get_info_prepare", 0)->a0, PB_INFO_UF2_TARGET);
    PBT_CHECK_EQ(pbt_nth("op_get_info_prepare", 0)->a1, PBT_UF2_FAMILY(0));

    // The same type with a partition table behind it answers that partition
    // instead, so dParam0 reached the device and decided the answer.
    pbt_begin();
    pbt_ops.get_info_prepare = pbt_uf2_get_info_prepare;
    pbt_ops.get_info         = pbt_uf2_get_info;
    pbt_set_partitions(2u);
    pbt_start();

    picoboot_cmd_t second = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 16u);
    pbt_args_get_info(&second, PB_INFO_UF2_TARGET, PBT_UF2_FAMILY(1));
    PBT_CHECK_STATUS(pbt_run_cmd(&second), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 16u);
    PBT_CHECK_EQ(payload_word(0), PBT_UF2_TARGET_WORDS);
    PBT_CHECK_EQ(payload_word(1), 1u);
    PBT_CHECK_EQ(payload_word(2), pbt_partition_word(1u, PBT_PART_LOC_FLAGS));

    // A family the table has no partition for goes nowhere again, with the
    // table unchanged — so it is the family id and not the table that moved.
    pbt_begin();
    pbt_ops.get_info_prepare = pbt_uf2_get_info_prepare;
    pbt_ops.get_info         = pbt_uf2_get_info;
    pbt_set_partitions(2u);
    pbt_start();
    picoboot_cmd_t stranger = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 16u);
    pbt_args_get_info(&stranger, PB_INFO_UF2_TARGET, 0xDEADBEEFu);
    PBT_CHECK_STATUS(pbt_run_cmd(&stranger), PB_STATUS_OK);
    PBT_CHECK_EQ(payload_word(1), PBT_UF2_TARGET_NOWHERE);

    // UF2_STATUS's four words, and no flags word in front of them either.
    // 5.6.4.11 gives it no parameter, so nothing about the request but the type
    // decides the answer.
    pbt_begin();
    pbt_ops.get_info_prepare = pbt_uf2_get_info_prepare;
    pbt_ops.get_info         = pbt_uf2_get_info;
    pbt_start();

    picoboot_cmd_t status = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 32u);
    pbt_args_get_info(&status, PB_INFO_UF2_STATUS, 0u);

    PBT_CHECK_STATUS(pbt_run_cmd(&status), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 32u);
    PBT_CHECK_EQ(payload_word(0), PBT_UF2_STATUS_WORDS);
    PBT_CHECK_EQ(payload_word(1), PBT_UF2_STATUS_WORD0);
    PBT_CHECK_EQ(payload_word(2), PBT_UF2_STATUS_FAMILY);
    PBT_CHECK_EQ(payload_word(3), PBT_UF2_STATUS_DONE);
    PBT_CHECK_EQ(payload_word(4), PBT_UF2_STATUS_TOTAL);
    for (uint32_t i = 5u; i < 8u; i++) {
        PBT_CHECK(payload_has_word(i));
        PBT_CHECK_EQ(payload_word(i), 0u);
    }

    // Twenty bytes is a word more than that answer and sixteen is the answer
    // exactly, so the boundary sits where the device's own word count put it.
    pbt_begin();
    pbt_ops.get_info_prepare = pbt_uf2_get_info_prepare;
    pbt_ops.get_info         = pbt_uf2_get_info;
    pbt_start();
    picoboot_cmd_t exact = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&exact, PB_INFO_UF2_STATUS, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&exact), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_payload_len(), 20u);
    PBT_CHECK_EQ(payload_word(4), PBT_UF2_STATUS_TOTAL);

    pbt_begin();
    pbt_ops.get_info_prepare = pbt_uf2_get_info_prepare;
    pbt_ops.get_info         = pbt_uf2_get_info;
    pbt_start();
    picoboot_cmd_t tight = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 16u);
    pbt_args_get_info(&tight, PB_INFO_UF2_STATUS, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&tight), PB_STATUS_BUFFER_TOO_SMALL);
    PBT_CHECK_EQ(pbt_packet_count(), 0u);

    // And the two types the defaults answer are still answered, since this
    // device hands them on rather than replacing them.
    pbt_begin();
    pbt_ops.get_info_prepare = pbt_uf2_get_info_prepare;
    pbt_ops.get_info         = pbt_uf2_get_info;
    pbt_start();
    picoboot_cmd_t sys = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&sys, PB_INFO_SYS, PBT_SYS_CHIP_INFO);
    PBT_CHECK_STATUS(pbt_run_cmd(&sys), PB_STATUS_OK);
    PBT_CHECK_EQ(payload_word(1), PBT_SYS_CHIP_INFO);
}

static void scenario_get_info_without_its_callbacks_is_refused(void) {
    // picobootx.h: "Both are needed: with either NULL, GET_INFO returns
    // PB_STATUS_UNKNOWN_CMD, which is a device that does not serve it at all."
    // That is a different answer from INVALID_ARG, and it has to be: a host
    // told INVALID_ARG would try another bType.
    const struct {
        const char *what;
        bool        drop_prepare;
        bool        drop_fill;
    } cases[] = {
        { "neither callback", true,  true },
        { "no prepare",       true,  false },
        { "no fill",          false, true },
    };

    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        pbt_begin();
        if (cases[i].drop_prepare) {
            pbt_ops.get_info_prepare = NULL;
        }
        if (cases[i].drop_fill) {
            pbt_ops.get_info = NULL;
        }
        pbt_start();

        // Twenty bytes is the whole of a CHIP_INFO response, so the transfer
        // has nothing to do with the refusal.
        picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
        pbt_args_get_info(&cmd, PB_INFO_SYS, PBT_SYS_CHIP_INFO);

        pb_status_t got = pbt_run_cmd(&cmd);
        if (got != PB_STATUS_UNKNOWN_CMD) {
            pbt_fail(__FILE__, __LINE__, "%s: expected %s, got %s",
                     cases[i].what,
                     pbt_status_name((int)PB_STATUS_UNKNOWN_CMD),
                     pbt_status_name((int)got));
        }
        if (pbt_packet_count() != 0u) {
            pbt_fail(__FILE__, __LINE__, "%s: %u packets went to the host",
                     cases[i].what, pbt_packet_count());
        }
    }

    // With both in place the same command is served, so what was refused was
    // the missing callback.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t again = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&again, PB_INFO_SYS, PBT_SYS_CHIP_INFO);
    PBT_CHECK_STATUS(pbt_run_cmd(&again), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_payload_len(), 20u);
}

static void scenario_otp_read_raw_and_ecc(void) {
    pbt_begin();
    // Rows whose upper half differs from the lower, so a raw read and an ECC
    // read of the same rows cannot produce the same bytes.
    for (unsigned i = 0; i < 4u; i++) {
        pbt_otp()[i] = 0xAABB0000u | (0x1000u * i) | i;
    }
    pbt_start();

    picoboot_cmd_t raw = pbt_cmd(PB_CMD_OTP_READ, 0x05u, 16u);
    pbt_args_otp(&raw, 0u, 4u, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&raw), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 16u);
    for (uint32_t i = 0; i < 4u; i++) {
        PBT_CHECK_EQ(payload_word(i), pbt_otp()[i]);
    }

    pbt_begin();
    for (unsigned i = 0; i < 4u; i++) {
        pbt_otp()[i] = 0xAABB0000u | (0x1000u * i) | i;
    }
    pbt_start();

    picoboot_cmd_t ecc = pbt_cmd(PB_CMD_OTP_READ, 0x05u, 8u);
    pbt_args_otp(&ecc, 0u, 4u, 1u);
    PBT_CHECK_STATUS(pbt_run_cmd(&ecc), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 8u);
    for (uint32_t i = 0; i < 4u; i++) {
        uint16_t half = 0;
        memcpy(&half, pbt_payload() + (i * 2u), sizeof(half));
        PBT_CHECK_EQ(half, (uint16_t)(pbt_otp()[i] & 0xFFFFu));
    }
}

static void scenario_otp_read_starts_at_the_requested_row(void) {
    pbt_begin();
    for (unsigned i = 0; i < 64u; i++) {
        pbt_otp()[i] = 0xC0DE0000u | i;
    }
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_OTP_READ, 0x05u, 8u);
    pbt_args_otp(&cmd, 17u, 2u, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);

    PBT_REQUIRE(pbt_payload_len() == 8u);
    PBT_CHECK_EQ(payload_word(0), 0xC0DE0011u);
    PBT_CHECK_EQ(payload_word(1), 0xC0DE0012u);

    PBT_REQUIRE(pbt_nth("op_otp_read", 0) != NULL);
    PBT_CHECK_EQ(pbt_nth("op_otp_read", 0)->a0, 17u);
}

static void scenario_otp_read_spans_several_packets(void) {
    pbt_begin();
    for (unsigned i = 0; i < 40u; i++) {
        pbt_otp()[i] = 0xB0000000u | i;
    }
    pbt_start();

    // Forty raw rows is a hundred and sixty bytes, so the transfer has to be
    // carried across packets and the row cursor kept between them.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_OTP_READ, 0x05u, 160u);
    pbt_args_otp(&cmd, 0u, 40u, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);

    PBT_REQUIRE(pbt_payload_len() == 160u);
    for (uint32_t i = 0; i < 40u; i++) {
        PBT_CHECK_EQ(payload_word(i), 0xB0000000u | i);
    }
    PBT_CHECK_EQ(pbt_packet_count(), 3u);
}

static void scenario_otp_read_without_its_callback_is_refused(void) {
    pbt_begin();
    pbt_ops.otp_read = NULL;
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_OTP_READ, 0x05u, 8u);
    pbt_args_otp(&cmd, 0u, 2u, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_UNKNOWN_CMD);
}

static void scenario_otp_read_without_a_bootrom_routine_is_refused(void) {
    pbt_begin();
    pbt_bootrom_withhold('O', 'A');
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_OTP_READ, 0x05u, 8u);
    pbt_args_otp(&cmd, 0u, 2u, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_NOT_FOUND);
}

static void scenario_status_names_the_command_in_flight(void) {
    pbt_begin();
    pbt_start();

    // Arm the status block with a different, finished command, so a device that
    // reported the last command it completed would be caught here rather than
    // reading the same as one that reported the right thing.
    picoboot_cmd_t first = pbt_cmd(PB_CMD_EXCLUSIVE_ACCESS, 0x01u, 0u);
    pbt_args_exclusive_access(&first, PB_EA_EXCL);
    PBT_CHECK_STATUS(pbt_run_cmd(&first), PB_STATUS_OK);

    picoboot_status_t before;
    PBT_REQUIRE(pbt_ctrl_get_status(&before));
    PBT_REQUIRE(before.token == first.token);
    PBT_REQUIRE(before.cmd_id == PB_CMD_EXCLUSIVE_ACCESS);
    PBT_REQUIRE(before.in_progress == 0u);

    // Start a second and stop with the data sent and the host's
    // acknowledgement not yet arrived.  The command is still running.
    picoboot_cmd_t second = pbt_cmd(PB_CMD_READ, 0x08u, 32u);
    pbt_args_addr_size(&second, RP2350_SRAM_BASE, 32u);
    pbt_host_send_cmd(&second);
    pbt_pump();
    PBT_REQUIRE(pbt_cur_state() == PB_STATE_AWAIT_ACK);

    // GET_COMMAND_STATUS answers for the command still in progress, which is
    // what the picoboot specification asks of it.  A host that asks mid-transfer
    // is asking about the transfer it is waiting on.
    picoboot_status_t status;
    PBT_REQUIRE(pbt_ctrl_get_status(&status));
    PBT_CHECK_EQ(status.token, second.token);
    PBT_CHECK_EQ(status.cmd_id, PB_CMD_READ);
    PBT_CHECK_EQ(status.in_progress, 1u);
    PBT_CHECK_STATUS(status.status_code, PB_STATUS_OK);

    // And it is the running command's identity, not the finished one's, and not
    // the empty block picoboot_init leaves behind.
    PBT_CHECK(status.token != first.token);
    PBT_CHECK(status.cmd_id != before.cmd_id);
    PBT_CHECK(status.token != 0u);

    // Acknowledging ends it: the same command, no longer in progress.
    pbt_host_ack();
    PBT_REQUIRE(pbt_ctrl_get_status(&status));
    PBT_CHECK_EQ(status.token, second.token);
    PBT_CHECK_EQ(status.cmd_id, PB_CMD_READ);
    PBT_CHECK_EQ(status.in_progress, 0u);
}

static const pbt_scenario_t k_scenarios[] = {
    { "READ returns what is in device memory",
      scenario_read_returns_device_memory },
    { "READ is correct on and off a word boundary",
      scenario_read_is_correct_aligned_and_unaligned },
    { "READ covers ROM, flash and SRAM",
      scenario_read_covers_flash_and_rom },
    { "READ outside every region is refused",
      scenario_read_outside_every_region_is_refused },
    { "READ running off the end of a region is refused",
      scenario_read_running_off_the_end_is_refused },
    { "READ without either of its callbacks is refused",
      scenario_read_without_its_callbacks_is_refused },
    { "a READ callback that fails partway halts the transfer",
      scenario_a_read_that_fails_partway_stalls },
    { "GET_INFO SYS sends a word count, the flags word, then the flag data",
      scenario_get_info_sys_sends_a_count_flags_then_the_data },
    { "GET_INFO SYS carries each flag's specified word count",
      scenario_get_info_sys_word_count_per_flag },
    { "GET_INFO SYS answers every flag it serves, in flag order",
      scenario_get_info_sys_answers_every_flag_in_order },
    { "GET_INFO SYS drops a flag the chip will not answer",
      scenario_get_info_sys_drops_a_flag_the_chip_will_not_answer },
    { "GET_INFO SYS refuses a transfer too short for its answer",
      scenario_get_info_sys_refuses_a_transfer_too_short },
    { "no data-in command sends more than the transfer length",
      scenario_no_data_in_command_overruns_its_transfer },
    { "GET_INFO SYS with no flags sends an empty flags word",
      scenario_get_info_sys_with_no_flags_sends_an_empty_flags_word },
    { "GET_INFO SYS with no flags in a transfer sized to the header",
      scenario_get_info_sys_no_flags_in_a_header_sized_transfer },
    { "GET_INFO SYS with nothing but unserved flags answers as none",
      scenario_get_info_sys_with_only_unserved_flags },
    { "GET_INFO answers a device with nothing to say in one word",
      scenario_get_info_answers_nothing_in_one_word },
    { "GET_INFO SYS answers a request whose highest flag it does not serve",
      scenario_get_info_sys_answers_under_an_unserved_high_flag },
    { "a GET_INFO prepare reporting more words than there is room for",
      scenario_get_info_prepare_reporting_too_many_words_is_refused },
    { "a GET_INFO callback that fills the wrong amount is refused",
      scenario_a_get_info_that_fills_the_wrong_amount_is_refused },
    { "a GET_INFO callback that refuses carries its status",
      scenario_a_get_info_callback_that_refuses_carries_its_status },
    { "GET_INFO PARTITION sends a word count, the flags word, then the data",
      scenario_get_info_partition_sends_a_count_flags_then_the_data },
    { "GET_INFO PARTITION answers each partition in turn",
      scenario_get_info_partition_answers_each_partition_in_turn },
    { "GET_INFO PARTITION drops a flag it does not answer",
      scenario_get_info_partition_drops_a_flag_it_does_not_answer },
    { "GET_INFO UF2_TARGET has nowhere to put a family",
      scenario_get_info_uf2_target_has_nowhere_to_put_a_family },
    { "GET_INFO UF2_TARGET answers alone when the table says less",
      scenario_get_info_uf2_target_alone_when_the_table_says_less },
    { "GET_INFO refuses an info type outside the four defined",
      scenario_get_info_refuses_a_type_outside_the_four },
    { "GET_INFO refuses an info type the device does not serve",
      scenario_get_info_refuses_a_type_the_device_does_not_serve },
    { "GET_INFO serves the UF2 types a device answers",
      scenario_get_info_serves_the_uf2_types_a_device_answers },
    { "GET_INFO without either of its callbacks is refused",
      scenario_get_info_without_its_callbacks_is_refused },
    { "OTP_READ returns raw and ECC views of the same rows",
      scenario_otp_read_raw_and_ecc },
    { "OTP_READ starts at the row it was asked for",
      scenario_otp_read_starts_at_the_requested_row },
    { "OTP_READ carries its row cursor across packets",
      scenario_otp_read_spans_several_packets },
    { "OTP_READ without its callback is refused",
      scenario_otp_read_without_its_callback_is_refused },
    { "OTP_READ without a bootrom routine is refused",
      scenario_otp_read_without_a_bootrom_routine_is_refused },
    { "GET_COMMAND_STATUS names the command still in flight",
      scenario_status_names_the_command_in_flight },
};

PBT_SUITE(pbt_suite_data_in, "data_in", k_scenarios);
