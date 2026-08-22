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

static void scenario_get_info_sys_sends_a_count_then_the_data(void) {
    pbt_begin();
    pbt_start();

    // Two flags, carrying three words and one word respectively.
    const uint32_t chip_info = 0x0001u;
    const uint32_t cpu_info  = 0x0004u;

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 64u);
    pbt_args_get_info(&cmd, PB_INFO_SYS, chip_info | cpu_info);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 64u);

    // The leading word is how many data words follow.
    PBT_CHECK_EQ(payload_word(0), 4u);

    // Then each requested flag's data, lowest flag first.
    PBT_CHECK_EQ(payload_word(1), pbt_sys_info_word(chip_info) + 0u);
    PBT_CHECK_EQ(payload_word(2), pbt_sys_info_word(chip_info) + 1u);
    PBT_CHECK_EQ(payload_word(3), pbt_sys_info_word(chip_info) + 2u);
    PBT_CHECK_EQ(payload_word(4), pbt_sys_info_word(cpu_info) + 0u);

    // And the rest of the transfer the host asked for is padded, not left
    // holding whatever was in the buffer.
    for (uint32_t i = 5; i < 16u; i++) {
        PBT_CHECK_EQ(payload_word(i), 0u);
    }

    // One call per flag, each told which flag it is answering.
    PBT_CHECK_EQ(pbt_count("op_get_info_sys"), 2);
    PBT_REQUIRE(pbt_nth("op_get_info_sys", 1) != NULL);
    PBT_CHECK_EQ(pbt_nth("op_get_info_sys", 0)->a0, chip_info);
    PBT_CHECK_EQ(pbt_nth("op_get_info_sys", 0)->a1, 12u);
    PBT_CHECK_EQ(pbt_nth("op_get_info_sys", 1)->a0, cpu_info);
    PBT_CHECK_EQ(pbt_nth("op_get_info_sys", 1)->a1, 4u);
}

static void scenario_get_info_sys_skips_flags_it_does_not_know(void) {
    pbt_begin();
    pbt_start();

    // A flag outside the table is dropped rather than refused, so a host that
    // asks for more than this device knows about still gets an answer.
    const uint32_t cpu_info = 0x0004u;
    const uint32_t unknown  = 0x8000u;

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 16u);
    pbt_args_get_info(&cmd, PB_INFO_SYS, cpu_info | unknown);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 16u);

    // The count covers the flags the device knows, not the ones asked for.
    PBT_CHECK_EQ(payload_word(0), 1u);
    PBT_CHECK_EQ(payload_word(1), pbt_sys_info_word(cpu_info));
    PBT_CHECK_EQ(pbt_count("op_get_info_sys"), 1);
}

static void scenario_get_info_sys_refuses_an_unsupported_flag(void) {
    pbt_begin();
    // The device knows the flag but the chip will not answer it.
    pbt_set_sys_info_supported(0x0004u);
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 32u);
    pbt_args_get_info(&cmd, PB_INFO_SYS, 0x0001u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_INVALID_ARG);

    // Nothing was put on the wire, so the host does not have to work out how
    // much of a truncated answer it received.
    PBT_CHECK_EQ(pbt_packet_count(), 0u);

    // The same request with the flag supported succeeds, so what was refused
    // was the chip's answer and not the request's shape.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t again = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 32u);
    pbt_args_get_info(&again, PB_INFO_SYS, 0x0001u);
    PBT_CHECK_STATUS(pbt_run_cmd(&again), PB_STATUS_OK);
}

static void scenario_get_info_sys_stops_when_the_transfer_runs_out(void) {
    pbt_begin();
    pbt_start();

    // Two flags asked for, and a transfer length with room for the count and
    // the first flag only.  The host gets what it made room for, and the device
    // stops rather than overrunning the length it was given.
    const uint32_t chip_info = 0x0001u;  // three words
    const uint32_t cpu_info  = 0x0004u;  // one word

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 16u);
    pbt_args_get_info(&cmd, PB_INFO_SYS, chip_info | cpu_info);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 16u);

    // The count still says what was asked for and answerable, which is how the
    // host knows its buffer was too small for it.
    PBT_CHECK_EQ(payload_word(0), 4u);
    PBT_CHECK_EQ(payload_word(1), pbt_sys_info_word(chip_info) + 0u);
    PBT_CHECK_EQ(payload_word(2), pbt_sys_info_word(chip_info) + 1u);
    PBT_CHECK_EQ(payload_word(3), pbt_sys_info_word(chip_info) + 2u);

    // The second flag was never asked for, since there was nowhere to put it.
    PBT_CHECK_EQ(pbt_count("op_get_info_sys"), 1);
    PBT_REQUIRE(pbt_nth("op_get_info_sys", 0) != NULL);
    PBT_CHECK_EQ(pbt_nth("op_get_info_sys", 0)->a0, chip_info);

    // Four bytes more and it fits, so what cut it short was the length.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t roomy = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&roomy, PB_INFO_SYS, chip_info | cpu_info);
    PBT_CHECK_STATUS(pbt_run_cmd(&roomy), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_payload_len(), 20u);
    PBT_CHECK_EQ(payload_word(4), pbt_sys_info_word(cpu_info));
    PBT_CHECK_EQ(pbt_count("op_get_info_sys"), 2);
}

static void scenario_get_info_sys_with_no_flags_sends_only_the_count(void) {
    pbt_begin();
    pbt_start();

    // A request for nothing is answered with a count of nothing.  There is no
    // data to pad around, so the transfer ends at the count even though the host
    // left room for more.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 8u);
    pbt_args_get_info(&cmd, PB_INFO_SYS, 0u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_payload_len(), 4u);
    PBT_CHECK_EQ(payload_word(0), 0u);
    PBT_CHECK_EQ(pbt_count("op_get_info_sys"), 0);
    PBT_CHECK_EQ(pbt_packet_count(), 1u);

    // One flag in the same request fills the whole eight bytes, so the short
    // answer above was the empty request and not the length.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t one = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 8u);
    pbt_args_get_info(&one, PB_INFO_SYS, 0x0004u);
    PBT_CHECK_STATUS(pbt_run_cmd(&one), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_payload_len(), 8u);
    PBT_CHECK_EQ(payload_word(0), 1u);
}

// A get_info_sys callback that reports fewer bytes than it was asked for.  The
// library cannot tell how much of the buffer such a callback actually filled,
// so the transfer is abandoned rather than sent with a hole in it.
static pb_status_t op_get_info_sys_short(uint32_t flags, uint8_t *buf,
                                         uint32_t buf_len,
                                         uint32_t *bytes_written, void *ctx) {
    (void)ctx;
    (void)flags;
    pbt_log("op_get_info_sys", flags, buf_len, 0, 0);
    memset(buf, 0xEE, buf_len);
    *bytes_written = buf_len / 2u;
    return PB_STATUS_OK;
}

static void scenario_get_info_sys_that_fills_the_wrong_amount_is_refused(void) {
    pbt_begin();
    pbt_ops.get_info_sys = op_get_info_sys_short;
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 16u);
    pbt_args_get_info(&cmd, PB_INFO_SYS, 0x0001u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_UNKNOWN_ERROR);
    PBT_CHECK_EQ(pbt_count("op_get_info_sys"), 1);

    // The leading count had been produced and is discarded with the rest, so
    // the host is not handed the beginning of an answer that has no end.
    PBT_CHECK_EQ(pbt_packet_count(), 0u);
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_STALLED);

    // The same request against a callback that fills what it says it filled is
    // answered, so what was refused was the disagreement.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t again = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 16u);
    pbt_args_get_info(&again, PB_INFO_SYS, 0x0001u);
    PBT_CHECK_STATUS(pbt_run_cmd(&again), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_payload_len(), 16u);
}

static void scenario_get_info_partition_streams_its_words(void) {
    pbt_begin();
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&cmd, PB_INFO_PARTITION, 0u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 20u);

    const uint32_t expected[] = {
        0x00000004u, 0x00000031u, 0x00000000u, 0xffffe000u, 0xfc078000u,
    };
    for (uint32_t i = 0; i < 5u; i++) {
        PBT_CHECK_EQ(payload_word(i), expected[i]);
    }

    // Partition information does not come from the ops table.
    PBT_CHECK_EQ(pbt_count("op_get_info_sys"), 0);
}

static void scenario_get_info_partition_pads_past_its_words(void) {
    pbt_begin();
    pbt_start();

    // Asking for more than there is gives zeros rather than running off the end
    // of the table.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 32u);
    pbt_args_get_info(&cmd, PB_INFO_PARTITION, 0u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 32u);
    PBT_CHECK_EQ(payload_word(4), 0xfc078000u);
    PBT_CHECK_EQ(payload_word(5), 0u);
    PBT_CHECK_EQ(payload_word(7), 0u);
}

static void scenario_get_info_refuses_an_unknown_type(void) {
    pbt_begin();
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 16u);
    pbt_args_get_info(&cmd, PB_INFO_UF2_TARGET, 0u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_UNKNOWN_CMD);
    PBT_CHECK_EQ(pbt_packet_count(), 0u);
}

static void scenario_get_info_sys_without_its_callback_is_refused(void) {
    pbt_begin();
    pbt_ops.get_info_sys = NULL;
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 16u);
    pbt_args_get_info(&cmd, PB_INFO_SYS, 0x0001u);
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_UNKNOWN_CMD);

    // Partition information does not go through that callback, so it still
    // works — which shows the refusal was about the callback and not about
    // GET_INFO as a whole.
    pbt_recover();
    picoboot_cmd_t partition = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&partition, PB_INFO_PARTITION, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&partition), PB_STATUS_OK);
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
    { "GET_INFO SYS sends a word count then the flag data",
      scenario_get_info_sys_sends_a_count_then_the_data },
    { "GET_INFO SYS stops when the transfer runs out before the flags",
      scenario_get_info_sys_stops_when_the_transfer_runs_out },
    { "GET_INFO SYS with no flags sends only the count",
      scenario_get_info_sys_with_no_flags_sends_only_the_count },
    { "a GET_INFO SYS callback that fills the wrong amount is refused",
      scenario_get_info_sys_that_fills_the_wrong_amount_is_refused },
    { "GET_INFO SYS skips flags it does not know",
      scenario_get_info_sys_skips_flags_it_does_not_know },
    { "GET_INFO SYS refuses a flag the chip will not answer",
      scenario_get_info_sys_refuses_an_unsupported_flag },
    { "GET_INFO PARTITION streams its words",
      scenario_get_info_partition_streams_its_words },
    { "GET_INFO PARTITION pads past its words",
      scenario_get_info_partition_pads_past_its_words },
    { "GET_INFO refuses an unknown info type",
      scenario_get_info_refuses_an_unknown_type },
    { "GET_INFO SYS without its callback is refused",
      scenario_get_info_sys_without_its_callback_is_refused },
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
