// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// Host-to-device transfers and the actions that change storage: WRITE,
// OTP_WRITE and FLASH_ERASE.

#include <string.h>

#include "pbt.h"

// One sector, which is the smallest thing FLASH_ERASE will accept.
#define SECTOR FLASH_SECTOR_SIZE

// Deliver a payload the way a host does, one endpoint's worth at a time,
// letting the device consume each packet before the next arrives.
static void send_data(const uint8_t *data, uint32_t len) {
    uint32_t offset = 0;
    while (offset < len) {
        uint32_t chunk = len - offset;
        if (chunk > PBT_PACKET_MAX) {
            chunk = PBT_PACKET_MAX;
        }
        pbt_host_send(data + offset, chunk);
        pbt_pump();
        offset += chunk;
    }
}

// A recognisable pattern: every byte differs from its neighbours and from the
// erased value, so neither a stale buffer nor an unerased page can match it.
static void fill_pattern(uint8_t *buf, uint32_t len, uint8_t seed) {
    for (uint32_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(seed + (i * 7u));
    }
}

// ---------------------------------------------------------------------------
// WRITE to SRAM
// ---------------------------------------------------------------------------

static void scenario_write_to_sram_lands_in_memory(void) {
    pbt_begin();
    pbt_start();

    uint8_t data[100];
    fill_pattern(data, sizeof(data), 0x31u);

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_WRITE, 0x08u, sizeof(data));
    pbt_args_addr_size(&cmd, RP2350_SRAM_BASE + 0x400u, sizeof(data));

    pbt_host_send_cmd(&cmd);
    pbt_pump();
    PBT_REQUIRE(pbt_cur_state() == PB_STATE_DATA_OUT);

    send_data(data, sizeof(data));

    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_IDLE);
    PBT_CHECK_EQ(memcmp(pbt_sram() + 0x400u, data, sizeof(data)), 0);

    // Acknowledged once, at the end, and not once per packet.
    PBT_CHECK_EQ(pbt_packet_count(), 1u);
    PBT_CHECK_EQ(pbt_packet(0)->len, 1u);

    picoboot_status_t status;
    PBT_REQUIRE(pbt_ctrl_get_status(&status));
    PBT_CHECK_STATUS(status.status_code, PB_STATUS_OK);
    PBT_CHECK_EQ(status.token, cmd.token);

    // SRAM does not go through the flash page path.
    PBT_CHECK_EQ(pbt_count("op_flash_page_write"), 0);
}

static void scenario_write_advances_across_packets(void) {
    pbt_begin();
    pbt_start();

    // More than one endpoint's worth, so the write address has to move on
    // between packets rather than restarting.
    uint8_t data[200];
    fill_pattern(data, sizeof(data), 0x80u);

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_WRITE, 0x08u, sizeof(data));
    pbt_args_addr_size(&cmd, RP2350_SRAM_BASE + 0x800u, sizeof(data));

    pbt_host_send_cmd(&cmd);
    pbt_pump();
    send_data(data, sizeof(data));

    PBT_CHECK_EQ(memcmp(pbt_sram() + 0x800u, data, sizeof(data)), 0);

    PBT_CHECK_EQ(pbt_count("op_write"), 4);
    PBT_REQUIRE(pbt_nth("op_write", 3) != NULL);
    PBT_CHECK_EQ(pbt_nth("op_write", 0)->a0, RP2350_SRAM_BASE + 0x800u);
    PBT_CHECK_EQ(pbt_nth("op_write", 1)->a0, RP2350_SRAM_BASE + 0x840u);
    PBT_CHECK_EQ(pbt_nth("op_write", 2)->a0, RP2350_SRAM_BASE + 0x880u);
    PBT_CHECK_EQ(pbt_nth("op_write", 3)->a0, RP2350_SRAM_BASE + 0x8C0u);
    PBT_CHECK_EQ(pbt_nth("op_write", 3)->a1, 8u);
}

static void scenario_status_names_a_write_still_taking_data(void) {
    pbt_begin();
    pbt_start();

    // Arm the status block with a different, finished command, so a device
    // still reporting the last one it completed is caught here.
    picoboot_cmd_t first = pbt_cmd(PB_CMD_EXCLUSIVE_ACCESS, 0x01u, 0u);
    pbt_args_exclusive_access(&first, PB_EA_EXCL);
    PBT_CHECK_STATUS(pbt_run_cmd(&first), PB_STATUS_OK);

    // A write large enough to need three packets, of which the host sends one.
    uint8_t data[200];
    fill_pattern(data, sizeof(data), 0x11u);

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_WRITE, 0x08u, sizeof(data));
    pbt_args_addr_size(&cmd, RP2350_SRAM_BASE + 0xC00u, sizeof(data));

    pbt_host_send_cmd(&cmd);
    pbt_pump();
    send_data(data, PBT_PACKET_MAX);
    PBT_REQUIRE(pbt_cur_state() == PB_STATE_DATA_OUT);

    // The data phase has started and not finished, so this is the command a
    // host asking about the transfer means.
    picoboot_status_t status;
    PBT_REQUIRE(pbt_ctrl_get_status(&status));
    PBT_CHECK_EQ(status.token, cmd.token);
    PBT_CHECK_EQ(status.cmd_id, PB_CMD_WRITE);
    PBT_CHECK_EQ(status.in_progress, 1u);
    PBT_CHECK_STATUS(status.status_code, PB_STATUS_OK);
    PBT_CHECK(status.token != first.token);
    PBT_CHECK(status.cmd_id != PB_CMD_EXCLUSIVE_ACCESS);

    // The rest of the data finishes it, and the same command is then reported
    // as done rather than running.
    send_data(data + PBT_PACKET_MAX, sizeof(data) - PBT_PACKET_MAX);
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_IDLE);
    PBT_CHECK_EQ(memcmp(pbt_sram() + 0xC00u, data, sizeof(data)), 0);

    PBT_REQUIRE(pbt_ctrl_get_status(&status));
    PBT_CHECK_EQ(status.token, cmd.token);
    PBT_CHECK_EQ(status.in_progress, 0u);
    PBT_CHECK_STATUS(status.status_code, PB_STATUS_OK);
}

static void scenario_write_to_sram_without_its_callback_is_refused(void) {
    pbt_begin();
    pbt_ops.write = NULL;
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_WRITE, 0x08u, 16u);
    pbt_args_addr_size(&cmd, RP2350_SRAM_BASE, 16u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_UNKNOWN_CMD);
}

// A write callback that serves one call and then refuses, so a transfer can be
// stopped partway with some of its data already in memory.  The default
// implementation never fails, so an integrator's that does is written here.
#define WRITE_REFUSAL_STATUS PB_STATUS_INVALID_STATE

static uint32_t s_writes_before_refusal;

static pb_status_t op_write_then_refuse(uint32_t addr, const uint8_t *buf,
                                        uint32_t len, void *ctx) {
    pbt_log("op_write", addr, len, 0, 0);
    if (s_writes_before_refusal == 0u) {
        return WRITE_REFUSAL_STATUS;
    }
    s_writes_before_refusal--;
    return picoboot_default_write(addr, buf, len, ctx);
}

static void scenario_a_write_that_fails_partway_stalls(void) {
    pbt_begin();
    s_writes_before_refusal = 1u;
    pbt_ops.write = op_write_then_refuse;
    pbt_start();

    uint8_t data[128];
    fill_pattern(data, sizeof(data), 0x93u);

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_WRITE, 0x08u, sizeof(data));
    pbt_args_addr_size(&cmd, RP2350_SRAM_BASE + 0x1000u, sizeof(data));
    pbt_host_send_cmd(&cmd);
    pbt_pump();
    send_data(data, sizeof(data));

    // The refusal halts the transfer and is reported as the callback's own
    // status, so a host is told why rather than merely that the pipe stopped.
    picoboot_status_t status;
    PBT_REQUIRE(pbt_ctrl_get_status(&status));
    PBT_CHECK_STATUS(status.status_code, WRITE_REFUSAL_STATUS);
    PBT_CHECK_EQ(status.token, cmd.token);
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_STALLED);
    PBT_CHECK_EQ(pbt_count("op_write"), 2);
    PBT_CHECK_EQ(pbt_packet_count(), 0u);

    // What the first call wrote is in memory and what the second refused is not,
    // so the halt stopped the transfer where it failed rather than unwinding it
    // or carrying on.
    PBT_CHECK_EQ(memcmp(pbt_sram() + 0x1000u, data, PBT_PACKET_MAX), 0);
    PBT_CHECK(memcmp(pbt_sram() + 0x1000u + PBT_PACKET_MAX,
                     data + PBT_PACKET_MAX, PBT_PACKET_MAX) != 0);

    // The same write against a callback that does not refuse lands whole.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t again = pbt_cmd(PB_CMD_WRITE, 0x08u, sizeof(data));
    pbt_args_addr_size(&again, RP2350_SRAM_BASE + 0x1000u, sizeof(data));
    pbt_host_send_cmd(&again);
    pbt_pump();
    send_data(data, sizeof(data));
    PBT_CHECK_EQ(memcmp(pbt_sram() + 0x1000u, data, sizeof(data)), 0);
}

static void scenario_a_lone_byte_during_a_data_phase_is_data(void) {
    pbt_begin();
    pbt_start();

    // A single byte on the OUT endpoint is the acknowledgement form the protocol
    // also accepts, and in idle it is swallowed.  Inside a data phase it is one
    // byte of the payload, and swallowing it would silently corrupt the write.
    const uint8_t data[4] = { 0xC1u, 0xC2u, 0xC3u, 0xC4u };

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_WRITE, 0x08u, sizeof(data));
    pbt_args_addr_size(&cmd, RP2350_SRAM_BASE + 0x1400u, sizeof(data));
    pbt_host_send_cmd(&cmd);
    pbt_pump();
    PBT_REQUIRE(pbt_cur_state() == PB_STATE_DATA_OUT);

    pbt_host_send(data, 1u);
    pbt_pump();
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_DATA_OUT);

    pbt_host_send(data + 1u, sizeof(data) - 1u);
    pbt_pump();

    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_IDLE);
    PBT_CHECK_EQ(memcmp(pbt_sram() + 0x1400u, data, sizeof(data)), 0);

    // Both parts reached the callback, the first as a one-byte write.
    PBT_CHECK_EQ(pbt_count("op_write"), 2);
    PBT_REQUIRE(pbt_nth("op_write", 1) != NULL);
    PBT_CHECK_EQ(pbt_nth("op_write", 0)->a1, 1u);
    PBT_CHECK_EQ(pbt_nth("op_write", 1)->a1, 3u);
}

static void scenario_write_outside_writable_memory_is_refused(void) {
    pbt_begin();
    pbt_start();

    // ROM is readable but not writable, so a write there is refused even
    // though a read of the same address would succeed.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_WRITE, 0x08u, 16u);
    pbt_args_addr_size(&cmd, RP2350_ROM_BASE, 16u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_INVALID_ARG);
    PBT_CHECK_EQ(pbt_count("op_write"), 0);

    pbt_recover();

    picoboot_cmd_t read = pbt_cmd(PB_CMD_READ, 0x08u, 16u);
    pbt_args_addr_size(&read, RP2350_ROM_BASE, 16u);
    PBT_CHECK_STATUS(pbt_run_cmd(&read), PB_STATUS_OK);
}

static void scenario_write_running_off_the_end_of_memory_is_refused(void) {
    pbt_begin();
    pbt_start();

    // Starts inside SRAM and ends past it.  A check that only looked at the
    // start address would let this through and then write over whatever the
    // address after SRAM happens to be.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_WRITE, 0x08u, 64u);
    pbt_args_addr_size(&cmd, RP2350_SRAM_BASE + RP2350_SRAM_SIZE - 32u, 64u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_INVALID_ARG);
    PBT_CHECK_EQ(pbt_count("op_write"), 0);
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_STALLED);

    // The same length wholly inside SRAM is accepted and lands, so what was
    // refused was the overrun.
    pbt_recover();
    uint8_t data[64];
    fill_pattern(data, sizeof(data), 0x4Bu);
    picoboot_cmd_t inside = pbt_cmd(PB_CMD_WRITE, 0x08u, sizeof(data));
    pbt_args_addr_size(&inside, RP2350_SRAM_BASE + RP2350_SRAM_SIZE - 64u,
                       sizeof(data));
    pbt_host_send_cmd(&inside);
    pbt_pump();
    send_data(data, sizeof(data));
    PBT_CHECK_EQ(memcmp(pbt_sram() + RP2350_SRAM_SIZE - 64u, data,
                        sizeof(data)), 0);
}

// ---------------------------------------------------------------------------
// WRITE to flash
// ---------------------------------------------------------------------------

static void scenario_write_to_flash_programs_whole_pages(void) {
    pbt_begin();
    pbt_start();

    // Not a multiple of the page size, so the last page is partial and has to
    // be padded out to a full page before it can be programmed.
    uint8_t data[300];
    fill_pattern(data, sizeof(data), 0x11u);

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_WRITE, 0x08u, sizeof(data));
    pbt_args_addr_size(&cmd, RP2350_FLASH_BASE, sizeof(data));

    pbt_host_send_cmd(&cmd);
    pbt_pump();
    send_data(data, sizeof(data));

    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_IDLE);

    // Two pages, at consecutive page addresses.
    PBT_CHECK_EQ(pbt_count("op_flash_page_write"), 2);
    PBT_REQUIRE(pbt_nth("op_flash_page_write", 1) != NULL);
    PBT_CHECK_EQ(pbt_nth("op_flash_page_write", 0)->a0, RP2350_FLASH_BASE);
    PBT_CHECK_EQ(pbt_nth("op_flash_page_write", 1)->a0,
                 RP2350_FLASH_BASE + FLASH_PAGE_SIZE);

    // Each reaching the chip as a full page at the right offset.
    PBT_CHECK_EQ(pbt_count("rom_flash_range_program"), 2);
    PBT_CHECK_EQ(pbt_nth("rom_flash_range_program", 0)->a0, 0u);
    PBT_CHECK_EQ(pbt_nth("rom_flash_range_program", 0)->a1, FLASH_PAGE_SIZE);
    PBT_CHECK_EQ(pbt_nth("rom_flash_range_program", 1)->a0, FLASH_PAGE_SIZE);
    PBT_CHECK_EQ(pbt_nth("rom_flash_range_program", 1)->a1, FLASH_PAGE_SIZE);

    // The data is there, and the tail of the final page is the zero padding
    // rather than whatever was in the buffer from the page before.
    PBT_CHECK_EQ(memcmp(pbt_flash(), data, sizeof(data)), 0);
    for (uint32_t i = sizeof(data); i < 2u * FLASH_PAGE_SIZE; i++) {
        if (pbt_flash()[i] != 0x00u) {
            pbt_fail(__FILE__, __LINE__,
                     "flash byte %u after the payload is 0x%02x, not padding",
                     i, pbt_flash()[i]);
            break;
        }
    }
}

static void scenario_a_skipped_erase_is_visible(void) {
    pbt_begin();
    // A page that has been written before and not erased since.
    memset(pbt_flash(), 0x00u, FLASH_PAGE_SIZE);
    pbt_start();

    uint8_t data[FLASH_PAGE_SIZE];
    fill_pattern(data, sizeof(data), 0x55u);

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_WRITE, 0x08u, sizeof(data));
    pbt_args_addr_size(&cmd, RP2350_FLASH_BASE, sizeof(data));
    pbt_host_send_cmd(&cmd);
    pbt_pump();
    send_data(data, sizeof(data));

    // Programming can only clear bits, so writing over a page that was never
    // erased does not put the data there.
    PBT_CHECK_EQ(pbt_count("rom_flash_range_program"), 1);
    for (uint32_t i = 0; i < sizeof(data); i++) {
        if (pbt_flash()[i] != 0x00u) {
            pbt_fail(__FILE__, __LINE__,
                     "flash byte %u is 0x%02x — the write appeared to succeed "
                     "over unerased storage", i, pbt_flash()[i]);
            break;
        }
    }
}

static void scenario_erase_then_write_puts_the_data_there(void) {
    pbt_begin();
    memset(pbt_flash(), 0x00u, FLASH_PAGE_SIZE);
    pbt_start();

    // The same starting condition as above, with the erase the device is
    // supposed to have issued first.
    picoboot_cmd_t erase = pbt_cmd(PB_CMD_FLASH_ERASE, 0x08u, 0u);
    pbt_args_addr_size(&erase, RP2350_FLASH_BASE, SECTOR);
    PBT_CHECK_STATUS(pbt_run_cmd(&erase), PB_STATUS_OK);

    uint8_t data[FLASH_PAGE_SIZE];
    fill_pattern(data, sizeof(data), 0x55u);

    picoboot_cmd_t write = pbt_cmd(PB_CMD_WRITE, 0x08u, sizeof(data));
    pbt_args_addr_size(&write, RP2350_FLASH_BASE, sizeof(data));
    pbt_host_send_cmd(&write);
    pbt_pump();
    send_data(data, sizeof(data));

    PBT_CHECK_EQ(memcmp(pbt_flash(), data, sizeof(data)), 0);
}

static void scenario_flash_write_refused_without_a_page_buffer(void) {
    pbt_begin();
    pbt_use_flash_buf = false;
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_WRITE, 0x08u, FLASH_PAGE_SIZE);
    pbt_args_addr_size(&cmd, RP2350_FLASH_BASE, FLASH_PAGE_SIZE);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_NOT_PERMITTED);
    PBT_CHECK_EQ(pbt_count("op_flash_page_write"), 0);

    // A write to SRAM needs no page buffer and is unaffected, so the refusal is
    // about accumulating a flash page and not about WRITE.
    pbt_recover();
    uint8_t data[16];
    fill_pattern(data, sizeof(data), 0x22u);
    picoboot_cmd_t sram = pbt_cmd(PB_CMD_WRITE, 0x08u, sizeof(data));
    pbt_args_addr_size(&sram, RP2350_SRAM_BASE, sizeof(data));
    pbt_host_send_cmd(&sram);
    pbt_pump();
    send_data(data, sizeof(data));
    PBT_CHECK_EQ(memcmp(pbt_sram(), data, sizeof(data)), 0);
}

static void scenario_flash_write_refused_without_a_page_callback(void) {
    pbt_begin();
    pbt_ops.flash_page_write = NULL;
    pbt_start();

    // A different missing piece from the one above, and the same refusal, since
    // both are needed before a page can be accumulated and programmed.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_WRITE, 0x08u, FLASH_PAGE_SIZE);
    pbt_args_addr_size(&cmd, RP2350_FLASH_BASE, FLASH_PAGE_SIZE);
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_NOT_PERMITTED);
}

static void scenario_unaligned_flash_write_is_refused(void) {
    pbt_begin();
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_WRITE, 0x08u, 16u);
    pbt_args_addr_size(&cmd, RP2350_FLASH_BASE + 1u, 16u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_BAD_ALIGNMENT);

    // A page boundary is accepted, so what was refused was the alignment.
    pbt_recover();
    picoboot_cmd_t aligned = pbt_cmd(PB_CMD_WRITE, 0x08u, 16u);
    pbt_args_addr_size(&aligned, RP2350_FLASH_BASE + FLASH_PAGE_SIZE, 16u);
    pbt_host_send_cmd(&aligned);
    pbt_pump();
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_DATA_OUT);
}

static void scenario_flash_write_without_a_bootrom_routine_is_refused(void) {
    pbt_begin();
    pbt_bootrom_withhold('R', 'P');
    pbt_start();

    uint8_t data[FLASH_PAGE_SIZE];
    fill_pattern(data, sizeof(data), 0x77u);

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_WRITE, 0x08u, sizeof(data));
    pbt_args_addr_size(&cmd, RP2350_FLASH_BASE, sizeof(data));
    pbt_host_send_cmd(&cmd);
    pbt_pump();
    send_data(data, sizeof(data));

    picoboot_status_t status;
    PBT_REQUIRE(pbt_ctrl_get_status(&status));
    PBT_CHECK_STATUS(status.status_code, PB_STATUS_NOT_FOUND);

    // And nothing reached the chip.
    PBT_CHECK_EQ(pbt_count("rom_flash_range_program"), 0);
}

// ---------------------------------------------------------------------------
// FLASH_ERASE
// ---------------------------------------------------------------------------

static void scenario_flash_erase_sequence(void) {
    pbt_begin();
    memset(pbt_flash(), 0x00u, SECTOR);
    // A divisor that could not arise by accident, so carrying it through is
    // demonstrable rather than assumed.
    pbt_set_xip_clkdiv(0x2Au);
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_FLASH_ERASE, 0x08u, 0u);
    pbt_args_addr_size(&cmd, RP2350_FLASH_BASE, SECTOR);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);

    // The order the chip has to be driven in.  Flash cannot be erased while it
    // is answering execute-in-place reads, and the interrupt handlers that
    // would run during the erase are themselves fetched from flash, so both
    // have to be down for the erase and back up afterwards.
    PBT_CHECK(pbt_before("op_flash_erase_prepare", "op_flash_erase"));
    PBT_CHECK(pbt_before("rom_connect_internal_flash", "xip_clkdiv_read"));
    PBT_CHECK(pbt_before("xip_clkdiv_read", "irq_disable"));
    PBT_CHECK(pbt_before("irq_disable", "rom_flash_exit_xip"));
    PBT_CHECK(pbt_before("rom_flash_exit_xip", "rom_flash_range_erase"));
    PBT_CHECK(pbt_before("rom_flash_range_erase",
                         "rom_flash_select_xip_read_mode"));
    PBT_CHECK(pbt_before("rom_flash_select_xip_read_mode",
                         "rom_flash_flush_cache"));
    PBT_CHECK(pbt_before("rom_flash_flush_cache", "irq_enable"));

    // The divisor is read before execute-in-place is taken down, which is the
    // reason it is read separately at all, and handed back to the call that
    // restores it.
    PBT_REQUIRE(pbt_nth("xip_clkdiv_read", 0) != NULL);
    PBT_CHECK_EQ(pbt_nth("xip_clkdiv_read", 0)->a0, 0x2Au);
    PBT_REQUIRE(pbt_nth("rom_flash_select_xip_read_mode", 0) != NULL);
    PBT_CHECK_EQ(pbt_nth("rom_flash_select_xip_read_mode", 0)->a0, 3u);
    PBT_CHECK_EQ(pbt_nth("rom_flash_select_xip_read_mode", 0)->a1, 0x2Au);

    // The erase itself, as an offset from the start of flash rather than a
    // mapped address, with the block size and command that let the chip use a
    // larger erase where it can.
    PBT_REQUIRE(pbt_nth("rom_flash_range_erase", 0) != NULL);
    PBT_CHECK_EQ(pbt_nth("rom_flash_range_erase", 0)->a0, 0u);
    PBT_CHECK_EQ(pbt_nth("rom_flash_range_erase", 0)->a1, SECTOR);
    PBT_CHECK_EQ(pbt_nth("rom_flash_range_erase", 0)->a2, FLASH_BLOCK_SIZE);
    PBT_CHECK_EQ(pbt_nth("rom_flash_range_erase", 0)->a3, 0xd8u);

    // The erase was not attempted with execute-in-place still up, which on a
    // real part would do nothing at all.
    PBT_CHECK_EQ(pbt_count("rom_flash_erase_while_xip"), 0);

    // The chip is left the way it was found.
    PBT_CHECK(!pbt_irq_disabled());
    PBT_CHECK(pbt_xip_active());

    // And the sector really is erased.
    for (uint32_t i = 0; i < SECTOR; i++) {
        if (pbt_flash()[i] != 0xFFu) {
            pbt_fail(__FILE__, __LINE__, "flash byte %u is 0x%02x after erase",
                     i, pbt_flash()[i]);
            break;
        }
    }
}

static void scenario_flash_erase_leaves_neighbouring_sectors_alone(void) {
    pbt_begin();
    memset(pbt_flash(), 0x00u, 2u * SECTOR);
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_FLASH_ERASE, 0x08u, 0u);
    pbt_args_addr_size(&cmd, RP2350_FLASH_BASE, SECTOR);
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);

    PBT_CHECK_EQ(pbt_flash()[0], 0xFFu);
    PBT_CHECK_EQ(pbt_flash()[SECTOR - 1u], 0xFFu);
    PBT_CHECK_EQ(pbt_flash()[SECTOR], 0x00u);
    PBT_CHECK_EQ(pbt_flash()[(2u * SECTOR) - 1u], 0x00u);
}

static void scenario_flash_erase_alignment_and_range(void) {
    const struct {
        const char *what;
        uint32_t    addr;
        uint32_t    size;
        pb_status_t expected;
    } cases[] = {
        { "unaligned address", RP2350_FLASH_BASE + 1u, SECTOR,
          PB_STATUS_BAD_ALIGNMENT },
        { "unaligned size", RP2350_FLASH_BASE, SECTOR + 1u,
          PB_STATUS_BAD_ALIGNMENT },
        { "before flash", RP2350_SRAM_BASE, SECTOR,
          PB_STATUS_INVALID_ADDRESS },
        { "past the end of flash",
          RP2350_FLASH_BASE + RP2350_FLASH_SIZE - SECTOR, 2u * SECTOR,
          PB_STATUS_INVALID_ADDRESS },
        { "a whole sector at the base", RP2350_FLASH_BASE, SECTOR,
          PB_STATUS_OK },
    };

    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        pbt_begin();
        pbt_start();

        picoboot_cmd_t cmd = pbt_cmd(PB_CMD_FLASH_ERASE, 0x08u, 0u);
        pbt_args_addr_size(&cmd, cases[i].addr, cases[i].size);

        pb_status_t got = pbt_run_cmd(&cmd);
        if (got != cases[i].expected) {
            pbt_fail(__FILE__, __LINE__, "%s: expected %s, got %s",
                     cases[i].what, pbt_status_name((int)cases[i].expected),
                     pbt_status_name((int)got));
        }
        if (cases[i].expected != PB_STATUS_OK &&
            pbt_count("rom_flash_range_erase") != 0) {
            pbt_fail(__FILE__, __LINE__, "%s: the erase was issued anyway",
                     cases[i].what);
        }
    }
}

static void scenario_flash_erase_needs_every_bootrom_routine(void) {
    // Each of the five routines the erase sequence uses.  Any one missing
    // refuses the command, and refuses it before the chip is touched — a
    // sequence that got halfway would leave flash out of execute-in-place with
    // nothing to put it back.
    const struct {
        char a;
        char b;
    } codes[] = {
        { 'I', 'F' }, { 'E', 'X' }, { 'R', 'E' }, { 'F', 'C' }, { 'X', 'M' },
    };

    for (unsigned i = 0; i < sizeof(codes) / sizeof(codes[0]); i++) {
        pbt_begin();
        memset(pbt_flash(), 0x00u, SECTOR);
        pbt_bootrom_withhold(codes[i].a, codes[i].b);
        pbt_start();

        picoboot_cmd_t cmd = pbt_cmd(PB_CMD_FLASH_ERASE, 0x08u, 0u);
        pbt_args_addr_size(&cmd, RP2350_FLASH_BASE, SECTOR);

        pb_status_t got = pbt_run_cmd(&cmd);
        if (got != PB_STATUS_NOT_FOUND) {
            pbt_fail(__FILE__, __LINE__, "without %c%c: expected NOT_FOUND, "
                     "got %s", codes[i].a, codes[i].b,
                     pbt_status_name((int)got));
        }
        if (pbt_count("rom_connect_internal_flash") != 0) {
            pbt_fail(__FILE__, __LINE__,
                     "without %c%c: the chip was touched before the routine "
                     "was found to be missing", codes[i].a, codes[i].b);
        }
        if (pbt_flash()[0] != 0x00u) {
            pbt_fail(__FILE__, __LINE__, "without %c%c: flash was erased anyway",
                     codes[i].a, codes[i].b);
        }
        if (pbt_irq_disabled() || !pbt_xip_active()) {
            pbt_fail(__FILE__, __LINE__,
                     "without %c%c: the chip was left with interrupts or "
                     "execute-in-place down", codes[i].a, codes[i].b);
        }
    }
}

static void scenario_flash_erase_without_its_callbacks_is_refused(void) {
    pbt_begin();
    pbt_ops.flash_erase = NULL;
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_FLASH_ERASE, 0x08u, 0u);
    pbt_args_addr_size(&cmd, RP2350_FLASH_BASE, SECTOR);
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_UNKNOWN_CMD);
    PBT_CHECK_EQ(pbt_count("op_flash_erase_prepare"), 0);

    pbt_begin();
    pbt_ops.flash_erase_prepare = NULL;
    pbt_start();

    picoboot_cmd_t again = pbt_cmd(PB_CMD_FLASH_ERASE, 0x08u, 0u);
    pbt_args_addr_size(&again, RP2350_FLASH_BASE, SECTOR);
    PBT_CHECK_STATUS(pbt_run_cmd(&again), PB_STATUS_UNKNOWN_CMD);
    PBT_CHECK_EQ(pbt_count("op_flash_erase"), 0);
}

// ---------------------------------------------------------------------------
// OTP_WRITE
// ---------------------------------------------------------------------------

static void scenario_otp_write_sets_rows(void) {
    pbt_begin();
    pbt_start();

    const uint32_t rows[2] = { 0x0000FF01u, 0x0000FF02u };

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_OTP_WRITE, 0x05u, sizeof(rows));
    pbt_args_otp(&cmd, 8u, 2u, 0u);

    pbt_host_send_cmd(&cmd);
    pbt_pump();
    PBT_REQUIRE(pbt_cur_state() == PB_STATE_DATA_OUT);

    send_data((const uint8_t *)rows, sizeof(rows));

    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_IDLE);
    PBT_CHECK_EQ(pbt_otp()[8], rows[0]);
    PBT_CHECK_EQ(pbt_otp()[9], rows[1]);

    // Written where it was asked for, and nowhere else.
    PBT_CHECK_EQ(pbt_otp()[7], 0u);
    PBT_CHECK_EQ(pbt_otp()[10], 0u);
}

static void scenario_otp_write_only_ever_sets_bits(void) {
    pbt_begin();
    pbt_start();

    const uint32_t first  = 0x0F0F0F0Fu;
    const uint32_t second = 0xF0F0F0F0u;

    picoboot_cmd_t a = pbt_cmd(PB_CMD_OTP_WRITE, 0x05u, sizeof(first));
    pbt_args_otp(&a, 4u, 1u, 0u);
    pbt_host_send_cmd(&a);
    pbt_pump();
    send_data((const uint8_t *)&first, sizeof(first));
    PBT_CHECK_EQ(pbt_otp()[4], first);

    picoboot_cmd_t b = pbt_cmd(PB_CMD_OTP_WRITE, 0x05u, sizeof(second));
    pbt_args_otp(&b, 4u, 1u, 0u);
    pbt_host_send_cmd(&b);
    pbt_pump();
    send_data((const uint8_t *)&second, sizeof(second));

    // A fuse that has been blown cannot be unblown, so the second write adds to
    // the first rather than replacing it.
    PBT_CHECK_EQ(pbt_otp()[4], first | second);
}

static void scenario_otp_write_needs_no_flash_page_buffer(void) {
    pbt_begin();
    pbt_use_flash_buf = false;
    pbt_start();

    // The flash page buffer accumulates a 256-byte page out of 64-byte
    // packets.  An OTP row is two or four bytes and there is nothing to
    // accumulate, so OTP_WRITE never consults the buffer and works without one.
    const uint32_t row = 0x000000A5u;
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_OTP_WRITE, 0x05u, sizeof(row));
    pbt_args_otp(&cmd, 2u, 1u, 0u);

    pbt_host_send_cmd(&cmd);
    pbt_pump();
    send_data((const uint8_t *)&row, sizeof(row));

    PBT_CHECK_EQ(pbt_otp()[2], row);
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_IDLE);
}

static void scenario_otp_write_through_the_ecc_view(void) {
    pbt_begin();
    pbt_start();

    // Through the ECC view a row is two bytes, not four, so the same row count
    // carries half the data and the row cursor has to advance by the ECC row
    // size rather than the raw one.
    const uint16_t halves[4] = { 0x1101u, 0x2202u, 0x3303u, 0x4404u };

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_OTP_WRITE, 0x05u, sizeof(halves));
    pbt_args_otp(&cmd, 16u, 4u, 1u);
    pbt_host_send_cmd(&cmd);
    pbt_pump();
    send_data((const uint8_t *)halves, sizeof(halves));

    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_IDLE);
    for (unsigned i = 0; i < 4u; i++) {
        PBT_CHECK_EQ(pbt_otp()[16u + i], halves[i]);
    }
    PBT_CHECK_EQ(pbt_otp()[20], 0u);

    // The chip was told this was an ECC access, which is what makes it two
    // bytes a row rather than the low two bytes of four.
    PBT_REQUIRE(pbt_nth("rom_otp_access", 0) != NULL);
    PBT_CHECK_EQ(pbt_nth("rom_otp_access", 0)->a2, 1u);
    PBT_CHECK_EQ(pbt_nth("rom_otp_access", 0)->a3, 1u);
    PBT_CHECK_EQ(pbt_nth("rom_otp_access", 0)->a1, sizeof(halves));

    // The same eight bytes written raw fill two rows rather than four, so the
    // rows above are the ECC view's doing and not the payload's.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t raw = pbt_cmd(PB_CMD_OTP_WRITE, 0x05u, sizeof(halves));
    pbt_args_otp(&raw, 16u, 2u, 0u);
    pbt_host_send_cmd(&raw);
    pbt_pump();
    send_data((const uint8_t *)halves, sizeof(halves));
    PBT_CHECK_EQ(pbt_otp()[16], 0x22021101u);
    PBT_CHECK_EQ(pbt_otp()[17], 0x44043303u);
    PBT_CHECK_EQ(pbt_otp()[18], 0u);
}

static void scenario_otp_write_carries_its_row_cursor_across_packets(void) {
    pbt_begin();
    pbt_start();

    // Thirty-two raw rows is a hundred and twenty-eight bytes, so the data
    // arrives in two packets and the cursor has to move on between them rather
    // than restarting at the row the command named.
    uint32_t rows[32];
    for (unsigned i = 0; i < 32u; i++) {
        rows[i] = 0x000A0000u | (i + 1u);
    }

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_OTP_WRITE, 0x05u, sizeof(rows));
    pbt_args_otp(&cmd, 64u, 32u, 0u);
    pbt_host_send_cmd(&cmd);
    pbt_pump();
    send_data((const uint8_t *)rows, sizeof(rows));

    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_IDLE);
    for (unsigned i = 0; i < 32u; i++) {
        PBT_CHECK_EQ(pbt_otp()[64u + i], rows[i]);
    }
    PBT_CHECK_EQ(pbt_otp()[96], 0u);

    // Two accesses, the second starting sixteen rows on from the first.
    PBT_CHECK_EQ(pbt_count("op_otp_write"), 2);
    PBT_REQUIRE(pbt_nth("op_otp_write", 1) != NULL);
    PBT_CHECK_EQ(pbt_nth("op_otp_write", 0)->a0, 64u);
    PBT_CHECK_EQ(pbt_nth("op_otp_write", 1)->a0, 80u);
}

static void scenario_a_packet_too_short_to_be_a_row_is_discarded(void) {
    pbt_begin();
    pbt_start();

    // A raw row is four bytes and cannot be assembled from fragments, so a
    // packet carrying fewer than one row is dropped.  Holding it back to join
    // to the next packet is what the library does not do, and a scenario that
    // did not send a whole row afterwards could not tell the two apart.
    const uint32_t row = 0x000C0FFEu;
    const uint8_t  runt[3] = { 0xDEu, 0xADu, 0xBEu };

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_OTP_WRITE, 0x05u, sizeof(row));
    pbt_args_otp(&cmd, 12u, 1u, 0u);
    pbt_host_send_cmd(&cmd);
    pbt_pump();

    pbt_host_send(runt, sizeof(runt));
    pbt_pump();
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_DATA_OUT);
    PBT_CHECK_EQ(pbt_count("op_otp_write"), 0);

    pbt_host_send(&row, sizeof(row));
    pbt_pump();

    // The row holds what the whole packet carried, with none of the fragment
    // in it — a fragment kept and prepended would have blown different fuses.
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_IDLE);
    PBT_CHECK_EQ(pbt_otp()[12], row);
    PBT_CHECK_EQ(pbt_count("op_otp_write"), 1);
    PBT_REQUIRE(pbt_nth("op_otp_write", 0) != NULL);
    PBT_CHECK_EQ(pbt_nth("op_otp_write", 0)->a2, sizeof(row));
}

static void scenario_otp_write_without_its_callback_is_refused(void) {
    pbt_begin();
    pbt_ops.otp_write = NULL;
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_OTP_WRITE, 0x05u, 4u);
    pbt_args_otp(&cmd, 0u, 1u, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_UNKNOWN_CMD);
    PBT_CHECK_EQ(pbt_otp()[0], 0u);
}

static const pbt_scenario_t k_scenarios[] = {
    { "WRITE to SRAM lands in memory and is acknowledged once",
      scenario_write_to_sram_lands_in_memory },
    { "WRITE advances its address across packets",
      scenario_write_advances_across_packets },
    { "GET_COMMAND_STATUS names a WRITE that is still taking data",
      scenario_status_names_a_write_still_taking_data },
    { "WRITE to SRAM without its callback is refused",
      scenario_write_to_sram_without_its_callback_is_refused },
    { "WRITE outside writable memory is refused",
      scenario_write_outside_writable_memory_is_refused },
    { "WRITE running off the end of memory is refused",
      scenario_write_running_off_the_end_of_memory_is_refused },
    { "a WRITE callback that fails partway halts the transfer",
      scenario_a_write_that_fails_partway_stalls },
    { "a lone byte during a data phase is data, not an acknowledgement",
      scenario_a_lone_byte_during_a_data_phase_is_data },
    { "WRITE to flash programs whole, padded pages",
      scenario_write_to_flash_programs_whole_pages },
    { "a write over unerased flash does not put the data there",
      scenario_a_skipped_erase_is_visible },
    { "erasing first puts the data there",
      scenario_erase_then_write_puts_the_data_there },
    { "WRITE to flash is refused without a page buffer",
      scenario_flash_write_refused_without_a_page_buffer },
    { "WRITE to flash is refused without a page callback",
      scenario_flash_write_refused_without_a_page_callback },
    { "an unaligned flash write is refused",
      scenario_unaligned_flash_write_is_refused },
    { "WRITE to flash without a bootrom routine is refused",
      scenario_flash_write_without_a_bootrom_routine_is_refused },
    { "FLASH_ERASE drives the chip in the required order",
      scenario_flash_erase_sequence },
    { "FLASH_ERASE leaves neighbouring sectors alone",
      scenario_flash_erase_leaves_neighbouring_sectors_alone },
    { "FLASH_ERASE checks alignment and range",
      scenario_flash_erase_alignment_and_range },
    { "FLASH_ERASE needs every bootrom routine before it starts",
      scenario_flash_erase_needs_every_bootrom_routine },
    { "FLASH_ERASE without either of its callbacks is refused",
      scenario_flash_erase_without_its_callbacks_is_refused },
    { "OTP_WRITE sets the rows it was asked for",
      scenario_otp_write_sets_rows },
    { "OTP_WRITE only ever sets bits",
      scenario_otp_write_only_ever_sets_bits },
    { "OTP_WRITE through the ECC view",
      scenario_otp_write_through_the_ecc_view },
    { "OTP_WRITE carries its row cursor across packets",
      scenario_otp_write_carries_its_row_cursor_across_packets },
    { "a packet too short to be an OTP row is discarded",
      scenario_a_packet_too_short_to_be_a_row_is_discarded },
    { "OTP_WRITE works without a flash page buffer",
      scenario_otp_write_needs_no_flash_page_buffer },
    { "OTP_WRITE without its callback is refused",
      scenario_otp_write_without_its_callback_is_refused },
};

PBT_SUITE(pbt_suite_data_out, "data_out", k_scenarios);
