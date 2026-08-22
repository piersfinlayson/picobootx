// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// picobootx's dealings with the chip underneath it.
//
// The default implementations do their work through bootrom routines they look
// up by a two-character code.  Two things can go wrong there and they are not
// the same: the routine may not be published at all, which is a property of the
// part and is discovered before anything is attempted, and the routine may be
// published and refuse, which is a property of the request and arrives as a
// negative return code that has to be turned into a status a host understands.
//
// A few of these reach the default implementations directly rather than through
// a command.  Those are the argument checks the protocol layer can never put a
// bad value past — it rounds every transfer to whole rows and sizes every buffer
// from the flag table — but which are part of the published interface an
// integrator calls, so they are tested where an integrator would meet them.

#include <string.h>

#include "pbt.h"

// The bootrom's own error numbers, written out here rather than shared with the
// library, so this asserts the mapping against the chip's documented values
// instead of against picobootx's copy of them.
#define ROM_TIMEOUT                  (-1)
#define ROM_GENERIC                  (-2)
#define ROM_NO_DATA                  (-3)
#define ROM_NOT_PERMITTED            (-4)
#define ROM_INVALID_ARG              (-5)
#define ROM_IO                       (-6)
#define ROM_BADAUTH                  (-7)
#define ROM_CONNECT_FAILED           (-8)
#define ROM_INSUFFICIENT_RESOURCES   (-9)
#define ROM_INVALID_ADDRESS         (-10)
#define ROM_BAD_ALIGNMENT           (-11)
#define ROM_INVALID_STATE           (-12)
#define ROM_BUFFER_TOO_SMALL        (-13)
#define ROM_PRECONDITION_NOT_MET    (-14)
#define ROM_MODIFIED_DATA           (-15)
#define ROM_INVALID_DATA            (-16)
#define ROM_NOT_FOUND               (-17)
#define ROM_UNSUPPORTED_MOD         (-18)
#define ROM_LOCK_REQUIRED           (-19)

// ---------------------------------------------------------------------------
// The error mapping
// ---------------------------------------------------------------------------

static void scenario_every_bootrom_code_maps_to_a_status(void) {
    // Every code the chip can return, and the status a host is told.  The ones
    // the RP2350 bootrom does not use are here too: an unmapped code has to
    // become a status rather than fall through as a negative number, and the
    // only way to show that is to hand it one.
    const struct {
        int         ret;
        pb_status_t expected;
    } cases[] = {
        { 0,                          PB_STATUS_OK },
        { ROM_TIMEOUT,                PB_STATUS_UNKNOWN_ERROR },
        { ROM_GENERIC,                PB_STATUS_UNKNOWN_ERROR },
        { ROM_NO_DATA,                PB_STATUS_UNKNOWN_ERROR },
        { ROM_NOT_PERMITTED,          PB_STATUS_NOT_PERMITTED },
        { ROM_INVALID_ARG,            PB_STATUS_INVALID_ARG },
        { ROM_IO,                     PB_STATUS_UNKNOWN_ERROR },
        { ROM_BADAUTH,                PB_STATUS_UNKNOWN_ERROR },
        { ROM_CONNECT_FAILED,         PB_STATUS_UNKNOWN_ERROR },
        { ROM_INSUFFICIENT_RESOURCES, PB_STATUS_UNKNOWN_ERROR },
        { ROM_INVALID_ADDRESS,        PB_STATUS_INVALID_ADDRESS },
        { ROM_BAD_ALIGNMENT,          PB_STATUS_BAD_ALIGNMENT },
        { ROM_INVALID_STATE,          PB_STATUS_INVALID_STATE },
        { ROM_BUFFER_TOO_SMALL,       PB_STATUS_BUFFER_TOO_SMALL },
        { ROM_PRECONDITION_NOT_MET,   PB_STATUS_PRECONDITION_NOT_MET },
        { ROM_MODIFIED_DATA,          PB_STATUS_MODIFIED_DATA },
        { ROM_INVALID_DATA,           PB_STATUS_INVALID_DATA },
        { ROM_NOT_FOUND,              PB_STATUS_NOT_FOUND },
        { ROM_UNSUPPORTED_MOD,        PB_STATUS_UNSUPPORTED_MOD },
        { ROM_LOCK_REQUIRED,          PB_STATUS_UNKNOWN_ERROR },
        { -99,                        PB_STATUS_UNKNOWN_ERROR },
    };

    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        pb_status_t got = pb_status_from_bootrom(cases[i].ret);
        if (got != cases[i].expected) {
            pbt_fail(__FILE__, __LINE__, "bootrom %d: expected %s, got %s",
                     cases[i].ret, pbt_status_name((int)cases[i].expected),
                     pbt_status_name((int)got));
        }
    }
}

static void scenario_an_otp_read_the_chip_refuses_carries_its_reason(void) {
    pbt_begin();
    pbt_otp()[0] = 0x11223344u;
    // A part refuses a read whose ECC cannot be corrected.  The host is told
    // which refusal it was, not merely that something failed.
    pbt_otp_fail(ROM_MODIFIED_DATA);
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_OTP_READ, 0x05u, 4u);
    pbt_args_otp(&cmd, 0u, 1u, 0u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_MODIFIED_DATA);
    PBT_CHECK_EQ(pbt_count("rom_otp_access"), 1);

    // Nothing went to the host, so it does not have to work out how much of an
    // answer it received before the refusal.
    PBT_CHECK_EQ(pbt_packet_count(), 0u);

    // A different refusal produces a different status, so the status is the
    // chip's reason and not a fixed one for OTP.
    pbt_begin();
    pbt_otp_fail(ROM_NOT_PERMITTED);
    pbt_start();
    picoboot_cmd_t locked = pbt_cmd(PB_CMD_OTP_READ, 0x05u, 4u);
    pbt_args_otp(&locked, 0u, 1u, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&locked), PB_STATUS_NOT_PERMITTED);

    // And with the chip answering, the same read succeeds.
    pbt_begin();
    pbt_otp()[0] = 0x11223344u;
    pbt_start();
    picoboot_cmd_t good = pbt_cmd(PB_CMD_OTP_READ, 0x05u, 4u);
    pbt_args_otp(&good, 0u, 1u, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&good), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_payload_len(), 4u);
}

static void scenario_an_otp_write_the_chip_refuses_carries_its_reason(void) {
    pbt_begin();
    pbt_otp_fail(ROM_NOT_PERMITTED);
    pbt_start();

    const uint32_t row = 0x0000BEEFu;
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_OTP_WRITE, 0x05u, sizeof(row));
    pbt_args_otp(&cmd, 6u, 1u, 0u);
    pbt_host_send_cmd(&cmd);
    pbt_pump();
    pbt_host_send(&row, sizeof(row));
    pbt_pump();

    picoboot_status_t status;
    PBT_REQUIRE(pbt_ctrl_get_status(&status));
    PBT_CHECK_STATUS(status.status_code, PB_STATUS_NOT_PERMITTED);
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_STALLED);

    // A refused write blows nothing, so the row is still clear.
    PBT_CHECK_EQ(pbt_otp()[6], 0u);

    // With the chip accepting, the same write lands.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t again = pbt_cmd(PB_CMD_OTP_WRITE, 0x05u, sizeof(row));
    pbt_args_otp(&again, 6u, 1u, 0u);
    pbt_host_send_cmd(&again);
    pbt_pump();
    pbt_host_send(&row, sizeof(row));
    pbt_pump();
    PBT_CHECK_EQ(pbt_otp()[6], row);
}

static void scenario_the_serial_is_empty_when_the_chip_refuses(void) {
    pbt_begin();
    pbt_otp()[0] = 0x00001122u;
    pbt_otp_fail(ROM_IO);
    pbt_start();

    uint16_t serial[17];
    memset(serial, 0xFFu, sizeof(serial));

    // A serial the chip would not tell us is reported as no serial at all.
    // Returning a partly built string would put whatever was in the buffer into
    // a USB string descriptor.
    PBT_CHECK_EQ(picoboot_get_serial(serial, 17u), 0u);
    PBT_CHECK_EQ(pbt_count("rom_otp_access"), 1);
    PBT_CHECK_EQ(serial[0], 0xFFFFu);

    // The same call with the chip answering produces the identifier, so the
    // refusal above was the chip's and not the buffer's.
    pbt_begin();
    pbt_otp()[0] = 0x00001122u;
    pbt_start();
    PBT_CHECK_EQ(picoboot_get_serial(serial, 17u), 16u);
    PBT_CHECK_EQ(serial[15], (uint16_t)'2');
}

// ---------------------------------------------------------------------------
// Routines the part does not publish
// ---------------------------------------------------------------------------

static void scenario_get_info_without_its_bootrom_routine(void) {
    pbt_begin();
    pbt_bootrom_withhold('G', 'S');
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 16u);
    pbt_args_get_info(&cmd, PB_INFO_SYS, 0x0001u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_NOT_FOUND);

    // The leading word count had already been produced when the flag data was
    // asked for, and none of it reached the host — a truncated answer would be
    // indistinguishable from a complete one of a different length.
    PBT_CHECK_EQ(pbt_packet_count(), 0u);

    // PARTITION information does not come from that routine and is unaffected,
    // so what was missing was the routine and not GET_INFO.
    pbt_recover();
    picoboot_cmd_t partition = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&partition, PB_INFO_PARTITION, 0u);
    PBT_CHECK_STATUS(pbt_run_cmd(&partition), PB_STATUS_OK);
}

static void scenario_otp_write_without_its_bootrom_routine(void) {
    pbt_begin();
    pbt_bootrom_withhold('O', 'A');
    pbt_start();

    const uint32_t row = 0x0000A5A5u;
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_OTP_WRITE, 0x05u, sizeof(row));
    pbt_args_otp(&cmd, 3u, 1u, 0u);
    pbt_host_send_cmd(&cmd);
    pbt_pump();
    pbt_host_send(&row, sizeof(row));
    pbt_pump();

    picoboot_status_t status;
    PBT_REQUIRE(pbt_ctrl_get_status(&status));
    PBT_CHECK_STATUS(status.status_code, PB_STATUS_NOT_FOUND);
    PBT_CHECK_EQ(pbt_otp()[3], 0u);

    // Nothing was attempted, as opposed to attempted and refused.
    PBT_CHECK_EQ(pbt_count("rom_otp_access"), 0);
}

static void scenario_a_reboot_the_part_no_longer_offers_does_not_happen(void) {
    pbt_begin();
    pbt_start();

    // Preparing found the routine, so the command was accepted and the
    // acknowledgement sent.  The reboot itself happens after that, and looks
    // the routine up again.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_REBOOT2, 0x10u, 0u);
    pbt_args_reboot2(&cmd, 0x0002u, 10u, 0u, 0u);
    pbt_host_send_cmd(&cmd);
    pbt_task();

    PBT_REQUIRE(pbt_cur_state() == PB_STATE_AWAIT_ZLP);
    PBT_REQUIRE(pbt_count("op_reboot2_prepare") == 1);
    PBT_CHECK_EQ(pbt_packet_count(), 1u);

    // Between the two the part stops publishing it.  Rebooting through a null
    // pointer would fault, so the second lookup is checked as well as the first.
    pbt_bootrom_withhold('R', 'B');
    pbt_complete_tx();

    PBT_CHECK_EQ(pbt_count("op_reboot2_execute"), 1);
    PBT_CHECK_EQ(pbt_count("rom_reboot"), 0);
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_IDLE);

    // Without the withdrawal the same sequence reboots, so what stopped it was
    // the missing routine.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t again = pbt_cmd(PB_CMD_REBOOT2, 0x10u, 0u);
    pbt_args_reboot2(&again, 0x0002u, 10u, 0u, 0u);
    pbt_host_send_cmd(&again);
    pbt_task();
    pbt_complete_tx();
    PBT_CHECK_EQ(pbt_count("rom_reboot"), 1);
}

// ---------------------------------------------------------------------------
// The default implementations' own argument checks
// ---------------------------------------------------------------------------

static void scenario_otp_access_of_part_of_a_row_is_refused(void) {
    pbt_begin();
    pbt_start();

    // A row is four bytes raw and two through ECC, and OTP is accessed a whole
    // row at a time.  A length that is not a whole number of rows is refused
    // rather than rounded, since rounding either way would touch a row the
    // caller did not name.
    uint8_t buf[8];
    memset(buf, 0x5Au, sizeof(buf));

    PBT_CHECK_STATUS(picoboot_default_otp_read(0u, 0u, buf, 3u, NULL),
                     PB_STATUS_INVALID_ARG);
    PBT_CHECK_STATUS(picoboot_default_otp_read(0u, 1u, buf, 3u, NULL),
                     PB_STATUS_INVALID_ARG);
    PBT_CHECK_STATUS(picoboot_default_otp_write(0u, 0u, buf, 3u, NULL),
                     PB_STATUS_INVALID_ARG);
    PBT_CHECK_STATUS(picoboot_default_otp_write(0u, 1u, buf, 3u, NULL),
                     PB_STATUS_INVALID_ARG);

    // Refused before the chip was asked, so nothing was read and nothing blown.
    PBT_CHECK_EQ(pbt_count("rom_otp_access"), 0);
    PBT_CHECK_EQ(pbt_otp()[0], 0u);

    // A whole row of either width is accepted, so what was refused was the
    // length and not the call.  Three bytes is a whole number of neither, which
    // is why the same length appears above for both.
    PBT_CHECK_STATUS(picoboot_default_otp_read(0u, 0u, buf, 4u, NULL),
                     PB_STATUS_OK);
    PBT_CHECK_STATUS(picoboot_default_otp_read(0u, 1u, buf, 2u, NULL),
                     PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_count("rom_otp_access"), 2);
}

static void scenario_get_info_sys_refuses_a_buffer_no_flag_fills(void) {
    pbt_begin();
    pbt_start();

    // The callback copies a whole flag's data out of a fixed stack buffer, so a
    // caller asking for more than the largest flag carries is refused rather
    // than served out of memory past the end of it.
    uint8_t buf[64];
    uint32_t written = 0xFFFFFFFFu;
    memset(buf, 0x00u, sizeof(buf));

    PBT_CHECK_STATUS(
        picoboot_default_get_info_sys(0x0040u, buf, 32u, &written, NULL),
        PB_STATUS_UNKNOWN_ERROR);
    PBT_CHECK_EQ(pbt_count("rom_get_sys_info"), 0);

    // Sixteen bytes is what that flag actually carries, and is served.
    written = 0xFFFFFFFFu;
    PBT_CHECK_STATUS(
        picoboot_default_get_info_sys(0x0040u, buf, 16u, &written, NULL),
        PB_STATUS_OK);
    PBT_CHECK_EQ(written, 16u);
    PBT_CHECK_EQ(pbt_count("rom_get_sys_info"), 1);
}

static void scenario_get_info_sys_reports_a_flag_the_chip_will_not_take(void) {
    pbt_begin();
    pbt_start();

    // A flag the chip does not recognise comes back as a refusal from the
    // bootrom, and is reported as the chip's reason.  The protocol layer filters
    // these out of a GET_INFO request before they get here, so this is the path
    // an integrator calling the implementation directly meets.
    uint8_t buf[16];
    uint32_t written = 0;

    PBT_CHECK_STATUS(
        picoboot_default_get_info_sys(0x8000u, buf, 4u, &written, NULL),
        PB_STATUS_INVALID_ARG);
    PBT_CHECK_EQ(pbt_count("rom_get_sys_info"), 1);

    // A flag it does recognise is answered, so the refusal was the flag's.
    PBT_CHECK_STATUS(
        picoboot_default_get_info_sys(0x0004u, buf, 4u, &written, NULL),
        PB_STATUS_OK);
    PBT_CHECK_EQ(written, 4u);
}

static const pbt_scenario_t k_scenarios[] = {
    { "every bootrom error code maps to a status",
      scenario_every_bootrom_code_maps_to_a_status },
    { "an OTP read the chip refuses carries the chip's reason",
      scenario_an_otp_read_the_chip_refuses_carries_its_reason },
    { "an OTP write the chip refuses carries the chip's reason",
      scenario_an_otp_write_the_chip_refuses_carries_its_reason },
    { "the serial is empty when the chip will not read its identifier",
      scenario_the_serial_is_empty_when_the_chip_refuses },
    { "GET_INFO SYS without its bootrom routine is refused",
      scenario_get_info_without_its_bootrom_routine },
    { "OTP_WRITE without its bootrom routine is refused",
      scenario_otp_write_without_its_bootrom_routine },
    { "a reboot the part no longer offers does not happen",
      scenario_a_reboot_the_part_no_longer_offers_does_not_happen },
    { "OTP access of part of a row is refused",
      scenario_otp_access_of_part_of_a_row_is_refused },
    { "get_info_sys refuses a buffer no flag fills",
      scenario_get_info_sys_refuses_a_buffer_no_flag_fills },
    { "get_info_sys reports a flag the chip will not take",
      scenario_get_info_sys_reports_a_flag_the_chip_will_not_take },
};

PBT_SUITE(pbt_suite_bootrom, "bootrom", k_scenarios);
