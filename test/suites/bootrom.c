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
// bad value past — it rounds every transfer to whole rows and offers a callback
// no more room than the answer has left — but which are part of the published
// interface an integrator calls, so they are tested where an integrator would
// meet them.

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

    // Twenty bytes is the whole of a CHIP_INFO response, so the transfer has
    // nothing to do with the refusal.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&cmd, PB_INFO_SYS, PBT_SYS_CHIP_INFO);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_NOT_FOUND);

    // Nothing reached the host — a truncated answer would be indistinguishable
    // from a complete one of a different length.
    PBT_CHECK_EQ(pbt_packet_count(), 0u);

    // PARTITION information comes from a different routine, which is still
    // there, so what was missing was the routine and not GET_INFO.
    pbt_recover();
    picoboot_cmd_t partition = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&partition, PB_INFO_PARTITION, PBT_PART_PT_INFO);
    PBT_CHECK_STATUS(pbt_run_cmd(&partition), PB_STATUS_OK);
}

// picobootx_impl.h: get_sys_info is "the only ROM routine either of these two
// reaches, and only PB_INFO_SYS reaches it.  On a part that publishes no
// bootrom routine at all, PB_INFO_SYS is refused with PB_STATUS_NOT_FOUND and
// the other two are answered as usual."
//
// The two constants are the partition question and the UF2 target question,
// and each is checked here against a part that publishes neither of the two
// routines 5.4.8.16 and 5.4.8.17 define.
static void scenario_the_constant_info_types_need_no_bootrom_routine(void) {
    const struct {
        const char    *what;
        pb_info_type_t type;
        uint32_t       param0;
        uint32_t       transfer;
        uint32_t       count;
        uint32_t       words[4];   // the significant words, after the count
    } types[] = {
        // 5.4.8.16's PT_INFO: the flags word, then the table's own word and
        // unpartitioned space's two.
        { "the partition question", PB_INFO_PARTITION, PBT_PART_PT_INFO, 20u,
          1u + PBT_DEFAULT_PT_INFO_WORDS,
          { PBT_PART_PT_INFO, PBT_DEFAULT_PT_TABLE, PBT_DEFAULT_PT_LOCATION,
            PBT_DEFAULT_PT_FLAGS } },

        // 5.6.4.11's three, with no flags word in front of them.
        { "the UF2 target question", PB_INFO_UF2_TARGET, 0u, 16u,
          PBT_DEFAULT_UF2_TARGET_WORDS,
          { PBT_DEFAULT_UF2_TARGET, PBT_DEFAULT_PT_LOCATION,
            PBT_DEFAULT_PT_FLAGS, 0u } },
    };

    for (unsigned i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        pbt_begin();
        pbt_bootrom_withhold('G', 'P');
        pbt_bootrom_withhold('G', 'S');
        pbt_start();

        picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u,
                                     types[i].transfer);
        pbt_args_get_info(&cmd, types[i].type, types[i].param0);

        pb_status_t got = pbt_run_cmd(&cmd);
        if (got != PB_STATUS_OK) {
            pbt_fail(__FILE__, __LINE__, "%s: %s", types[i].what,
                     pbt_status_name((int)got));
            continue;
        }
        if (pbt_payload_len() != types[i].transfer) {
            pbt_fail(__FILE__, __LINE__, "%s: %u bytes for a transfer of %u",
                     types[i].what, pbt_payload_len(), types[i].transfer);
            continue;
        }

        // The whole answer, not one cut short to get past an absent routine.
        uint32_t words[5];
        memcpy(words, pbt_payload(), sizeof(words));
        if (words[0] != types[i].count) {
            pbt_fail(__FILE__, __LINE__, "%s: counted %u words, expected %u",
                     types[i].what, words[0], types[i].count);
        }
        for (uint32_t w = 0; w < types[i].count; w++) {
            if (words[1u + w] != types[i].words[w]) {
                pbt_fail(__FILE__, __LINE__, "%s: word %u is 0x%08x, expected "
                         "0x%08x", types[i].what, w, words[1u + w],
                         types[i].words[w]);
            }
        }

        // Neither routine was reached, as opposed to reached and found
        // missing.
        if (pbt_count("rom_get_partition_table_info") != 0 ||
            pbt_count("rom_get_sys_info") != 0) {
            pbt_fail(__FILE__, __LINE__, "%s reached the chip: "
                     "get_partition_table_info %d, get_sys_info %d",
                     types[i].what,
                     pbt_count("rom_get_partition_table_info"),
                     pbt_count("rom_get_sys_info"));
        }

        // The routines really are withheld.  System information is the type
        // that needs one, and on this same device it cannot be served.  Table
        // 471: NOT_FOUND is "Attempted to access something that doesn't
        // exist; or a search failed", which is the lookup for a routine the
        // part does not publish.
        pbt_recover();
        picoboot_cmd_t sys = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
        pbt_args_get_info(&sys, PB_INFO_SYS, PBT_SYS_CHIP_INFO);
        pb_status_t sys_got = pbt_run_cmd(&sys);
        if (sys_got != PB_STATUS_NOT_FOUND) {
            pbt_fail(__FILE__, __LINE__, "%s: system information answered %s "
                     "on a part publishing nothing", types[i].what,
                     pbt_status_name((int)sys_got));
        }
    }

    // With the routine published, system information is served — so what
    // refused it above was its absence, and the two constants were answered
    // through the same absence.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t served = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&served, PB_INFO_SYS, PBT_SYS_CHIP_INFO);
    PBT_CHECK_STATUS(pbt_run_cmd(&served), PB_STATUS_OK);
    PBT_CHECK(pbt_count("rom_get_sys_info") >= 1);
}

// Which routine each served type reaches.  picobootx_impl.h names get_sys_info
// as the only one, and 5.4.8.16's get_partition_table_info is reached by
// nothing — the partition question and the UF2 target question are both
// constants now.
static void scenario_only_system_information_reaches_the_bootrom(void) {
    const struct {
        const char    *what;
        pb_info_type_t type;
        uint32_t       param0;
        int            sys_calls;
    } types[] = {
        // Once to learn how long the answer is, once for the answer itself.
        { "system information", PB_INFO_SYS, PBT_SYS_CHIP_INFO, 2 },
        { "the partition question", PB_INFO_PARTITION, PBT_PART_PT_INFO, 0 },
        { "the UF2 target question", PB_INFO_UF2_TARGET, 0u, 0 },
    };

    for (unsigned i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        pbt_begin();
        pbt_start();

        picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
        pbt_args_get_info(&cmd, types[i].type, types[i].param0);

        pb_status_t got = pbt_run_cmd(&cmd);
        if (got != PB_STATUS_OK) {
            pbt_fail(__FILE__, __LINE__, "%s: %s", types[i].what,
                     pbt_status_name((int)got));
            continue;
        }
        if (pbt_count("rom_get_sys_info") != types[i].sys_calls) {
            pbt_fail(__FILE__, __LINE__, "%s asked get_sys_info %d times, "
                     "expected %d", types[i].what,
                     pbt_count("rom_get_sys_info"), types[i].sys_calls);
        }
        if (pbt_count("rom_get_partition_table_info") != 0) {
            pbt_fail(__FILE__, __LINE__, "%s asked get_partition_table_info %d "
                     "times", types[i].what,
                     pbt_count("rom_get_partition_table_info"));
        }
    }

    // The part publishes both routines all the same, so what keeps
    // get_partition_table_info at nothing is the library not looking it up.
    pbt_begin();
    pbt_start();
    PBT_CHECK(picoboot_lookup_boot_fn('G', 'S') != NULL);
    PBT_CHECK(picoboot_lookup_boot_fn('G', 'P') != NULL);
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

static void scenario_a_zero_length_otp_access_is_nothing_to_do(void) {
    pbt_begin();
    pbt_start();

    // An integrator's loop whose count came out zero reaches these with a
    // length of zero and whatever pointer it was holding, which may be a null.
    // Nothing is read and no fuse is blown, and the caller is told so rather
    // than being faulted for asking.
    PBT_CHECK_STATUS(picoboot_default_otp_read(0u, 0u, NULL, 0u, NULL),
                     PB_STATUS_OK);
    PBT_CHECK_STATUS(picoboot_default_otp_write(0u, 0u, NULL, 0u, NULL),
                     PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_otp()[0], 0u);

    // The same buffer with a row's worth in it does blow the row, so what did
    // nothing above was the length and not the call.
    uint8_t row[4] = { 0x0Fu, 0x00u, 0x00u, 0x00u };
    PBT_CHECK_STATUS(picoboot_default_otp_write(0u, 0u, row, 4u, NULL),
                     PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_otp()[0], 0x0Fu);
}

// ---------------------------------------------------------------------------
// Finding a routine at all
// ---------------------------------------------------------------------------

static void scenario_a_bootrom_routine_is_looked_up_by_its_two_characters(void) {
    pbt_begin();
    pbt_start();

    // The code is the two characters with the second one high, and the entry
    // asked for is the Arm secure one.  A lookup assembled any other way finds
    // a different routine or none at all, and every implementation above goes
    // through this one function to reach the chip.
    PBT_CHECK(picoboot_lookup_boot_fn('R', 'B') != NULL);
    PBT_REQUIRE(pbt_nth("bootrom_lookup", 0) != NULL);
    PBT_CHECK_EQ(pbt_nth("bootrom_lookup", 0)->a0,
                 ((uint32_t)(uint8_t)'B' << 8) | (uint32_t)(uint8_t)'R');
    // 0x0004 is RP2350_ROM_TABLE_FLAG_FUNC_ARM_SEC, written out rather than
    // named.  The macro is what the library passes, so an assertion against it
    // agrees with whatever the library asks for and pins nothing.
    PBT_CHECK_EQ(pbt_nth("bootrom_lookup", 0)->a1, 0x0004u);

    // A code this part does not publish is a null, not a pointer to whatever
    // the table happened to hold next.
    PBT_CHECK(picoboot_lookup_boot_fn('Z', 'Z') == NULL);

    // And the answer follows the part: withhold the routine that was there and
    // the same two characters find nothing.
    pbt_begin();
    pbt_bootrom_withhold('R', 'B');
    pbt_start();
    PBT_CHECK(picoboot_lookup_boot_fn('R', 'B') == NULL);
}

static void scenario_a_sys_info_refusal_carries_the_chips_reason(void) {
    pbt_begin();
    // 5.4.8.17 has get_sys_info return "negative error code on error".  A part
    // that will not answer at all refuses the whole call, and the host is told
    // which refusal it was rather than merely that something failed.
    pbt_sys_info_fail(ROM_PRECONDITION_NOT_MET);
    pbt_start();

    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&cmd, PB_INFO_SYS, PBT_SYS_CHIP_INFO);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_PRECONDITION_NOT_MET);
    PBT_CHECK(pbt_count("rom_get_sys_info") >= 1);

    // Nothing went to the host, so it does not have to work out how much of an
    // answer it received before the refusal.
    PBT_CHECK_EQ(pbt_packet_count(), 0u);

    // A different refusal produces a different status, so what a host is told
    // is the chip's reason and not a fixed one for GET_INFO.
    pbt_begin();
    pbt_sys_info_fail(ROM_INVALID_STATE);
    pbt_start();
    picoboot_cmd_t other = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&other, PB_INFO_SYS, PBT_SYS_CHIP_INFO);
    PBT_CHECK_STATUS(pbt_run_cmd(&other), PB_STATUS_INVALID_STATE);

    // And with the chip answering, the same request is served — so what was
    // refused was the chip's answer and not the request's shape.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t good = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&good, PB_INFO_SYS, PBT_SYS_CHIP_INFO);
    PBT_CHECK_STATUS(pbt_run_cmd(&good), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_payload_len(), 20u);
}

// 5.4.8.16 names two ways get_partition_table_info refuses on a part that is
// otherwise working — the table never loaded, and the resident copy no longer
// matching flash.  Nothing in GET_INFO asks that routine any more, so none of
// those refusals can reach a host — the two types 5.4.8.16 and 5.6.4.11 used
// to draw on it for are answered from constants instead.
static void scenario_a_partition_refusal_is_never_asked_for(void) {
    const struct {
        const char *what;
        int         rc;
    } refusals[] = {
        // 5.4.8.16: "If the partition table hasn't been loaded (for example,
        // from a watchdog or RAM boot), this method returns
        // BOOTROM_ERROR_PRECONDITION_NOT_MET".
        { "the table was never loaded", ROM_PRECONDITION_NOT_MET },
        // 5.4.8.16: "If the hash has changed by the time this method is
        // called, then it will return BOOTROM_ERROR_INVALID_STATE."
        { "the table changed under it", ROM_INVALID_STATE },
        // The resident copy no longer matching what it was built from.
        { "the resident copy went stale", ROM_MODIFIED_DATA },
    };

    const struct {
        const char    *what;
        pb_info_type_t type;
        uint32_t       param0;
        uint32_t       transfer;
    } types[] = {
        { "the partition question", PB_INFO_PARTITION, PBT_PART_PT_INFO, 20u },
        { "the UF2 target question", PB_INFO_UF2_TARGET, 0u, 16u },
    };

    for (unsigned i = 0; i < sizeof(refusals) / sizeof(refusals[0]); i++) {
        for (unsigned t = 0; t < sizeof(types) / sizeof(types[0]); t++) {
            pbt_begin();
            pbt_partition_fail(refusals[i].rc);
            pbt_start();

            picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u,
                                         types[t].transfer);
            pbt_args_get_info(&cmd, types[t].type, types[t].param0);

            pb_status_t got = pbt_run_cmd(&cmd);
            if (got != PB_STATUS_OK) {
                pbt_fail(__FILE__, __LINE__, "%s, with %s: %s", types[t].what,
                         refusals[i].what, pbt_status_name((int)got));
                continue;
            }
            if (pbt_payload_len() != types[t].transfer) {
                pbt_fail(__FILE__, __LINE__, "%s, with %s: %u bytes for a "
                         "transfer of %u", types[t].what, refusals[i].what,
                         pbt_payload_len(), types[t].transfer);
            }
            if (pbt_count("rom_get_partition_table_info") != 0) {
                pbt_fail(__FILE__, __LINE__, "%s, with %s: the routine was "
                         "asked %d times", types[t].what, refusals[i].what,
                         pbt_count("rom_get_partition_table_info"));
            }
        }
    }

    // A refusal the library does still ask for reaches the host as the chip's
    // own reason, so the answers above are the routine going unasked and not
    // the harness failing to arm one.  5.4.8.17 has get_sys_info return a
    // "negative error code on error", and Table 471 has a status for each.
    pbt_begin();
    pbt_sys_info_fail(ROM_PRECONDITION_NOT_MET);
    pbt_start();
    picoboot_cmd_t sys = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&sys, PB_INFO_SYS, PBT_SYS_CHIP_INFO);
    PBT_CHECK_STATUS(pbt_run_cmd(&sys), PB_STATUS_PRECONDITION_NOT_MET);
    PBT_CHECK(pbt_count("rom_get_sys_info") >= 1);
    PBT_CHECK_EQ(pbt_packet_count(), 0u);
}

static void scenario_a_refusal_partway_through_an_answer_is_reported(void) {
    // One GET_INFO reaches the chip twice: once to learn how long the answer
    // will be, and once for the answer itself.  A part whose state moves
    // between the two answers the first and refuses the second, and the host
    // has to be told rather than handed the prefix that had already been
    // produced.
    //
    // System information is the only type that reaches a routine at all, so it
    // is the only one that can meet a refusal partway through — picobootx_impl.h
    // has get_sys_info as "the only ROM routine either of these two reaches,
    // and only PB_INFO_SYS reaches it."  5.4.8.17 has it return a "negative
    // error code on error", and a part whose state moved between the two calls
    // answers the first and refuses the second.
    const struct {
        const char *what;
        int         rc;
        pb_status_t expected;
        const char *rom_event;
        uint32_t    words;      // what preparing said the answer would be
    } cases[] = {
        { "the chip stopped answering", ROM_INVALID_STATE,
          PB_STATUS_INVALID_STATE, "rom_get_sys_info", 4u },
        { "the chip refused the read", ROM_NOT_PERMITTED,
          PB_STATUS_NOT_PERMITTED, "rom_get_sys_info", 4u },
        // 5.4.8.16 describes a part that answers once and then refuses.  The
        // bootrom holds a hash of the partition table as of the time it loaded
        // it, and "If the hash has changed by the time this method is called,
        // then it will return BOOTROM_ERROR_INVALID_STATE".  Nothing asks that
        // routine now, but a part in that state is one 5.4.8.17's routine can
        // be in too, and it is reported the same way.
        { "the resident copy went stale", ROM_MODIFIED_DATA,
          PB_STATUS_MODIFIED_DATA, "rom_get_sys_info", 4u },
    };

    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        pbt_begin();
        pbt_sys_info_fail_after(1u, cases[i].rc);
        pbt_start();

        picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
        pbt_args_get_info(&cmd, PB_INFO_SYS, PBT_SYS_CHIP_INFO);

        pb_status_t got = pbt_run_cmd(&cmd);
        if (got != cases[i].expected) {
            pbt_fail(__FILE__, __LINE__, "%s: expected %s, got %s",
                     cases[i].what, pbt_status_name((int)cases[i].expected),
                     pbt_status_name((int)got));
        }

        // The chip was asked twice and refused the second time, which is what
        // says the refusal was met partway through and not at the outset.
        if (pbt_count(cases[i].rom_event) != 2) {
            pbt_fail(__FILE__, __LINE__, "%s: the chip was asked %d times, "
                     "expected twice", cases[i].what,
                     pbt_count(cases[i].rom_event));
        }

        // The first of those two is what the device answered the word count
        // from, and it succeeded — so the command got past preparing and failed
        // while producing.
        const pbt_event_t *prepare = pbt_nth("op_get_info_prepare", 0);
        if (prepare == NULL || prepare->a3 != (uint32_t)PB_STATUS_OK) {
            pbt_fail(__FILE__, __LINE__, "%s: the request never got past "
                     "preparing", cases[i].what);
        } else if (prepare->a2 != cases[i].words) {
            pbt_fail(__FILE__, __LINE__, "%s: prepared %u words, expected %u",
                     cases[i].what, prepare->a2, cases[i].words);
        }
        if (pbt_count("op_get_info") != 1) {
            pbt_fail(__FILE__, __LINE__, "%s: %d calls to produce the answer, "
                     "expected one", cases[i].what, pbt_count("op_get_info"));
        }

        // Nothing reached the host.  The leading word count had been produced
        // by then, and a host handed that and no more could not tell a short
        // answer from a complete one.
        if (pbt_packet_count() != 0u) {
            pbt_fail(__FILE__, __LINE__, "%s: %u packets went to the host",
                     cases[i].what, pbt_packet_count());
        }
        if (pbt_cur_state() != PB_STATE_STALLED) {
            pbt_fail(__FILE__, __LINE__, "%s: state %s", cases[i].what,
                     pbt_state_name(pbt_cur_state()));
        }
    }

    // The two constant types cannot meet a refusal partway through, because
    // they reach nothing that could refuse.  A part told to answer its first
    // call and refuse the second serves both of them whole.
    const struct {
        const char    *what;
        pb_info_type_t type;
        uint32_t       param0;
        uint32_t       transfer;
    } constants[] = {
        { "the partition question", PB_INFO_PARTITION, PBT_PART_PT_INFO, 20u },
        { "the UF2 target question", PB_INFO_UF2_TARGET, 0u, 16u },
    };

    for (unsigned i = 0; i < sizeof(constants) / sizeof(constants[0]); i++) {
        pbt_begin();
        pbt_partition_fail_after(1u, ROM_INVALID_STATE);
        pbt_start();

        picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u,
                                     constants[i].transfer);
        pbt_args_get_info(&cmd, constants[i].type, constants[i].param0);

        pb_status_t got = pbt_run_cmd(&cmd);
        if (got != PB_STATUS_OK) {
            pbt_fail(__FILE__, __LINE__, "%s: %s", constants[i].what,
                     pbt_status_name((int)got));
            continue;
        }
        if (pbt_payload_len() != constants[i].transfer) {
            pbt_fail(__FILE__, __LINE__, "%s: %u bytes for a transfer of %u",
                     constants[i].what, pbt_payload_len(),
                     constants[i].transfer);
        }
        if (pbt_count("op_get_info") != 1) {
            pbt_fail(__FILE__, __LINE__, "%s: %d calls to produce the answer",
                     constants[i].what, pbt_count("op_get_info"));
        }
    }

    // A part that answers both calls serves the same request, so what was
    // reported above was the second refusal and not the shape of the request.
    pbt_begin();
    pbt_start();
    picoboot_cmd_t good = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&good, PB_INFO_SYS, PBT_SYS_CHIP_INFO);
    PBT_CHECK_STATUS(pbt_run_cmd(&good), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_count("rom_get_sys_info"), 2);
    PBT_CHECK_EQ(pbt_payload_len(), 20u);

    // And one told to refuse from the first call fails while preparing
    // instead, which is the other side of the same boundary.
    pbt_begin();
    pbt_sys_info_fail_after(0u, ROM_INVALID_STATE);
    pbt_start();
    picoboot_cmd_t upfront = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 20u);
    pbt_args_get_info(&upfront, PB_INFO_SYS, PBT_SYS_CHIP_INFO);
    PBT_CHECK_STATUS(pbt_run_cmd(&upfront), PB_STATUS_INVALID_STATE);
    PBT_CHECK_EQ(pbt_count("rom_get_sys_info"), 1);
    PBT_CHECK_EQ(pbt_count("op_get_info"), 0);
}

// ---------------------------------------------------------------------------
// The GET_INFO defaults, called directly
//
// picobootx.h: "A type outside this enumeration never reaches it - the library
// refuses that itself, with the same status."  So through a command these two
// never meet a bType outside the four, and the protocol layer's own refusal is
// tested in the data_in suite.
//
// They are published functions all the same, and an integrator writing a device
// that serves a type of its own calls them for the rest.  Nothing stops that
// integrator handing one a type neither it nor the protocol defines, and the
// answer has to be the same one the protocol gives: Table 471's INVALID_ARG,
// "Argument is outside of range of supported values".
// ---------------------------------------------------------------------------

// Every bType outside the four 5.6.4.11 defines that a byte can hold: below
// them, one past them, and the two ends of the rest of the range.
static const uint8_t k_undefined_types[] = { 0x00u, 0x05u, 0x7Fu, 0xFFu };

#define UNDEFINED_TYPE_COUNT \
    (sizeof(k_undefined_types) / sizeof(k_undefined_types[0]))

static void scenario_the_get_info_defaults_refuse_an_undefined_type(void) {
    for (unsigned i = 0; i < UNDEFINED_TYPE_COUNT; i++) {
        const pb_info_type_t type = (pb_info_type_t)k_undefined_types[i];

        pbt_begin();
        pbt_start();

        // Sentinels, so a default that wrote something on its way to refusing
        // is visible rather than merely improbable.
        uint32_t words   = 0xA5A5A5A5u;
        uint32_t written = 0xA5A5A5A5u;
        uint8_t  buf[32];
        memset(buf, 0xEEu, sizeof(buf));

        pb_status_t prepared =
            picoboot_default_get_info_prepare(type, 0u, &words, NULL);
        if (prepared != PB_STATUS_INVALID_ARG) {
            pbt_fail(__FILE__, __LINE__, "prepare of bType 0x%02x: expected "
                     "%s, got %s", k_undefined_types[i],
                     pbt_status_name((int)PB_STATUS_INVALID_ARG),
                     pbt_status_name((int)prepared));
        }

        pb_status_t filled = picoboot_default_get_info(
            type, 0u, 0u, buf, sizeof(buf), &written, NULL);
        if (filled != PB_STATUS_INVALID_ARG) {
            pbt_fail(__FILE__, __LINE__, "fill of bType 0x%02x: expected %s, "
                     "got %s", k_undefined_types[i],
                     pbt_status_name((int)PB_STATUS_INVALID_ARG),
                     pbt_status_name((int)filled));
        }

        // Refused on the type alone.  Neither routine the two served types come
        // from was reached, so nothing was read on the way to the refusal.
        if (pbt_count("rom_get_sys_info") != 0 ||
            pbt_count("rom_get_partition_table_info") != 0) {
            pbt_fail(__FILE__, __LINE__, "bType 0x%02x reached the chip: "
                     "get_sys_info %d, get_partition_table_info %d",
                     k_undefined_types[i], pbt_count("rom_get_sys_info"),
                     pbt_count("rom_get_partition_table_info"));
        }

        // And the caller's buffer is as it was handed over.
        for (unsigned b = 0; b < sizeof(buf); b++) {
            if (buf[b] != 0xEEu) {
                pbt_fail(__FILE__, __LINE__, "fill of bType 0x%02x wrote 0x%02x "
                         "at byte %u of a buffer it refused",
                         k_undefined_types[i], buf[b], b);
                break;
            }
        }
    }

    // A type the defaults do serve, through the same two calls, is answered —
    // so what was refused was the type and not the way they were called.
    pbt_begin();
    pbt_start();

    uint32_t words   = 0u;
    uint32_t written = 0u;
    uint8_t  buf[32];
    memset(buf, 0xEEu, sizeof(buf));

    PBT_CHECK_STATUS(
        picoboot_default_get_info_prepare(PB_INFO_SYS, PBT_SYS_CPU_INFO,
                                          &words, NULL),
        PB_STATUS_OK);

    // The flags word and CPU_INFO's single word.
    PBT_CHECK_EQ(words, 2u);

    PBT_CHECK_STATUS(
        picoboot_default_get_info(PB_INFO_SYS, PBT_SYS_CPU_INFO, 0u, buf,
                                  words * 4u, &written, NULL),
        PB_STATUS_OK);
    PBT_CHECK_EQ(written, words * 4u);
    PBT_CHECK_EQ(pbt_count("rom_get_sys_info"), 2);

    uint32_t first = 0u;
    memcpy(&first, buf, sizeof(first));
    PBT_CHECK_EQ(first, PBT_SYS_CPU_INFO);

    // And the two served types that go to no routine at all.  picobootx_impl.h:
    // "PB_INFO_PARTITION and PB_INFO_UF2_TARGET are constants, so their lengths
    // are arithmetic."
    const struct {
        const char    *what;
        pb_info_type_t type;
        uint32_t       param0;
        uint32_t       words;
    } constants[] = {
        { "the partition question", PB_INFO_PARTITION, PBT_PART_PT_INFO,
          1u + PBT_DEFAULT_PT_INFO_WORDS },
        { "the UF2 target question", PB_INFO_UF2_TARGET, 0u,
          PBT_DEFAULT_UF2_TARGET_WORDS },
    };

    for (unsigned i = 0; i < sizeof(constants) / sizeof(constants[0]); i++) {
        pbt_begin();
        pbt_start();

        words = 0xA5A5A5A5u;
        pb_status_t st = picoboot_default_get_info_prepare(
            constants[i].type, constants[i].param0, &words, NULL);
        if (st != PB_STATUS_OK) {
            pbt_fail(__FILE__, __LINE__, "%s: %s", constants[i].what,
                     pbt_status_name((int)st));
            continue;
        }
        if (words != constants[i].words) {
            pbt_fail(__FILE__, __LINE__, "%s prepared %u words, expected %u",
                     constants[i].what, words, constants[i].words);
        }
        if (pbt_count("rom_get_sys_info") != 0 ||
            pbt_count("rom_get_partition_table_info") != 0) {
            pbt_fail(__FILE__, __LINE__, "%s reached the chip: get_sys_info "
                     "%d, get_partition_table_info %d", constants[i].what,
                     pbt_count("rom_get_sys_info"),
                     pbt_count("rom_get_partition_table_info"));
        }
    }
}

// picobootx_impl.h has picoboot_default_get_info produce its answer "from
// at_word onwards, in whole words — a max_len that is not a whole number of them
// has the remainder left alone."  The room the library offers is always a whole
// number of words, so through a command a part word never arises.  These are
// published functions all the same, and an integrator serving a type of its own
// calls them for the rest with whatever length it has.  Both implementations
// have to make the same thing of that length.
//
// PB_INFO_PARTITION is the type to ask it of.  picobootx.h has it "Served as a
// constant", so the default holds the whole answer and can hand out any window
// of it, which is what makes a length and an offset separable here.
static void scenario_the_get_info_default_writes_whole_words(void) {
    pbt_begin();
    pbt_start();

    uint32_t words = 0u;
    PBT_CHECK_STATUS(
        picoboot_default_get_info_prepare(PB_INFO_PARTITION, PBT_PART_PT_INFO,
                                          &words, NULL),
        PB_STATUS_OK);
    // The flags word and PT_INFO's three.
    PBT_REQUIRE(words == 1u + PBT_DEFAULT_PT_INFO_WORDS);

    // A length holding two whole words and part of a third.  Sentinels past
    // them, so a default that wrote into the part word is visible.
    uint32_t written = 0xA5A5A5A5u;
    uint8_t  buf[16];
    memset(buf, 0xEEu, sizeof(buf));

    PBT_CHECK_STATUS(
        picoboot_default_get_info(PB_INFO_PARTITION, PBT_PART_PT_INFO, 0u, buf,
                                  11u, &written, NULL),
        PB_STATUS_OK);
    PBT_CHECK_EQ(written, 8u);

    uint32_t first  = 0u;
    uint32_t second = 0u;
    memcpy(&first, buf, sizeof(first));
    memcpy(&second, buf + 4, sizeof(second));
    PBT_CHECK_EQ(first, PBT_PART_PT_INFO);
    PBT_CHECK_EQ(second, PBT_DEFAULT_PT_TABLE);

    for (unsigned b = 8; b < sizeof(buf); b++) {
        if (buf[b] != 0xEEu) {
            pbt_fail(__FILE__, __LINE__, "byte %u past the last whole word is "
                     "0x%02x", b, buf[b]);
            break;
        }
    }

    // Eight bytes take the same answer, so what the three spare bytes changed
    // was nothing — which is what says they were rounded away rather than
    // filled.
    written = 0u;
    memset(buf, 0xEEu, sizeof(buf));
    PBT_CHECK_STATUS(
        picoboot_default_get_info(PB_INFO_PARTITION, PBT_PART_PT_INFO, 0u, buf,
                                  8u, &written, NULL),
        PB_STATUS_OK);
    PBT_CHECK_EQ(written, 8u);
    memcpy(&second, buf + 4, sizeof(second));
    PBT_CHECK_EQ(second, PBT_DEFAULT_PT_TABLE);

    // And a length shorter than one word is no words at all rather than a part
    // of one.
    written = 0xA5A5A5A5u;
    memset(buf, 0xEEu, sizeof(buf));
    PBT_CHECK_STATUS(
        picoboot_default_get_info(PB_INFO_PARTITION, PBT_PART_PT_INFO, 0u, buf,
                                  3u, &written, NULL),
        PB_STATUS_OK);
    PBT_CHECK_EQ(written, 0u);
    PBT_CHECK_EQ(buf[0], 0xEEu);

    // From a word in, it is the window at_word names that is produced — the two
    // words after the two the first call above wrote, and not the answer from
    // its start again.
    written = 0xA5A5A5A5u;
    memset(buf, 0xEEu, sizeof(buf));
    PBT_CHECK_STATUS(
        picoboot_default_get_info(PB_INFO_PARTITION, PBT_PART_PT_INFO, 2u, buf,
                                  sizeof(buf), &written, NULL),
        PB_STATUS_OK);
    PBT_CHECK_EQ(written, 8u);
    memcpy(&first, buf, sizeof(first));
    memcpy(&second, buf + 4, sizeof(second));
    PBT_CHECK_EQ(first, PBT_DEFAULT_PT_LOCATION);
    PBT_CHECK_EQ(second, PBT_DEFAULT_PT_FLAGS);

    // Past the end of the answer there is nothing to give.
    written = 0xA5A5A5A5u;
    memset(buf, 0xEEu, sizeof(buf));
    PBT_CHECK_STATUS(
        picoboot_default_get_info(PB_INFO_PARTITION, PBT_PART_PT_INFO, words,
                                  buf, sizeof(buf), &written, NULL),
        PB_STATUS_OK);
    PBT_CHECK_EQ(written, 0u);
    PBT_CHECK_EQ(buf[0], 0xEEu);
}

// picobootx_impl.h on the system information half: it "is written straight into
// buf ... written whole, in one call.  The ROM routine produces the answer from
// its start and takes no offset, so this default cannot hand out a piece of one
// and has nothing to keep the rest in.  A max_len too short for the whole answer
// is declined — nothing is written and zero reported."
//
// The library asks for the whole of it in one call, from its start, so neither
// refusal arises through a command.  An integrator calling the default for a
// type it does not serve itself can meet both.
static void scenario_the_system_information_default_answers_whole(void) {
    pbt_begin();
    pbt_start();

    uint32_t words = 0u;
    PBT_CHECK_STATUS(
        picoboot_default_get_info_prepare(PB_INFO_SYS, PBT_SYS_CHIP_INFO,
                                          &words, NULL),
        PB_STATUS_OK);
    // The flags word and CHIP_INFO's three.
    PBT_REQUIRE(words == 4u);
    const uint32_t whole = words * 4u;

    // Anything short of the whole answer is declined, from nothing at all up to
    // a single byte short of it.
    const uint32_t shorts[] = { 0u, 3u, 4u, whole - 4u, whole - 1u };
    for (unsigned i = 0; i < sizeof(shorts) / sizeof(shorts[0]); i++) {
        uint32_t written = 0xA5A5A5A5u;
        uint8_t  buf[32];
        memset(buf, 0xEEu, sizeof(buf));

        pb_status_t st = picoboot_default_get_info(
            PB_INFO_SYS, PBT_SYS_CHIP_INFO, 0u, buf, shorts[i], &written, NULL);
        if (st != PB_STATUS_OK) {
            pbt_fail(__FILE__, __LINE__, "%u bytes of room: %s", shorts[i],
                     pbt_status_name((int)st));
            continue;
        }
        if (written != 0u) {
            pbt_fail(__FILE__, __LINE__, "%u bytes of room produced %u",
                     shorts[i], written);
        }
        for (unsigned b = 0; b < sizeof(buf); b++) {
            if (buf[b] != 0xEEu) {
                pbt_fail(__FILE__, __LINE__, "%u bytes of room wrote 0x%02x at "
                         "byte %u of a call it declined", shorts[i], buf[b], b);
                break;
            }
        }
    }

    // Room for the whole answer exactly, and it is served — so what was
    // declined above was the room and not the request.
    uint32_t written = 0xA5A5A5A5u;
    uint8_t  buf[32];
    memset(buf, 0xEEu, sizeof(buf));
    PBT_CHECK_STATUS(
        picoboot_default_get_info(PB_INFO_SYS, PBT_SYS_CHIP_INFO, 0u, buf,
                                  whole, &written, NULL),
        PB_STATUS_OK);
    PBT_CHECK_EQ(written, whole);

    uint32_t first  = 0u;
    uint32_t second = 0u;
    memcpy(&first, buf, sizeof(first));
    memcpy(&second, buf + 4, sizeof(second));
    PBT_CHECK_EQ(first, PBT_SYS_CHIP_INFO);
    PBT_CHECK_EQ(second, pbt_sys_info_word(PBT_SYS_CHIP_INFO));

    // A window from part way in is declined however much room comes with it,
    // because there is no piece of this answer to hand out.  Nothing is read
    // on the way to saying so.
    for (uint32_t at = 1u; at <= words + 1u; at++) {
        pbt_begin();
        pbt_start();

        written = 0xA5A5A5A5u;
        memset(buf, 0xEEu, sizeof(buf));

        pb_status_t st = picoboot_default_get_info(
            PB_INFO_SYS, PBT_SYS_CHIP_INFO, at, buf, sizeof(buf), &written,
            NULL);
        if (st != PB_STATUS_OK) {
            pbt_fail(__FILE__, __LINE__, "at_word %u: %s", at,
                     pbt_status_name((int)st));
            continue;
        }
        if (written != 0u) {
            pbt_fail(__FILE__, __LINE__, "at_word %u produced %u bytes", at,
                     written);
        }
        if (pbt_count("rom_get_sys_info") != 0) {
            pbt_fail(__FILE__, __LINE__, "at_word %u asked the chip %d times",
                     at, pbt_count("rom_get_sys_info"));
        }
        for (unsigned b = 0; b < sizeof(buf); b++) {
            if (buf[b] != 0xEEu) {
                pbt_fail(__FILE__, __LINE__, "at_word %u wrote 0x%02x at byte "
                         "%u of a call it declined", at, buf[b], b);
                break;
            }
        }
    }

    // A part that does not publish the routine has no answer to give, and says
    // so with Table 471's NOT_FOUND: "Attempted to access something that
    // doesn't exist; or a search failed".  Reached through a command, that is
    // refused while preparing and the fill is never called, so the fill's own
    // answer to it is an integrator's to meet.
    pbt_begin();
    pbt_bootrom_withhold('G', 'S');
    pbt_start();
    written = 0xA5A5A5A5u;
    memset(buf, 0xEEu, sizeof(buf));
    PBT_CHECK_STATUS(
        picoboot_default_get_info(PB_INFO_SYS, PBT_SYS_CHIP_INFO, 0u, buf,
                                  sizeof(buf), &written, NULL),
        PB_STATUS_NOT_FOUND);
    PBT_CHECK_EQ(buf[0], 0xEEu);

    // The same room from the answer's start is served, so what was declined was
    // the offset and not the call.
    pbt_begin();
    pbt_start();
    written = 0xA5A5A5A5u;
    memset(buf, 0xEEu, sizeof(buf));
    PBT_CHECK_STATUS(
        picoboot_default_get_info(PB_INFO_SYS, PBT_SYS_CHIP_INFO, 0u, buf,
                                  sizeof(buf), &written, NULL),
        PB_STATUS_OK);
    PBT_CHECK_EQ(written, whole);
    PBT_CHECK(pbt_count("rom_get_sys_info") >= 1);
    memcpy(&first, buf, sizeof(first));
    PBT_CHECK_EQ(first, PBT_SYS_CHIP_INFO);
}

// ---------------------------------------------------------------------------
// Ranges that wrap the address space
// ---------------------------------------------------------------------------

static void scenario_a_read_range_that_wraps_is_refused(void) {
    pbt_begin();
    pbt_start();

    // A region check adds the size to the address, and a 32-bit sum wraps.  The
    // first of these starts in SRAM and its end lands back in the flash window,
    // the second starts in flash and its end lands on the top of the ROM
    // window, so each looks like a range inside a region it does not touch a
    // byte of.
    PBT_CHECK_STATUS(picoboot_default_read_prepare(0x20000000u, 0xF0000000u, NULL),
                     PB_STATUS_INVALID_ARG);
    PBT_CHECK_STATUS(picoboot_default_read_prepare(0x10000000u, 0xF0008000u, NULL),
                     PB_STATUS_INVALID_ARG);

    // The same two addresses with a size that stays inside the region are
    // accepted, so what was refused was the wrap and not the address.
    PBT_CHECK_STATUS(picoboot_default_read_prepare(0x20000000u, 0x1000u, NULL),
                     PB_STATUS_OK);
    PBT_CHECK_STATUS(picoboot_default_read_prepare(0x10000000u, 0x1000u, NULL),
                     PB_STATUS_OK);
}

static void scenario_a_write_range_that_wraps_is_refused(void) {
    pbt_begin();
    pbt_start();

    // Same wrap, and a write reaching it would be handed a pointer for an
    // address the part does not answer.
    bool is_flash = true;
    PBT_CHECK_STATUS(
        picoboot_default_write_prepare(0x20000000u, 0xF0000000u, &is_flash, NULL),
        PB_STATUS_INVALID_ARG);
    PBT_CHECK_STATUS(
        picoboot_default_write_prepare(0x10000000u, 0xF0000000u, &is_flash, NULL),
        PB_STATUS_INVALID_ARG);

    // Inside the region both are accepted, and each is reported as the kind of
    // storage it is.
    is_flash = true;
    PBT_CHECK_STATUS(
        picoboot_default_write_prepare(0x20000000u, 0x1000u, &is_flash, NULL),
        PB_STATUS_OK);
    PBT_CHECK(!is_flash);
    PBT_CHECK_STATUS(
        picoboot_default_write_prepare(0x10000000u, 0x1000u, &is_flash, NULL),
        PB_STATUS_OK);
    PBT_CHECK(is_flash);
}

static void scenario_an_erase_range_that_wraps_is_refused(void) {
    pbt_begin();
    pbt_start();

    // The whole of flash and then some.  The sum wraps to zero, which is below
    // the top of the flash window, and the size is a whole number of sectors,
    // so neither of the two checks an erase makes sees anything wrong with it.
    pb_addr_size_args_t wrapping = { .addr = 0x10000000u, .size = 0xF0000000u };
    PBT_CHECK_STATUS(picoboot_default_flash_erase_prepare(&wrapping, NULL),
                     PB_STATUS_INVALID_ADDRESS);

    // A sector at that same address is accepted, so what was refused was the
    // size.
    pb_addr_size_args_t sector = { .addr = 0x10000000u, .size = 4096u };
    PBT_CHECK_STATUS(picoboot_default_flash_erase_prepare(&sector, NULL),
                     PB_STATUS_OK);
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
    { "the constant GET_INFO types need no bootrom routine",
      scenario_the_constant_info_types_need_no_bootrom_routine },
    { "only system information reaches the bootrom",
      scenario_only_system_information_reaches_the_bootrom },
    { "OTP_WRITE without its bootrom routine is refused",
      scenario_otp_write_without_its_bootrom_routine },
    { "a reboot the part no longer offers does not happen",
      scenario_a_reboot_the_part_no_longer_offers_does_not_happen },
    { "OTP access of part of a row is refused",
      scenario_otp_access_of_part_of_a_row_is_refused },
    { "a zero-length OTP access is nothing to do",
      scenario_a_zero_length_otp_access_is_nothing_to_do },
    { "a bootrom routine is looked up by its two characters",
      scenario_a_bootrom_routine_is_looked_up_by_its_two_characters },
    { "a get_sys_info refusal carries the chip's reason",
      scenario_a_sys_info_refusal_carries_the_chips_reason },
    { "a get_partition_table_info refusal is never asked for",
      scenario_a_partition_refusal_is_never_asked_for },
    { "a refusal partway through an answer is reported",
      scenario_a_refusal_partway_through_an_answer_is_reported },
    { "the GET_INFO defaults refuse an info type outside the four defined",
      scenario_the_get_info_defaults_refuse_an_undefined_type },
    { "the GET_INFO default writes whole words whatever room it is given",
      scenario_the_get_info_default_writes_whole_words },
    { "the system information default answers whole or not at all",
      scenario_the_system_information_default_answers_whole },
    { "a read range that wraps the address space is refused",
      scenario_a_read_range_that_wraps_is_refused },
    { "a write range that wraps the address space is refused",
      scenario_a_write_range_that_wraps_is_refused },
    { "an erase range that wraps the address space is refused",
      scenario_an_erase_range_that_wraps_is_refused },
};

PBT_SUITE(pbt_suite_bootrom, "bootrom", k_scenarios);
