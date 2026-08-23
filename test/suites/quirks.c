// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// The things picobootx does on purpose that look wrong, and the numbers on the
// wire that a host decodes.
//
// picotool departs from the PICOBOOT specification in several places, and
// picobootx accommodates each departure deliberately.  Those accommodations are
// the ones a later tidy-up would remove — they read as bugs — so they are
// pinned here with what they are for.
//
// Not everything in the README's quirk list can be pinned from this side.  Two
// of them are about the USB descriptor rather than the protocol: that the
// picoboot interface is interface 0 when it is the only one and interface 1
// otherwise, and that interface 0 must be vendor class with a zero subclass and
// protocol whatever else the device exposes.  Neither is visible to the core,
// which never sees a descriptor.

#include <stddef.h>
#include <string.h>

#include "pbt.h"
#include "pbt_lib.h"

static uint32_t payload_word(uint32_t index) {
    uint32_t word = 0;
    if ((index + 1u) * 4u <= pbt_payload_len()) {
        memcpy(&word, pbt_payload() + (index * 4u), sizeof(word));
    }
    return word;
}

static void scenario_get_info_accepts_a_256_byte_transfer(void) {
    pbt_begin();
    pbt_start();

    // The specification says a GET_INFO transfer length must be "a multiple of
    // 4, and less than 256".  picotool asks for exactly 256.  Refusing it would
    // make every picotool query fail, so 256 is accepted.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 256u);
    pbt_args_get_info(&cmd, PB_INFO_SYS, 0x0001u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_payload_len(), 256u);
}

static void scenario_get_info_transfer_length_bounds(void) {
    // Where the accommodation stops.  256 is in and 260 is out, so the bound
    // moved by exactly the one value picotool needs and not by more.
    const struct {
        uint32_t    length;
        pb_status_t expected;
    } cases[] = {
        { 0u,   PB_STATUS_INVALID_TRANSFER_LEN },
        { 2u,   PB_STATUS_INVALID_TRANSFER_LEN },
        { 4u,   PB_STATUS_OK },
        { 254u, PB_STATUS_INVALID_TRANSFER_LEN },
        { 252u, PB_STATUS_OK },
        { 256u, PB_STATUS_OK },
        { 260u, PB_STATUS_INVALID_TRANSFER_LEN },
    };

    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        pbt_begin();
        pbt_start();

        picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, cases[i].length);
        pbt_args_get_info(&cmd, PB_INFO_SYS, 0x0004u);

        pb_status_t got = pbt_run_cmd(&cmd);
        if (got != cases[i].expected) {
            pbt_fail(__FILE__, __LINE__,
                     "GET_INFO transfer_len %u: expected %s, got %s",
                     cases[i].length, pbt_status_name((int)cases[i].expected),
                     pbt_status_name((int)got));
        }
    }
}

static void scenario_get_info_gives_the_host_the_length_it_asked_for(void) {
    pbt_begin();
    pbt_start();

    // picotool asks for 256 bytes whatever it actually wants, so GET_INFO's
    // transfer length is not checked against the data the request implies.
    // Every other data-in command derives its length from its arguments and
    // insists the two agree.  This one pads instead.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_GET_INFO, 0x10u, 256u);
    pbt_args_get_info(&cmd, PB_INFO_SYS, 0x0004u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_OK);
    PBT_REQUIRE(pbt_payload_len() == 256u);

    // Eight bytes of answer, then padding to the length asked for.
    PBT_CHECK_EQ(payload_word(0), 1u);
    PBT_CHECK_EQ(payload_word(1), pbt_sys_info_word(0x0004u));
    for (uint32_t i = 2; i < 64u; i++) {
        if (payload_word(i) != 0u) {
            pbt_fail(__FILE__, __LINE__, "word %u of the padding is 0x%08x", i,
                     payload_word(i));
            break;
        }
    }

    // Four packets: three full and a tail.
    PBT_CHECK_EQ(pbt_packet_count(), 4u);
}

static void scenario_read_still_insists_its_lengths_agree(void) {
    pbt_begin();
    pbt_start();

    // The accommodation above is specific to GET_INFO.  Every other data-in
    // command still requires the transfer length to match its arguments, so the
    // relaxation was not applied across the board.
    picoboot_cmd_t cmd = pbt_cmd(PB_CMD_READ, 0x08u, 256u);
    pbt_args_addr_size(&cmd, RP2350_SRAM_BASE, 16u);

    PBT_CHECK_STATUS(pbt_run_cmd(&cmd), PB_STATUS_INVALID_TRANSFER_LEN);
}

static void scenario_the_control_endpoint_is_64_bytes(void) {
    // picoboot requires a 64-byte control endpoint.  picobootx.h asserts this
    // at compile time against the tinyusb configuration, which is where it is
    // enforced.  Recording it here says what the number is and why.
    PBT_CHECK_EQ(CFG_TUD_ENDPOINT0_SIZE, 64);
}

static void scenario_the_wire_structures(void) {
    // A host decodes these byte for byte, so their layout is the protocol.
    PBT_CHECK_EQ(sizeof(picoboot_cmd_t), PICOBOOT_CMD_LEN);
    PBT_CHECK_EQ(PICOBOOT_CMD_LEN, 32u);
    PBT_CHECK_EQ(sizeof(picoboot_status_t), PICOBOOT_STATUS_LEN);
    PBT_CHECK_EQ(PICOBOOT_STATUS_LEN, 16u);
    PBT_CHECK_EQ(PICOBOOT_ARGS_LEN, 16u);

    PBT_CHECK_EQ(offsetof(picoboot_cmd_t, magic), 0u);
    PBT_CHECK_EQ(offsetof(picoboot_cmd_t, token), 4u);
    PBT_CHECK_EQ(offsetof(picoboot_cmd_t, cmd_id), 8u);
    PBT_CHECK_EQ(offsetof(picoboot_cmd_t, cmd_size), 9u);
    PBT_CHECK_EQ(offsetof(picoboot_cmd_t, transfer_len), 12u);
    PBT_CHECK_EQ(offsetof(picoboot_cmd_t, args), 16u);

    PBT_CHECK_EQ(offsetof(picoboot_status_t, token), 0u);
    PBT_CHECK_EQ(offsetof(picoboot_status_t, status_code), 4u);
    PBT_CHECK_EQ(offsetof(picoboot_status_t, cmd_id), 8u);
    PBT_CHECK_EQ(offsetof(picoboot_status_t, in_progress), 9u);

    // The argument overlays a host fills in.
    PBT_CHECK_EQ(sizeof(pb_addr_size_args_t), 8u);
    PBT_CHECK_EQ(sizeof(pb_reboot2_args_t), 16u);
    PBT_CHECK_EQ(sizeof(pb_get_info_args_t), 8u);
    PBT_CHECK_EQ(sizeof(pb_otp_args_t), 5u);
    PBT_CHECK_EQ(sizeof(pb_exclusive_access_args_t), 1u);
}

static void scenario_the_wire_numbers(void) {
    PBT_CHECK_EQ(PICOBOOT_MAGIC, 0x431fd10bu);
    PBT_CHECK_EQ(PICOBOOT_DIR_IN, 0x80u);

    // Command identifiers, and which of them the host reads data back from.
    PBT_CHECK_EQ(PB_CMD_EXCLUSIVE_ACCESS, 0x01u);
    PBT_CHECK_EQ(PB_CMD_REBOOT, 0x02u);
    PBT_CHECK_EQ(PB_CMD_FLASH_ERASE, 0x03u);
    PBT_CHECK_EQ(PB_CMD_WRITE, 0x05u);
    PBT_CHECK_EQ(PB_CMD_EXIT_XIP, 0x06u);
    PBT_CHECK_EQ(PB_CMD_ENTER_XIP, 0x07u);
    PBT_CHECK_EQ(PB_CMD_EXEC, 0x08u);
    PBT_CHECK_EQ(PB_CMD_VECTORIZE_FLASH, 0x09u);
    PBT_CHECK_EQ(PB_CMD_REBOOT2, 0x0au);
    PBT_CHECK_EQ(PB_CMD_OTP_WRITE, 0x0du);
    PBT_CHECK_EQ(PB_CMD_READ, 0x84u);
    PBT_CHECK_EQ(PB_CMD_GET_INFO, 0x8bu);
    PBT_CHECK_EQ(PB_CMD_OTP_READ, 0x8cu);

    // Status codes, which a host reports to its user by number.
    PBT_CHECK_EQ(PB_STATUS_OK, 0);
    PBT_CHECK_EQ(PB_STATUS_UNKNOWN_CMD, 1);
    PBT_CHECK_EQ(PB_STATUS_INVALID_CMD_LENGTH, 2);
    PBT_CHECK_EQ(PB_STATUS_INVALID_TRANSFER_LEN, 3);
    PBT_CHECK_EQ(PB_STATUS_INVALID_ADDRESS, 4);
    PBT_CHECK_EQ(PB_STATUS_BAD_ALIGNMENT, 5);
    PBT_CHECK_EQ(PB_STATUS_UNSUPPORTED_MOD, 17);

    // GET_INFO types, and the flash geometry the arguments are expressed in.
    PBT_CHECK_EQ(PB_INFO_SYS, 0x01u);
    PBT_CHECK_EQ(PB_INFO_PARTITION, 0x02u);
    PBT_CHECK_EQ(FLASH_PAGE_SIZE, 256u);
    PBT_CHECK_EQ(FLASH_SECTOR_SIZE, 4096u);
    PBT_CHECK_EQ(FLASH_BLOCK_SIZE, 65536u);
}

static void scenario_the_control_request_numbers(void) {
    pbt_begin();
    pbt_start();

    // A host addresses these two by number, so the numbers are the interface.
    // Their neighbours are not claimed, which is what makes the two assertions
    // above about these requests rather than about any vendor request.
    PBT_CHECK(pbt_ctrl(TUSB_REQ_TYPE_VENDOR, TUSB_REQ_RCPT_INTERFACE, 0x41u, 0u,
                       0u, 0u));
    PBT_CHECK(pbt_ctrl(TUSB_REQ_TYPE_VENDOR, TUSB_REQ_RCPT_INTERFACE, 0x42u, 0u,
                       0u, 16u));
    PBT_CHECK(!pbt_ctrl(TUSB_REQ_TYPE_VENDOR, TUSB_REQ_RCPT_INTERFACE, 0x40u,
                        0u, 0u, 0u));
    PBT_CHECK(!pbt_ctrl(TUSB_REQ_TYPE_VENDOR, TUSB_REQ_RCPT_INTERFACE, 0x43u,
                        0u, 0u, 0u));
}

static void scenario_the_serial_number_is_sixteen_hex_digits(void) {
    pbt_begin();
    // A chip identifier whose bytes are all different, so a serial built in the
    // wrong order does not come out looking right.
    pbt_otp()[0] = 0x00001122u;
    pbt_otp()[1] = 0x00003344u;
    pbt_otp()[2] = 0x00005566u;
    pbt_otp()[3] = 0x00007788u;
    pbt_start();

    uint16_t serial[17];
    memset(serial, 0, sizeof(serial));
    size_t len = picoboot_get_serial(serial, 17u);

    // Sixteen UTF-16 code units and a terminator, which is what a USB string
    // descriptor is filled from.
    PBT_CHECK_EQ(len, 16u);
    PBT_CHECK_EQ(serial[16], 0u);

    // Most significant word first, four hex digits each.
    const char *expected = "7788556633441122";
    for (unsigned i = 0; i < 16u; i++) {
        if (serial[i] != (uint16_t)expected[i]) {
            pbt_fail(__FILE__, __LINE__,
                     "serial digit %u is '%c', expected '%c'", i,
                     (char)serial[i], expected[i]);
            break;
        }
    }

    // Read through the ECC view, which is why only the low half of each row
    // appears above.
    PBT_REQUIRE(pbt_nth("rom_otp_access", 0) != NULL);
    PBT_CHECK_EQ(pbt_nth("rom_otp_access", 0)->a2, 1u);
}

static void scenario_the_serial_refuses_a_buffer_that_is_too_small(void) {
    pbt_begin();
    pbt_start();

    uint16_t serial[16];
    memset(serial, 0xFFu, sizeof(serial));

    // One code unit short of what it needs, since the terminator has to fit
    // too.  Writing anyway would run off the end of a caller's descriptor.
    PBT_CHECK_EQ(picoboot_get_serial(serial, 16u), 0u);
    PBT_CHECK_EQ(pbt_count("rom_otp_access"), 0);
    PBT_CHECK_EQ(serial[0], 0xFFFFu);
}

static void scenario_the_serial_without_a_bootrom_routine(void) {
    pbt_begin();
    pbt_bootrom_withhold('O', 'A');
    pbt_start();

    uint16_t serial[17];
    memset(serial, 0, sizeof(serial));

    PBT_CHECK_EQ(picoboot_get_serial(serial, 17u), 0u);
    PBT_CHECK_EQ(serial[0], 0u);
}

// ---------------------------------------------------------------------------
// The library's own types
// ---------------------------------------------------------------------------

static void scenario_the_library_built_the_wire_it_was_given(void) {
    // Everything above measures picobootx.h, which is compiled into this binary
    // whichever library is linked, so it says nothing about a library that
    // declares its own copies of these types.  This asks the library what it
    // built, and holds it to the header.
    //
    // The C library is built from that header and so agrees by construction.
    // For any other, this is the only thing standing between a status of the
    // wrong width and every operation reading a different byte — a
    // disagreement no linker can see.
    uint32_t got[PBT_LAYOUT_COUNT];
    uint32_t count = pbt_lib_layout(got, PBT_LAYOUT_COUNT);
    PBT_REQUIRE(count == PBT_LAYOUT_COUNT);

    PBT_CHECK_EQ(got[PBT_LAYOUT_STATUS_SIZE], sizeof(pb_status_t));
    PBT_CHECK_EQ(got[PBT_LAYOUT_CMD_SIZE], sizeof(picoboot_cmd_t));
    PBT_CHECK_EQ(got[PBT_LAYOUT_CMD_ALIGN], _Alignof(picoboot_cmd_t));
    PBT_CHECK_EQ(got[PBT_LAYOUT_CMD_OFF_MAGIC], offsetof(picoboot_cmd_t, magic));
    PBT_CHECK_EQ(got[PBT_LAYOUT_CMD_OFF_TOKEN], offsetof(picoboot_cmd_t, token));
    PBT_CHECK_EQ(got[PBT_LAYOUT_CMD_OFF_CMD_ID], offsetof(picoboot_cmd_t, cmd_id));
    PBT_CHECK_EQ(got[PBT_LAYOUT_CMD_OFF_CMD_SIZE], offsetof(picoboot_cmd_t, cmd_size));
    PBT_CHECK_EQ(got[PBT_LAYOUT_CMD_OFF_TRANSFER_LEN],
                 offsetof(picoboot_cmd_t, transfer_len));
    PBT_CHECK_EQ(got[PBT_LAYOUT_CMD_OFF_ARGS], offsetof(picoboot_cmd_t, args));
    PBT_CHECK_EQ(got[PBT_LAYOUT_STATUS_PACKET_SIZE], sizeof(picoboot_status_t));

    // The two callback tables and the setup packet.  A member inserted into
    // the middle of one of these still compiles on both sides and reads a
    // different function pointer at run time, which is the quietest way this
    // could go wrong.
    PBT_CHECK_EQ(got[PBT_LAYOUT_OPS_SIZE], sizeof(picoboot_ops_t));
    PBT_CHECK_EQ(got[PBT_LAYOUT_OPS_OFF_OTP_WRITE], offsetof(picoboot_ops_t, otp_write));
    PBT_CHECK_EQ(got[PBT_LAYOUT_CUSTOM_OPS_SIZE], sizeof(picoboot_custom_ops_t));
    PBT_CHECK_EQ(got[PBT_LAYOUT_CUSTOM_OPS_OFF_FILL],
                 offsetof(picoboot_custom_ops_t, fill));
    PBT_CHECK_EQ(got[PBT_LAYOUT_CTRL_REQUEST_SIZE], sizeof(tusb_control_request_t));
}

static void scenario_the_library_names_its_own_states(void) {
    // The state machine is internal, so the harness asks the library what it
    // calls a state rather than keeping a table of its own — a failure message
    // and a log line then say the library's word.  A library whose names are
    // in a different order from its numbers puts the wrong word on every one,
    // which nothing else here would notice.
    const struct {
        pb_state_t  state;
        const char *name;
    } cases[] = {
        { PB_STATE_IDLE,      "IDLE" },
        { PB_STATE_DATA_OUT,  "DATA_OUT" },
        { PB_STATE_DATA_IN,   "DATA_IN" },
        { PB_STATE_CUSTOM_IN, "CUSTOM_IN" },
        { PB_STATE_AWAIT_ZLP, "AWAIT_ZLP" },
        { PB_STATE_AWAIT_ACK, "AWAIT_ACK" },
        { PB_STATE_STALLED,   "STALLED" },
    };

    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const char *got = pbt_lib_state_name(cases[i].state);
        if (got == NULL) {
            pbt_fail(__FILE__, __LINE__, "state %u has no name",
                     (unsigned)cases[i].state);
            continue;
        }
        if (strcmp(got, cases[i].name) != 0) {
            pbt_fail(__FILE__, __LINE__, "state %u: expected %s, got %s",
                     (unsigned)cases[i].state, cases[i].name, got);
        }
    }

    // A number that is not a state has no name, so the harness prints that it
    // is not one rather than whatever sits past the end of the table.
    PBT_CHECK(pbt_lib_state_name((pb_state_t)(PB_STATE_STALLED + 1)) == NULL);
    PBT_CHECK(pbt_lib_state_name((pb_state_t)0xFFu) == NULL);
}

static const pbt_scenario_t k_scenarios[] = {
    { "GET_INFO accepts the 256-byte transfer picotool asks for",
      scenario_get_info_accepts_a_256_byte_transfer },
    { "GET_INFO's transfer length bounds",
      scenario_get_info_transfer_length_bounds },
    { "GET_INFO returns the length asked for, padded",
      scenario_get_info_gives_the_host_the_length_it_asked_for },
    { "READ still insists its two lengths agree",
      scenario_read_still_insists_its_lengths_agree },
    { "the control endpoint is 64 bytes",
      scenario_the_control_endpoint_is_64_bytes },
    { "the wire structures",
      scenario_the_wire_structures },
    { "the wire numbers",
      scenario_the_wire_numbers },
    { "the control request numbers",
      scenario_the_control_request_numbers },
    { "the serial number is sixteen hex digits, most significant first",
      scenario_the_serial_number_is_sixteen_hex_digits },
    { "the serial refuses a buffer that is too small",
      scenario_the_serial_refuses_a_buffer_that_is_too_small },
    { "the serial without a bootrom routine",
      scenario_the_serial_without_a_bootrom_routine },
    { "the library built the wire it was given",
      scenario_the_library_built_the_wire_it_was_given },
    { "the library names its own states",
      scenario_the_library_names_its_own_states },
};

PBT_SUITE(pbt_suite_quirks, "quirks", k_scenarios);
