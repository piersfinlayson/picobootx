// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// The stall protocol: halting both bulk endpoints on a failure, reporting the
// failure over the control endpoint, and the two ways a host clears it.

#include "pbt.h"

// Produces a stall, by the shortest route that does not need any callback to
// cooperate: a command whose declared size disagrees with the table's.
static picoboot_cmd_t stalling_command(void) {
    return pbt_cmd(0x01u, 0x02u, 0u);
}

static void scenario_stall_halts_both_endpoints(void) {
    pbt_begin();
    pbt_start();

    picoboot_cmd_t cmd = stalling_command();
    pbt_host_send_cmd(&cmd);
    pbt_pump();

    PBT_CHECK(pbt_ep_stalled(PBT_EP_OUT));
    PBT_CHECK(pbt_ep_stalled(PBT_EP_IN));

    // Both, and only both.  Halting one endpoint and not the other leaves the
    // host able to keep pushing at a device that has given up.
    PBT_CHECK_EQ(pbt_count("stall"), 2);
    PBT_REQUIRE(pbt_nth("stall", 0) != NULL && pbt_nth("stall", 1) != NULL);
    PBT_CHECK_EQ(pbt_nth("stall", 0)->a0, PBT_EP_OUT);
    PBT_CHECK_EQ(pbt_nth("stall", 1)->a0, PBT_EP_IN);

    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_STALLED);
}

static void scenario_a_halt_stops_the_host_being_heard(void) {
    pbt_begin();
    pbt_start();

    picoboot_cmd_t bad = stalling_command();
    pbt_host_send_cmd(&bad);
    pbt_pump();
    PBT_REQUIRE(pbt_ep_stalled(PBT_EP_OUT));

    // A perfectly good command sent to a halted endpoint does not reach the
    // device at all.
    picoboot_cmd_t good = pbt_cmd(0x01u, 0x01u, 0u);
    pbt_args_exclusive_access(&good, PB_EA_EXCL);
    pbt_host_send_cmd(&good);
    pbt_pump();

    PBT_CHECK_EQ(pbt_count("op_exclusive_access"), 0);
    PBT_CHECK_EQ(pbt_count("packet_out_stalled"), 1);

    // Once the host clears the halt, the same command is acted on, so what
    // stopped it was the halt and nothing about the command.
    pbt_recover();
    PBT_CHECK_STATUS(pbt_run_cmd(&good), PB_STATUS_OK);
    PBT_CHECK_EQ(pbt_count("op_exclusive_access"), 1);
}

static void scenario_status_reports_the_failure(void) {
    pbt_begin();
    pbt_start();

    // Arm the status block with a different command that succeeded.  This is
    // the case the picoboot specification cares most about — a host asks for
    // the status to find out why the bulk pipe halted — so the reported
    // identity has to be the command that halted it, not the one before.
    picoboot_cmd_t good = pbt_cmd(PB_CMD_EXIT_XIP, 0x00u, 0u);
    pbt_host_send_cmd(&good);
    pbt_pump();

    picoboot_status_t armed;
    PBT_REQUIRE(pbt_ctrl_get_status(&armed));
    PBT_REQUIRE(armed.token == good.token);
    PBT_REQUIRE(armed.cmd_id == PB_CMD_EXIT_XIP);

    picoboot_cmd_t cmd = stalling_command();
    pbt_host_send_cmd(&cmd);
    pbt_pump();

    picoboot_status_t status;
    PBT_REQUIRE(pbt_ctrl_get_status(&status));

    PBT_CHECK_STATUS(status.status_code, PB_STATUS_INVALID_CMD_LENGTH);
    PBT_CHECK_EQ(status.token, cmd.token);
    PBT_CHECK_EQ(status.cmd_id, cmd.cmd_id);
    PBT_CHECK(status.token != good.token);
    PBT_CHECK(status.cmd_id != PB_CMD_EXIT_XIP);

    // A failed command is not in progress.  A host that saw this set would keep
    // waiting for a command that has already died.
    PBT_CHECK_EQ(status.in_progress, 0u);

    // The status arrives as a sixteen-byte data stage, not as a bare
    // acknowledgement.
    PBT_CHECK_EQ(pbt_count("control_xfer"), 2);
    PBT_CHECK_EQ(pbt_ctrl_reply_len(), sizeof(picoboot_status_t));
}

static void scenario_status_explains_an_unattributed_halt(void) {
    pbt_begin();
    pbt_start();

    // Nothing has failed, so the recorded status is success — and yet an
    // endpoint is halted.  A host asking for the status has to be told
    // something has gone wrong, or it will wait forever on an endpoint that
    // will never answer.
    pbt_force_stall(PBT_EP_IN);

    picoboot_status_t status;
    PBT_REQUIRE(pbt_ctrl_get_status(&status));
    PBT_CHECK_STATUS(status.status_code, PB_STATUS_UNKNOWN_ERROR);
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_STALLED);
}

static void scenario_status_does_not_overwrite_a_known_failure(void) {
    pbt_begin();
    pbt_start();

    // The same halted-endpoint condition, but this time the library knows why.
    // The recorded reason must survive being asked for.
    picoboot_cmd_t cmd = stalling_command();
    pbt_host_send_cmd(&cmd);
    pbt_pump();

    picoboot_status_t first;
    PBT_REQUIRE(pbt_ctrl_get_status(&first));
    PBT_CHECK_STATUS(first.status_code, PB_STATUS_INVALID_CMD_LENGTH);

    // And asking twice does not turn it into something vaguer either.
    picoboot_status_t second;
    PBT_REQUIRE(pbt_ctrl_get_status(&second));
    PBT_CHECK_STATUS(second.status_code, PB_STATUS_INVALID_CMD_LENGTH);
    PBT_CHECK_EQ(second.token, cmd.token);
}

static void scenario_interface_reset_clears_everything(void) {
    pbt_begin();
    pbt_start();

    picoboot_cmd_t cmd = stalling_command();
    pbt_host_send_cmd(&cmd);
    pbt_pump();
    PBT_REQUIRE(pbt_cur_state() == PB_STATE_STALLED);

    PBT_REQUIRE(pbt_ctrl_interface_reset());

    PBT_CHECK(!pbt_ep_stalled(PBT_EP_OUT));
    PBT_CHECK(!pbt_ep_stalled(PBT_EP_IN));
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_IDLE);
    PBT_CHECK_EQ(pbt_count("unstall"), 2);

    // Answered with a status stage only — there is no data to return.
    PBT_CHECK_EQ(pbt_count("control_status"), 1);
    PBT_CHECK_EQ(pbt_count("control_xfer"), 0);

    picoboot_status_t status;
    PBT_REQUIRE(pbt_ctrl_get_status(&status));
    PBT_CHECK_STATUS(status.status_code, PB_STATUS_OK);
}

static void scenario_clear_halt_rearms_the_out_endpoint(void) {
    pbt_begin();
    pbt_start();

    picoboot_cmd_t cmd = stalling_command();
    pbt_host_send_cmd(&cmd);
    pbt_pump();
    PBT_REQUIRE(pbt_cur_state() == PB_STATE_STALLED);

    PBT_CHECK(pbt_ctrl_clear_ep_halt(PBT_EP_OUT));

    // Clearing a halt leaves the endpoint unarmed, so the receive path is
    // reset ready for the next transfer.
    PBT_CHECK_EQ(pbt_count("rx_clear"), 1);
    PBT_CHECK_EQ(pbt_count("tx_clear"), 0);
    PBT_CHECK_EQ(pbt_count("control_status"), 1);

    // The state machine is deliberately left alone: clearing a halt is the
    // host's business with the endpoint, and says nothing about the command
    // that failed.  Only INTERFACE RESET returns the device to idle.
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_STALLED);
}

static void scenario_clear_halt_resets_the_in_endpoint(void) {
    pbt_begin();
    pbt_start();

    picoboot_cmd_t cmd = stalling_command();
    pbt_host_send_cmd(&cmd);
    pbt_pump();

    PBT_CHECK(pbt_ctrl_clear_ep_halt(PBT_EP_IN));

    PBT_CHECK_EQ(pbt_count("tx_clear"), 1);
    PBT_CHECK_EQ(pbt_count("rx_clear"), 0);
    PBT_CHECK_EQ(pbt_cur_state(), PB_STATE_STALLED);
}

static void scenario_clear_halt_of_another_endpoint_is_declined(void) {
    pbt_begin();
    pbt_start();

    // An endpoint that is not picoboot's belongs to some other interface in the
    // application, and the application has to get the chance to handle it.
    PBT_CHECK(!pbt_ctrl_clear_ep_halt(0x05u));
    PBT_CHECK_EQ(pbt_count("rx_clear"), 0);
    PBT_CHECK_EQ(pbt_count("tx_clear"), 0);

    // Whereas picoboot's own endpoints are claimed, so the difference is about
    // which endpoint it is and not about the request.
    PBT_CHECK(pbt_ctrl_clear_ep_halt(PBT_EP_OUT));
    PBT_CHECK(pbt_ctrl_clear_ep_halt(PBT_EP_IN));
}

static void scenario_clear_feature_of_another_selector_is_declined(void) {
    pbt_begin();
    pbt_start();

    picoboot_cmd_t cmd = stalling_command();
    pbt_host_send_cmd(&cmd);
    pbt_pump();
    PBT_REQUIRE(pbt_ep_stalled(PBT_EP_OUT));

    // CLEAR_FEATURE carries the feature in wValue, and the only one picoboot
    // acts on is the endpoint halt.  Another selector on the same endpoint is
    // somebody else's business, so it is declined rather than treated as a
    // halt clear and used to re-arm the endpoint.
    PBT_CHECK(!pbt_ctrl(TUSB_REQ_TYPE_STANDARD, TUSB_REQ_RCPT_ENDPOINT,
                        TUSB_REQ_CLEAR_FEATURE, TUSB_REQ_FEATURE_REMOTE_WAKEUP,
                        PBT_EP_OUT, 0u));
    PBT_CHECK_EQ(pbt_count("rx_clear"), 0);
    PBT_CHECK_EQ(pbt_count("control_status"), 0);
    PBT_CHECK(pbt_ep_stalled(PBT_EP_OUT));

    // The halt selector on the same endpoint is acted on, so what was declined
    // was the selector.
    PBT_CHECK(pbt_ctrl_clear_ep_halt(PBT_EP_OUT));
    PBT_CHECK_EQ(pbt_count("rx_clear"), 1);
}

static void scenario_the_later_stages_of_a_transfer_are_claimed(void) {
    // A control transfer reaches a class driver three times: the SETUP packet,
    // then the data stage, then the acknowledgement.  picoboot answers at SETUP
    // and has nothing to add afterwards, but it still has to claim the later
    // stages — returning false from one would hand the rest of a transfer it had
    // already answered to some other driver.
    const struct {
        const char *name;
        uint8_t     type;
        uint8_t     recipient;
        uint8_t     b_request;
        uint16_t    w_value;
        uint16_t    w_index;
        uint16_t    w_length;
    } requests[] = {
        { "INTERFACE RESET", TUSB_REQ_TYPE_VENDOR, TUSB_REQ_RCPT_INTERFACE,
          0x41u, 0u, 0u, 0u },
        { "GET_COMMAND_STATUS", TUSB_REQ_TYPE_VENDOR, TUSB_REQ_RCPT_INTERFACE,
          0x42u, 0u, 0u, 16u },
        { "CLEAR_FEATURE(ENDPOINT_HALT)", TUSB_REQ_TYPE_STANDARD,
          TUSB_REQ_RCPT_ENDPOINT, TUSB_REQ_CLEAR_FEATURE,
          TUSB_REQ_FEATURE_EDPT_HALT, PBT_EP_OUT, 0u },
    };
    const uint8_t stages[] = { CONTROL_STAGE_DATA, CONTROL_STAGE_ACK };

    for (unsigned i = 0; i < sizeof(requests) / sizeof(requests[0]); i++) {
        for (unsigned s = 0; s < sizeof(stages) / sizeof(stages[0]); s++) {
            pbt_begin();
            pbt_start();

            // Arm the device with something to lose, so a later stage that
            // acted would be visible as the state or the status moving.
            picoboot_cmd_t cmd = stalling_command();
            pbt_host_send_cmd(&cmd);
            pbt_pump();
            PBT_REQUIRE(pbt_cur_state() == PB_STATE_STALLED);

            bool claimed = pbt_ctrl_at_stage(
                stages[s], requests[i].type, requests[i].recipient,
                requests[i].b_request, requests[i].w_value, requests[i].w_index,
                requests[i].w_length);

            if (!claimed) {
                pbt_fail(__FILE__, __LINE__, "%s at stage %u was declined",
                         requests[i].name, stages[s]);
            }
            if (pbt_count("control_xfer") != 0 ||
                pbt_count("control_status") != 0) {
                pbt_fail(__FILE__, __LINE__,
                         "%s at stage %u answered the host a second time",
                         requests[i].name, stages[s]);
            }
            if (pbt_cur_state() != PB_STATE_STALLED ||
                pbt_count("rx_clear") != 0 || pbt_count("tx_clear") != 0 ||
                pbt_count("unstall") != 0) {
                pbt_fail(__FILE__, __LINE__,
                         "%s at stage %u acted on the device", requests[i].name,
                         stages[s]);
            }

            // The same request at SETUP does act, so claiming the later stages
            // above is the library saying "already handled" and not the library
            // ignoring the request.
            bool setup = pbt_ctrl_at_stage(
                CONTROL_STAGE_SETUP, requests[i].type, requests[i].recipient,
                requests[i].b_request, requests[i].w_value, requests[i].w_index,
                requests[i].w_length);
            if (!setup ||
                (pbt_count("control_xfer") + pbt_count("control_status")) != 1) {
                pbt_fail(__FILE__, __LINE__,
                         "%s at SETUP did not answer the host",
                         requests[i].name);
            }
        }
    }
}

static void scenario_unrelated_control_requests_are_declined(void) {
    pbt_begin();
    pbt_start();

    // A standard request that is not a halt clear.
    PBT_CHECK(!pbt_ctrl(TUSB_REQ_TYPE_STANDARD, TUSB_REQ_RCPT_DEVICE,
                        TUSB_REQ_GET_DESCRIPTOR, 0x0100u, 0u, 18u));

    // A vendor request aimed at something other than an interface.
    PBT_CHECK(!pbt_ctrl(TUSB_REQ_TYPE_VENDOR, TUSB_REQ_RCPT_DEVICE, 0x42u, 0u,
                        0u, 16u));

    // A vendor request to the interface that picoboot does not define.
    PBT_CHECK(!pbt_ctrl(TUSB_REQ_TYPE_VENDOR, TUSB_REQ_RCPT_INTERFACE, 0x43u,
                        0u, 0u, 0u));

    // GET_COMMAND_STATUS to our own interface, under the request type the
    // specification reserves.  Every other field is one picoboot answers, so
    // what declines this is the type and nothing else.
    PBT_CHECK(!pbt_ctrl(TUSB_REQ_TYPE_INVALID, TUSB_REQ_RCPT_INTERFACE, 0x42u,
                        0u, 0u, 16u));

    // The same request addressed to a recipient that is neither the device,
    // an interface nor an endpoint.
    PBT_CHECK(!pbt_ctrl(TUSB_REQ_TYPE_VENDOR, TUSB_REQ_RCPT_OTHER, 0x42u, 0u,
                        0u, 16u));

    // Nothing was answered on the device's behalf for any of them.
    PBT_CHECK_EQ(pbt_count("control_xfer"), 0);
    PBT_CHECK_EQ(pbt_count("control_status"), 0);

    // The two the library does define are claimed, so declining above was about
    // the request and not about the library refusing everything.
    PBT_CHECK(pbt_ctrl(TUSB_REQ_TYPE_VENDOR, TUSB_REQ_RCPT_INTERFACE, 0x41u, 0u,
                       0u, 0u));
    PBT_CHECK(pbt_ctrl(TUSB_REQ_TYPE_VENDOR, TUSB_REQ_RCPT_INTERFACE, 0x42u, 0u,
                       0u, 16u));
}

static void scenario_class_requests_to_the_interface_are_claimed(void) {
    pbt_begin();
    pbt_start();

    // picoboot's control requests are vendor requests, but the library accepts
    // them as class requests too, which is what lets it sit behind a
    // tud_vendor_control_xfer_cb that sees both.
    PBT_CHECK(pbt_ctrl(TUSB_REQ_TYPE_CLASS, TUSB_REQ_RCPT_INTERFACE, 0x42u, 0u,
                       0u, 16u));
    PBT_CHECK_EQ(pbt_count("control_xfer"), 1);
}

static const pbt_scenario_t k_scenarios[] = {
    { "a failure halts both bulk endpoints",
      scenario_stall_halts_both_endpoints },
    { "a halted endpoint stops the host being heard",
      scenario_a_halt_stops_the_host_being_heard },
    { "GET_COMMAND_STATUS reports the failure and its command",
      scenario_status_reports_the_failure },
    { "GET_COMMAND_STATUS explains a halt nothing accounted for",
      scenario_status_explains_an_unattributed_halt },
    { "GET_COMMAND_STATUS does not overwrite a known failure",
      scenario_status_does_not_overwrite_a_known_failure },
    { "INTERFACE RESET clears the halt, the state and the status",
      scenario_interface_reset_clears_everything },
    { "clearing the OUT halt re-arms it and leaves the state alone",
      scenario_clear_halt_rearms_the_out_endpoint },
    { "clearing the IN halt resets it and leaves the state alone",
      scenario_clear_halt_resets_the_in_endpoint },
    { "clearing another interface's halt is declined",
      scenario_clear_halt_of_another_endpoint_is_declined },
    { "clearing a feature that is not the halt is declined",
      scenario_clear_feature_of_another_selector_is_declined },
    { "the data and acknowledgement stages are claimed without acting",
      scenario_the_later_stages_of_a_transfer_are_claimed },
    { "unrelated control requests are declined",
      scenario_unrelated_control_requests_are_declined },
    { "class-typed requests to the interface are claimed",
      scenario_class_requests_to_the_interface_are_claimed },
};

PBT_SUITE(pbt_suite_stall, "stall", k_scenarios);
