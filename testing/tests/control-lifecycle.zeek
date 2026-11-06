# @TEST-DOC: Check conservative MMS Write candidate lifecycle correlation,
# @TEST-DOC: response totals, errors, direction checks, reuse, and cleanup.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut classification outcome invoke_id object_scope object_domain object_name variable_count data_count data_node_count result_count success_count failure_count error_class error_class_code error_code provenance < iccp_controls.log > output
# @TEST-EXEC: btest-diff output

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.90, $orig_p=49152/tcp,
             $resp_h=192.0.2.100, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs, $service=set("iccp"),
        $history="", $uid="Ccontrol"
    ];

    event ICCP::presentation_message_v2(c, T, T, 2, 3,
                                     "2.2.1.0.1", "2.1.1", T, F, F, 32);
    event ICCP::acse_message(c, T, T, 0, "1.3.6.1.4.1", -1, -1, -1,
                            F, 0, F, T, 24);
    event ICCP::mms_message(
        c, T, T, 8, T, 16, -1, 0, 0, F, 0, "\x00", "\x01",
        0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);

    event ICCP::mms_control_request_deferred(c, T, 40, 1, "BILATERAL",
                                             "SETPOINT", 1, 1, 3);
    event ICCP::mms_control_message(c, F, 1, 40, 5, 0, "", "",
                                    0, 0, 0, 1, 1, 0);
    event ICCP::mms_control_request_deferred(c, T, 41, 0, "", "",
                                             2, 2, 4);
    event ICCP::mms_control_message(c, F, 1, 41, 5, 0, "", "",
                                    0, 0, 0, 2, 1, 1);
    event ICCP::mms_control_request_deferred(c, T, 42, 0, "", "",
                                             1, 1, 1);
    event ICCP::mms_control_message(c, T, 1, 42, 5, 0, "", "",
                                    0, 0, 0, 1, 1, 0);
    event ICCP::mms_control_message(c, F, 1, 42, 5, 0, "", "",
                                    0, 0, 0, 1, 1, 0);
    event ICCP::mms_control_message(c, F, 1, 99, 5, 0, "", "",
                                    0, 0, 0, 1, 1, 0);
    event ICCP::mms_control_request_deferred(c, T, 43, 0, "", "FIRST",
                                             1, 1, 1);
    event ICCP::mms_control_request_deferred(c, T, 43, 0, "", "LATEST",
                                             1, 1, 2);
    event ICCP::mms_control_message(c, F, 1, 43, 5, 0, "", "",
                                    0, 0, 0, 1, 1, 0);
    event ICCP::mms_control_request_deferred(c, T, 44, 0, "", "REJECTED",
                                             1, 1, 1);
    event ICCP::mms_error_message(c, T, 2, 44, -1, 7, 3, -1, "");
    event ICCP::mms_error_message(c, F, 2, 44, -1, 7, 3, -1, "");
    event ICCP::mms_control_request_deferred(c, T, 45, 0, "", "ABORTED",
                                             1, 1, 1);
    event ICCP::acse_message(c, F, T, 4, "", -1, 1, 2,
                            F, 0, F, F, 0);
    event ICCP::mms_control_message(c, F, 1, 45, 5, 0, "", "",
                                    0, 0, 0, 1, 1, 0);
    }
