# @TEST-DOC: Check bounded confirmed-request/service-error correlation,
# @TEST-DOC: direction validation, and preservation of MMS diagnostics.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut association_kind outcome invoke_id operation service_tag modifier_position error_class error_class_code error_code additional_code description provenance < iccp_errors.log > output
# @TEST-EXEC: btest-diff output

function establish_tase_evidence(c: connection, invoke_id: int)
    {
    event ICCP::mms_read_message_v3(
        c, T, 0, invoke_id, 0, 1, 0, "", "Supported_Features", 1,
        0, 0, 0, "", 0, 0, 0, 0, 0, 0, 1);
    event ICCP::mms_read_message_v3(
        c, F, 1, invoke_id, 0, 0, 0, "", "", 0,
        1, 0, 4, "\x07\x80", 0, 0, 0, 0, 0, 0, 1);
    }

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.50, $orig_p=49152/tcp,
             $resp_h=192.0.2.60, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs, $service=set("iccp"),
        $history="", $uid="Cerror"
    ];
    event ICCP::presentation_message_v2(c, T, T, 2, 3, "2.2.1.0.1", "2.1.1", T, F, F, 32);
    event ICCP::acse_message(c, T, T, 0, "1.3.6.1.4.1", -1, -1, -1,
                            F, 0, F, T, 24);
    event ICCP::acse_message(c, F, T, 1, "1.3.6.1.4.1", 0, -1, 0,
                            F, 0, F, T, 24);
    event ICCP::mms_message(
        c, T, T, 8, T, 16, -1, 0, 0, F, 0, "\x00", "\x01",
        0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    establish_tase_evidence(c, 100);
    event ICCP::mms_message(
        c, T, T, 0, T, 24, 6, 6, 0, T, 4, "", "",
        0, "", "Supported_Features", 1, T,
        0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);

    event ICCP::mms_message(
        c, T, T, 0, T, 12, 7, 4, 0, T, 2, "", "",
        0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_error_message(c, F, 2, 7, 1, 4, 2, 7, "read failed");

    event ICCP::mms_message(
        c, T, T, 0, T, 12, 8, 5, 0, T, 3, "", "",
        0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_error_message(c, T, 2, 8, -1, 7, 3, -1, "");
    event ICCP::mms_error_message(c, F, 2, 8, -1, 7, 3, -1, "");
    event ICCP::mms_error_message(c, F, 2, 9, -1, 2, 1, -1, "");
    }
