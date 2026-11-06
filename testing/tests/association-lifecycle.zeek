# @TEST-DOC: Check association negotiation, established, release, abort, and
# @TEST-DOC: MMS conclude phases plus terminal semantic-state clearing.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT > output
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

event ICCP::presentation_message_v2(
    c: connection, is_orig: bool, recognized: bool, ppdu_type: count,
    context_id: count, abstract_syntax: string, transfer_syntax: string,
    dispatch_acse: bool, dispatch_mms: bool, inferred_mms: bool,
    payload_length: count) &priority=-20
    {
    if ( dispatch_acse )
        print fmt("presentation phase=%s kind=%s",
                  ICCP::association_phase(c), ICCP::association_kind(c));
    }

event ICCP::acse_message(
    c: connection, is_orig: bool, recognized: bool, apdu_type: count,
    application_context: string, association_result: int, reason: int,
    diagnostic_code: int, authentication_present: bool,
    authentication_length: count, is_opaque: bool, dispatch_mms: bool,
    payload_length: count) &priority=-20
    {
    print fmt("acse=%d phase=%s kind=%s", apdu_type,
              ICCP::association_phase(c), ICCP::association_kind(c));
    if ( apdu_type == 3 || apdu_type == 4 )
        print fmt("terminal pending_read=%s", ICCP::pending_read(c, 9)$name);
    }

event ICCP::mms_message(
    c: connection, is_orig: bool, recognized: bool, pdu_type: count,
    semantic_decoded: bool, body_length: count, invoke_id: int,
    service_tag: count, unconfirmed_service_tag: count,
    iccp_required_service: bool, candidate_operation: count,
    parameter_cbb: string, services: string, object_scope: count,
    object_domain: string, object_name: string, object_category: count,
    tase2_object_evidence: bool, first_variable_scope: count,
    first_variable_domain: string, first_variable_name: string,
    first_variable_category: count, first_result_type: count,
    first_result_raw: string, result_integer_count: count,
    result_first_integer: int, result_second_integer: int,
    result_component_count: count, result_first_choice: count,
    result_second_choice: count, result_third_choice: count,
    result_integer_value: int, result_floating_value: double,
    result_flags_raw: string, result_timestamp_value: int) &priority=-20
    {
    if ( pdu_type == 8 || pdu_type == 9 || pdu_type == 11 ||
         pdu_type == 12 || tase2_object_evidence )
        print fmt("mms=%d phase=%s kind=%s", pdu_type,
                  ICCP::association_phase(c), ICCP::association_kind(c));
    }

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.70, $orig_p=49152/tcp,
             $resp_h=192.0.2.80, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs, $service=set("iccp"),
        $history="", $uid="Clifecycle"
    ];
    event ICCP::presentation_message_v2(c, T, T, 2, 3, "2.2.1.0.1", "2.1.1", T, F, F, 32);
    event ICCP::acse_message(c, T, T, 0, "1.0.9506.2.3", -1, -1, -1, F, 0, F, T, 24);
    event ICCP::mms_message(c, T, T, 8, T, 16, -1, 0, 0, F, 0, "\x00", "\x01", 0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::acse_message(c, F, T, 1, "1.0.9506.2.3", 0, -1, 0, F, 0, F, T, 24);
    event ICCP::mms_message(c, F, T, 9, T, 16, -1, 0, 0, F, 0, "\x00", "\x01", 0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);
    establish_tase_evidence(c, 100);
    event ICCP::mms_message(c, T, T, 0, T, 12, 1, 6, 0, T, 4, "", "", 0, "", "Supported_Features", 1, T, 0, "", "", 0, 0, "", 0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_message(c, T, T, 0, T, 12, 9, 4, 0, T, 2, "", "", 0, "", "", 0, F, 1, "CONTROL_CENTER_B", "MW_FLOW", 0, 0, "", 0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::acse_lifecycle_v1(c, T, 2, 9);
    event ICCP::acse_message(c, T, T, 2, "", -1, 30, -1, F, 0, F, F, 0);
    event ICCP::acse_lifecycle_v1(c, F, 3, 10);
    event ICCP::acse_message(c, F, T, 3, "", -1, 0, -1, F, 0, F, F, 0);

    event ICCP::acse_message(c, T, T, 0, "1.0.9506.2.3", -1, -1, -1, F, 0, F, T, 24);
    event ICCP::mms_message(c, T, T, 8, T, 16, -1, 0, 0, F, 0, "\x00", "\x01", 0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::acse_message(c, F, T, 1, "1.0.9506.2.3", 0, -1, 0, F, 0, F, T, 24);
    event ICCP::mms_message(c, F, T, 9, T, 16, -1, 0, 0, F, 0, "\x00", "\x01", 0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::session_spdu_marker_v1(c, F, 25);
    event ICCP::acse_message(c, F, T, 4, "", -1, 1, 2, F, 0, F, F, 0);

    # Session ABORT clears Presentation state. A later association on the same
    # TCP connection must begin with a fresh CONNECT/Presentation envelope.
    event ICCP::session_spdu_marker_v1(c, T, 13);
    event ICCP::presentation_message_v2(
        c, T, T, 2, 3, "2.2.1.0.1", "2.1.1", T, F, F, 32);
    event ICCP::acse_message(c, T, T, 0, "1.0.9506.2.3", -1, -1, -1, F, 0, F, T, 24);
    event ICCP::mms_message(c, T, T, 8, T, 16, -1, 0, 0, F, 0, "\x00", "\x01", 0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::acse_message(c, F, T, 1, "1.0.9506.2.3", 0, -1, 0, F, 0, F, T, 24);
    event ICCP::mms_message(c, F, T, 9, T, 16, -1, 0, 0, F, 0, "\x00", "\x01", 0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_message(c, T, T, 11, T, 0, -1, 0, 0, F, 0, "", "", 0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_message(c, F, T, 12, T, 0, -1, 0, 0, F, 0, "", "", 0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);
    }
