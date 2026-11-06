# @TEST-DOC: Verify conservative GetVariableAccessAttributes lifecycle state.
# @TEST-DOC: Invoke reuse becomes ambiguous, direction is enforced, connection
# @TEST-DOC: state is isolated, errors clear pending state, and later fully
# @TEST-DOC: correlated discovery activates only explicit site mappings.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut uid action outcome list_name named_type < iccp_transfers.log > output
# @TEST-EXEC: btest-diff output

module ICCP;

redef ICCP::legacy_gva_direct_event_compatibility = T;

function establish_tase2(c: connection)
    {
    event ICCP::presentation_message_v2(
        c, T, T, 2, 3, "2.2.1.0.1", "2.1.1", T, F, F, 32);
    event ICCP::acse_message(
        c, T, T, 0, "1.0.9506.2.3", -1, -1, -1,
        F, 0, F, T, 24);
    event ICCP::mms_message(
        c, T, T, 8, T, 16, -1, 0, 0, F, 0, "\x00", "\x01",
        0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::acse_message(
        c, F, T, 1, "1.0.9506.2.3", 0, -1, 0,
        F, 0, F, T, 24);
    event ICCP::mms_read_message_v3(
        c, T, 0, 8, 0, 1, 0, "", "Supported_Features", 1,
        0, 0, 0, "", 0, 0, 0, 0, 0, 0, 1);
    event ICCP::mms_read_message_v3(
        c, F, 1, 8, 0, 0, 0, "", "", 0,
        1, 0, 4, "\x04\xa0", 0, 0, 0, 0, 0, 0, 1);
    }

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.10, $orig_p=49152/tcp,
             $resp_h=192.0.2.20, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs, $service=set("iccp"),
        $history="", $uid="Ctype-lifecycle"
    ];
    local other: connection = [
        $id=[$orig_h=192.0.2.30, $orig_p=49153/tcp,
             $resp_h=192.0.2.40, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs, $service=set("iccp"),
        $history="", $uid="Ctype-other"
    ];
    establish_tase2(c);
    establish_tase2(other);

    ICCP::configured_variable_types[c$id$resp_h, c$id$orig_h, 0, "", "PointA"] =
        "Data_RealQ";
    ICCP::configured_variable_types[c$id$resp_h, c$id$orig_h, 0, "", "PointC"] =
        "Data_State";
    ICCP::configured_variable_types[c$id$resp_h, c$id$orig_h, 0, "", "PointD"] =
        "Data_Discrete";
    ICCP::configured_variable_types[c$id$resp_h, c$id$orig_h, 0, "", "PointE"] =
        "Data_RealQ";
    ICCP::configured_variable_types[c$id$resp_h, c$id$orig_h, 0, "", "PointF"] =
        "Data_Real";
    ICCP::configured_variable_types[c$id$resp_h, c$id$orig_h, 0, "", "PointG"] =
        "Data_RealQ";
    ICCP::configured_variable_types[c$id$resp_h, c$id$orig_h, 0, "", "PointH"] =
        "Not_TASE2";

    event ICCP::mms_variable_type_message(
        c, T, 0, 30, 6, 0, "", "PointA", 0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, T, 0, 30, 6, 0, "", "PointB", 0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, F, 1, 30, 6, 0, "", "", 0, 0, "", "Data_Real");
    event ICCP::mms_variable_type_message(
        c, T, 0, 30, 6, 0, "", "PointA", 0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, F, 1, 30, 6, 0, "", "", 0, 0, "", "Data_RealQ");

    event ICCP::mms_variable_type_message(
        c, T, 0, 31, 6, 0, "", "PointC", 0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, T, 1, 31, 6, 0, "", "", 0, 0, "", "Data_State");
    event ICCP::mms_variable_type_message(
        c, F, 1, 31, 6, 0, "", "", 0, 0, "", "Data_State");

    event ICCP::mms_variable_type_message(
        c, T, 0, 32, 6, 0, "", "PointD", 0, 0, "", "");
    event ICCP::mms_variable_type_message(
        other, F, 1, 32, 6, 0, "", "", 0, 0, "", "Data_Discrete");
    event ICCP::mms_variable_type_message(
        c, F, 1, 32, 6, 0, "", "", 0, 0, "", "Data_Discrete");

    event ICCP::mms_variable_type_message(
        c, T, 0, 33, 6, 0, "", "PointE", 0, 0, "", "");
    event ICCP::mms_error_message(c, F, 2, 33, -1, 7, 3, -1, "");
    event ICCP::mms_variable_type_message(
        c, F, 1, 33, 6, 0, "", "", 0, 0, "", "Data_RealQ");
    event ICCP::mms_variable_type_message(
        c, T, 0, 34, 6, 0, "", "PointA", 0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, F, 1, 34, 6, 0, "", "", 0, 0, "", "Data_Discrete");

    # A same-direction error is not a valid terminal for the request.
    event ICCP::mms_variable_type_message(
        c, T, 0, 35, 6, 0, "", "PointF", 0, 0, "", "");
    event ICCP::mms_error_message(c, T, 2, 35, -1, 7, 3, -1, "");
    event ICCP::mms_variable_type_message(
        c, F, 1, 35, 6, 0, "", "", 0, 0, "", "Data_Real");

    # A response before its request is unmatched and cannot poison fresh state.
    event ICCP::mms_variable_type_message(
        c, F, 1, 36, 6, 0, "", "", 0, 0, "", "Data_RealQ");
    event ICCP::mms_variable_type_message(
        c, T, 0, 36, 6, 0, "", "PointG", 0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, F, 1, 36, 6, 0, "", "", 0, 0, "", "Data_RealQ");

    # Address-form requests and unsupported named types cannot teach state.
    event ICCP::mms_variable_type_message(
        c, T, 0, 37, 6, 0, "", "PointH", 0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, F, 1, 37, 6, 0, "", "", 0, 0, "", "Not_TASE2");
    event ICCP::mms_variable_type_message(
        c, T, 0, 38, 6, 0, "", "", 0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, F, 1, 38, 6, 0, "", "", 0, 0, "", "Data_Real");
    event ICCP::mms_variable_type_message(
        c, T, 0, 39, 6, 0, "", "PointI", 0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, F, 1, 39, 6, 0, "", "", 0, 0, "", "Data_Real");
    event connection_state_remove(c);
    }
