# @TEST-DOC: Check conservative live association classification, endpoint roles,
# @TEST-DOC: MMS negotiation state, candidate operation mapping, and parsing a
# @TEST-DOC: valid service even when every advertised capability bit is clear.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut layer association_kind endpoint_role operation transfer_kind invoke_id service_tag object_scope object_domain object_name object_category name_model domain_kind bilateral_domain value_type standardized_value conformance_blocks point_type state_value integer_value floating_value validity value_source normal_value timestamp_quality timestamp_value cov_value < iccp.log > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: zeek-cut observation_kind association_kind operation invoke_id object_scope object_domain object_name object_category name_model domain_kind bilateral_domain value_type standardized_value conformance_blocks point_type state_value integer_value floating_value validity value_source normal_value timestamp_quality timestamp_value cov_value < iccp_objects.log > objects
# @TEST-EXEC: btest-diff objects
# @TEST-EXEC: zeek-cut object_name conditions condition_mask point_type < iccp_objects.log | grep '^DSConditions_Detected' > conditions
# @TEST-EXEC: btest-diff conditions
# @TEST-EXEC: zeek-cut object_name point_type standardized_value < iccp_objects.log | grep -E '^MW_(WRONG_ORDER|WIDE_REAL)' > type-order
# @TEST-EXEC: btest-diff type-order
# @TEST-EXEC: zeek-cut action list_name named_type < iccp_transfers.log | grep '^type_discovery' > types
# @TEST-EXEC: btest-diff types

redef ICCP::legacy_gva_direct_event_compatibility = T;

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[
            $orig_h=192.0.2.10,
            $orig_p=49152/tcp,
            $resp_h=192.0.2.20,
            $resp_p=102/tcp
        ],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(),
        $duration=0secs,
        $service=set("iccp"),
        $history="",
        $uid="Cassociation"
    ];

    event ICCP::presentation_message_v2(
        c, T, T, 2, 3, "2.2.1.0.1", "2.1.1", T, F, F, 32);
    event ICCP::acse_message(
        c, T, T, 0, "1.3.6.1.4.1", -1, -1, -1,
        F, 0, F, T, 24);
    event ICCP::acse_message(
        c, F, T, 1, "1.3.6.1.4.1", 0, -1, 0,
        F, 0, F, T, 24);
    event ICCP::mms_message(
        c, T, T, 8, T, 16, -1, 0, 0, F, 0, "\x00", "\x01",
        0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_message(
        c, T, T, 0, T, 12, 7, 4, 0, T, 2, "", "",
        0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_message(
        c, T, T, 0, T, 24, 8, 6, 0, T, 4, "", "",
        0, "", "Supported_Features", 1, T,
        0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_message(
        c, T, T, 0, T, 24, 9, 6, 0, T, 4, "", "",
        1, "CONTROL_CENTER_B", "Bilateral_Table_ID", 2, T,
        0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    # A standardized name in a GVA request is only a peer claim.  Learn the
    # bilateral domain from an exact explicit-variable Read whose successful
    # VisibleString response is correlated to the opposite endpoint.
    event ICCP::mms_provenance_marker_v1(c, T, 1);
    event ICCP::mms_read_message_v3(
        c, T, 0, 19, 0, 1,
        1, "CONTROL_CENTER_B", "Bilateral_Table_ID", 2,
        0, 0, 0, "", 0, 0, 0, 0, 0, 0, 1);
    event ICCP::mms_message(
        c, T, T, 0, T, 24, 19, 4, 0, T, 2, "", "",
        0, "", "", 0, F,
        1, "CONTROL_CENTER_B", "Bilateral_Table_ID", 2,
        0, "", 0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_provenance_marker_v1(c, F, 1);
    event ICCP::mms_read_message_v3(
        c, F, 1, 19, 0, 0, 0, "", "", 0,
        1, 0, 10, "CONTROL_CENTER_B", 0, 0, 0, 0, 0, 0, 1);
    event ICCP::mms_message(
        c, F, T, 1, T, 16, 19, 4, 0, T, 2, "", "",
        0, "", "", 0, F,
        0, "", "", 0, 10, "CONTROL_CENTER_B", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_message(
        c, T, T, 0, T, 24, 10, 4, 0, T, 2, "", "",
        0, "", "", 0, F,
        0, "", "Supported_Features", 1, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_message(
        c, F, T, 1, T, 8, 10, 4, 0, T, 2, "", "",
        0, "", "", 0, F,
        0, "", "", 0, 4, "\x04\xa0", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_message(
        c, T, T, 0, T, 24, 11, 4, 0, T, 2, "", "",
        0, "", "", 0, F,
        0, "", "TASE.2_Version", 5, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_message(
        c, F, T, 1, T, 12, 11, 4, 0, T, 2, "", "",
        0, "", "", 0, F,
        0, "", "", 0, 2, "\x85\x02\x07\xd0\x85\x01\x08",
        2, 2000, 8, 2, 5, 5, 0, 2000, 0.0, "", 0);
    ICCP::configured_variable_types[
        c$id$resp_h, c$id$orig_h, 1, "CONTROL_CENTER_B", "MW_FLOW"] =
            "Data_RealQTimeTag";
    event ICCP::mms_variable_type_message(
        c, T, 0, 60, 6, 1, "CONTROL_CENTER_B", "MW_FLOW",
        0, 0, "", "");
    ICCP::configured_variable_types[
        c$id$resp_h, c$id$orig_h, 1, "CONTROL_CENTER_B",
        "MW_WRONG_ORDER"] =
            "Data_RealQTimeTag";
    event ICCP::mms_variable_type_message(
        c, F, 1, 60, 6, 0, "", "", 0, 0, "",
        "Data_RealQTimeTag");
    event ICCP::mms_message(
        c, T, T, 0, T, 24, 12, 4, 0, T, 2, "", "",
        0, "", "", 0, F,
        1, "CONTROL_CENTER_B", "MW_FLOW", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_point_value_shape_v2(c, F, 0, 5, 4, 2);
    event ICCP::mms_message(
        c, F, T, 1, T, 17, 12, 4, 0, T, 2, "", "",
        0, "", "", 0, F,
        0, "", "", 0, 2, "", 1, 1700000000, 0,
        3, 7, 5, 4, 0, 10.0, "\x00\x2a", 1700000000);
    # The former Value/Flags/TimeStamp order remains bounded raw evidence even
    # when the discovered type is Data_RealQTimeTag.
    ICCP::configured_variable_types[
        c$id$resp_h, c$id$orig_h, 1, "CONTROL_CENTER_B", "MW_WIDE_REAL"] =
            "Data_RealQ";
    event ICCP::mms_variable_type_message(
        c, T, 0, 63, 6, 1, "CONTROL_CENTER_B", "MW_WRONG_ORDER",
        0, 0, "", "");
    ICCP::configured_variable_types[
        c$id$resp_h, c$id$orig_h, 1, "CONTROL_CENTER_B", "BREAKER_STATE"] =
            "Data_State";
    event ICCP::mms_variable_type_message(
        c, F, 1, 63, 6, 0, "", "", 0, 0, "",
        "Data_RealQTimeTag");
    event ICCP::mms_message(
        c, T, T, 0, T, 24, 13, 4, 0, T, 2, "", "",
        0, "", "", 0, F,
        1, "CONTROL_CENTER_B", "MW_WRONG_ORDER", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_point_value_shape_v2(c, F, 0, 5, 2, 4);
    event ICCP::mms_message(
        c, F, T, 1, T, 17, 13, 4, 0, T, 2, "", "",
        0, "", "", 0, F,
        0, "", "", 0, 2, "\x87\x05\x08\x41\x20\x00\x00\x84\x02\x00\x2a\x85\x04\x65\x53\xf1\x00",
        1, 1700000000, 0, 3, 7, 4, 5, 0, 10.0,
        "\x00\x2a", 1700000000);
    # A discovered Data_RealQ still requires its supported floating
    # representation; a mismatched MMS floating value remains raw.
    ICCP::configured_variable_types[
        c$id$resp_h, c$id$orig_h, 1, "CONTROL_CENTER_B", "MW_REPORT"] =
            "Data_RealQ";
    event ICCP::mms_variable_type_message(
        c, T, 0, 64, 6, 1, "CONTROL_CENTER_B", "MW_WIDE_REAL",
        0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, F, 1, 64, 6, 0, "", "", 0, 0, "", "Data_RealQ");
    event ICCP::mms_message(
        c, T, T, 0, T, 24, 15, 4, 0, T, 2, "", "",
        0, "", "", 0, F,
        1, "CONTROL_CENTER_B", "MW_WIDE_REAL", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_point_value_shape_v2(c, F, 0, 9, 2, 0);
    event ICCP::mms_message(
        c, F, T, 1, T, 17, 15, 4, 0, T, 2, "", "",
        0, "", "", 0, F,
        0, "", "", 0, 2,
        "\x87\x09\x0b\x40\x24\x00\x00\x00\x00\x00\x00\x84\x02\x00\x2a",
        0, 0, 0, 2, 7, 4, 0, 0, 10.0, "\x00\x2a", 0);
    event ICCP::mms_variable_type_message(
        c, T, 0, 61, 6, 1, "CONTROL_CENTER_B", "BREAKER_STATE",
        0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, F, 1, 61, 6, 0, "", "", 0, 0, "", "Data_State");
    event ICCP::mms_message(
        c, T, T, 0, T, 24, 14, 4, 0, T, 2, "", "",
        0, "", "", 0, F,
        1, "CONTROL_CENTER_B", "BREAKER_STATE", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_point_value_shape_v2(c, F, 2, 0, 0, 0);
    event ICCP::mms_message(
        c, F, T, 1, T, 8, 14, 4, 0, T, 2, "", "",
        0, "", "", 0, F,
        0, "", "", 0, 4, "\x00\xaa", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_message(
        c, T, T, 0, T, 24, 16, 4, 0, T, 2, "", "",
        0, "", "", 0, F,
        1, "CONTROL_CENTER_B", "MW_EXTENDED", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_message(
        c, F, T, 1, T, 17, 16, 4, 0, T, 2, "", "",
        0, "", "", 0, F,
        0, "", "", 0, 2, "", 0, 0, 0,
        3, 7, 4, 17, 0, 12.5, "\x00\x2a", 1700000000123);
    event ICCP::mms_message(
        c, T, T, 0, T, 24, 18, 4, 0, T, 2, "", "",
        0, "", "", 0, F,
        1, "CONTROL_CENTER_B", "MW_COV", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_message(
        c, F, T, 1, T, 20, 18, 4, 0, T, 2, "", "",
        0, "", "", 0, F,
        0, "", "", 0, 2, "", 2, 1700000000, 42,
        4, 7, 4, 5, 0, 15.0, "\x00\x2a", 1700000000);
    event ICCP::mms_variable_type_message(
        c, T, 0, 62, 6, 1, "CONTROL_CENTER_B", "MW_REPORT",
        0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, F, 1, 62, 6, 0, "", "", 0, 0, "", "Data_RealQ");
    event ICCP::mms_point_value_shape_v2(c, F, 0, 5, 2, 0);
    event ICCP::mms_message(
        c, F, T, 3, T, 13, -1, 0, 0, T, 8, "", "",
        1, "CONTROL_CENTER_B", "MW_REPORT", 0, F,
        1, "CONTROL_CENTER_B", "MW_REPORT", 0, 2, "", 0, 0, 0,
        2, 7, 4, 0, 0, 25.0, "\x00\x2a", 0);

    event ICCP::mms_message(
        c, T, T, 0, T, 24, 20, 4, 0, T, 2, "", "",
        0, "", "", 0, F,
        1, "CONTROL_CENTER_B", "DSConditions_Detected", 3,
        0, "", 0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_message(
        c, F, T, 1, T, 8, 20, 4, 0, T, 2, "", "",
        0, "", "", 0, F,
        0, "", "", 0, 4, "\x03\xa8", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);

    # Negotiated capabilities are context, not a parser allowlist. This second
    # association advertises no parameter or service bits, but its valid Write
    # request must remain decoded and visible as a candidate operation.
    local c_no_capabilities: connection = [
        $id=[
            $orig_h=192.0.2.30,
            $orig_p=49153/tcp,
            $resp_h=192.0.2.40,
            $resp_p=102/tcp
        ],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(),
        $duration=0secs,
        $service=set("iccp"),
        $history="",
        $uid="Cno-capabilities"
    ];
    event ICCP::presentation_message_v2(
        c_no_capabilities, T, T, 2, 3, "2.2.1.0.1", "2.1.1", T, F, F, 32);
    event ICCP::acse_message(
        c_no_capabilities, T, T, 0, "1.3.6.1.4.1", -1, -1, -1,
        F, 0, F, T, 24);
    event ICCP::acse_message(
        c_no_capabilities, F, T, 1, "1.3.6.1.4.1", 0, -1, 0,
        F, 0, F, T, 24);
    event ICCP::mms_message(
        c_no_capabilities, T, T, 8, T, 16, -1, 0, 0, F, 0,
        "\x00", "\x00", 0, "", "", 0, F, 0, "", "", 0, 0, "",
        0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_message(
        c_no_capabilities, T, T, 0, T, 12, 13, 5, 0, T, 3,
        "", "", 0, "", "", 0, F, 0, "", "", 0, 0, "",
        0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);
    }
