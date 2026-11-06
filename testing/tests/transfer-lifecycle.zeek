# @TEST-DOC: Check the Domain-specific TASE.2 Data Set definition/deletion
# @TEST-DOC: profile, inspection, named-list report correlation, lifecycle
# @TEST-DOC: state, and standardized IM_Transfer_Set Boolean Start/Stop.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut action outcome invoke_id list_scope list_domain list_name variable_count first_variable_scope first_variable_domain first_variable_name deletable delete_scope number_matched number_deleted result_count failure_count known_list provenance < iccp_transfers.log > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: zeek-cut action outcome invoke_id conformance conformance_reasons < iccp_transfers.log | grep '^define.*confirmed_existing_name' > duplicates
# @TEST-EXEC: btest-diff duplicates
# @TEST-EXEC: zeek-cut action outcome list_name first_variable_name result_index result_type result_error result_raw < iccp_transfers.log | grep '^report_value' > pairs
# @TEST-EXEC: btest-diff pairs
# @TEST-EXEC: zeek-cut action outcome invoke_id list_scope list_domain list_name first_variable_scope first_variable_domain first_variable_name timestamp_value < iccp_transfers.log | grep -E '^(next_transfer_set|transfer_set_name|transfer_timestamp|read_report_ack_value|read_report_nack_value)' > support
# @TEST-EXEC: btest-diff support

redef ICCP::legacy_gva_direct_event_compatibility = T;

event zeek_init() &priority=-5
    {
    local no_counts: vector of count = vector();
    local no_ints: vector of int = vector();
    local one_failure: vector of int = vector();
    one_failure[0] = 4;
    local report_errors: vector of int = vector();
    report_errors[0] = -1;
    report_errors[1] = 3;
    local no_strings: vector of string = vector();
    local ds_values: vector of int = vector();
    ds_values[0] = 0;
    ds_values[1] = 1700000000;
    ds_values[2] = 60;
    ds_values[3] = 5;
    ds_values[4] = 2;
    ds_values[5] = 3600;
    ds_values[6] = 0;
    ds_values[7] = 0;
    ds_values[8] = 0;
    ds_values[9] = 0;
    ds_values[10] = 0;
    ds_values[11] = 0;
    ds_values[12] = 7;
    local ds_name_values: vector of int = vector();
    ds_name_values[0] = 0;
    ds_name_values[1] = 0;
    ds_name_values[2] = 0;
    local member_scopes: vector of count = vector(1, 1);
    local member_domains: vector of string =
        vector("CONTROL_CENTER_B", "CONTROL_CENTER_B");
    local member_names: vector of string = vector("MW_FLOW", "BREAKER_STATE");
    local delete_scopes: vector of count = vector(1);
    local delete_domains: vector of string = vector("CONTROL_CENTER_B");
    local delete_names: vector of string = vector("TS1");
    local redefined_names: vector of string =
        vector("MW_FLOW", "BREAKER_STATE", "MW_COV");
    local c: connection = [
        $id=[$orig_h=192.0.2.10, $orig_p=49152/tcp,
             $resp_h=192.0.2.20, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs, $service=set("iccp"),
        $history="", $uid="Ctransfer"
    ];

    event ICCP::presentation_message_v2(c, T, T, 2, 3, "2.2.1.0.1", "2.1.1", T, F, F, 32);
    event ICCP::acse_message(c, T, T, 0, "1.0.9506.2.3", -1, -1, -1,
                            F, 0, F, T, 24);
    event ICCP::mms_message(
        c, T, T, 8, T, 16, -1, 0, 0, F, 0, "\x00", "\x01",
        0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::acse_message(c, F, T, 1, "1.0.9506.2.3", 0, -1, 0,
                            F, 0, F, T, 24);
    event ICCP::mms_read_message_v3(
        c, T, 0, 20, 0, 1, 0, "", "Supported_Features", 1,
        0, 0, 0, "", 0, 0, 0, 0, 0, 0, 1);
    event ICCP::mms_read_message_v3(
        c, F, 1, 20, 0, 0, 0, "", "", 0,
        1, 0, 4, "\x07\x80", 0, 0, 0, 0, 0, 0, 1);

    event ICCP::mms_transfer_set_message(
        c, T, 0, 21, 11, 0, 0, 1, "CONTROL_CENTER_B", "TS1", 2,
        1, "CONTROL_CENTER_B", "MW_FLOW", F, 0, 0, 0, 0, 0, 0,
        member_scopes, member_domains, member_names,
        no_counts, no_ints, no_strings);
    event ICCP::mms_transfer_set_message(
        c, F, 1, 21, 11, 0, 0, 0, "", "", 0,
        0, "", "", F, 0, 0, 0, 0, 0, 0,
        no_counts, no_strings, no_strings, no_counts, no_ints, no_strings);
    event ICCP::mms_transfer_set_message(
        c, T, 0, 22, 12, 0, 0, 1, "CONTROL_CENTER_B", "TS1", 0,
        0, "", "", F, 0, 0, 0, 0, 0, 0,
        no_counts, no_strings, no_strings, no_counts, no_ints, no_strings);
    event ICCP::mms_transfer_set_message(
        c, F, 1, 22, 12, 0, 0, 0, "", "", 2,
        1, "CONTROL_CENTER_B", "MW_FLOW", T, 0, 0, 0, 0, 0, 0,
        member_scopes, member_domains, member_names,
        no_counts, no_ints, no_strings);
    # A server must reject an existing name. A positive duplicate response is
    # visible as a deviation and must preserve the original membership.
    event ICCP::mms_transfer_set_message(
        c, T, 0, 24, 11, 0, 0, 1, "CONTROL_CENTER_B", "TS1", 3,
        1, "CONTROL_CENTER_B", "MW_FLOW", F, 0, 0, 0, 0, 0, 0,
        vector(1, 1, 1),
        vector("CONTROL_CENTER_B", "CONTROL_CENTER_B", "CONTROL_CENTER_B"),
        redefined_names, no_counts, no_ints, no_strings);
    event ICCP::mms_transfer_set_message(
        c, F, 1, 24, 11, 0, 0, 0, "", "", 0,
        0, "", "", F, 0, 0, 0, 0, 0, 0,
        no_counts, no_strings, no_strings, no_counts, no_ints, no_strings);
    event ICCP::mms_transfer_set_message(
        c, F, 3, -1, 0, 0, 1, 1, "CONTROL_CENTER_B", "TS1", 0,
        0, "", "", F, 0, 0, 0, 0, 2, 0,
        no_counts, no_strings, no_strings, vector(7, 0), report_errors,
        vector("\x08\x41\x20\x00\x00", ""));
    event ICCP::mms_transfer_set_message(
        c, T, 0, 23, 13, 0, 0, 1, "CONTROL_CENTER_B", "TS1", 0,
        0, "", "", F, 0, 1, 0, 0, 0, 0,
        delete_scopes, delete_domains, delete_names,
        no_counts, no_ints, no_strings);
    event ICCP::mms_transfer_set_message(
        c, F, 1, 23, 13, 0, 0, 0, "", "", 0,
        0, "", "", F, 0, 0, 1, 1, 0, 0,
        no_counts, no_strings, no_strings, no_counts, no_ints, no_strings);
    # A report after deletion remains visible but cannot be paired to known
    # membership state.
    event ICCP::mms_transfer_set_message(
        c, F, 3, -1, 0, 0, 1, 1, "CONTROL_CENTER_B", "TS1", 0,
        0, "", "", F, 0, 0, 0, 0, 1, 1,
        no_counts, no_strings, no_strings, vector(0), one_failure, no_strings);
    # Reusing an outstanding invoke ID replaces the stale request. The reply
    # therefore correlates to the most recent request.
    event ICCP::mms_transfer_set_message(
        c, T, 0, 25, 12, 0, 0, 1, "CONTROL_CENTER_B", "TS1", 0,
        0, "", "", F, 0, 0, 0, 0, 0, 0,
        no_counts, no_strings, no_strings, no_counts, no_ints, no_strings);
    event ICCP::mms_transfer_set_message(
        c, T, 0, 25, 13, 0, 0, 1, "CONTROL_CENTER_B", "TS1", 0,
        0, "", "", F, 0, 1, 0, 0, 0, 0,
        delete_scopes, delete_domains, delete_names,
        no_counts, no_ints, no_strings);
    event ICCP::mms_transfer_set_message(
        c, T, 1, 25, 13, 0, 0, 0, "", "", 0,
        0, "", "", F, 0, 0, 0, 0, 0, 0,
        no_counts, no_strings, no_strings, no_counts, no_ints, no_strings);
    event ICCP::mms_transfer_set_message(
        c, F, 1, 25, 13, 0, 0, 0, "", "", 0,
        0, "", "", F, 0, 0, 0, 0, 0, 0,
        no_counts, no_strings, no_strings, no_counts, no_ints, no_strings);
    event ICCP::mms_transfer_set_message(
        c, F, 1, 99, 12, 0, 0, 0, "", "", 0,
        0, "", "", F, 0, 0, 0, 0, 0, 0,
        no_counts, no_strings, no_strings, no_counts, no_ints, no_strings);

    event ICCP::mms_transfer_control_message(
        c, T, 0, 30, 5, 0, 2, "", "IM_Transfer_Set", 1, 1, 3, T,
        0, 0, F, F, 0, 0, 0);
    event ICCP::mms_transfer_control_message(
        c, F, 1, 30, 5, 0, 0, "", "", 0, 0, 0, F,
        0, 0, F, F, 1, 1, 0);
    event ICCP::mms_transfer_control_message(
        c, T, 0, 31, 5, 0, 2, "", "IM_Transfer_Set", 1, 1, 3, F,
        0, 0, F, F, 0, 0, 0);
    event ICCP::mms_transfer_control_message(
        c, F, 1, 31, 5, 0, 0, "", "", 0, 0, 0, F,
        0, 0, F, F, 1, 0, 1);

    # These near misses must remain generic MMS Writes.
    event ICCP::mms_transfer_control_message(
        c, T, 0, 32, 5, 0, 2, "", "Other_Boolean", 1, 1, 3, T,
        0, 0, F, F, 0, 0, 0);
    event ICCP::mms_transfer_control_message(
        c, T, 0, 33, 5, 0, 2, "", "IM_Transfer_Set", 1, 1, 5, T,
        0, 0, F, F, 0, 0, 0);
    event ICCP::mms_transfer_control_message(
        c, T, 0, 34, 5, 0, 2, "", "IM_Transfer_Set", 1, 1, 3, T,
        0, 0, F, F, 0, 0, 0);
    event ICCP::mms_error_message(c, F, 2, 34, -1, 7, 3, -1, "");

    # A structurally valid DSTransferSet is not promoted before its named type
    # has been learned from a correlated variable-attributes exchange.
    event ICCP::mms_transfer_control_message(
        c, T, 0, 39, 5, 0, 1, "CONTROL_CENTER_B", "TS_TYPED",
        1, 1, 2, F, 13, 3, T, T, 0, 0, 0);
    ICCP::configured_variable_types[
        c$id$resp_h, c$id$orig_h, 1, "CONTROL_CENTER_B", "TS_TYPED"] =
            "DSTransferSet";
    event ICCP::mms_variable_type_message(
        c, T, 0, 40, 6, 1, "CONTROL_CENTER_B", "TS_TYPED",
        0, 0, "", "");
    ICCP::configured_variable_types[
        c$id$resp_h, c$id$orig_h, 1, "CONTROL_CENTER_B",
        "DSConditions_Detected"] =
            "DSConditions";
    event ICCP::mms_variable_type_message(
        c, F, 1, 40, 6, 0, "", "", 0, 0, "", "DSTransferSet");
    event ICCP::mms_ds_transfer_set_message_v1(
        c, T, 0, 41, 5, 0, 1, "CONTROL_CENTER_B", "TS_TYPED", 1, 1, 2,
        vector(2, 5, 5, 5, 5, 5, 4, 3, 3, 3, 3, 3, 5),
        vector("", "\x65\x53\xf1\x00", "\x3c", "\x05", "\x02",
               "\x0e\x10", "\x03\xa8", "\x00", "\xff", "\xff",
               "\x00", "\xff", "\x07"),
        ds_values,
        vector(6, 10, 10), vector("\x00", "IGNORED", "DATA_SET"),
        ds_name_values, 0);
    event ICCP::mms_transfer_control_message(
        c, F, 1, 41, 5, 0, 0, "", "", 0, 0, 0, F,
        0, 0, F, F, 1, 1, 0);
    event ICCP::mms_variable_type_message(
        c, T, 0, 42, 6, 1, "CONTROL_CENTER_B", "DSConditions_Detected",
        0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, F, 1, 42, 6, 0, "", "", 0, 0, "", "DSConditions");

    event ICCP::mms_transfer_support_value_message(
        c, T, 0, 50, 4, 1, "CONTROL_CENTER_B",
        "Transfer_Set_Time_Stamp", 0, 0, 0, "", 0, 0, 0, 0, 0, "", "");
    event ICCP::mms_transfer_support_value_message(
        c, F, 1, 50, 4, 0, "", "", 1, 0, 5,
        "\x65\x53\xf1\x00", 0, 0, 0, 0, 1700000000, "", "");

    event ICCP::mms_transfer_support_value_message(
        c, T, 0, 51, 4, 1, "CONTROL_CENTER_B",
        "Next_DSTransfer_Set", 0, 0, 0, "", 0, 0, 0, 0, 0, "", "");
    event ICCP::mms_transfer_support_value_message(
        c, F, 1, 51, 4, 0, "", "", 1, 0, 2, "", 3, 6, 10, 10,
        1, "CONTROL_CENTER_B", "TS_NEXT");
    event ICCP::mms_transfer_support_value_message(
        c, T, 0, 52, 4, 1, "CONTROL_CENTER_B",
        "Transfer_Set_Name", 0, 0, 0, "", 0, 0, 0, 0, 0, "", "");
    event ICCP::mms_transfer_support_value_message(
        c, F, 1, 52, 4, 0, "", "", 1, 0, 2, "", 3, 6, 10, 10,
        1, "CONTROL_CENTER_B", "TS1");
    event ICCP::mms_transfer_support_value_message(
        c, T, 0, 53, 4, 1, "CONTROL_CENTER_B",
        "Transfer_Report_ACK", 0, 0, 0, "", 0, 0, 0, 0, 0, "", "");
    event ICCP::mms_transfer_support_value_message(
        c, F, 1, 53, 4, 0, "", "", 1, 0, 2, "", 3, 6, 10, 10,
        0, "IGNORED", "TS_ACK");
    event ICCP::mms_transfer_support_value_message(
        c, T, 0, 54, 4, 1, "CONTROL_CENTER_B",
        "Transfer_Report_NACK", 0, 0, 0, "", 0, 0, 0, 0, 0, "", "");
    event ICCP::mms_transfer_support_value_message(
        c, F, 1, 54, 4, 0, "", "", 1, 0, 2, "", 3, 6, 10, 10,
        1, "CONTROL_CENTER_B", "TS_NACK");

    # A non-Identifier character keeps the standardized object visible but
    # prevents promotion of its malformed embedded ObjectName value.
    event ICCP::mms_transfer_support_value_message(
        c, T, 0, 55, 4, 1, "CONTROL_CENTER_B",
        "Next_DSTransfer_Set", 0, 0, 0, "", 0, 0, 0, 0, 0, "", "");
    event ICCP::mms_transfer_support_value_message(
        c, F, 1, 55, 4, 0, "", "", 1, 0, 2, "", 3, 6, 10, 10,
        1, "CONTROL_CENTER_B", "bad-name");
    event ICCP::mms_transfer_support_value_message(
        c, T, 0, 56, 4, 1, "CONTROL_CENTER_B", "Transfer_Report_ACK",
        0, 0, 0, "", 0, 0, 0, 0, 0, "", "");
    event ICCP::mms_error_message(c, F, 2, 56, -1, 7, 3, -1, "");

    # Transfer references are Domain-specific and remain within the Domain of
    # the outer support object.
    event ICCP::mms_transfer_support_value_message(
        c, T, 0, 57, 4, 1, "CONTROL_CENTER_B", "Transfer_Report_ACK",
        0, 0, 0, "", 0, 0, 0, 0, 0, "", "");
    event ICCP::mms_transfer_support_value_message(
        c, F, 1, 57, 4, 0, "", "", 1, 0, 2, "", 3, 6, 10, 10,
        1, "CONTROL_CENTER_C", "TS_WRONG_DOMAIN");
    }
