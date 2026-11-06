# @TEST-DOC: A zero result-row cap preserves one historical first-result row,
# @TEST-DOC: while a zero raw-byte cap preserves the field as an empty value
# @TEST-DOC: marked truncated.  Verify both generic/object and named-list
# @TEST-DOC: transfer-report output paths use the same semantics.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut result_count failure_count logged_result_count omitted_result_count result_pairing_status result_index result_type result_raw result_raw_truncated integer_value < iccp.log | awk '$1 != "-"' > summary
# @TEST-EXEC: btest-diff summary
# @TEST-EXEC: zeek-cut observation_kind object_name result_count result_pairing_status result_index result_type result_raw result_raw_truncated integer_value < iccp_objects.log | awk '$3 != "-"' > objects
# @TEST-EXEC: btest-diff objects
# @TEST-EXEC: zeek-cut action outcome list_name result_count logged_result_count omitted_result_count result_index result_type result_raw result_raw_truncated first_variable_name < iccp_transfers.log | grep '^report' > transfers
# @TEST-EXEC: btest-diff transfers

redef ICCP::max_logged_information_report_results = 0;
redef ICCP::max_logged_result_raw_bytes = 0;

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.10, $orig_p=49152/tcp,
             $resp_h=192.0.2.20, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Czero-report-limits"
    ];
    local empty_counts: vector of count = vector();
    local empty_ints: vector of int = vector();
    local empty_strings: vector of string = vector();
    local member_scopes: vector of count = vector(1, 1);
    local member_domains: vector of string =
        vector("CONTROL_CENTER_B", "CONTROL_CENTER_B");
    local member_names: vector of string =
        vector("MW_FLOW", "BREAKER_STATE");
    local result_choices: vector of count = vector(5, 10);
    local result_errors: vector of int = vector(-1, -1);
    local result_raws: vector of string =
        vector("\x01\x02\x03\x04", "second-value");
    local result_integers: vector of int = vector();
    result_integers[0] = 42;
    result_integers[1] = 0;
    local result_floats: vector of double = vector(0.0, 0.0);
    local result_booleans: vector of bool = vector(F, F);
    local result_strings: vector of string = vector("", "second-value");

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
        c, T, 0, 20, 0, 1, 0, "", "Supported_Features", 1,
        0, 0, 0, "", 0, 0, 0, 0, 0, 0, 1);
    event ICCP::mms_read_message_v3(
        c, F, 1, 20, 0, 0, 0, "", "", 0,
        1, 0, 4, "\x04\xa0", 0, 0, 0, 0, 0, 0, 1);

    # Confirm list membership so both the object and transfer paths can pair
    # the first result to an exact object identity.
    event ICCP::mms_transfer_set_message(
        c, T, 0, 21, 11, 0, 0, 1, "CONTROL_CENTER_B", "TS_ZERO", 2,
        1, "CONTROL_CENTER_B", "MW_FLOW", F, 0, 0, 0, 0, 0, 0,
        member_scopes, member_domains, member_names,
        empty_counts, empty_ints, empty_strings);
    event ICCP::mms_transfer_set_message(
        c, F, 1, 21, 11, 0, 0, 0, "", "", 0,
        0, "", "", F, 0, 0, 0, 0, 0, 0,
        empty_counts, empty_strings, empty_strings,
        empty_counts, empty_ints, empty_strings);

    event ICCP::mms_information_report_results_v2(
        c, F, 1, 1, "CONTROL_CENTER_B", "TS_ZERO", 2, 0,
        empty_counts, empty_strings, empty_strings,
        result_choices, result_errors, result_raws,
        result_integers, result_floats, result_booleans,
        result_strings, 1);

    # This compatibility event exercises the generic summary/object path.
    event ICCP::mms_message(
        c, F, T, 3, T, 32, -1, 0, 0, F, 0, "", "",
        0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);

    # The dedicated named-list event independently exercises transfer rows.
    event ICCP::mms_transfer_set_message(
        c, F, 3, -1, 0, 0, 1, 1, "CONTROL_CENTER_B", "TS_ZERO", 0,
        0, "", "", F, 0, 0, 0, 0, 2, 0,
        empty_counts, empty_strings, empty_strings,
        result_choices, result_errors, result_raws);
    }
