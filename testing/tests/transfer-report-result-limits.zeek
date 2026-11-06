# @TEST-DOC: Verify named-list transfer reports honor the shared result-row
# @TEST-DOC: and raw-value caps, while the summary accounts for omitted rows.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut action outcome list_name result_count failure_count logged_result_count omitted_result_count result_index result_type result_raw result_raw_truncated first_variable_name < iccp_transfers.log | grep '^report' > output
# @TEST-EXEC: btest-diff output

redef ICCP::max_logged_information_report_results = 1;
redef ICCP::max_logged_result_raw_bytes = 2;

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.10, $orig_p=49152/tcp,
             $resp_h=192.0.2.20, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs, $service=set("iccp"),
        $history="", $uid="Ctransferlimits"
    ];
    local no_counts: vector of count = vector();
    local no_ints: vector of int = vector();
    local no_strings: vector of string = vector();
    local member_scopes: vector of count = vector(1, 1);
    local member_domains: vector of string =
        vector("CONTROL_CENTER_B", "CONTROL_CENTER_B");
    local member_names: vector of string =
        vector("MW_FLOW", "BREAKER_STATE");

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

    event ICCP::mms_transfer_set_message(
        c, T, 0, 21, 11, 0, 0, 1, "CONTROL_CENTER_B", "TS_LIMIT", 2,
        1, "CONTROL_CENTER_B", "MW_FLOW", F, 0, 0, 0, 0, 0, 0,
        member_scopes, member_domains, member_names,
        no_counts, no_ints, no_strings);
    event ICCP::mms_transfer_set_message(
        c, F, 1, 21, 11, 0, 0, 0, "", "", 0,
        0, "", "", F, 0, 0, 0, 0, 0, 0,
        no_counts, no_strings, no_strings,
        no_counts, no_ints, no_strings);

    event ICCP::mms_transfer_set_message(
        c, F, 3, -1, 0, 0, 1, 1, "CONTROL_CENTER_B", "TS_LIMIT", 0,
        0, "", "", F, 0, 0, 0, 0, 2, 0,
        no_counts, no_strings, no_strings,
        vector(5, 5), vector(-1, -1),
        vector("\x01\x02\x03\x04", "\x05\x06\x07\x08"));
    }
