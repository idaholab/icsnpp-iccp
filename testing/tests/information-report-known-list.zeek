# @TEST-DOC: Verify that only exact bounded membership from a confirmed
# @TEST-DOC: connection-scoped named-list definition authorizes ordered report
# @TEST-DOC: result-to-object association.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut observation_kind object_scope object_domain object_name result_count result_pairing_status result_index result_type result_error result_raw integer_value string_value provenance < iccp_objects.log | awk '$7 != "-"' > objects
# @TEST-EXEC: btest-diff objects

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.10, $orig_p=49152/tcp,
             $resp_h=192.0.2.20, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs, $service=set("iccp"),
        $history="", $uid="Creportlist"
    ];
    local empty_counts: vector of count = vector();
    local empty_ints: vector of int = vector();
    local normalized_ints: vector of int = vector();
    normalized_ints[0] = 42;
    normalized_ints[1] = 0;
    local normalized_doubles: vector of double = vector(0.0, 0.0);
    local normalized_bools: vector of bool = vector(F, F);
    local empty_strings: vector of string = vector();
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
    # Establish TASE.2 state with a complete direction-correct Read of the
    # fixed VMD bootstrap object. A request spelling alone is not evidence.
    event ICCP::mms_read_message_v3(
        c, T, 0, 20, 0, 1, 0, "", "Supported_Features", 1,
        0, 0, 0, "", 0, 0, 0, 0, 0, 0, 1);
    event ICCP::mms_read_message_v3(
        c, F, 1, 20, 0, 0, 0, "", "", 0,
        1, 0, 4, "\x04\xa0", 0, 0, 0, 0, 0, 0, 1);

    event ICCP::mms_transfer_set_message(
        c, T, 0, 21, 11, 0, 0, 1, "CONTROL_CENTER_B", "TS1", 2,
        1, "CONTROL_CENTER_B", "MW_FLOW", F, 0, 0, 0, 0, 0, 0,
        member_scopes, member_domains, member_names,
        empty_counts, empty_ints, empty_strings);
    event ICCP::mms_transfer_set_message(
        c, F, 1, 21, 11, 0, 0, 0, "", "", 0,
        0, "", "", F, 0, 0, 0, 0, 0, 0,
        empty_counts, empty_strings, empty_strings,
        empty_counts, empty_ints, empty_strings);

    event ICCP::mms_information_report_results_v2(
        c, F, 1, 1, "CONTROL_CENTER_B", "TS1", 2, 0,
        empty_counts, empty_strings, empty_strings,
        vector(5, 10), vector(-1, -1), vector("\x2a", "ok"),
        normalized_ints, normalized_doubles, normalized_bools,
        vector("", "ok"), 1);
    event ICCP::mms_message(
        c, F, T, 3, T, 22, -1, 0, 0, F, 0, "", "",
        0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    }
