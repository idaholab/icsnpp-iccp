# @TEST-DOC: Packet Read specializations trust first-variable identity only
# @TEST-DOC: when authoritative v3 evidence says the access specification is
# @TEST-DOC: an explicit variable list. Named-list selectors cannot become
# @TEST-DOC: Select/GetTag or transfer-support objects in any sibling order,
# @TEST-DOC: while direct compatibility events retain their legacy behavior.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT > output
# @TEST-EXEC: btest-diff output

module ICCP;

function test_connection(uid: string, orig_p: port): connection
    {
    return [
        $id=[$orig_h=192.0.2.210, $orig_p=orig_p,
             $resp_h=192.0.2.220, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid=uid
    ];
    }

function establish_tase(c: connection)
    {
    event ICCP::presentation_message_v2(
        c, T, T, 2, 3, "2.2.1.0.1", "2.1.1", T, F, F, 32);
    event ICCP::acse_message(
        c, T, T, 0, "1.0.9506.2.3", -1, -1, -1,
        F, 0, F, T, 24);
    event ICCP::acse_message(
        c, F, T, 1, "1.0.9506.2.3", 0, -1, 0,
        F, 0, F, T, 24);
    event ICCP::mms_read_message_v3(
        c, T, 0, 1, 0, 1, 0, "", "Supported_Features", 1,
        0, 0, 0, "", 0, 0, 0, 0, 0, 0, 1);
    event ICCP::mms_read_message_v3(
        c, F, 1, 1, 0, 0, 0, "", "", 0,
        1, 0, 4, "\x07\x80", 0, 0, 0, 0, 0, 0, 1);
    }

function aggregate_read_request(
    c: connection, invoke_id: int, scope: count,
    domain: string, name: string, category: count)
    {
    event ICCP::mms_message(
        c, T, T, 0, T, 24, invoke_id, 4, 0, T, 2, "", "",
        0, "", "", 0, F, scope, domain, name, category,
        0, "", 0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);
    }

function v3_read_request(
    c: connection, invoke_id: int, access_choice: count,
    variable_count: count, scope: count, domain: string,
    name: string, category: count)
    {
    event ICCP::mms_read_message_v3(
        c, T, 0, invoke_id, access_choice, variable_count,
        scope, domain, name, category, 0, 0, 0, "",
        0, 0, 0, 0, 0, 0, 1);
    }

function control_compat_request(
    c: connection, invoke_id: int, scope: count,
    domain: string, name: string, variable_count: count)
    {
    event ICCP::mms_control_message(
        c, T, 0, invoke_id, 4, scope, domain, name,
        variable_count, 0, 0, 0, 0, 0);
    }

function support_compat_request(
    c: connection, invoke_id: int, domain: string, name: string)
    {
    event ICCP::mms_transfer_support_value_message(
        c, T, 0, invoke_id, 4, 1, domain, name,
        0, 0, 0, "", 0, 0, 0, 0, 0, "", "");
    }

event inspect_read_gate(c: connection, label: string, invoke_id: int)
    {
    local key = int_to_count(invoke_id);
    print fmt("%s control=%s support=%s", label,
              [c$uid, T, key] in pending_control_reads,
              [c$uid, T, key] in pending_transfer_support);
    }

event zeek_init()
    {
    local legacy_first = test_connection(
        "Cread-gate-legacy-first", 49152/tcp);
    establish_tase(legacy_first);
    known_variable_types[
        legacy_first$uid, F, 0, "", "BREAKER_SBO"] =
            "SBO_CheckBackName";
    event ICCP::mms_provenance_marker_v1(legacy_first, T, 1);
    control_compat_request(legacy_first, 10, 0, "", "BREAKER_SBO", 0);
    aggregate_read_request(legacy_first, 10, 0, "", "BREAKER_SBO", 0);
    v3_read_request(legacy_first, 10, 1, 0, 0, "", "BREAKER_SBO", 0);
    event inspect_read_gate(legacy_first, "named-control-legacy-first", 10);

    local aggregate_first = test_connection(
        "Cread-gate-aggregate-first", 49153/tcp);
    establish_tase(aggregate_first);
    known_variable_types[
        aggregate_first$uid, F, 0, "", "BREAKER_SBO"] =
            "SBO_CheckBackName";
    event ICCP::mms_provenance_marker_v1(aggregate_first, T, 1);
    aggregate_read_request(aggregate_first, 11, 0, "", "BREAKER_SBO", 0);
    control_compat_request(aggregate_first, 11, 0, "", "BREAKER_SBO", 0);
    v3_read_request(aggregate_first, 11, 1, 0, 0, "", "BREAKER_SBO", 0);
    event inspect_read_gate(
        aggregate_first, "named-control-aggregate-first", 11);

    local v3_first = test_connection("Cread-gate-v3-first", 49154/tcp);
    establish_tase(v3_first);
    known_variable_types[v3_first$uid, F, 0, "", "BREAKER_SBO"] =
        "SBO_CheckBackName";
    event ICCP::mms_provenance_marker_v1(v3_first, T, 1);
    v3_read_request(v3_first, 12, 1, 0, 0, "", "BREAKER_SBO", 0);
    aggregate_read_request(v3_first, 12, 0, "", "BREAKER_SBO", 0);
    control_compat_request(v3_first, 12, 0, "", "BREAKER_SBO", 0);
    event inspect_read_gate(v3_first, "named-control-v3-first", 12);

    local named_support = test_connection(
        "Cread-gate-named-support", 49155/tcp);
    establish_tase(named_support);
    event ICCP::mms_provenance_marker_v1(named_support, T, 1);
    aggregate_read_request(
        named_support, 13, 1, "CONTROL_CENTER_B", "Next_DSTransfer_Set", 6);
    support_compat_request(
        named_support, 13, "CONTROL_CENTER_B", "Next_DSTransfer_Set");
    v3_read_request(
        named_support, 13, 1, 0, 1, "CONTROL_CENTER_B",
        "Next_DSTransfer_Set", 6);
    event inspect_read_gate(named_support, "named-transfer-support", 13);

    local explicit = test_connection("Cread-gate-explicit", 49156/tcp);
    establish_tase(explicit);
    known_variable_types[explicit$uid, F, 0, "", "BREAKER_SBO"] =
        "SBO_CheckBackName";
    event ICCP::mms_provenance_marker_v1(explicit, T, 1);
    control_compat_request(explicit, 14, 0, "", "BREAKER_SBO", 1);
    aggregate_read_request(explicit, 14, 0, "", "BREAKER_SBO", 0);
    v3_read_request(explicit, 14, 0, 1, 0, "", "BREAKER_SBO", 0);
    event inspect_read_gate(explicit, "explicit-packet-control", 14);

    local direct_control = test_connection(
        "Cread-gate-direct-control", 49157/tcp);
    establish_tase(direct_control);
    known_variable_types[
        direct_control$uid, F, 0, "", "BREAKER_SBO"] =
            "SBO_CheckBackName";
    control_compat_request(
        direct_control, 20, 0, "", "BREAKER_SBO", 1);
    event inspect_read_gate(direct_control, "direct-control", 20);

    local direct_support = test_connection(
        "Cread-gate-direct-support", 49158/tcp);
    establish_tase(direct_support);
    support_compat_request(
        direct_support, 21, "CONTROL_CENTER_B", "Next_DSTransfer_Set");
    event inspect_read_gate(direct_support, "direct-transfer-support", 21);
    }
