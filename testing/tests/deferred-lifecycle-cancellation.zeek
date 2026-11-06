# @TEST-DOC: Zero-delay MMS policy callbacks belong to the association that
# @TEST-DOC: queued them. Verify cancellation at CONNECT, DISCONNECT/RLRE,
# @TEST-DOC: ABORT, Conclude-Response, and connection removal. Parser failure
# @TEST-DOC: is not a lifecycle boundary and must retain a completed earlier
# @TEST-DOC: PDU in the same event batch. Session NOT-FINISHED must also retain
# @TEST-DOC: callbacks. Parser PDU sequence numbers remain monotonic across
# @TEST-DOC: association replacement, and unconsumed legacy-alert provenance
# @TEST-DOC: markers must not survive parser errors or lifecycle boundaries.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT | sort > output
# @TEST-EXEC: zeek-cut uid is_orig message_type invoke_id identify_outcome vendor_name provenance < iccp.log | awk -F '\t' '$1 ~ /^Cguard-(connect|not-finished|remove)$/ && $3 == "0"' | sort -t '	' -k1,1 -k6,6 >> output
# @TEST-EXEC: zeek-cut uid is_orig message_type transfer_kind object_name integer_value provenance < iccp.log | awk -F '\t' '$1 == "Cguard-abort" && $3 == "3"' >> output
# @TEST-EXEC: zeek-cut uid is_orig message_type invoke_id status object_name provenance < iccp.log | awk -F '\t' '$1 == "Cguard-disconnect" && $3 == "1"' >> output
# @TEST-EXEC: zeek-cut uid is_orig classification outcome invoke_id object_name named_type tag_value tag_state tag_reason provenance < iccp_controls.log | awk -F '\t' '$1 ~ /^Cguard-(conclude|disconnect|parser-error)$/' | sort -t '	' -k1,1 -k6,6 -k4,4 >> output
# @TEST-EXEC: btest-diff output

module ICCP;

global lifecycle_probe: event(c: connection, label: string);
global lifecycle_after_connect: event(c: connection);
global lifecycle_after_abort: event(c: connection);
global lifecycle_after_disconnect: event(c: connection);
global lifecycle_after_conclude: event(c: connection);
global lifecycle_after_parser_error: event(c: connection);
global lifecycle_after_remove: event(c: connection);

function test_connection(uid: string, orig_port: port): connection
    {
    return [
        $id=[$orig_h=192.0.2.230, $orig_p=orig_port,
             $resp_h=192.0.2.240, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid=uid
    ];
    }

function seed_tase2(c: connection)
    {
    local state = current_state(c);
    state$phase = "established";
    state$presentation_profile = T;
    state$acse_association = T;
    state$mms_negotiation = T;
    state$tase2_evidence = T;
    state$originator_known = T;
    state$originator_is_orig = T;
    associations[c$uid] = state;
    }

function emit_aggregate(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    service_tag: count, unconfirmed_service_tag: count,
    candidate_operation: count, first_variable_name: string,
    first_result_type: count, first_result_raw: string,
    result_integer_value: int)
    {
    event ICCP::mms_message(
        c, is_orig, T, pdu_type, T, 16, invoke_id,
        service_tag, unconfirmed_service_tag, F, candidate_operation,
        "", "", 0, "", "", 0, F,
        0, "", first_variable_name, 0,
        first_result_type, first_result_raw, 0, 0, 0, 0, 0, 0, 0,
        result_integer_value, 0.0, "", 0);
    }

function emit_identify(
    c: connection, is_orig: bool, invoke_id: int, vendor: string,
    provenance: count)
    {
    emit_aggregate(c, is_orig, 0, invoke_id, 2, 0, 10, "", 0, "", 0);
    event ICCP::mms_identify_message_v2(
        c, is_orig, 0, invoke_id, vendor, "model", "revision",
        1, "1.0.9506.2.3", provenance);
    }

function emit_information_report(
    c: connection, name: string, integer_value: int, provenance: count)
    {
    local scopes: vector of count = vector(0);
    local domains: vector of string = vector("");
    local names: vector of string = vector(name);
    local choices: vector of count = vector(5);
    local errors: vector of int = vector(-1);
    local raws: vector of string = vector("value");
    local integers: vector of int = vector();
    integers[0] = integer_value;
    local floats: vector of double = vector(0.0);
    local booleans: vector of bool = vector(F);
    local strings: vector of string = vector("");

    emit_aggregate(c, T, 3, -1, 0, 0, 8, name, 5, "value",
                   integer_value);
    event ICCP::mms_information_report_results_v2(
        c, T, 0, 0, "", "", 1, 0,
        scopes, domains, names, choices, errors, raws, integers, floats,
        booleans, strings, provenance);
    event ICCP::mms_point_value_shape_v2(c, T, 5, 0, 0, 0);
    }

function emit_write(c: connection, invoke_id: int, name: string)
    {
    emit_aggregate(c, T, 0, invoke_id, 5, 0, 3, name, 0, "", 0);
    event ICCP::mms_control_message(
        c, T, 0, invoke_id, 5, 0, "", name, 1, 1, 1, 0, 0, 0);
    event ICCP::mms_control_value_shape_v3(c, T, 5, "\x01", 1, 0.0);
    }

function emit_get_tag_request(
    c: connection, invoke_id: int, name: string, provenance: count)
    {
    emit_aggregate(c, T, 0, invoke_id, 4, 0, 2, name, 0, "", 0);
    # Model the authoritative packet Read hook even when exercising the
    # aggregate-before-additive completion-order permutation.  The compatibility
    # control hook cannot distinguish an explicit variable list from a named
    # list and must therefore remain a no-op for parser-marked delivery.
    event ICCP::mms_read_message_v3(
        c, T, 0, invoke_id, 0, 1, 0, "", name, 0,
        0, 0, 0, "", 0, 0, 0, 0, 0, 0, provenance);
    event ICCP::mms_control_message(
        c, T, 0, invoke_id, 4, 0, "", name, 1, 0, 0, 0, 0, 0);
    }

function emit_get_tag_response(c: connection, invoke_id: int)
    {
    local choices: vector of count = vector(4, 10);
    local raws: vector of string = vector("\x05\xa0", "maintenance");
    local integers: vector of int = vector();
    integers[0] = 0;
    integers[1] = 0;
    local none_count: vector of count = vector();
    local none_string: vector of string = vector();
    local none_int: vector of int = vector();

    emit_aggregate(c, F, 1, invoke_id, 4, 0, 2, "", 2, "", 0);
    event ICCP::mms_transfer_support_value_message(
        c, F, 1, invoke_id, 4, 0, "", "",
        1, 0, 2, "", 2, 4, 10, 0, 0, "maintenance", "");
    event ICCP::mms_point_value_shape_v3(
        c, F, 2, choices, raws, integers, 0,
        none_count, none_string, none_int);
    event ICCP::mms_control_read_value_shape_v1(
        c, F, 1, invoke_id, 4, 2, choices, raws, integers);
    }

function pending_control_total(uid: string): count
    {
    local total: count = 0;
    for ( [entry_uid, direction, invoke] in pending_controls )
        if ( entry_uid == uid ) ++total;
    for ( [read_uid, read_direction, read_invoke] in pending_control_reads )
        if ( read_uid == uid ) ++total;
    return total;
    }

function deferred_evidence_total(uid: string): count
    {
    local total: count = 0;
    for ( [identify_uid, identify_direction, identify_sequence,
           identify_pdu, identify_invoke] in identify_evidence )
        if ( identify_uid == uid ) ++total;
    for ( [report_uid, report_direction, report_sequence] in
          information_report_results_evidence )
        if ( report_uid == uid ) ++total;
    for ( [point_uid, point_direction, point_sequence] in
          point_value_shape_evidence )
        if ( point_uid == uid ) ++total;
    for ( [control_uid, control_direction, control_sequence] in
          control_value_shape_evidence )
        if ( control_uid == uid ) ++total;
    for ( [read_uid, read_direction, read_sequence, read_invoke] in
          control_read_value_shape_evidence )
        if ( read_uid == uid ) ++total;
    return total;
    }

function legacy_alert_marker_total(uid: string): count
    {
    local total: count = 0;
    for ( [entry_uid, direction, alert_kind] in
          pending_legacy_alert_provenance )
        if ( entry_uid == uid ) ++total;
    return total;
    }

event lifecycle_probe(c: connection, label: string)
    {
    local generation: count = c$uid in current_mms_policy_generation ?
        current_mms_policy_generation[c$uid] : 0;
    print fmt("%s generation=%d orig-sequence=%d resp-sequence=%d controls=%d evidence=%d alert-markers=%d",
              label, generation, mms_parser_sequence(c, T),
              mms_parser_sequence(c, F), pending_control_total(c$uid),
              deferred_evidence_total(c$uid),
              legacy_alert_marker_total(c$uid));
    }

event lifecycle_after_connect(c: connection)
    {
    event ICCP::mms_provenance_marker_v1(c, T, 2);
    emit_identify(c, T, 7, "NEW_ASSOCIATION", 2);
    schedule 1msec { lifecycle_probe(c, "connect") };
    }

event lifecycle_after_abort(c: connection)
    {
    event ICCP::mms_provenance_marker_v1(c, T, 2);
    emit_information_report(c, "NEW_REPORT", 202, 2);
    schedule 1msec { lifecycle_probe(c, "abort") };
    }

event lifecycle_after_disconnect(c: connection)
    {
    seed_tase2(c);
    known_variable_types[c$uid, F, 0, "", "NEW_TAG"] = "Tag_Value";
    event ICCP::mms_provenance_marker_v1(c, T, 2);
    emit_get_tag_request(c, 40, "NEW_TAG", 2);
    event ICCP::mms_provenance_marker_v1(c, F, 2);
    emit_get_tag_response(c, 40);
    schedule 1msec { lifecycle_probe(c, "disconnect") };
    }

event lifecycle_after_conclude(c: connection)
    {
    schedule 1msec { lifecycle_probe(c, "conclude") };
    }

event lifecycle_after_parser_error(c: connection)
    {
    schedule 1msec { lifecycle_probe(c, "parser-error") };
    }

event lifecycle_after_remove(c: connection)
    {
    schedule 1msec { lifecycle_probe(c, "connection-remove") };
    }

event zeek_init() &priority=-5
    {
    local connect = test_connection("Cguard-connect", 49201/tcp);
    pending_legacy_alert_provenance[
        connect$uid, T, "orphan_test"] = "verified";
    event ICCP::mms_provenance_marker_v1(connect, T, 1);
    emit_identify(connect, T, 7, "OLD_ASSOCIATION", 1);
    event ICCP::session_spdu_marker_v1(connect, T, 13);
    event lifecycle_after_connect(connect);

    local not_finished = test_connection(
        "Cguard-not-finished", 49202/tcp);
    event ICCP::mms_provenance_marker_v1(not_finished, T, 1);
    emit_identify(not_finished, T, 8, "RETAINED_RELEASE", 1);
    event ICCP::acse_lifecycle_v1(not_finished, F, 3, 8);
    event ICCP::acse_message(
        not_finished, F, T, 3, "1.0.9506.2.3", -1, -1, -1,
        F, 0, F, F, 0);
    schedule 1msec { lifecycle_probe(not_finished, "not-finished") };

    local abort = test_connection("Cguard-abort", 49203/tcp);
    pending_legacy_alert_provenance[
        abort$uid, T, "orphan_test"] = "verified";
    event ICCP::mms_provenance_marker_v1(abort, T, 1);
    emit_information_report(abort, "OLD_REPORT", 101, 1);
    event ICCP::session_spdu_marker_v1(abort, F, 25);
    event lifecycle_after_abort(abort);

    local conclude = test_connection("Cguard-conclude", 49204/tcp);
    seed_tase2(conclude);
    pending_legacy_alert_provenance[
        conclude$uid, T, "orphan_test"] = "verified";
    event ICCP::mms_provenance_marker_v1(conclude, T, 1);
    emit_write(conclude, 31, "OLD_WRITE");
    # A Conclude response is terminal only when it answers the peer's pending
    # Conclude request on a negotiated association.
    emit_aggregate(conclude, T, 11, -1, 0, 0, 0, "", 0, "", 0);
    emit_aggregate(conclude, F, 12, -1, 0, 0, 0, "", 0, "", 0);
    event lifecycle_after_conclude(conclude);

    local disconnect = test_connection("Cguard-disconnect", 49205/tcp);
    pending_legacy_alert_provenance[
        disconnect$uid, T, "orphan_test"] = "verified";
    seed_tase2(disconnect);
    known_variable_types[
        disconnect$uid, F, 0, "", "OLD_TAG"] = "Tag_Value";
    event ICCP::mms_provenance_marker_v1(disconnect, T, 1);
    emit_get_tag_request(disconnect, 40, "OLD_TAG", 1);
    event ICCP::mms_provenance_marker_v1(disconnect, F, 1);
    emit_get_tag_response(disconnect, 40);
    event ICCP::acse_lifecycle_v1(disconnect, F, 3, 10);
    event ICCP::acse_message(
        disconnect, F, T, 3, "1.0.9506.2.3", -1, -1, -1,
        F, 0, F, F, 0);
    event lifecycle_after_disconnect(disconnect);

    local parser_failure = test_connection("Cguard-parser-error", 49206/tcp);
    pending_legacy_alert_provenance[
        parser_failure$uid, T, "orphan_test"] = "verified";
    event ICCP::mms_provenance_marker_v1(parser_failure, T, 1);
    emit_write(parser_failure, 32, "FAILED_WRITE");
    # Model two parser units delivered in one batch: the valid first PDU has
    # queued its policy callback, then the next PDU reaches %init but fails
    # before its aggregate completion hook. The failure may discard only that
    # incomplete PDU's one-shot marker, not the completed write's evidence.
    event ICCP::mms_provenance_marker_v1(parser_failure, T, 2);
    event ICCP::mms_control_value_shape_v3(
        parser_failure, T, 5, "\x02", 2, 0.0);
    event ICCP::parser_error(parser_failure, "later malformed PDU");
    event lifecycle_after_parser_error(parser_failure);

    local removed = test_connection("Cguard-remove", 49207/tcp);
    pending_legacy_alert_provenance[
        removed$uid, T, "orphan_test"] = "verified";
    event ICCP::mms_provenance_marker_v1(removed, T, 1);
    emit_identify(removed, T, 9, "REMOVED_CONNECTION", 1);
    event connection_state_remove(removed);
    event lifecycle_after_remove(removed);
    }
