# @TEST-DOC: Deferred parser policy must bind additive evidence, provenance,
# @TEST-DOC: and correlation to the exact MMS PDU. Exercise back-to-back
# @TEST-DOC: Identify, InformationReport, Write, and Get-Tag delivery, retain
# @TEST-DOC: state across Session NOT-FINISHED, preserve direct-event API
# @TEST-DOC: behavior without parser markers, bind deferred v2 alerts to their
# @TEST-DOC: captured provenance, and keep one reused invoke from deleting an
# @TEST-DOC: unrelated queued Write's sequence-keyed value shape. Adjacent
# @TEST-DOC: same-kind Write and Get-Tag failure alerts must consume their
# @TEST-DOC: provenance markers in FIFO pair order.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT | sort > output
# @TEST-EXEC: zeek-cut uid is_orig message_type status invoke_id identify_outcome vendor_name provenance < iccp.log | awk -F '\t' '$1 == "Cdeferred-races" && $6 != "-"' | sort -t '	' -k7,7 >> output
# @TEST-EXEC: zeek-cut uid is_orig message_type transfer_kind object_name value_type point_type integer_value standardized_value result_pairing_status provenance < iccp.log | awk -F '\t' '$1 == "Cdeferred-races" && $4 == "information_report"' | sort -t '	' -k5,5 >> output
# @TEST-EXEC: zeek-cut uid is_orig message_type status invoke_id identify_outcome vendor_name provenance < iccp.log | awk -F '\t' '$1 == "Cdirect-evidence"' >> output
# @TEST-EXEC: zeek-cut uid is_orig classification outcome invoke_id object_name named_type integer_value tag_value tag_state tag_reason provenance < iccp_controls.log | awk -F '\t' '$1 == "Cdeferred-races" && ($5 == 31 || $5 == 32 || $5 == 40)' | sort -t '	' -k5,5n -k2,2 >> output
# @TEST-EXEC: zeek-cut uid is_orig classification outcome invoke_id object_name named_type integer_value provenance < iccp_controls.log | awk -F '\t' '$1 == "Cshape-reuse"' >> output
# @TEST-EXEC: btest-diff output

module ICCP;

global inspect_deferred_cleanup: event(c: connection);
global lifecycle_begin: event(c: connection);
global lifecycle_after_not_finished: event(c: connection);
global lifecycle_after_disconnect: event(c: connection);
global lifecycle_after_abort_marker: event(c: connection);
global inspect_shape_reuse: event(c: connection);

event ICCP::write_attempt_v2(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, invoke_id: int, object_scope: string,
    object_domain: string, object_name: string, variable_count: count,
    data_count: count, data_node_count: count, provenance: string)
    {
    if ( c$uid == "Cdeferred-races" &&
         (invoke_id == 31 || invoke_id == 32) )
        print fmt("write alert invoke=%d object=%s provenance=%s",
                  invoke_id, object_name, provenance);
    }

event ICCP::control_failure_v2(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, invoke_id: int, classification: string,
    outcome: string, object_scope: string, object_domain: string,
    object_name: string, named_type: string, failure_count: count,
    error_class: string, error_code: int, provenance: string)
    {
    if ( c$uid == "Cdeferred-races" &&
         (invoke_id == 41 || invoke_id == 42) )
        print fmt("control alert invoke=%d object=%s provenance=%s",
                  invoke_id, object_name, provenance);
    }

function test_connection(uid: string, orig_port: port): connection
    {
    return [
        $id=[$orig_h=192.0.2.210, $orig_p=orig_port,
             $resp_h=192.0.2.220, $resp_p=102/tcp],
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
    candidate_operation: count, object_scope: count,
    object_domain: string, object_name: string,
    first_variable_scope: count, first_variable_domain: string,
    first_variable_name: string, first_result_type: count,
    first_result_raw: string, result_integer_value: int)
    {
    event ICCP::mms_message(
        c, is_orig, T, pdu_type, T, 16, invoke_id,
        service_tag, unconfirmed_service_tag, F, candidate_operation,
        "", "", object_scope, object_domain, object_name, 0, F,
        first_variable_scope, first_variable_domain, first_variable_name,
        0, first_result_type, first_result_raw, 0, 0, 0, 0, 0, 0, 0,
        result_integer_value, 0.0, "", 0);
    }

function emit_identify(
    c: connection, is_orig: bool, invoke_id: int, vendor: string,
    provenance: count)
    {
    emit_aggregate(c, is_orig, 0, invoke_id, 2, 0, 10,
                   0, "", "", 0, "", "", 0, "", 0);
    event ICCP::mms_identify_message_v2(
        c, is_orig, 0, invoke_id, vendor, fmt("%s-model", vendor),
        fmt("%s-revision", vendor), 1, "1.0.9506.2.3", provenance);
    }

function emit_information_report(
    c: connection, name: string, integer_value: int,
    raw: string, provenance: count)
    {
    local scopes: vector of count = vector(0);
    local domains: vector of string = vector("");
    local names: vector of string = vector(name);
    local choices: vector of count = vector(5);
    local errors: vector of int = vector(-1);
    local raws: vector of string = vector(raw);
    local integers: vector of int = vector(integer_value);
    local floats: vector of double = vector(0.0);
    local booleans: vector of bool = vector(F);
    local strings: vector of string = vector("");

    emit_aggregate(c, T, 3, -1, 0, 0, 8,
                   0, "", name, 0, "", name, 5, raw, integer_value);
    event ICCP::mms_information_report_results_v2(
        c, T, 0, 0, "", "", 1, 0,
        scopes, domains, names, choices, errors, raws, integers, floats,
        booleans, strings, provenance);
    event ICCP::mms_point_value_shape_v2(
        c, T, |raw|, 0, 0, 0);
    }

function emit_write(
    c: connection, invoke_id: int, name: string,
    raw: string, integer_value: int)
    {
    emit_aggregate(c, T, 0, invoke_id, 5, 0, 3,
                   0, "", "", 0, "", name, 0, "", 0);
    # Parser completion order is aggregate, legacy service event, then the
    # richer value-shape event.  The service handler therefore must defer.
    event ICCP::mms_control_message(
        c, T, 0, invoke_id, 5, 0, "", name, 1, 1, 1, 0, 0, 0);
    event ICCP::mms_control_value_shape_v3(
        c, T, 5, raw, integer_value, 0.0);
    }

function emit_get_tag(c: connection, invoke_id: int, provenance: count)
    {
    emit_aggregate(c, T, 0, invoke_id, 4, 0, 2,
                   0, "", "", 0, "", "BREAKER_TAG", 0, "", 0);
    # Exercise the reverse of the analyzer's usual declaration order: once the
    # aggregate hook has marked this as a parser Read, the self-contained v3
    # hook is authoritative for the explicit-variable identity.  The legacy
    # hook below must then remain a no-op instead of double-classifying it.
    event ICCP::mms_read_message_v3(
        c, T, 0, invoke_id, 0, 1, 0, "", "BREAKER_TAG", 0,
        0, 0, 0, "", 0, 0, 0, 0, 0, 0, provenance);
    event ICCP::mms_control_message(
        c, T, 0, invoke_id, 4, 0, "", "BREAKER_TAG",
        1, 0, 0, 0, 0, 0);
    }

function emit_get_tag_response(c: connection, invoke_id: int)
    {
    local choices: vector of count = vector(4, 10);
    local raws: vector of string = vector("\x05\xa0", "maintenance");
    local integers: vector of int = vector();
    integers[0] = 0;
    integers[1] = 0;
    local no_choices: vector of count = vector();
    local no_raws: vector of string = vector();
    local no_integers: vector of int = vector();

    emit_aggregate(c, F, 1, invoke_id, 4, 0, 2,
                   0, "", "", 0, "", "", 2, "", 0);
    event ICCP::mms_transfer_support_value_message(
        c, F, 1, invoke_id, 4, 0, "", "",
        1, 0, 2, "", 2, 4, 10, 0, 0, "maintenance", "");
    event ICCP::mms_point_value_shape_v3(
        c, F, 2, choices, raws, integers, 0,
        no_choices, no_raws, no_integers);
    event ICCP::mms_control_read_value_shape_v1(
        c, F, 1, invoke_id, 4, 2, choices, raws, integers);
    }

function emit_get_tag_failure_response(c: connection, invoke_id: int)
    {
    emit_aggregate(c, F, 1, invoke_id, 4, 0, 2,
                   0, "", "", 0, "", "", 0, "", 0);
    event ICCP::mms_transfer_support_value_message(
        c, F, 1, invoke_id, 4, 0, "", "",
        1, 1, 0, "", 0, 0, 0, 0, 0, "", "");
    }

function deferred_evidence_count(uid: string): count
    {
    local total: count = 0;
    for ( [identify_uid, identify_dir, identify_sequence,
           identify_pdu, identify_invoke] in identify_evidence )
        if ( identify_uid == uid ) ++total;
    for ( [report_uid, report_dir, report_sequence] in
          information_report_results_evidence )
        if ( report_uid == uid ) ++total;
    for ( [point_uid, point_dir, point_sequence] in
          point_value_shape_evidence )
        if ( point_uid == uid ) ++total;
    for ( [control_uid, control_dir, control_sequence] in
          control_value_shape_evidence )
        if ( control_uid == uid ) ++total;
    for ( [read_uid, read_dir, read_sequence, read_invoke] in
          control_read_value_shape_evidence )
        if ( read_uid == uid ) ++total;
    return total;
    }

event inspect_deferred_cleanup(c: connection)
    {
    print fmt("deferred cleanup evidence=%d marker_orig=%s marker_resp=%s tag_pending=%s",
              deferred_evidence_count(c$uid),
              [c$uid, T] in pending_mms_parser_markers,
              [c$uid, F] in pending_mms_parser_markers,
              [c$uid, T, 40] in pending_control_reads);
    }

event inspect_shape_reuse(c: connection)
    {
    local pending_b = [c$uid, T, 52] in pending_controls;
    local classification = pending_b ?
        pending_controls[c$uid, T, 52]$classification : "missing";
    print fmt("shape reuse pending_b=%s classification=%s evidence=%d",
              pending_b, classification, deferred_evidence_count(c$uid));
    }

# The aggregate consumer runs at normal priority.  A direct caller without a
# parser marker must therefore have consumed Identify evidence by this final
# same-event probe, rather than scheduling it for later.
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
    result_flags_raw: string, result_timestamp_value: int) &priority=-35
    {
    if ( c$uid == "Cdirect-evidence" && invoke_id == 99 )
        print fmt("direct identify synchronous=%s",
                  [c$uid, is_orig, mms_parser_sequence(c, is_orig),
                   pdu_type, int_to_count(invoke_id)] !in identify_evidence);
    }

function seed_lifecycle_state(c: connection)
    {
    pending_confirmed[c$uid, T, 88] = [
        $service_tag=4, $operation=2, $request_is_orig=T
    ];
    pending_name_lists[c$uid, T, 88] = [
        $object_class_choice=0, $object_class=0,
        $scope=0, $domain="", $continue_after=""
    ];
    identify_evidence[c$uid, T, 77, 0, 88] = [
        $vendor_name="lifecycle", $model_name="", $revision="",
        $abstract_syntax_count=0, $first_abstract_syntax=""
    ];
    current_mms_provenance[c$uid, T] = "verified";
    current_mms_parser_sequence[c$uid, T] = 77;
    add pending_mms_parser_markers[c$uid, T];
    }

function print_lifecycle_state(c: connection, stage: string)
    {
    print fmt("lifecycle %s confirmed=%s evidence=%s deferred=%s provenance=%s marker=%s",
              stage,
              [c$uid, T, 88] in pending_confirmed,
              [c$uid, T, 88] in pending_name_lists,
              [c$uid, T, 77, 0, 88] in identify_evidence,
              mms_provenance(c, T),
              [c$uid, T] in pending_mms_parser_markers);
    }

event lifecycle_begin(c: connection)
    {
    seed_lifecycle_state(c);
    event ICCP::acse_lifecycle_v1(c, F, 3, 8);
    event ICCP::acse_message(
        c, F, T, 3, "1.3.6.1.4.1", -1, -1, -1,
        F, 0, F, F, 0);
    event lifecycle_after_not_finished(c);
    }

event lifecycle_after_not_finished(c: connection)
    {
    print_lifecycle_state(c, "not-finished");
    event ICCP::acse_lifecycle_v1(c, F, 3, 10);
    event ICCP::acse_message(
        c, F, T, 3, "1.3.6.1.4.1", -1, -1, -1,
        F, 0, F, F, 0);
    event lifecycle_after_disconnect(c);
    }

event lifecycle_after_disconnect(c: connection)
    {
    print_lifecycle_state(c, "disconnect");
    seed_lifecycle_state(c);
    event ICCP::session_spdu_marker_v1(c, F, 25);
    event lifecycle_after_abort_marker(c);
    }

event lifecycle_after_abort_marker(c: connection)
    {
    print_lifecycle_state(c, "abort-marker");
    }

event zeek_init() &priority=-5
    {
    local c = test_connection("Cdeferred-races", 49152/tcp);
    seed_tase2(c);
    known_variable_types[c$uid, T, 0, "", "REPORT_A"] = "Data_Discrete";
    known_variable_types[c$uid, T, 0, "", "REPORT_B"] = "Data_Discrete";
    known_variable_types[c$uid, F, 0, "", "WRITE_A"] = "Control_Command";
    known_variable_types[c$uid, F, 0, "", "WRITE_B"] = "Control_Command";
    known_variable_types[c$uid, F, 0, "", "BREAKER_TAG"] = "Tag_Value";

    event ICCP::mms_provenance_marker_v1(c, T, 1);
    emit_identify(c, T, 7, "FIRST", 1);
    event ICCP::mms_provenance_marker_v1(c, T, 2);
    emit_identify(c, T, 7, "SECOND", 2);

    event ICCP::mms_provenance_marker_v1(c, T, 1);
    emit_information_report(c, "REPORT_A", 101, "\x65", 1);
    event ICCP::mms_provenance_marker_v1(c, T, 2);
    emit_information_report(
        c, "REPORT_B", 202, "\x00\xca\xfe\xba\xbe", 2);

    event ICCP::mms_provenance_marker_v1(c, T, 1);
    emit_write(c, 31, "WRITE_A", "\x11", 17);
    event ICCP::mms_provenance_marker_v1(c, T, 2);
    emit_write(c, 32, "WRITE_B", "\x22", 34);

    event ICCP::mms_provenance_marker_v1(c, T, 1);
    emit_get_tag(c, 40, 1);
    event ICCP::mms_provenance_marker_v1(c, F, 1);
    emit_get_tag_response(c, 40);

    event ICCP::mms_provenance_marker_v1(c, T, 1);
    emit_get_tag(c, 41, 1);
    event ICCP::mms_provenance_marker_v1(c, T, 2);
    emit_get_tag(c, 42, 2);
    event ICCP::mms_provenance_marker_v1(c, F, 1);
    emit_get_tag_failure_response(c, 41);
    event ICCP::mms_provenance_marker_v1(c, F, 2);
    emit_get_tag_failure_response(c, 42);

    # Mutate live provenance before zero-delay callbacks run.  Every deferred
    # record above must retain the provenance captured for its own PDU.
    event ICCP::mms_provenance_marker_v1(c, F, 2);
    emit_aggregate(c, F, 99, -1, 0, 0, 0,
                   0, "", "", 0, "", "", 0, "", 0);

    # Reusing A invalidates both A requests, but B remains independently
    # admitted. Its queued shape must survive until B's deferred classifier.
    local shape_reuse = test_connection("Cshape-reuse", 49155/tcp);
    seed_tase2(shape_reuse);
    known_variable_types[
        shape_reuse$uid, F, 0, "", "REUSED_A"] = "Control_Command";
    known_variable_types[
        shape_reuse$uid, F, 0, "", "PRESERVED_B"] = "Control_Command";
    event ICCP::mms_provenance_marker_v1(shape_reuse, T, 1);
    emit_write(shape_reuse, 51, "REUSED_A", "\x11", 17);
    event ICCP::mms_provenance_marker_v1(shape_reuse, T, 2);
    emit_write(shape_reuse, 52, "PRESERVED_B", "\x22", 34);
    event ICCP::mms_provenance_marker_v1(shape_reuse, T, 1);
    emit_write(shape_reuse, 51, "REUSED_A", "\x33", 51);
    schedule 1msec { inspect_shape_reuse(shape_reuse) };

    local direct = test_connection("Cdirect-evidence", 49153/tcp);
    event ICCP::mms_identify_message_v2(
        direct, T, 0, 99, "DIRECT", "direct-model", "direct-revision",
        0, "", 1);
    emit_aggregate(direct, T, 0, 99, 2, 0, 10,
                   0, "", "", 0, "", "", 0, "", 0);

    schedule 1msec { inspect_deferred_cleanup(c) };
    local lifecycle = test_connection("Clifecycle-context", 49154/tcp);
    schedule 2msec { lifecycle_begin(lifecycle) };
    }
