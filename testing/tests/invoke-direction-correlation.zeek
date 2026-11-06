# @TEST-DOC: Invoke IDs are scoped to the request sender. Verify simultaneous
# @TEST-DOC: opposite-direction requests with the same ID correlate
# @TEST-DOC: independently, same-direction replies do not consume state, and
# @TEST-DOC: same-direction reuse becomes an ambiguity tombstone across services.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT > output
# @TEST-EXEC: zeek-cut is_orig message_type status invoke_id identify_outcome vendor_name < iccp.log | awk -F '\t' '$4 >= 11' >> output
# @TEST-EXEC: zeek-cut uid is_orig message_type status invoke_id provenance object_name < iccp.log | awk -F '\t' '$1 == "Cinvoke-races"' >> output
# @TEST-EXEC: zeek-cut is_orig outcome invoke_id service_tag operation < iccp_errors.log | awk -F '\t' '$3 == 16' >> output
# @TEST-EXEC: btest-diff output

module ICCP;

global inspect_pending: event(c: connection, invoke_id: int);
global seed_specialized_pending: event(c: connection, invoke_id: int);
global inspect_specialized_pending: event(c: connection, invoke_id: int);
global seed_transfer_service_check: event(c: connection, invoke_id: int);
global inspect_transfer_service_check: event(
    c: connection, invoke_id: int, stage: string);
global inspect_deferred_read_race: event(c: connection, invoke_id: int);
global inspect_provenance_lifecycle: event(c: connection, stage: string);

event inspect_pending(c: connection, invoke_id: int)
    {
    print fmt("ambiguous compatibility=%s", pending_read(c, invoke_id)$name);
    }

event seed_specialized_pending(c: connection, invoke_id: int)
    {
    local key = int_to_count(invoke_id);
    pending_controls[c$uid, T, key] = [
        $request_is_orig=T, $scope=0, $domain="", $name="CONTROL",
        $variable_count=1, $data_count=1, $data_node_count=1,
        $classification="write_candidate", $named_type=""
    ];
    pending_control_reads[c$uid, T, key] = [
        $request_is_orig=T, $scope=0, $domain="", $name="SELECT_SBO",
        $variable_count=1, $classification="select_candidate",
        $named_type=""
    ];
    invalid_control_read_invokes[c$uid, T, key] = [
        $classification="select_candidate"
    ];
    pending_transfer_sets[c$uid, T, key] = [
        $action="inspect", $scope=0, $domain="", $name="TS",
        $variable_count=0, $first_variable_scope=0,
        $first_variable_domain="", $first_variable_name="",
        $prior_known=F,
        $delete_scope=0, $name_count=0, $profile_valid=T,
        $member_scopes=vector(), $member_domains=vector(),
        $member_names=vector(),
        $member_alternate_access_counts=vector(),
        $exact_member_access_evidence=T, $profile_reasons=""
    ];
    pending_transfer_support[c$uid, T, key] = [
        $request_is_orig=T, $scope=1, $domain="ICC",
        $name="Event_Code_Detected"
    ];
    pending_transfer_controls[c$uid, T, key] = [
        $action="start", $request_is_orig=T, $scope=2, $domain="",
        $name="IM_Transfer_Set"
    ];
    pending_variable_types[c$uid, T, key] = [
        $request_is_orig=T, $server=c$id$resp_h, $peer=c$id$orig_h,
        $scope=0, $domain="", $name="POINT"
    ];
    invalid_variable_type_invokes[c$uid, T, key] = T;
    control_read_value_shape_evidence[
        c$uid, F, mms_parser_sequence(c, F), key] = [
        $first_result_length=1, $first_component_length=0,
        $second_component_length=0, $third_component_length=0
    ];
    local state = current_state(c);
    state$pending_reads[T, key] = [
        $scope=0, $domain="", $name="SEEDED_READ", $category=0
    ];
    associations[c$uid] = state;
    }

event inspect_specialized_pending(c: connection, invoke_id: int)
    {
    local key = int_to_count(invoke_id);
    local state = current_state(c);
    print fmt("reuse purge invoke=%d generic=%s invalid=%s read=%s controls=%s control_reads=%s invalid_reads=%s sets=%s support=%s transfer_controls=%s types=%s invalid_types=%s shape=%s",
              invoke_id,
              [c$uid, T, key] in pending_confirmed,
              [c$uid, T, key] in invalid_confirmed_invokes,
              [T, key] in state$pending_reads,
              [c$uid, T, key] in pending_controls,
              [c$uid, T, key] in pending_control_reads,
              [c$uid, T, key] in invalid_control_read_invokes,
              [c$uid, T, key] in pending_transfer_sets,
              [c$uid, T, key] in pending_transfer_support,
              [c$uid, T, key] in pending_transfer_controls,
              [c$uid, T, key] in pending_variable_types,
              [c$uid, T, key] in invalid_variable_type_invokes,
              [c$uid, F, mms_parser_sequence(c, F), key] in
                  control_read_value_shape_evidence);
    }

event seed_transfer_service_check(c: connection, invoke_id: int)
    {
    local state = current_state(c);
    state$presentation_profile = T;
    state$acse_association = T;
    state$mms_negotiation = T;
    state$tase2_evidence = T;
    state$phase = "established";
    associations[c$uid] = state;

    local key = int_to_count(invoke_id);
    pending_transfer_sets[c$uid, T, key] = [
        $action="define", $scope=0, $domain="", $name="TS_SAFE",
        $variable_count=1, $first_variable_scope=0,
        $first_variable_domain="", $first_variable_name="POINT",
        $prior_known=T,
        $delete_scope=0, $name_count=1, $profile_valid=T,
        $member_scopes=vector(0), $member_domains=vector(""),
        $member_names=vector("POINT"),
        $member_alternate_access_counts=vector(0),
        $exact_member_access_evidence=T, $profile_reasons=""
    ];
    known_transfer_sets[c$uid, F, 0, "", "TS_SAFE"] = [
        $scopes=vector(0), $domains=vector(""), $names=vector("POINT")
    ];
    }

event inspect_transfer_service_check(
    c: connection, invoke_id: int, stage: string)
    {
    local key = int_to_count(invoke_id);
    print fmt("transfer service %s pending=%s known=%s", stage,
              [c$uid, T, key] in pending_transfer_sets,
              [c$uid, F, 0, "", "TS_SAFE"] in known_transfer_sets);
    }

event inspect_deferred_read_race(c: connection, invoke_id: int)
    {
    local key = int_to_count(invoke_id);
    local state = current_state(c);
    local name = [T, key] in state$pending_reads ?
        state$pending_reads[T, key]$name : "";
    print fmt("deferred reuse final generic=%s invalid=%s read=%s",
              [c$uid, T, key] in pending_confirmed,
              [c$uid, T, key] in invalid_confirmed_invokes, name);
    }

event inspect_provenance_lifecycle(c: connection, stage: string)
    {
    print fmt("%s provenance marker=%s value=%s", stage,
              [c$uid, T] in pending_mms_parser_markers,
              mms_provenance(c, T));
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
    result_flags_raw: string, result_timestamp_value: int) &priority=0
    {
    if ( pdu_type == 1 && service_tag == 4 && invoke_id >= 0 )
        print fmt("read response dir=%s invoke=%d object=%s",
                  is_orig, invoke_id,
                  pending_read_for_response(c, is_orig, invoke_id)$name);
    }

# Schedule this probe from the response's final event priority.  It therefore
# runs after both the later same-timestamp request and the response's deferred
# policy callback.
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
    if ( c$uid == "Cinvoke-races" && is_orig == F && pdu_type == 1 &&
         service_tag == 4 && invoke_id == 3 )
        schedule 0secs { inspect_deferred_read_race(c, invoke_id) };
    }

event ICCP::mms_error_message(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    modifier_position: int, error_class: count, error_code: int,
    additional_code: int, additional_description: string) &priority=0
    {
    if ( pdu_type == 2 && invoke_id >= 0 )
        print fmt("error response dir=%s invoke=%d object=%s",
                  is_orig, invoke_id,
                  pending_read_for_response(c, is_orig, invoke_id)$name);
    }

function emit_mms(c: connection, is_orig: bool, pdu_type: count,
                  invoke_id: int, service_tag: count,
                  first_variable_name: string)
    {
    event ICCP::mms_message(
        c, is_orig, T, pdu_type, T, 8, invoke_id, service_tag, 0, F,
        service_tag == 2 ? 10 : 2, "", "", 0, "", "", 0, F,
        0, "", first_variable_name, 0, 0, "", 0, 0, 0, 0, 0, 0,
        0, 0, 0.0, "", 0);
    }

function emit_read_response_with_value(c: connection, is_orig: bool,
                                       invoke_id: int)
    {
    event ICCP::mms_message(
        c, is_orig, T, 1, T, 8, invoke_id, 4, 0, F, 2,
        "", "", 0, "", "", 0, F,
        0, "", "", 0, 5, "\x01", 0, 0, 0, 0, 0, 0,
        1, 0, 0.0, "", 0);
    }

function identify(c: connection, is_orig: bool, pdu_type: count,
                  invoke_id: int, vendor: string)
    {
    event ICCP::mms_identify_message_v2(
        c, is_orig, pdu_type, invoke_id, vendor, "model", "revision",
        0, "", 0);
    emit_mms(c, is_orig, pdu_type, invoke_id, 2, "");
    }

function transfer_set_response(c: connection, invoke_id: int,
                               service_tag: count, number_deleted: int)
    {
    event ICCP::mms_transfer_set_message(
        c, F, 1, invoke_id, service_tag, 0, 0, 0, "", "", 0,
        0, "", "", F, 0, 0, 0, number_deleted, 0, 0,
        vector(), vector(), vector(), vector(), vector(), vector());
    }

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.10, $orig_p=49152/tcp,
             $resp_h=192.0.2.20, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Cinvoke-directions"
    ];

    # Read correlation carries distinguishable request identities.
    emit_mms(c, T, 0, 7, 4, "ORIG_POINT");
    emit_mms(c, F, 0, 7, 4, "RESP_POINT");
    event inspect_pending(c, 7);
    emit_mms(c, T, 1, 7, 4, "");
    emit_mms(c, F, 1, 7, 4, "");

    # A same-direction response has no matching request and must leave the
    # outstanding request available for the peer's subsequent response.
    emit_mms(c, T, 0, 8, 4, "KEEP_POINT");
    emit_mms(c, T, 1, 8, 4, "");
    emit_mms(c, F, 1, 8, 4, "");

    emit_mms(c, T, 0, 9, 4, "KEEP_ERROR");
    event ICCP::mms_error_message(c, T, 2, 9, -1, 7, 3, -1, "");
    event ICCP::mms_error_message(c, F, 2, 9, -1, 7, 3, -1, "");

    # Generic confirmed/Identify correlation uses the same directional key.
    identify(c, T, 0, 11, "request-orig");
    identify(c, F, 0, 11, "request-resp");
    identify(c, T, 1, 11, "response-to-resp");
    identify(c, F, 1, 11, "response-to-orig");
    identify(c, T, 0, 12, "request-keep");
    identify(c, T, 1, 12, "wrong-direction");
    identify(c, F, 1, 12, "right-direction");

    # Same-service reuse never replaces the first request identity.
    identify(c, T, 0, 13, "reuse-first");
    identify(c, T, 0, 13, "reuse-second");
    identify(c, F, 1, 13, "reuse-ambiguous");
    identify(c, F, 1, 13, "reuse-consumed");

    # Reuse is global across confirmed services and purges every specialized
    # interpretation, including the aggregate Read identity and shape evidence.
    identify(c, T, 0, 14, "cross-service-first");
    event seed_specialized_pending(c, 14);
    emit_mms(c, T, 0, 14, 4, "REUSED_POINT");
    event inspect_specialized_pending(c, 14);
    emit_mms(c, F, 1, 14, 4, "");

    # A reused namespace in one direction does not poison a simultaneous peer
    # request carrying the same numeric invoke ID.
    identify(c, T, 0, 15, "orig-first");
    identify(c, F, 0, 15, "resp-only");
    identify(c, T, 0, 15, "orig-reused");
    identify(c, T, 1, 15, "response-to-resp");
    identify(c, F, 1, 15, "response-to-orig-ambiguous");

    # ConfirmedError has no service tag and therefore consumes the ambiguity
    # marker without attributing the error to either reused request.
    identify(c, T, 0, 16, "error-first");
    emit_mms(c, T, 0, 16, 4, "ERROR_SECOND");
    event ICCP::mms_error_message(c, F, 2, 16, -1, 7, 3, -1, "");

    # Terminal association and MMS lifecycle messages remove tombstones.
    identify(c, T, 0, 17, "release-first");
    identify(c, T, 0, 17, "release-second");
    event ICCP::acse_message(c, F, T, 3, "", -1, -1, -1,
                            F, 0, F, F, 0);
    identify(c, F, 1, 17, "after-release");

    identify(c, T, 0, 18, "cancel-target");
    emit_mms(c, F, 6, 18, 0, "");
    identify(c, F, 1, 18, "after-cancel-response");

    identify(c, T, 0, 19, "conclude-first");
    identify(c, T, 0, 19, "conclude-second");
    # State emits this result only for a direction-matched successful Conclude;
    # an unmatched pdu_type 12 must not clear the ambiguity tombstone.
    event ICCP::mms_conclude_result_v1(c, F, T, T);
    identify(c, F, 1, 19, "after-conclude");

    # A confirmed-requestPDU Reject retires only the peer request.  The Reject
    # sender's simultaneous request with the same numeric ID remains valid.
    identify(c, T, 0, 23, "reject-peer-request");
    identify(c, F, 0, 23, "reject-sender-request");
    event ICCP::mms_reject_message_v1(c, F, 23, 1, 0, 0);
    emit_mms(c, F, 4, 23, 0, "");
    identify(c, T, 1, 23, "response-to-reject-sender");
    identify(c, F, 1, 23, "response-to-rejected-peer");

    # A response in the shared Define/Get/Delete pending family must match the
    # request service before it can mutate transfer-list lifecycle state.
    event seed_transfer_service_check(c, 24);
    transfer_set_response(c, 24, 13, 1);
    event inspect_transfer_service_check(c, 24, "mismatch");
    transfer_set_response(c, 24, 11, 0);
    event inspect_transfer_service_check(c, 24, "matched");

    local race: connection = [
        $id=[$orig_h=198.51.100.10, $orig_p=49153/tcp,
             $resp_h=198.51.100.20, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Cinvoke-races"
    ];

    # A deferred PDU retains its own provenance even when a later parser PDU
    # in the same direction changes the direction-scoped current value.
    event ICCP::mms_provenance_marker_v1(race, T, 1);
    emit_mms(race, T, 0, 1, 2, "");
    event ICCP::mms_identify_message_v2(
        race, T, 0, 1, "race-vendor", "", "", 0, "", 1);
    event ICCP::mms_provenance_marker_v1(race, T, 2);
    emit_mms(race, T, 0, 2, 5, "LATER_WRITE");

    # A terminal deferred Read response retires the old invoke synchronously.
    # The caller can then legally reuse the ID, while the callback still logs
    # the response against the immutable identity of the old request.
    emit_mms(race, T, 0, 3, 4, "OLD_POINT");
    event ICCP::mms_provenance_marker_v1(race, F, 1);
    event ICCP::mms_read_message_v3(
        race, F, 1, 3, 0, 0, 0, "", "", 0,
        1, 0, 5, "\x01", 0, 0, 0, 0, 0, 0, 1);
    emit_read_response_with_value(race, F, 3);
    emit_mms(race, T, 0, 3, 4, "NEW_POINT");

    # A failed/incomplete MMS parse can leave a %init marker without a matching
    # aggregate event. Terminal association lifecycle must clear that marker.
    local stale: connection = [
        $id=[$orig_h=203.0.113.10, $orig_p=49154/tcp,
             $resp_h=203.0.113.20, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Cstale-provenance"
    ];
    event ICCP::mms_provenance_marker_v1(stale, T, 1);
    event ICCP::acse_message(stale, F, T, 3, "", -1, -1, -1,
                            F, 0, F, F, 0);
    event inspect_provenance_lifecycle(stale, "terminal");
    event ICCP::mms_provenance_marker_v1(stale, T, 2);
    event ICCP::parser_error(stale, "incomplete MMS PDU");
    event inspect_provenance_lifecycle(stale, "parser-error");
    }
