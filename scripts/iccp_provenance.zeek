# Copyright 2026, Battelle Energy Alliance, LLC. All Rights Reserved.

################################################################################
##
## ICSNPP - ICCP
##
## This file tracks parser provenance for ICCP/MMS observations and alerts.
##
## Christopher B. Peterson and Christian J Weelborg
## Idaho National Lab, November 2026
##
################################################################################

module ICCP;

export {
    const provenance_state_timeout = 1hr &redef;

    global mms_provenance: function(c: connection, is_orig: bool): string;
}

global current_mms_provenance: table[string, bool] of string
    &read_expire=provenance_state_timeout;
global pending_mms_parser_markers: set[string, bool]
    &read_expire=provenance_state_timeout;
global current_mms_parser_sequence: table[string, bool] of count
    &read_expire=provenance_state_timeout;
global current_mms_policy_generation: table[string] of count
    &read_expire=provenance_state_timeout;
global provenance_acse_lifecycle_spdu: table[string, bool] of count
    &read_expire=provenance_state_timeout;
global provenance_session_cleanup_spdu: table[string, bool] of count
    &read_expire=provenance_state_timeout;
global pending_legacy_alert_provenance: table[string, bool, string] of string
    &read_expire=provenance_state_timeout;

# Deferred policy retains immutable per-PDU provenance, while the stable legacy
# alert signatures do not carry it.  A marker emitted immediately before one
# legacy alert lets that alert's v2 compatibility bridge consume the captured
# value without consulting direction-wide state that a later PDU may have
# replaced.  The marker and legacy alert must remain adjacent in event order.
global legacy_alert_provenance_marker_v1: event(
    c: connection, is_orig: bool, alert_kind: string, provenance: string);

function provenance_name(code: count): string
    {
    if ( code == 1 ) return "verified";
    if ( code == 2 ) return "inferred";
    return "unknown";
    }

function set_mms_provenance(c: connection, is_orig: bool, code: count)
    {
    current_mms_provenance[c$uid, is_orig] = provenance_name(code);
    }

function mms_parser_sequence(c: connection, is_orig: bool): count
    {
    if ( [c$uid, is_orig] in current_mms_parser_sequence )
        return current_mms_parser_sequence[c$uid, is_orig];
    return 0;
    }

# Deferred policy callbacks capture this connection-scoped generation.  An
# association boundary advances it before any zero-delay callback can run, so
# work queued for an earlier association cannot log or recreate state in the
# replacement association.
function mms_policy_generation(c: connection): count
    {
    if ( c$uid !in current_mms_policy_generation )
        current_mms_policy_generation[c$uid] = 1;
    return current_mms_policy_generation[c$uid];
    }

function mms_policy_generation_is_current(
    c: connection, generation: count): bool
    {
    return c$uid in current_mms_policy_generation &&
           current_mms_policy_generation[c$uid] == generation;
    }

function advance_mms_policy_generation(c: connection)
    {
    current_mms_policy_generation[c$uid] =
        mms_policy_generation(c) + 1;
    }

# Only the parser emits the %init marker. Direct script callers may emit the
# public v2 evidence events without it, so policy can use this one-shot token
# to defer solely when sibling parser completion hooks may be reordered.
function consume_mms_parser_marker(c: connection, is_orig: bool): bool
    {
    if ( [c$uid, is_orig] !in pending_mms_parser_markers )
        return F;

    delete pending_mms_parser_markers[c$uid, is_orig];
    return T;
    }

function mms_provenance(c: connection, is_orig: bool): string
    {
    if ( [c$uid, is_orig] in current_mms_provenance )
        return current_mms_provenance[c$uid, is_orig];
    return "unknown";
    }

function legacy_alert_provenance(
    c: connection, is_orig: bool, alert_kind: string): string
    {
    if ( [c$uid, is_orig, alert_kind] in pending_legacy_alert_provenance )
        {
        local provenance = pending_legacy_alert_provenance[
            c$uid, is_orig, alert_kind];
        delete pending_legacy_alert_provenance[c$uid, is_orig, alert_kind];
        return provenance;
        }

    return mms_provenance(c, is_orig);
    }

event legacy_alert_provenance_marker_v1(
    c: connection, is_orig: bool, alert_kind: string,
    provenance: string) &priority=20
    {
    pending_legacy_alert_provenance[c$uid, is_orig, alert_kind] = provenance;
    }

function clear_legacy_alert_provenance(uid: string, is_orig: bool)
    {
    local alert_kinds: vector of string;
    for ( [entry_uid, entry_is_orig, alert_kind] in
          pending_legacy_alert_provenance )
        if ( entry_uid == uid && entry_is_orig == is_orig )
            alert_kinds[|alert_kinds|] = alert_kind;

    for ( index in alert_kinds )
        delete pending_legacy_alert_provenance[
            uid, is_orig, alert_kinds[index]];
    }

function clear_mms_provenance(c: connection)
    {
    # Keep parser sequences monotonic for the lifetime of the TCP connection.
    # A replacement association may begin before zero-delay callbacks from the
    # preceding association are dispatched; reusing a sequence there would let
    # the two generations address the same evidence key.
    delete current_mms_provenance[c$uid, T];
    delete current_mms_provenance[c$uid, F];
    delete pending_mms_parser_markers[c$uid, T];
    delete pending_mms_parser_markers[c$uid, F];
    clear_legacy_alert_provenance(c$uid, T);
    clear_legacy_alert_provenance(c$uid, F);
    }

event ICCP::mms_provenance_marker_v1(
    c: connection, is_orig: bool, provenance: count) &priority=20
    {
    mms_policy_generation(c);
    set_mms_provenance(c, is_orig, provenance);
    current_mms_parser_sequence[c$uid, is_orig] =
        mms_parser_sequence(c, is_orig) + 1;
    add pending_mms_parser_markers[c$uid, is_orig];
    }

event ICCP::mms_message_v2(
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
    result_flags_raw: string, result_timestamp_value: int,
    provenance: count) &priority=20
    {
    set_mms_provenance(c, is_orig, provenance);
    }

event ICCP::mms_identify_message_v2(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    vendor_name: string, model_name: string, revision: string,
    abstract_syntax_count: count, first_abstract_syntax: string,
    provenance: count) &priority=20
    {
    set_mms_provenance(c, is_orig, provenance);
    }

event ICCP::mms_information_report_results_v2(
    c: connection, is_orig: bool, access_choice: count,
    list_scope: count, list_domain: string, list_name: string,
    result_count: count, failure_count: count,
    variable_scopes: vector of count,
    variable_domains: vector of string,
    variable_names: vector of string,
    result_choices: vector of count,
    result_errors: vector of int,
    result_raws: vector of string,
    result_integer_values: vector of int,
    result_floating_values: vector of double,
    result_boolean_values: vector of bool,
    result_string_values: vector of string,
    provenance: count) &priority=20
    {
    set_mms_provenance(c, is_orig, provenance);
    }

event ICCP::mms_device_action_message_v1(
    c: connection, is_orig: bool,
    enrollment_scope: count, enrollment_domain: string,
    enrollment_name: string, condition_scope: count,
    condition_domain: string, condition_name: string,
    severity: int, current_state_present: bool, current_state: int,
    transition_time_kind: count, transition_time_raw: string,
    transition_time_value: int, notification_lost: bool,
    alarm_ack_rule_present: bool, alarm_ack_rule: int,
    action_result_present: bool, provenance: count) &priority=20
    {
    set_mms_provenance(c, is_orig, provenance);
    }

event ICCP::mms_transfer_set_message_v2(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    service_tag: count, unconfirmed_service_tag: count,
    access_choice: count, list_scope: count, list_domain: string,
    list_name: string, variable_count: count,
    first_variable_scope: count, first_variable_domain: string,
    first_variable_name: string, deletable: bool, delete_scope: int,
    name_count: count, number_matched: int, number_deleted: int,
    result_count: count, failure_count: count,
    member_scopes: vector of count, member_domains: vector of string,
    member_names: vector of string, result_choices: vector of count,
    result_errors: vector of int, result_raws: vector of string,
    provenance: count) &priority=20
    {
    set_mms_provenance(c, is_orig, provenance);
    }

event ICCP::mms_error_message_v2(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    modifier_position: int, error_class: count, error_code: int,
    additional_code: int, additional_description: string,
    provenance: count) &priority=20
    {
    set_mms_provenance(c, is_orig, provenance);
    }

event ICCP::mms_control_message_v2(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    service_tag: count, object_scope: count, object_domain: string,
    object_name: string, variable_count: count, data_count: count,
    data_node_count: count, result_count: count, success_count: count,
    failure_count: count, provenance: count) &priority=20
    {
    set_mms_provenance(c, is_orig, provenance);
    }

event ICCP::mms_transfer_control_message_v2(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    service_tag: count, access_choice: count, object_scope: count,
    object_domain: string, object_name: string, variable_count: count,
    data_count: count, first_data_choice: count,
    first_data_boolean: bool, first_data_child_count: count,
    first_data_twelfth_choice: count, first_data_twelfth_boolean: bool,
    first_data_dst_transfer_set_shape: bool, result_count: count,
    success_count: count, failure_count: count,
    provenance: count) &priority=20
    {
    set_mms_provenance(c, is_orig, provenance);
    }

event ICCP::mms_ds_transfer_set_message_v1(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    service_tag: count, access_choice: count, object_scope: count,
    object_domain: string, object_name: string, variable_count: count,
    data_count: count, first_data_choice: count,
    component_choices: vector of count,
    component_raws: vector of string,
    component_integer_values: vector of int,
    data_set_component_choices: vector of count,
    data_set_component_raws: vector of string,
    data_set_component_integer_values: vector of int,
    provenance: count) &priority=20
    {
    set_mms_provenance(c, is_orig, provenance);
    }

event ICCP::mms_variable_type_message_v2(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    service_tag: count, object_scope: count, object_domain: string,
    object_name: string, type_choice: count, named_type_scope: count,
    named_type_domain: string, named_type_name: string,
    provenance: count) &priority=20
    {
    set_mms_provenance(c, is_orig, provenance);
    }

event ICCP::mms_transfer_support_value_message_v2(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    service_tag: count, object_scope: count, object_domain: string,
    object_name: string, result_count: count, failure_count: count,
    first_result_choice: count, first_result_raw: string,
    component_count: count, first_component_choice: count,
    second_component_choice: count, third_component_choice: count,
    first_integer_value: int, second_component_raw: string,
    third_component_raw: string, provenance: count) &priority=20
    {
    set_mms_provenance(c, is_orig, provenance);
    }

# Legacy alerts remain source-compatible.  Their v2 companions attach the
# provenance of the MMS PDU that caused the alert.  ACSE rejection evidence is
# directly decoded and malformed top-level input has no MMS provenance.
event ICCP::unknown_object_access(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, operation: string, invoke_id: int,
    object_scope: string, object_domain: string, object_name: string,
    name_model: string) &priority=-20
    {
    event ICCP::unknown_object_access_v2(
        c, is_orig, association_kind, endpoint_role, operation, invoke_id,
        object_scope, object_domain, object_name, name_model,
        legacy_alert_provenance(c, is_orig, "unknown_object_access"));
    }

event ICCP::write_attempt(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, invoke_id: int, object_scope: string,
    object_domain: string, object_name: string, variable_count: count,
    data_count: count, data_node_count: count) &priority=-20
    {
    event ICCP::write_attempt_v2(
        c, is_orig, association_kind, endpoint_role, invoke_id, object_scope,
        object_domain, object_name, variable_count, data_count,
        data_node_count,
        legacy_alert_provenance(c, is_orig, "write_attempt"));
    }

event ICCP::write_failure(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, invoke_id: int, outcome: string,
    object_scope: string, object_domain: string, object_name: string,
    failure_count: count, error_class: string, error_code: int) &priority=-20
    {
    event ICCP::write_failure_v2(
        c, is_orig, association_kind, endpoint_role, invoke_id, outcome,
        object_scope, object_domain, object_name, failure_count, error_class,
        error_code,
        legacy_alert_provenance(c, is_orig, "write_failure"));
    }

event ICCP::control_failure(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, invoke_id: int, classification: string,
    outcome: string, object_scope: string, object_domain: string,
    object_name: string, named_type: string, failure_count: count,
    error_class: string, error_code: int) &priority=-20
    {
    event ICCP::control_failure_v2(
        c, is_orig, association_kind, endpoint_role, invoke_id,
        classification, outcome, object_scope, object_domain, object_name,
        named_type, failure_count, error_class, error_code,
        legacy_alert_provenance(c, is_orig, "control_failure"));
    }

event ICCP::device_action(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, classification: string, outcome: string,
    enrollment_scope: string, enrollment_domain: string,
    enrollment_name: string, condition_name: string) &priority=-20
    {
    event ICCP::device_action_v2(
        c, is_orig, association_kind, endpoint_role, classification,
        outcome, enrollment_scope, enrollment_domain, enrollment_name,
        condition_name,
        legacy_alert_provenance(c, is_orig, "device_action"));
    }

event ICCP::dst_transfer_set_anomaly(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, invoke_id: int, object_scope: string,
    object_domain: string, object_name: string, classification: string,
    conformance: string, reasons: string) &priority=-20
    {
    event ICCP::dst_transfer_set_anomaly_v2(
        c, is_orig, association_kind, endpoint_role, invoke_id,
        object_scope, object_domain, object_name, classification,
        conformance, reasons,
        legacy_alert_provenance(c, is_orig, "dst_transfer_set_anomaly"));
    }

event ICCP::transfer_report_anomaly(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, transfer_set_scope: string,
    transfer_set_domain: string, transfer_set_name: string,
    report_correlation: string, reason: string) &priority=-20
    {
    event ICCP::transfer_report_anomaly_v2(
        c, is_orig, association_kind, endpoint_role, transfer_set_scope,
        transfer_set_domain, transfer_set_name, report_correlation, reason,
        legacy_alert_provenance(c, is_orig, "transfer_report_anomaly"));
    }

event ICCP::unexpected_service(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, association_phase: string, invoke_id: int,
    service_tag: count, operation: string) &priority=-20
    {
    event ICCP::unexpected_service_v2(
        c, is_orig, association_kind, endpoint_role, association_phase,
        invoke_id, service_tag, operation,
        legacy_alert_provenance(c, is_orig, "unexpected_service"));
    }

event ICCP::authenticated_association_rejected(
    c: connection, response_is_orig: bool, request_is_orig: bool,
    authentication_length: count, association_result: int,
    diagnostic_code: int) &priority=-20
    {
    event ICCP::authenticated_association_rejected_v2(
        c, response_is_orig, request_is_orig, authentication_length,
        association_result, diagnostic_code, "verified");
    }

event ICCP::resource_limit_exceeded(
    c: connection, is_orig: bool, resource: string, limit: count,
    current: count, invoke_id: int) &priority=-20
    {
    event ICCP::resource_limit_exceeded_v2(
        c, is_orig, resource, limit, current, invoke_id,
        legacy_alert_provenance(c, is_orig, "resource_limit_exceeded"));
    }

event ICCP::malformed_structure(c: connection, reason: string) &priority=-20
    {
    event ICCP::malformed_structure_v2(c, reason, "unknown");
    }

# A failed parser dispatch may have emitted the parser-only %init marker but
# never reach the aggregate %done hook that consumes it.  Do not let that
# one-shot token or its provenance leak into the next PDU.  Parser failure is
# not an association boundary: completed PDUs have already captured their
# generation and provenance, and their deferred callbacks must remain valid.
event ICCP::parser_error(c: connection, reason: string) &priority=-40
    {
    clear_mms_provenance(c);
    delete provenance_acse_lifecycle_spdu[c$uid, T];
    delete provenance_acse_lifecycle_spdu[c$uid, F];
    delete provenance_session_cleanup_spdu[c$uid, T];
    delete provenance_session_cleanup_spdu[c$uid, F];
    }

event ICCP::session_spdu_marker_v1(
    c: connection, is_orig: bool, spdu_type: count) &priority=-40
    {
    delete provenance_acse_lifecycle_spdu[c$uid, is_orig];
    delete provenance_session_cleanup_spdu[c$uid, is_orig];
    if ( spdu_type != 10 && spdu_type != 12 && spdu_type != 13 &&
         spdu_type != 25 && spdu_type != 26 )
        return;
    advance_mms_policy_generation(c);
    clear_mms_provenance(c);
    provenance_session_cleanup_spdu[c$uid, is_orig] = spdu_type;
    }

event ICCP::cotp_lifecycle_v1(
    c: connection, is_orig: bool, tpdu_type: count) &priority=-40
    {
    if ( tpdu_type != 0xe0 && tpdu_type != 0xd0 &&
         tpdu_type != 0x80 &&
         tpdu_type != 0xc0 && tpdu_type != 0x70 )
        return;

    delete provenance_acse_lifecycle_spdu[c$uid, T];
    delete provenance_acse_lifecycle_spdu[c$uid, F];
    delete provenance_session_cleanup_spdu[c$uid, T];
    delete provenance_session_cleanup_spdu[c$uid, F];
    advance_mms_policy_generation(c);
    clear_mms_provenance(c);
    }

function clear_provenance_after_observation_gap(c: connection)
    {
    delete provenance_acse_lifecycle_spdu[c$uid, T];
    delete provenance_acse_lifecycle_spdu[c$uid, F];
    delete provenance_session_cleanup_spdu[c$uid, T];
    delete provenance_session_cleanup_spdu[c$uid, F];
    advance_mms_policy_generation(c);
    clear_mms_provenance(c);
    }

event ICCP::stream_gap(
    c: connection, is_orig: bool, length: count) &priority=-40
    {
    clear_provenance_after_observation_gap(c);
    }

event content_gap(
    c: connection, is_orig: bool, seq: count, length: count) &priority=-40
    {
    if ( lookup_connection_analyzer_id(
             c$id, Analyzer::ANALYZER_ICCP_TCP) == 0 )
        return;

    clear_provenance_after_observation_gap(c);
    }

event ICCP::acse_lifecycle_v1(
    c: connection, is_orig: bool, apdu_type: count,
    spdu_type: count) &priority=-40
    {
    provenance_acse_lifecycle_spdu[c$uid, is_orig] = spdu_type;
    }

event ICCP::acse_message(
    c: connection, is_orig: bool, recognized: bool, apdu_type: count,
    application_context: string, association_result: int, reason: int,
    diagnostic_code: int, authentication_present: bool,
    authentication_length: count, is_opaque: bool, dispatch_mms: bool,
    payload_length: count) &priority=-40
    {
    local parser_lifecycle =
        [c$uid, is_orig] in provenance_acse_lifecycle_spdu;
    local spdu_type: count = 0;
    if ( parser_lifecycle )
        {
        spdu_type = provenance_acse_lifecycle_spdu[c$uid, is_orig];
        delete provenance_acse_lifecycle_spdu[c$uid, is_orig];
        }
    local session_already_cleared = parser_lifecycle &&
        [c$uid, is_orig] in provenance_session_cleanup_spdu &&
        provenance_session_cleanup_spdu[c$uid, is_orig] == spdu_type;
    delete provenance_session_cleanup_spdu[c$uid, is_orig];
    local terminal = recognized &&
        ((apdu_type == 1 && association_result != 0) ||
         apdu_type == 4 ||
         (apdu_type == 3 && (! parser_lifecycle || spdu_type == 10)));
    if ( terminal && ! session_already_cleared )
        {
        advance_mms_policy_generation(c);
        clear_mms_provenance(c);
        }
    }

event ICCP::mms_conclude_result_v1(
    c: connection, response_is_orig: bool, request_is_orig: bool,
    accepted: bool)
    {
    if ( accepted )
        {
        advance_mms_policy_generation(c);
        clear_mms_provenance(c);
        }
    }

event connection_state_remove(c: connection) &priority=-20
    {
    clear_mms_provenance(c);
    delete current_mms_parser_sequence[c$uid, T];
    delete current_mms_parser_sequence[c$uid, F];
    delete current_mms_policy_generation[c$uid];
    delete provenance_acse_lifecycle_spdu[c$uid, T];
    delete provenance_acse_lifecycle_spdu[c$uid, F];
    delete provenance_session_cleanup_spdu[c$uid, T];
    delete provenance_session_cleanup_spdu[c$uid, F];
    }
