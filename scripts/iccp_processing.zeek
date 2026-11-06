# Copyright 2026, Battelle Energy Alliance, LLC. All Rights Reserved.

################################################################################
##
## ICSNPP - ICCP
##
## This file correlates ICCP/MMS events and produces protocol classifications
## and logs.
##
## Christopher B. Peterson and Christian J Weelborg
## Idaho National Lab, November 2026
##
################################################################################

module ICCP;

export {
    const max_pending_confirmed = 128 &redef;
    const max_pending_controls = 128 &redef;
    const max_pending_transfer_sets = 128 &redef;
    const max_known_transfer_sets = 128 &redef;
    const max_active_transfer_sets = 128 &redef;
    const max_logged_information_report_results = 128 &redef;
    const max_logged_result_raw_bytes = 256 &redef;

    ## Authoritative bilateral/site mapping used for exact TASE.2 typing.
    ## Keys are server and peer addresses, MMS object scope, domain, and name.
    ## A mapping is activated for a connection only after exact bootstrap Read
    ## evidence has classified the association as TASE.2 and a verified,
    ## direction-correct, structurally valid GetVariableAccessAttributes
    ## exchange has described that object.
    option configured_variable_types:
        table[addr, addr, count, string, string] of string = table();

    ## Test-only adapter for scripts that raise the legacy coarse GVA event
    ## directly. Packet-driven production learning always uses mms_gva_message_v3.
    option legacy_gva_direct_event_compatibility = F;
}

type PendingConfirmed: record {
    service_tag: count;
    operation: count;
    request_is_orig: bool;
};

global pending_confirmed: table[string, bool, count] of PendingConfirmed
    &read_expire=association_state_timeout;
global invalid_confirmed_invokes: set[string, bool, count]
    &read_expire=association_state_timeout;
global processing_acse_lifecycle_spdu: table[string, bool] of count
    &read_expire=association_state_timeout;
global processing_session_cleanup_spdu: table[string, bool] of count
    &read_expire=association_state_timeout;

global confirmed_request_tracking_allowed: function(
    c: connection, is_orig: bool, invoke_id: int): bool;
global confirmed_response_is_ambiguous: function(
    c: connection, is_orig: bool, invoke_id: int): bool;
global purge_confirmed_request_state: function(
    c: connection, request_is_orig: bool, invoke_id: int);
global clear_mms_deferred_evidence: function(uid_to_clear: string);

type IdentifyEvidence: record {
    vendor_name: string;
    model_name: string;
    revision: string;
    abstract_syntax_count: count;
    first_abstract_syntax: string;
};

global identify_evidence:
    table[string, bool, count, count, count] of IdentifyEvidence
    &read_expire=association_state_timeout;

function identify_evidence_available(
    c: connection, is_orig: bool, sequence: count, pdu_type: count,
    invoke: count): bool
    {
    return [c$uid, is_orig, sequence, pdu_type, invoke] in
        identify_evidence;
    }

type InformationReportResultsEvidence: record {
    access_choice: count;
    list_scope: count;
    list_domain: string;
    list_name: string;
    result_count: count;
    failure_count: count;
    variable_scopes: vector of count;
    variable_domains: vector of string;
    variable_names: vector of string;
    result_choices: vector of count;
    result_errors: vector of int;
    result_raws: vector of string;
    result_integer_values: vector of int;
    result_floating_values: vector of double;
    result_boolean_values: vector of bool;
    result_string_values: vector of string;
};

type PointValueShapeEvidence: record {
    first_result_length: count;
    first_component_length: count;
    second_component_length: count;
    third_component_length: count;
    component_choices: vector of count &optional;
    component_raws: vector of string &optional;
    component_integer_values: vector of int &optional;
    nested_component_index: count &optional;
    nested_choices: vector of count &optional;
    nested_raws: vector of string &optional;
    nested_integer_values: vector of int &optional;
};

global point_value_shape_evidence:
    table[string, bool, count] of PointValueShapeEvidence
    &read_expire=association_state_timeout;

global control_read_value_shape_evidence:
    table[string, bool, count, count] of PointValueShapeEvidence
    &read_expire=association_state_timeout;

function point_value_shape_available(
    c: connection, is_orig: bool, sequence: count): bool
    {
    return [c$uid, is_orig, sequence] in point_value_shape_evidence;
    }

global information_report_results_evidence:
    table[string, bool, count] of InformationReportResultsEvidence
    &read_expire=association_state_timeout;

function information_report_results_available(
    c: connection, is_orig: bool, sequence: count): bool
    {
    return [c$uid, is_orig, sequence] in
        information_report_results_evidence;
    }

type PendingControl: record {
    request_is_orig: bool;
    scope: count;
    domain: string;
    name: string;
    variable_count: count;
    data_count: count;
    data_node_count: count;
    classification: string;
    named_type: string;
    integer_value: int &optional;
    floating_value: double &optional;
    tag_value: count &optional;
    tag_state: string &optional;
    tag_reason: string &optional;
};

type PendingControlRead: record {
    request_is_orig: bool;
    scope: count;
    domain: string;
    name: string;
    variable_count: count;
    classification: string;
    named_type: string;
};

type InvalidControlReadInvoke: record {
    classification: string;
};

type ControlValueShapeEvidence: record {
    choice: count;
    raw: string;
    integer_value: int;
    floating_value: double;
    component_choices: vector of count &optional;
    component_raws: vector of string &optional;
    component_integer_values: vector of int &optional;
};

global control_value_shape_evidence:
    table[string, bool, count] of ControlValueShapeEvidence
    &read_expire=association_state_timeout;
global control_value_shape_invokes: table[string, bool, count] of count
    &read_expire=association_state_timeout;

function clear_control_value_shapes(uid: string, is_orig: bool)
    {
    # A parser-delivered Write records its invoke alongside the sequence before
    # the richer shape hooks run. Clear both indexed and standalone/direct-event
    # evidence when the whole direction or association is retired.
    local indexed_sequences: vector of count;
    for ( [indexed_uid, indexed_is_orig, indexed_sequence] in
          control_value_shape_invokes )
        if ( indexed_uid == uid && indexed_is_orig == is_orig )
            indexed_sequences[|indexed_sequences|] = indexed_sequence;
    for ( indexed_index in indexed_sequences )
        {
        delete control_value_shape_invokes[
            uid, is_orig, indexed_sequences[indexed_index]];
        delete control_value_shape_evidence[
            uid, is_orig, indexed_sequences[indexed_index]];
        }

    local orphan_sequences: vector of count;
    for ( [entry_uid, entry_is_orig, sequence] in
          control_value_shape_evidence )
        if ( entry_uid == uid && entry_is_orig == is_orig )
            orphan_sequences[|orphan_sequences|] = sequence;
    for ( orphan_index in orphan_sequences )
        delete control_value_shape_evidence[
            uid, is_orig, orphan_sequences[orphan_index]];
    }

function clear_control_value_shapes_for_invoke(
    uid: string, is_orig: bool, invoke: count)
    {
    local sequences: vector of count;
    for ( [entry_uid, entry_is_orig, sequence] in
          control_value_shape_invokes )
        if ( entry_uid == uid && entry_is_orig == is_orig &&
             control_value_shape_invokes[
                 entry_uid, entry_is_orig, sequence] == invoke )
            sequences[|sequences|] = sequence;

    for ( index in sequences )
        {
        delete control_value_shape_invokes[
            uid, is_orig, sequences[index]];
        delete control_value_shape_evidence[
            uid, is_orig, sequences[index]];
        }
    }

function clear_control_read_shapes(
    uid: string, is_orig: bool, invoke: count)
    {
    local sequences: vector of count;
    for ( [entry_uid, entry_is_orig, sequence, entry_invoke] in
          control_read_value_shape_evidence )
        if ( entry_uid == uid && entry_is_orig == is_orig &&
             entry_invoke == invoke )
            sequences[|sequences|] = sequence;
    for ( index in sequences )
        delete control_read_value_shape_evidence[
            uid, is_orig, sequences[index], invoke];
    }

global classify_control_write: function(
    c: connection, server_is_orig: bool,
    scope: count, domain: string, name: string,
    variable_count: count, data_count: count,
    shape: ControlValueShapeEvidence): string;
global learned_variable_type_name: function(
    c: connection, server_is_orig: bool,
    scope: count, domain: string, name: string): string;

event ICCP::mms_control_value_shape_v3(
    c: connection, is_orig: bool, first_data_choice: count,
    first_data_raw: string, first_data_integer_value: int,
    first_data_floating_value: double) &priority=20
    {
    local sequence = mms_parser_sequence(c, is_orig);
    if ( first_data_choice == 0 )
        {
        delete control_value_shape_evidence[c$uid, is_orig, sequence];
        return;
        }
    local evidence: ControlValueShapeEvidence = [
        $choice=first_data_choice, $raw=first_data_raw,
        $integer_value=first_data_integer_value,
        $floating_value=first_data_floating_value
    ];
    if ( [c$uid, is_orig, sequence] in control_value_shape_evidence )
        {
        local existing = control_value_shape_evidence[
            c$uid, is_orig, sequence];
        if ( existing?$component_choices )
            evidence$component_choices = existing$component_choices;
        if ( existing?$component_raws )
            evidence$component_raws = existing$component_raws;
        if ( existing?$component_integer_values )
            evidence$component_integer_values =
                existing$component_integer_values;
        }
    control_value_shape_evidence[c$uid, is_orig, sequence] = evidence;
    }

event ICCP::mms_control_value_shape_v4(
    c: connection, is_orig: bool, first_data_choice: count,
    first_data_raw: string, first_data_integer_value: int,
    first_data_floating_value: double,
    component_choices: vector of count,
    component_raws: vector of string,
    component_integer_values: vector of int) &priority=20
    {
    local sequence = mms_parser_sequence(c, is_orig);
    if ( first_data_choice == 0 )
        {
        delete control_value_shape_evidence[c$uid, is_orig, sequence];
        return;
        }
    control_value_shape_evidence[c$uid, is_orig, sequence] = [
        $choice=first_data_choice, $raw=first_data_raw,
        $integer_value=first_data_integer_value,
        $floating_value=first_data_floating_value,
        $component_choices=component_choices,
        $component_raws=component_raws,
        $component_integer_values=component_integer_values
    ];
    }

global pending_controls: table[string, bool, count] of PendingControl
    &read_expire=association_state_timeout;
global pending_control_reads: table[string, bool, count] of PendingControlRead
    &read_expire=association_state_timeout;
global invalid_control_read_invokes:
    table[string, bool, count] of InvalidControlReadInvoke
    &read_expire=association_state_timeout;

# The compatibility Read events do not expose VariableAccessSpecification.
# A packet-derived event must therefore be handled by mms_read_message_v3,
# whose access_choice distinguishes an explicit variable list from a named
# variable list.  These short-lived tokens let the legacy policy handlers
# recognize their parser sibling independently of completion-hook order while
# leaving direct script events synchronous and source-compatible.
global parser_read_deliveries: set[string, bool, count, count, count]
    &read_expire=association_state_timeout;
global parser_read_delivery_cleanup_stage_v1: event(
    c: connection, is_orig: bool, invoke: count, parser_sequence: count,
    policy_generation: count);
global parser_read_delivery_cleanup_v1: event(
    c: connection, is_orig: bool, invoke: count, parser_sequence: count,
    policy_generation: count);

function parser_read_delivery_is_current(
    c: connection, is_orig: bool, invoke_id: int): bool
    {
    if ( invoke_id < 0 ) return F;
    local invoke = int_to_count(invoke_id);
    local sequence = mms_parser_sequence(c, is_orig);
    local generation = mms_policy_generation(c);
    return [c$uid, is_orig] in pending_mms_parser_markers ||
           [c$uid, is_orig, invoke, sequence, generation] in
               parser_read_deliveries;
    }

function mark_parser_read_delivery(
    c: connection, is_orig: bool, invoke_id: int)
    {
    if ( invoke_id < 0 ) return;
    local invoke = int_to_count(invoke_id);
    local sequence = mms_parser_sequence(c, is_orig);
    local generation = mms_policy_generation(c);
    add parser_read_deliveries[
        c$uid, is_orig, invoke, sequence, generation];
    schedule 0secs {
        ICCP::parser_read_delivery_cleanup_stage_v1(
            c, is_orig, invoke, sequence, generation)
    };
    }

event ICCP::parser_read_delivery_cleanup_stage_v1(
    c: connection, is_orig: bool, invoke: count, parser_sequence: count,
    policy_generation: count)
    {
    # Queue the actual deletion one scheduler turn later.  Whether the v3,
    # aggregate, or compatibility hook ran first, every sibling hook has then
    # had an opportunity to recognize this token.
    schedule 0secs {
        ICCP::parser_read_delivery_cleanup_v1(
            c, is_orig, invoke, parser_sequence, policy_generation)
    };
    }

event ICCP::parser_read_delivery_cleanup_v1(
    c: connection, is_orig: bool, invoke: count, parser_sequence: count,
    policy_generation: count)
    {
    delete parser_read_deliveries[
        c$uid, is_orig, invoke, parser_sequence, policy_generation];
    }

global mms_control_read_shape_cleanup: event(
    c: connection, is_orig: bool, parser_sequence: count,
    invoke_id: int);

global bounded_detail: function(value: string): string;
global bounded_information_report_result_raw: function(raw: string): string;

function write_control_record_with_provenance(
    c: connection, is_orig: bool, rec: ControlInfo, provenance: string)
    {
    rec$provenance = provenance;
    rec$stream_completeness = output_completeness(c, is_orig);
    Log::write(ICCP::CONTROL_LOG, rec);
    }

function write_control_record(c: connection, is_orig: bool, rec: ControlInfo)
    {
    write_control_record_with_provenance(
        c, is_orig, rec, mms_provenance(c, is_orig));
    }

function write_transfer_record_with_provenance(
    c: connection, is_orig: bool, rec: TransferInfo, provenance: string)
    {
    rec$provenance = provenance;
    rec$stream_completeness = output_completeness(c, is_orig);
    Log::write(ICCP::TRANSFER_LOG, rec);
    }

function write_transfer_record(c: connection, is_orig: bool,
                               rec: TransferInfo)
    {
    write_transfer_record_with_provenance(
        c, is_orig, rec, mms_provenance(c, is_orig));
    }

function write_error_record(c: connection, is_orig: bool, rec: ErrorInfo)
    {
    rec$provenance = mms_provenance(c, is_orig);
    rec$stream_completeness = output_completeness(c, is_orig);
    Log::write(ICCP::ERROR_LOG, rec);
    }

function event_action_classification(condition_name: string): string
    {
    if ( /^.+_time$/ in condition_name ) return "device_timeout";
    if ( /^.+_reset$/ in condition_name ) return "device_local_reset";
    if ( /^.+_success$/ in condition_name ) return "device_success";
    if ( /^.+_fail$/ in condition_name ) return "device_failure";
    return "device_action";
    }

function event_action_current_state(state: int): string
    {
    if ( state == 0 ) return "disabled";
    if ( state == 1 ) return "idle";
    if ( state == 2 ) return "active";
    return "unknown";
    }

function event_action_time_kind(kind: count): string
    {
    if ( kind == 0 ) return "time_of_day";
    if ( kind == 1 ) return "time_sequence_identifier";
    if ( kind == 2 ) return "undefined";
    return "unknown";
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
    action_result_present: bool, provenance: count) &priority=5
    {
    local base_classification = event_action_classification(condition_name);
    local exact = association_kind(c) == "tase2" &&
        condition_scope == 0 && condition_domain == "" &&
        ((enrollment_scope == 0 && enrollment_domain == "") ||
         (enrollment_scope == 1 && enrollment_domain != "")) &&
        enrollment_name != "" && base_classification != "device_action" &&
        severity == 0 && current_state_present && current_state == 2 &&
        ! notification_lost && ! action_result_present;
    local classification = exact ? base_classification :
        fmt("%s_candidate", base_classification);
    local rec: ControlInfo = [
        $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
        $association_kind=association_kind(c),
        $association_phase=association_phase(c),
        $endpoint_role=endpoint_role(c, is_orig),
        $classification=classification,
        $outcome=exact ? "notified" : "candidate_notification",
        $invoke_id=-1,
        $object_scope=condition_scope == 0 ? "vcc" :
            condition_scope == 1 ? "icc" : "aa",
        $object_name=condition_name,
        $event_enrollment_scope=enrollment_scope == 0 ? "vcc" :
            enrollment_scope == 1 ? "icc" : "aa",
        $event_enrollment_name=enrollment_name,
        $event_condition_scope=condition_scope == 0 ? "vcc" :
            condition_scope == 1 ? "icc" : "aa",
        $severity=severity,
        $transition_time_kind=event_action_time_kind(transition_time_kind),
        $transition_time_raw=bounded_information_report_result_raw(
            transition_time_raw),
        $notification_lost=notification_lost,
        $action_result_present=action_result_present
    ];
    if ( condition_domain != "" )
        {
        rec$object_domain = condition_domain;
        rec$event_condition_domain = condition_domain;
        }
    if ( enrollment_domain != "" )
        rec$event_enrollment_domain = enrollment_domain;
    if ( current_state_present )
        rec$current_state = event_action_current_state(current_state);
    if ( transition_time_kind == 1 && transition_time_value >= 0 )
        rec$transition_time_value = transition_time_value;
    write_control_record(c, is_orig, rec);

    if ( exact )
        event ICCP::device_action(
            c, is_orig, association_kind(c), endpoint_role(c, is_orig),
            classification, "notified", rec$event_enrollment_scope,
            enrollment_domain, enrollment_name, condition_name);
    }

function pending_confirmed_count(uid: string): count
    {
    local total: count = 0;
    for ( [entry_uid, request_is_orig, invoke] in pending_confirmed )
        if ( entry_uid == uid ) ++total;
    for ( [invalid_uid, invalid_is_orig, invalid_invoke] in
          invalid_confirmed_invokes )
        if ( invalid_uid == uid ) ++total;
    return total;
    }

function mms_error_class_name(error_class: count): string
    {
    switch ( error_class )
        {
        case 0: return "vmd_state";
        case 1: return "application_reference";
        case 2: return "definition";
        case 3: return "resource";
        case 4: return "service";
        case 5: return "service_preempt";
        case 6: return "time_resolution";
        case 7: return "access";
        case 8: return "initiate";
        case 9: return "conclude";
        case 10: return "cancel";
        case 11: return "file";
        default: return "others";
        }
    }

event ICCP::mms_identify_message_v2(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    vendor_name: string, model_name: string, revision: string,
    abstract_syntax_count: count, first_abstract_syntax: string,
    provenance: count) &priority=20
    {
    if ( invoke_id < 0 || (pdu_type != 0 && pdu_type != 1) ) return;
    local sequence = mms_parser_sequence(c, is_orig);
    identify_evidence[
        c$uid, is_orig, sequence, pdu_type, int_to_count(invoke_id)
    ] = [
        $vendor_name=vendor_name, $model_name=model_name,
        $revision=revision, $abstract_syntax_count=abstract_syntax_count,
        $first_abstract_syntax=first_abstract_syntax
    ];
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
    local sequence = mms_parser_sequence(c, is_orig);
    information_report_results_evidence[c$uid, is_orig, sequence] = [
        $access_choice=access_choice,
        $list_scope=list_scope, $list_domain=list_domain,
        $list_name=list_name, $result_count=result_count,
        $failure_count=failure_count,
        $variable_scopes=variable_scopes,
        $variable_domains=variable_domains,
        $variable_names=variable_names,
        $result_choices=result_choices,
        $result_errors=result_errors, $result_raws=result_raws,
        $result_integer_values=result_integer_values,
        $result_floating_values=result_floating_values,
        $result_boolean_values=result_boolean_values,
        $result_string_values=result_string_values
    ];
    }

event ICCP::mms_point_value_shape_v2(
    c: connection, is_orig: bool, first_result_length: count,
    first_component_length: count, second_component_length: count,
    third_component_length: count) &priority=20
    {
    local sequence = mms_parser_sequence(c, is_orig);
    # The legacy v2 and additive v3 shape events are emitted for the same
    # PDU. Event-hook delivery order is not an API contract, so retain any
    # richer v3 vectors that have already arrived instead of replacing them
    # with the four legacy lengths.
    if ( [c$uid, is_orig, sequence] in point_value_shape_evidence )
        {
        local existing = point_value_shape_evidence[
            c$uid, is_orig, sequence];
        existing$first_result_length = first_result_length;
        existing$first_component_length = first_component_length;
        existing$second_component_length = second_component_length;
        existing$third_component_length = third_component_length;
        point_value_shape_evidence[c$uid, is_orig, sequence] = existing;
        return;
        }
    point_value_shape_evidence[c$uid, is_orig, sequence] = [
        $first_result_length=first_result_length,
        $first_component_length=first_component_length,
        $second_component_length=second_component_length,
        $third_component_length=third_component_length
    ];
    }

event ICCP::mms_point_value_shape_v3(
    c: connection, is_orig: bool, first_result_length: count,
    component_choices: vector of count,
    component_raws: vector of string,
    component_integer_values: vector of int,
    nested_component_index: count,
    nested_choices: vector of count,
    nested_raws: vector of string,
    nested_integer_values: vector of int) &priority=20
    {
    local sequence = mms_parser_sequence(c, is_orig);
    point_value_shape_evidence[c$uid, is_orig, sequence] = [
        $first_result_length=first_result_length,
        $first_component_length=|component_raws| > 0 ?
            |component_raws[0]| : 0,
        $second_component_length=|component_raws| > 1 ?
            |component_raws[1]| : 0,
        $third_component_length=|component_raws| > 2 ?
            |component_raws[2]| : 0,
        $component_choices=component_choices,
        $component_raws=component_raws,
        $component_integer_values=component_integer_values,
        $nested_component_index=nested_component_index,
        $nested_choices=nested_choices,
        $nested_raws=nested_raws,
        $nested_integer_values=nested_integer_values
    ];
    }

event ICCP::mms_control_read_value_shape_v1(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    service_tag: count, first_result_length: count,
    component_choices: vector of count,
    component_raws: vector of string,
    component_integer_values: vector of int) &priority=20
    {
    if ( pdu_type != 1 || service_tag != 4 || invoke_id < 0 ) return;
    local key = int_to_count(invoke_id);
    local sequence = mms_parser_sequence(c, is_orig);
    control_read_value_shape_evidence[
        c$uid, is_orig, sequence, key] = [
        $first_result_length=first_result_length,
        $first_component_length=|component_raws| > 0 ?
            |component_raws[0]| : 0,
        $second_component_length=|component_raws| > 1 ?
            |component_raws[1]| : 0,
        $third_component_length=|component_raws| > 2 ?
            |component_raws[2]| : 0,
        $component_choices=component_choices,
        $component_raws=component_raws,
        $component_integer_values=component_integer_values
    ];
    }

function pending_control_count(uid: string): count
    {
    local total: count = 0;
    for ( [entry_uid, request_is_orig, invoke] in pending_controls )
        if ( entry_uid == uid ) ++total;
    return total;
    }

function pending_control_read_count(uid: string): count
    {
    local total: count = 0;
    for ( [entry_uid, request_is_orig, invoke] in pending_control_reads )
        if ( entry_uid == uid ) ++total;
    for ( [invalid_uid, request_is_orig, invoke] in
          invalid_control_read_invokes )
        if ( invalid_uid == uid ) ++total;
    return total;
    }

function control_scope_name(scope: count): string
    {
    if ( scope == 0 ) return "vcc";
    if ( scope == 1 ) return "icc";
    if ( scope == 2 ) return "aa";
    return "unknown";
    }

function add_control_identity(rec: ControlInfo, pending: PendingControl): ControlInfo
    {
    if ( pending$name == "" ) return rec;
    rec$object_scope = control_scope_name(pending$scope);
    rec$object_name = pending$name;
    if ( pending$domain != "" ) rec$object_domain = pending$domain;
    if ( pending$named_type != "" ) rec$named_type = pending$named_type;
    if ( pending?$integer_value ) rec$integer_value = pending$integer_value;
    if ( pending?$floating_value ) rec$floating_value = pending$floating_value;
    if ( pending?$tag_value ) rec$tag_value = pending$tag_value;
    if ( pending?$tag_state ) rec$tag_state = pending$tag_state;
    if ( pending?$tag_reason ) rec$tag_reason = pending$tag_reason;
    return rec;
    }

function add_control_read_identity(rec: ControlInfo, pending: PendingControlRead): ControlInfo
    {
    rec$object_scope = control_scope_name(pending$scope);
    rec$object_name = pending$name;
    if ( pending$domain != "" ) rec$object_domain = pending$domain;
    if ( pending$named_type != "" ) rec$named_type = pending$named_type;
    return rec;
    }

function valid_tase2_identifier(name: string): bool
    {
    # IEC 60870-6-503 narrows MMS Identifier by prohibiting a leading digit.
    # The MMS parser owns the supported base Identifier repertoire and length,
    # so policy adds only the TASE.2 leading-character rule here.
    return name != "" && ! ( /^[0-9]/ in name );
    }

function valid_tase2_visible_identifier(name: string): bool
    {
    # Embedded ObjectName fields observed here are VisibleString values rather
    # than parser-validated Identifier TLVs.
    return /^[A-Za-z_$][A-Za-z0-9_$]{0,31}$/ in name;
    }

function valid_tase2_object_identifier(scope: count, domain: string,
                                       name: string): bool
    {
    if ( ! valid_tase2_identifier(name) ) return F;
    if ( scope == 1 ) return valid_tase2_identifier(domain);
    return (scope == 0 || scope == 2) && domain == "";
    }

# IEC 60870-6-802 maps IndicationPoint and ControlPoint variables to VMD- or
# Domain-specific MMS Named Variables.  IEC 60870-6-503 applies the same scope
# rule to the associated SBO check-back and Tag_Value variables.
function standardized_point_control_scope(scope: count,
                                           domain: string): bool
    {
    return (scope == 0 && domain == "") ||
           (scope == 1 && valid_tase2_identifier(domain));
    }

function select_name_candidate(name: string): bool
    {
    return valid_tase2_identifier(name) && /^.+_SBO$/ in name;
    }

function tag_name_candidate(name: string): bool
    {
    return valid_tase2_identifier(name) && /^.+_TAG$/ in name;
    }

function control_read_candidate_classification(classification: string): string
    {
    if ( classification == "select" ||
         classification == "select_candidate" )
        return "select_candidate";
    if ( classification == "get_tag" ||
         classification == "get_tag_candidate" )
        return "get_tag_candidate";
    return "control_read_candidate";
    }

function classify_control_read(
    c: connection, server_is_orig: bool,
    scope: count, domain: string, name: string,
    variable_count: count): string
    {
    if ( ! valid_tase2_object_identifier(scope, domain, name) ) return "";
    local named_type = learned_variable_type_name(
        c, server_is_orig, scope, domain, name);
    local valid_scope = standardized_point_control_scope(scope, domain);
    if ( select_name_candidate(name) ||
         named_type == "SBO_CheckBackName" )
        {
        if ( association_kind(c) == "tase2" && valid_scope &&
             variable_count == 1 && select_name_candidate(name) &&
             named_type == "SBO_CheckBackName" )
            return "select";
        return "select_candidate";
        }
    if ( tag_name_candidate(name) || named_type == "Tag_Value" )
        {
        if ( association_kind(c) == "tase2" && valid_scope &&
             variable_count == 1 && tag_name_candidate(name) &&
             named_type == "Tag_Value" )
            return "get_tag";
        return "get_tag_candidate";
        }
    return "";
    }

function exact_tag_value_components(
    choices: vector of count, raws: vector of string): bool
    {
    if ( |choices| != 2 || |raws| != 2 ||
         choices[0] != 4 || choices[1] != 10 ||
         |raws[0]| != 2 || |raws[1]| > 255 )
        return F;
    local unused = bytestring_to_count(sub_bytes(raws[0], 1, 1));
    local flags = bytestring_to_count(sub_bytes(raws[0], 2, 1));
    local tag_value = ((flags & 0x80) != 0 ? 2 : 0) +
                      ((flags & 0x40) != 0 ? 1 : 0);
    return unused == 5 && (flags & 0x1f) == 0 && tag_value <= 2;
    }

function control_tag_value_shape(shape: ControlValueShapeEvidence): bool
    {
    return shape$choice == 2 && shape?$component_choices &&
           shape?$component_raws &&
           exact_tag_value_components(
               shape$component_choices, shape$component_raws);
    }

function point_tag_value_shape(shape: PointValueShapeEvidence): bool
    {
    return shape?$component_choices && shape?$component_raws &&
           exact_tag_value_components(
               shape$component_choices, shape$component_raws);
    }

function add_tag_value(
    rec: ControlInfo, flags_raw: string, reason: string): ControlInfo
    {
    local flags = bytestring_to_count(sub_bytes(flags_raw, 2, 1));
    rec$tag_value = ((flags & 0x80) != 0 ? 2 : 0) +
                    ((flags & 0x40) != 0 ? 1 : 0);
    rec$tag_state = (flags & 0x20) != 0 ? "armed" : "idle";
    rec$tag_reason = reason;
    return rec;
    }

function is_classified_control(classification: string): bool
    {
    return classification == "select" ||
           classification == "get_tag" ||
           classification == "set_tag" ||
           classification == "operate_command" ||
           classification == "operate_setpoint_discrete" ||
           classification == "operate_setpoint_real";
    }

function emit_control_failure(
    c: connection, is_orig: bool, invoke_id: int, outcome: string,
    pending: PendingControl, failure_count: count,
    error_class: string, error_code: int)
    {
    if ( ! is_classified_control(pending$classification) ) return;
    event ICCP::control_failure(
        c, is_orig, association_kind(c), endpoint_role(c, is_orig),
        invoke_id, pending$classification, outcome,
        pending$name == "" ? "" : control_scope_name(pending$scope),
        pending$domain, pending$name, pending$named_type, failure_count,
        error_class, error_code);
    }


function emit_control_read_failure_with_provenance(
    c: connection, is_orig: bool, invoke_id: int, outcome: string,
    pending: PendingControlRead, failure_count: count,
    error_class: string, error_code: int, provenance: string)
    {
    if ( pending$classification != "select" &&
         pending$classification != "get_tag" ) return;
    event ICCP::legacy_alert_provenance_marker_v1(
        c, is_orig, "control_failure", provenance);
    event ICCP::control_failure(
        c, is_orig, association_kind(c), endpoint_role(c, is_orig),
        invoke_id, pending$classification, outcome,
        control_scope_name(pending$scope), pending$domain, pending$name,
        pending$named_type, failure_count, error_class, error_code);
    }

function emit_control_read_failure(
    c: connection, is_orig: bool, invoke_id: int, outcome: string,
    pending: PendingControlRead, failure_count: count,
    error_class: string, error_code: int)
    {
    emit_control_read_failure_with_provenance(
        c, is_orig, invoke_id, outcome, pending, failure_count,
        error_class, error_code, mms_provenance(c, is_orig));
    }

function invalidate_control_read_for_other_request(
    c: connection, is_orig: bool, invoke_id: int)
    {
    local key = int_to_count(invoke_id);
    if ( [c$uid, is_orig, key] in pending_control_reads )
        {
        local prior = pending_control_reads[c$uid, is_orig, key];
        delete pending_control_reads[c$uid, is_orig, key];
        invalid_control_read_invokes[c$uid, is_orig, key] = [
            $classification=control_read_candidate_classification(
                prior$classification)
        ];
        local reused: ControlInfo = [
            $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
            $association_kind=association_kind(c),
            $association_phase=association_phase(c),
            $endpoint_role=endpoint_role(c, is_orig),
            $classification=prior$classification,
            $outcome="invoke_reused", $invoke_id=invoke_id
        ];
        reused = add_control_read_identity(reused, prior);
        write_control_record(c, is_orig, reused);
        return;
        }
    # A request from the other endpoint owns a distinct invoke-ID namespace
    # and must not be invalidated by this request.
    }

function finish_invalid_control_read_for_other_response(
    c: connection, is_orig: bool, invoke_id: int,
    result_count: count, success_count: count, failure_count: count)
    {
    local key = int_to_count(invoke_id);
    local request_is_orig = ! is_orig;
    local outcome = "ambiguous_response";
    if ( [c$uid, request_is_orig, key] !in invalid_control_read_invokes )
        {
        request_is_orig = is_orig;
        if ( [c$uid, request_is_orig, key] !in
             invalid_control_read_invokes ) return;
        outcome = "direction_mismatch";
        }
    local invalid = invalid_control_read_invokes[
        c$uid, request_is_orig, key];
    if ( outcome != "direction_mismatch" )
        delete invalid_control_read_invokes[c$uid, request_is_orig, key];
    local ambiguous: ControlInfo = [
        $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
        $association_kind=association_kind(c),
        $association_phase=association_phase(c),
        $endpoint_role=endpoint_role(c, is_orig),
        $classification=invalid$classification, $outcome=outcome,
        $invoke_id=invoke_id, $result_count=result_count,
        $success_count=success_count, $failure_count=failure_count
    ];
    write_control_record(c, is_orig, ambiguous);
    }

function begin_control_read_request(
    c: connection, is_orig: bool, invoke_id: int,
    object_scope: count, object_domain: string, object_name: string,
    variable_count: count)
    {
    if ( association_kind(c) != "tase2" ) return;
    local named_type = learned_variable_type_name(
        c, ! is_orig, object_scope, object_domain, object_name);
    local classification = classify_control_read(
        c, ! is_orig, object_scope, object_domain, object_name,
        variable_count);
    if ( classification == "" ) return;

    local key = int_to_count(invoke_id);
    local reused = [c$uid, is_orig, key] in pending_controls ||
                   [c$uid, is_orig, key] in pending_control_reads ||
                   [c$uid, is_orig, key] in invalid_control_read_invokes;
    local state_full = ! reused &&
        pending_control_read_count(c$uid) >= max_pending_controls;
    local pending: PendingControlRead = [
        $request_is_orig=is_orig, $scope=object_scope,
        $domain=object_domain, $name=object_name,
        $variable_count=variable_count, $classification=classification,
        $named_type=named_type
    ];

    if ( [c$uid, is_orig, key] in pending_controls )
        {
        delete pending_controls[c$uid, is_orig, key];
        if ( [c$uid, is_orig, key] in pending_control_reads )
            delete pending_control_reads[c$uid, is_orig, key];
        invalid_control_read_invokes[c$uid, is_orig, key] = [
            $classification=control_read_candidate_classification(
                classification)
        ];
        }
    else if ( [c$uid, is_orig, key] in pending_control_reads )
        {
        local prior = pending_control_reads[c$uid, is_orig, key];
        delete pending_control_reads[c$uid, is_orig, key];
        invalid_control_read_invokes[c$uid, is_orig, key] = [
            $classification=control_read_candidate_classification(
                prior$classification)
        ];
        }
    else if ( ! state_full && ! reused )
        pending_control_reads[c$uid, is_orig, key] = pending;

    if ( state_full )
        event ICCP::resource_limit_exceeded(
            c, is_orig, "pending_control_reads", max_pending_controls,
            pending_control_read_count(c$uid), invoke_id);

    local request: ControlInfo = [
        $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
        $association_kind=association_kind(c),
        $association_phase=association_phase(c),
        $endpoint_role=endpoint_role(c, is_orig),
        $classification=classification,
        $outcome=state_full ? "state_limit" :
            reused ? "invoke_reused" : "requested",
        $invoke_id=invoke_id, $variable_count=variable_count
    ];
    request = add_control_read_identity(request, pending);
    write_control_record(c, is_orig, request);
    }

function finish_control_read_response(
    c: connection, is_orig: bool, invoke_id: int,
    result_count: count, failure_count: count,
    first_result_choice: count, first_result_raw: string,
    first_integer_value: int)
    {
    local key = int_to_count(invoke_id);
    local request_is_orig = ! is_orig;
    local direction_valid = T;
    if ( [c$uid, request_is_orig, key] in invalid_control_read_invokes )
        {
        local invalid = invalid_control_read_invokes[
            c$uid, request_is_orig, key];
        delete invalid_control_read_invokes[c$uid, request_is_orig, key];
        local ambiguous: ControlInfo = [
            $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
            $association_kind=association_kind(c),
            $association_phase=association_phase(c),
            $endpoint_role=endpoint_role(c, is_orig),
            $classification=invalid$classification,
            $outcome="ambiguous_response", $invoke_id=invoke_id,
            $result_count=result_count,
            $success_count=result_count >= failure_count ?
                result_count - failure_count : 0,
            $failure_count=failure_count
        ];
        write_control_record(c, is_orig, ambiguous);
        return;
        }
    if ( [c$uid, request_is_orig, key] !in pending_control_reads )
        {
        request_is_orig = is_orig;
        direction_valid = F;
        if ( [c$uid, request_is_orig, key] in
             invalid_control_read_invokes )
            {
            local invalid_same = invalid_control_read_invokes[
                c$uid, request_is_orig, key];
            local mismatch: ControlInfo = [
                $ts=network_time(), $uid=c$uid, $id=c$id,
                $is_orig=is_orig, $association_kind=association_kind(c),
                $association_phase=association_phase(c),
                $endpoint_role=endpoint_role(c, is_orig),
                $classification=invalid_same$classification,
                $outcome="direction_mismatch", $invoke_id=invoke_id,
                $result_count=result_count,
                $success_count=result_count >= failure_count ?
                    result_count - failure_count : 0,
                $failure_count=failure_count
            ];
            write_control_record(c, is_orig, mismatch);
            return;
            }
        if ( [c$uid, request_is_orig, key] !in pending_control_reads ) return;
        }

    local prior = pending_control_reads[c$uid, request_is_orig, key];
    local select_success = result_count == 1 && failure_count == 0 &&
        first_result_choice == 5 && |first_result_raw| >= 1 &&
        |first_result_raw| <= 2;
    local tag_shape: PointValueShapeEvidence = [
        $first_result_length=0, $first_component_length=0,
        $second_component_length=0, $third_component_length=0
    ];
    local parser_sequence = mms_parser_sequence(c, is_orig);
    local tag_shape_available =
        [c$uid, is_orig, parser_sequence, key] in
            control_read_value_shape_evidence;
    if ( tag_shape_available )
        {
        tag_shape = control_read_value_shape_evidence[
            c$uid, is_orig, parser_sequence, key];
        delete control_read_value_shape_evidence[
            c$uid, is_orig, parser_sequence, key];
        }
    local tag_success = result_count == 1 && failure_count == 0 &&
        first_result_choice == 2 && point_tag_value_shape(tag_shape);
    local failed = result_count == 1 && failure_count == 1 &&
        first_result_choice == 0;
    local exact_select = prior$classification == "select";
    local exact_get_tag = prior$classification == "get_tag";
    local tag_candidate = exact_get_tag ||
        prior$classification == "get_tag_candidate";
    local success = tag_candidate ? tag_success : select_success;
    local exact_operation = exact_select || exact_get_tag;
    local outcome = ! direction_valid ? "direction_mismatch" :
        success ? (exact_operation ? "confirmed" : "candidate_response") :
        failed ? (exact_operation ? "failed" : "candidate_failure") :
        "invalid_response";
    local response: ControlInfo = [
        $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
        $association_kind=association_kind(c),
        $association_phase=association_phase(c),
        $endpoint_role=endpoint_role(c, is_orig),
        $classification=prior$classification, $outcome=outcome,
        $invoke_id=invoke_id, $result_count=result_count,
        $success_count=result_count >= failure_count ?
            result_count - failure_count : 0,
        $failure_count=failure_count
    ];
    response = add_control_read_identity(response, prior);
    if ( direction_valid && success && exact_select )
        response$integer_value = first_integer_value;
    else if ( direction_valid && success && exact_get_tag )
        response = add_tag_value(
            response, tag_shape$component_raws[0],
            tag_shape$component_raws[1]);
    write_control_record(c, is_orig, response);

    if ( direction_valid )
        {
        if ( failed && exact_operation )
            emit_control_read_failure(
                c, is_orig, invoke_id, "failed", prior, failure_count,
                "", -1);
        delete pending_control_reads[c$uid, request_is_orig, key];
        }
    }

function finish_deferred_control_read_response(
    c: connection, is_orig: bool, invoke_id: int,
    result_count: count, failure_count: count,
    first_result_choice: count, first_result_raw: string,
    first_integer_value: int, context: MMSControlReadProcessingContext)
    {
    if ( ! mms_policy_generation_is_current(
             c, context$policy_generation) )
        return;

    local key = int_to_count(invoke_id);
    local shape: PointValueShapeEvidence = [
        $first_result_length=0, $first_component_length=0,
        $second_component_length=0, $third_component_length=0
    ];
    if ( [c$uid, is_orig, context$parser_sequence, key] in
         control_read_value_shape_evidence )
        {
        shape = control_read_value_shape_evidence[
            c$uid, is_orig, context$parser_sequence, key];
        delete control_read_value_shape_evidence[
            c$uid, is_orig, context$parser_sequence, key];
        }

    local prior: PendingControlRead = [
        $request_is_orig=context$request_is_orig,
        $scope=context$scope, $domain=context$domain, $name=context$name,
        $variable_count=context$variable_count,
        $classification=context$classification,
        $named_type=context$named_type
    ];
    local success = result_count == 1 && failure_count == 0 &&
        first_result_choice == 2 && point_tag_value_shape(shape);
    local failed = result_count == 1 && failure_count == 1 &&
        first_result_choice == 0;
    local exact = prior$classification == "get_tag";
    local outcome = ! context$direction_valid ? "direction_mismatch" :
        success ? (exact ? "confirmed" : "candidate_response") :
        failed ? (exact ? "failed" : "candidate_failure") :
        "invalid_response";
    local response: ControlInfo = [
        $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
        $association_kind=association_kind(c),
        $association_phase=association_phase(c),
        $endpoint_role=endpoint_role(c, is_orig),
        $classification=prior$classification, $outcome=outcome,
        $invoke_id=invoke_id, $result_count=result_count,
        $success_count=result_count >= failure_count ?
            result_count - failure_count : 0,
        $failure_count=failure_count
    ];
    response = add_control_read_identity(response, prior);
    if ( context$direction_valid && success && exact )
        response = add_tag_value(
            response, shape$component_raws[0], shape$component_raws[1]);
    write_control_record_with_provenance(
        c, is_orig, response, context$provenance);

    if ( context$direction_valid && failed && exact )
        emit_control_read_failure_with_provenance(
            c, is_orig, invoke_id, "failed", prior, failure_count,
            "", -1, context$provenance);
    }

event mms_control_read_response_deferred(
    c: connection, is_orig: bool, invoke_id: int,
    result_count: count, failure_count: count,
    first_result_choice: count, first_result_raw: string,
    first_integer_value: int)
    {
    # Preserve the historical direct-event API.  Direct script callers have
    # no parser marker and therefore do not require an immutable deferred
    # snapshot; all evidence is already present when this event runs.
    finish_control_read_response(
        c, is_orig, invoke_id, result_count, failure_count,
        first_result_choice, first_result_raw, first_integer_value);
    }

event mms_control_read_response_deferred_v2(
    c: connection, is_orig: bool, invoke_id: int,
    result_count: count, failure_count: count,
    first_result_choice: count, first_result_raw: string,
    first_integer_value: int, context: MMSControlReadProcessingContext)
    {
    finish_deferred_control_read_response(
        c, is_orig, invoke_id, result_count, failure_count,
        first_result_choice, first_result_raw, first_integer_value,
        context);
    }

event mms_control_read_shape_cleanup(
    c: connection, is_orig: bool, parser_sequence: count, invoke_id: int)
    {
    if ( invoke_id >= 0 )
        delete control_read_value_shape_evidence[
            c$uid, is_orig, parser_sequence, int_to_count(invoke_id)];
    }

event ICCP::mms_error_message(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    modifier_position: int, error_class: count, error_code: int,
    additional_code: int, additional_description: string)
    {
    if ( pdu_type != 2 ) return;

    local rec: ErrorInfo = [
        $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
        $association_kind=association_kind(c), $outcome="unexpected_error",
        $error_class=mms_error_class_name(error_class),
        $error_class_code=error_class, $error_code=error_code
    ];
    if ( invoke_id >= 0 ) rec$invoke_id = invoke_id;
    if ( modifier_position >= 0 ) rec$modifier_position = modifier_position;
    if ( additional_code >= 0 ) rec$additional_code = additional_code;
    if ( additional_description != "" )
        rec$description = bounded_detail(additional_description);

    local confirmed_error_ambiguous = F;
    if ( invoke_id >= 0 )
        {
        local key = int_to_count(invoke_id);
        local confirmed_request_is_orig = ! is_orig;
        if ( [c$uid, confirmed_request_is_orig, key] in
             invalid_confirmed_invokes )
            {
            # ConfirmedError carries no service discriminator.  Once a caller
            # reuses an outstanding invoke ID, attributing the error to either
            # request would be unsafe.
            rec$outcome = "ambiguous_response";
            confirmed_error_ambiguous = T;
            }
        else if ( [c$uid, confirmed_request_is_orig, key] in
                  pending_confirmed )
            {
            local pending = pending_confirmed[
                c$uid, confirmed_request_is_orig, key];
            rec$service_tag = pending$service_tag;
            if ( association_kind(c) == "tase2" && pending$operation > 0 )
                rec$operation = operation_name(pending$operation);
            rec$outcome = "correlated";
            delete pending_confirmed[
                c$uid, confirmed_request_is_orig, key];
            }
        else if ( [c$uid, is_orig, key] in invalid_confirmed_invokes )
            rec$outcome = "direction_mismatch";
        else if ( [c$uid, is_orig, key] in pending_confirmed )
            {
            local direction_pending = pending_confirmed[
                c$uid, is_orig, key];
            rec$service_tag = direction_pending$service_tag;
            if ( association_kind(c) == "tase2" &&
                 direction_pending$operation > 0 )
                rec$operation = operation_name(direction_pending$operation);
            rec$outcome = "direction_mismatch";
            }
        }

    if ( invoke_id >= 0 && ! confirmed_error_ambiguous )
        {
        local control_key = int_to_count(invoke_id);
        local control_request_is_orig = ! is_orig;
        local control_direction_valid = T;
        if ( [c$uid, control_request_is_orig, control_key] !in
             pending_controls )
            {
            control_request_is_orig = is_orig;
            control_direction_valid = F;
            }
        if ( [c$uid, control_request_is_orig, control_key] in
             pending_controls )
            {
            local control_pending = pending_controls[
                c$uid, control_request_is_orig, control_key];
            local control_error: ControlInfo = [
                $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
                $association_kind=association_kind(c),
                $association_phase=association_phase(c),
                $endpoint_role=endpoint_role(c, is_orig),
                $classification=control_pending$classification,
                $outcome=control_direction_valid ? "rejected" :
                    "direction_mismatch", $invoke_id=invoke_id,
                $error_class=mms_error_class_name(error_class),
                $error_class_code=error_class, $error_code=error_code
            ];
            control_error = add_control_identity(
                control_error, control_pending);
            write_control_record(c, is_orig, control_error);
            if ( control_direction_valid )
                {
                event ICCP::write_failure(
                    c, is_orig, association_kind(c), endpoint_role(c, is_orig),
                    invoke_id, "rejected",
                    control_pending$name == "" ? "" :
                        control_scope_name(control_pending$scope),
                    control_pending$domain, control_pending$name, 0,
                    mms_error_class_name(error_class), error_code);
                emit_control_failure(
                    c, is_orig, invoke_id, "rejected", control_pending, 0,
                    mms_error_class_name(error_class), error_code);
                delete pending_controls[
                    c$uid, control_request_is_orig, control_key];
                }
            }
        }

    if ( invoke_id >= 0 && ! confirmed_error_ambiguous )
        {
        local invalid_read_key = int_to_count(invoke_id);
        local read_request_is_orig = ! is_orig;
        local read_direction_valid = T;
        local invalid_read_found = [c$uid, read_request_is_orig,
                                    invalid_read_key] in
                                   invalid_control_read_invokes;
        local read_found = [c$uid, read_request_is_orig, invalid_read_key] in
                           pending_control_reads;
        if ( ! invalid_read_found && ! read_found )
            {
            read_request_is_orig = is_orig;
            read_direction_valid = F;
            invalid_read_found = [c$uid, read_request_is_orig,
                                  invalid_read_key] in
                                 invalid_control_read_invokes;
            read_found = [c$uid, read_request_is_orig, invalid_read_key] in
                         pending_control_reads;
            }
        if ( invalid_read_found )
            {
            local invalid_read = invalid_control_read_invokes[
                c$uid, read_request_is_orig, invalid_read_key];
            if ( read_direction_valid )
                delete invalid_control_read_invokes[
                    c$uid, read_request_is_orig, invalid_read_key];
            local ambiguous_read_error: ControlInfo = [
                $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
                $association_kind=association_kind(c),
                $association_phase=association_phase(c),
                $endpoint_role=endpoint_role(c, is_orig),
                $classification=invalid_read$classification,
                $outcome=read_direction_valid ? "ambiguous_response" :
                    "direction_mismatch", $invoke_id=invoke_id,
                $error_class=mms_error_class_name(error_class),
                $error_class_code=error_class, $error_code=error_code
            ];
            write_control_record(c, is_orig, ambiguous_read_error);
            }
        else if ( read_found )
            {
            local read_pending = pending_control_reads[
                c$uid, read_request_is_orig, invalid_read_key];
            local read_error: ControlInfo = [
                $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
                $association_kind=association_kind(c),
                $association_phase=association_phase(c),
                $endpoint_role=endpoint_role(c, is_orig),
                $classification=read_pending$classification,
                $outcome=! read_direction_valid ? "direction_mismatch" :
                    (read_pending$classification == "select" ||
                     read_pending$classification == "get_tag") ?
                        "rejected" : "candidate_rejection",
                $invoke_id=invoke_id,
                $error_class=mms_error_class_name(error_class),
                $error_class_code=error_class, $error_code=error_code
            ];
            read_error = add_control_read_identity(read_error, read_pending);
            write_control_record(c, is_orig, read_error);
            if ( read_direction_valid )
                {
                emit_control_read_failure(
                    c, is_orig, invoke_id, "rejected", read_pending, 0,
                    mms_error_class_name(error_class), error_code);
                delete pending_control_reads[
                    c$uid, read_request_is_orig, invalid_read_key];
                }
            }
        }
    write_error_record(c, is_orig, rec);
    }

event ICCP::mms_reject_message_v1(
    c: connection, is_orig: bool, invoke_id: int,
    reason_tag: count, reason: int, provenance: count)
    {
    # Only confirmed-requestPDU identifies the peer's request namespace.
    # Other Reject alternatives refer to responses, errors, Cancel/Conclude,
    # or top-level parsing and cannot safely retire this pending family.
    if ( invoke_id < 0 || reason_tag != 1 ) return;
    local request_is_orig = ! is_orig;
    local key = int_to_count(invoke_id);
    delete pending_confirmed[c$uid, request_is_orig, key];
    delete invalid_confirmed_invokes[c$uid, request_is_orig, key];
    purge_confirmed_request_state(c, request_is_orig, invoke_id);
    }

event ICCP::mms_control_message(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    service_tag: count, object_scope: count, object_domain: string,
    object_name: string, variable_count: count, data_count: count,
    data_node_count: count, result_count: count, success_count: count,
    failure_count: count)
    {
    if ( invoke_id < 0 ||
         (pdu_type != 0 && pdu_type != 1) )
        return;

    # Packet Read requests are correlated only by the self-contained v3
    # event.  In particular, firstVariableName is the named-list selector when
    # accessChoice is 1 and must not be classified as a Select/GetTag object.
    if ( pdu_type == 0 && service_tag == 4 &&
         parser_read_delivery_is_current(c, is_orig, invoke_id) )
        return;

    if ( pdu_type == 0 && service_tag != 5 &&
         ! confirmed_request_tracking_allowed(c, is_orig, invoke_id) )
        {
        local rejected_sequence = mms_parser_sequence(c, is_orig);
        delete control_value_shape_evidence[
            c$uid, is_orig, rejected_sequence];
        delete control_value_shape_invokes[
            c$uid, is_orig, rejected_sequence];
        return;
        }
    if ( pdu_type == 1 &&
         confirmed_response_is_ambiguous(c, is_orig, invoke_id) )
        return;

    if ( service_tag != 4 && pdu_type == 0 )
        invalidate_control_read_for_other_request(c, is_orig, invoke_id);
    else if ( service_tag != 4 && pdu_type == 1 )
        finish_invalid_control_read_for_other_response(
            c, is_orig, invoke_id, result_count, success_count,
            failure_count);

    if ( service_tag == 4 )
        {
        if ( pdu_type == 0 )
            begin_control_read_request(
                c, is_orig, invoke_id, object_scope, object_domain,
                object_name, variable_count);
        return;
        }
    if ( service_tag != 5 ) return;

    local key = int_to_count(invoke_id);
    if ( pdu_type == 0 )
        {
        local control_sequence = mms_parser_sequence(c, is_orig);
        local control_generation = mms_policy_generation(c);
        local control_provenance = mms_provenance(c, is_orig);
        control_value_shape_invokes[
            c$uid, is_orig, control_sequence] = key;
        schedule 0secs {
            ICCP::mms_control_request_deferred_v3(
                c, is_orig, invoke_id, object_scope, object_domain,
                object_name, variable_count, data_count, data_node_count,
                control_sequence, control_generation, control_provenance)
        };
        return;
        }

    local response_request_is_orig = ! is_orig;
    local response_direction_valid = T;
    if ( [c$uid, response_request_is_orig, key] !in pending_controls )
        {
        response_request_is_orig = is_orig;
        response_direction_valid = F;
        }
    if ( [c$uid, response_request_is_orig, key] !in pending_controls )
        {
        local unexpected: ControlInfo = [
            $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
            $association_kind=association_kind(c),
            $association_phase=association_phase(c),
            $endpoint_role=endpoint_role(c, is_orig),
            $classification="write_candidate", $outcome="unexpected_response",
            $invoke_id=invoke_id, $result_count=result_count,
            $success_count=success_count, $failure_count=failure_count
        ];
        write_control_record(c, is_orig, unexpected);
        return;
        }

    local prior = pending_controls[c$uid, response_request_is_orig, key];
    local response: ControlInfo = [
        $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
        $association_kind=association_kind(c),
        $association_phase=association_phase(c),
        $endpoint_role=endpoint_role(c, is_orig),
        $classification=prior$classification,
        $outcome=! response_direction_valid ? "direction_mismatch" :
            failure_count == 0 ? "confirmed" : "partial_or_failed",
        $invoke_id=invoke_id, $result_count=result_count,
        $success_count=success_count, $failure_count=failure_count
    ];
    response = add_control_identity(response, prior);
    write_control_record(c, is_orig, response);
    if ( response_direction_valid )
        {
        if ( failure_count > 0 )
            {
            event ICCP::write_failure(
                c, is_orig, association_kind(c), endpoint_role(c, is_orig),
                invoke_id, "partial_or_failed",
                prior$name == "" ? "" : control_scope_name(prior$scope),
                prior$domain, prior$name, failure_count, "", -1);
            emit_control_failure(
                c, is_orig, invoke_id, "partial_or_failed", prior,
                failure_count, "", -1);
            }
        delete pending_controls[c$uid, response_request_is_orig, key];
        }
    }

function process_control_request_deferred(
    c: connection, is_orig: bool, invoke_id: int,
    object_scope: count, object_domain: string, object_name: string,
    variable_count: count, data_count: count, data_node_count: count,
    parser_sequence: count, policy_generation: count, provenance: string)
    {
    if ( ! mms_policy_generation_is_current(c, policy_generation) )
        {
        delete control_value_shape_evidence[
            c$uid, is_orig, parser_sequence];
        delete control_value_shape_invokes[
            c$uid, is_orig, parser_sequence];
        return;
        }

    if ( ! confirmed_request_tracking_allowed(c, is_orig, invoke_id) )
        {
        delete control_value_shape_evidence[
            c$uid, is_orig, parser_sequence];
        delete control_value_shape_invokes[
            c$uid, is_orig, parser_sequence];
        return;
        }

    local shape: ControlValueShapeEvidence = [
        $choice=0, $raw="", $integer_value=0, $floating_value=0.0
    ];
    if ( [c$uid, is_orig, parser_sequence] in
         control_value_shape_evidence )
        {
        shape = control_value_shape_evidence[
            c$uid, is_orig, parser_sequence];
        delete control_value_shape_evidence[
            c$uid, is_orig, parser_sequence];
        }
    delete control_value_shape_invokes[c$uid, is_orig, parser_sequence];

    local key = int_to_count(invoke_id);
    local reused = [c$uid, is_orig, key] in pending_controls;
    local read_reused = [c$uid, is_orig, key] in
                        invalid_control_read_invokes;
    reused = reused || read_reused;
    local state_full = ! reused &&
        pending_control_count(c$uid) >= max_pending_controls;
    local control_classification = classify_control_write(
        c, ! is_orig, object_scope, object_domain, object_name,
        variable_count, data_count, shape);
    local control_named_type = learned_variable_type_name(
        c, ! is_orig, object_scope, object_domain, object_name);
    local pending: PendingControl = [
        $request_is_orig=is_orig, $scope=object_scope,
        $domain=object_domain, $name=object_name,
        $variable_count=variable_count, $data_count=data_count,
        $data_node_count=data_node_count,
        $classification=control_classification,
        $named_type=control_named_type
    ];
    if ( control_classification == "operate_command" ||
         control_classification == "operate_setpoint_discrete" )
        pending$integer_value = shape$integer_value;
    else if ( control_classification == "operate_setpoint_real" )
        pending$floating_value = shape$floating_value;
    else if ( control_classification == "set_tag" )
        {
        local flags_raw = shape$component_raws[0];
        local flags = bytestring_to_count(sub_bytes(flags_raw, 2, 1));
        pending$tag_value = ((flags & 0x80) != 0 ? 2 : 0) +
                            ((flags & 0x40) != 0 ? 1 : 0);
        pending$tag_state = (flags & 0x20) != 0 ? "armed" : "idle";
        pending$tag_reason = shape$component_raws[1];
        }
    if ( ! state_full && ! read_reused )
        pending_controls[c$uid, is_orig, key] = pending;
    else if ( state_full )
        {
        event ICCP::legacy_alert_provenance_marker_v1(
            c, is_orig, "resource_limit_exceeded", provenance);
        event ICCP::resource_limit_exceeded(
            c, is_orig, "pending_controls", max_pending_controls,
            pending_control_count(c$uid), invoke_id);
        }

    local request: ControlInfo = [
        $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
        $association_kind=association_kind(c),
        $association_phase=association_phase(c),
        $endpoint_role=endpoint_role(c, is_orig),
        $classification=control_classification,
        $outcome=state_full ? "state_limit" :
            reused ? "invoke_reused" : "requested",
        $invoke_id=invoke_id, $variable_count=variable_count,
        $data_count=data_count, $data_node_count=data_node_count
    ];
    request = add_control_identity(request, pending);
    write_control_record_with_provenance(c, is_orig, request, provenance);
    event ICCP::legacy_alert_provenance_marker_v1(
        c, is_orig, "write_attempt", provenance);
    event ICCP::write_attempt(
        c, is_orig, association_kind(c), endpoint_role(c, is_orig),
        invoke_id, object_name == "" ? "" : control_scope_name(object_scope),
        object_domain, object_name, variable_count, data_count,
        data_node_count);
    }

event ICCP::mms_control_request_deferred(
    c: connection, is_orig: bool, invoke_id: int,
    object_scope: count, object_domain: string, object_name: string,
    variable_count: count, data_count: count, data_node_count: count)
    {
    process_control_request_deferred(
        c, is_orig, invoke_id, object_scope, object_domain, object_name,
        variable_count, data_count, data_node_count,
        mms_parser_sequence(c, is_orig), mms_policy_generation(c),
        mms_provenance(c, is_orig));
    }

event ICCP::mms_control_request_deferred_v2(
    c: connection, is_orig: bool, invoke_id: int,
    object_scope: count, object_domain: string, object_name: string,
    variable_count: count, data_count: count, data_node_count: count,
    parser_sequence: count, provenance: string)
    {
    process_control_request_deferred(
        c, is_orig, invoke_id, object_scope, object_domain, object_name,
        variable_count, data_count, data_node_count,
        parser_sequence, mms_policy_generation(c), provenance);
    }

event ICCP::mms_control_request_deferred_v3(
    c: connection, is_orig: bool, invoke_id: int,
    object_scope: count, object_domain: string, object_name: string,
    variable_count: count, data_count: count, data_node_count: count,
    parser_sequence: count, policy_generation: count, provenance: string)
    {
    process_control_request_deferred(
        c, is_orig, invoke_id, object_scope, object_domain, object_name,
        variable_count, data_count, data_node_count,
        parser_sequence, policy_generation, provenance);
    }

function clear_control_processing_state(uid_to_clear: string)
    {
    local keys: vector of count;
    local directions: vector of bool;
    for ( [uid, request_is_orig, invoke] in pending_controls )
        if ( uid == uid_to_clear )
            {
            keys[|keys|] = invoke;
            directions[|directions|] = request_is_orig;
            }
    for ( index in keys )
        delete pending_controls[
            uid_to_clear, directions[index], keys[index]];
    local select_keys: vector of count;
    local select_directions: vector of bool;
    for ( [select_uid, select_is_orig, select_invoke] in
          pending_control_reads )
        if ( select_uid == uid_to_clear )
            {
            select_keys[|select_keys|] = select_invoke;
            select_directions[|select_directions|] = select_is_orig;
            }
    for ( select_index in select_keys )
        delete pending_control_reads[
            uid_to_clear, select_directions[select_index],
            select_keys[select_index]];
    local invalid_select_keys: vector of count;
    local invalid_select_directions: vector of bool;
    for ( [invalid_uid, invalid_is_orig, invalid_invoke] in
          invalid_control_read_invokes )
        if ( invalid_uid == uid_to_clear )
            {
            invalid_select_keys[|invalid_select_keys|] = invalid_invoke;
            invalid_select_directions[|invalid_select_directions|] =
                invalid_is_orig;
            }
    for ( invalid_select_index in invalid_select_keys )
        delete invalid_control_read_invokes[
            uid_to_clear, invalid_select_directions[invalid_select_index],
            invalid_select_keys[invalid_select_index]];
    clear_control_value_shapes(uid_to_clear, T);
    clear_control_value_shapes(uid_to_clear, F);
    }

event connection_state_remove(c: connection)
    {
    clear_control_processing_state(c$uid);
    }

type PendingTransferSet: record {
    action: string;
    scope: count;
    domain: string;
    name: string;
    variable_count: count;
    first_variable_scope: count;
    first_variable_domain: string;
    first_variable_name: string;
    prior_known: bool;
    delete_scope: int;
    name_count: count;
    profile_valid: bool;
    member_scopes: vector of count;
    member_domains: vector of string;
    member_names: vector of string;
    member_alternate_access_counts: vector of count;
    exact_member_access_evidence: bool;
    profile_reasons: string;
};

# Packet parsing emits both the stable unversioned transfer event and the
# self-contained v3 event for confirmed NamedVariableList services 11-13.
# Only v3 may mutate that list-lifecycle state. These immutable, short-lived
# tokens let the unversioned internal handler recognize its parser sibling in
# every completion-hook order while direct script callers and packet-derived
# InformationReports retain synchronous legacy behavior.
global parser_transfer_deliveries:
    set[string, bool, count, int, count, count, count, count]
    &read_expire=association_state_timeout;
global parser_transfer_delivery_cleanup_stage_v1: event(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    service_tag: count, unconfirmed_service_tag: count,
    parser_sequence: count, policy_generation: count);
global parser_transfer_delivery_cleanup_v1: event(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    service_tag: count, unconfirmed_service_tag: count,
    parser_sequence: count, policy_generation: count);

function parser_transfer_delivery_is_current(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    service_tag: count, unconfirmed_service_tag: count): bool
    {
    local sequence = mms_parser_sequence(c, is_orig);
    local generation = mms_policy_generation(c);
    return [c$uid, is_orig] in pending_mms_parser_markers ||
           [c$uid, is_orig, pdu_type, invoke_id, service_tag,
            unconfirmed_service_tag, sequence, generation] in
               parser_transfer_deliveries;
    }

function mark_parser_transfer_delivery(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    service_tag: count, unconfirmed_service_tag: count)
    {
    local sequence = mms_parser_sequence(c, is_orig);
    local generation = mms_policy_generation(c);
    add parser_transfer_deliveries[
        c$uid, is_orig, pdu_type, invoke_id, service_tag,
        unconfirmed_service_tag, sequence, generation];
    schedule 0secs {
        ICCP::parser_transfer_delivery_cleanup_stage_v1(
            c, is_orig, pdu_type, invoke_id, service_tag,
            unconfirmed_service_tag, sequence, generation)
    };
    }

event ICCP::parser_transfer_delivery_cleanup_stage_v1(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    service_tag: count, unconfirmed_service_tag: count,
    parser_sequence: count, policy_generation: count)
    {
    schedule 0secs {
        ICCP::parser_transfer_delivery_cleanup_v1(
            c, is_orig, pdu_type, invoke_id, service_tag,
            unconfirmed_service_tag, parser_sequence,
            policy_generation)
    };
    }

event ICCP::parser_transfer_delivery_cleanup_v1(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    service_tag: count, unconfirmed_service_tag: count,
    parser_sequence: count, policy_generation: count)
    {
    delete parser_transfer_deliveries[
        c$uid, is_orig, pdu_type, invoke_id, service_tag,
        unconfirmed_service_tag, parser_sequence, policy_generation];
    }

function is_transfer_set_special_member(name: string): bool
    {
    return name == "Transfer_Set_Name" ||
           name == "DSConditions_Detected" ||
           name == "Event_Code_Detected" ||
           name == "Transfer_Set_Time_Stamp";
    }

function add_transfer_profile_reason(current: string,
                                     reason: string): string
    {
    return current == "" ? reason : fmt("%s,%s", current, reason);
    }

function transfer_set_profile_reasons(pending: PendingTransferSet): string
    {
    if ( pending$action == "inspect" ) return "";
    if ( pending$action == "define" )
        {
        local reasons = "";
        if ( pending$scope != 1 || pending$domain == "" )
            reasons = add_transfer_profile_reason(
                reasons, "create_list_not_domain_specific");
        if ( |pending$member_scopes| != pending$variable_count ||
             |pending$member_domains| != pending$variable_count ||
             |pending$member_names| != pending$variable_count )
            reasons = add_transfer_profile_reason(
                reasons, "create_member_vector_mismatch");
        if ( pending$exact_member_access_evidence &&
             |pending$member_alternate_access_counts| !=
                 pending$variable_count )
            reasons = add_transfer_profile_reason(
                reasons, "create_alternate_access_vector_mismatch");

        local member_count = |pending$member_names|;
        if ( |pending$member_scopes| < member_count )
            member_count = |pending$member_scopes|;
        if ( |pending$member_domains| < member_count )
            member_count = |pending$member_domains|;
        local special_scope_invalid = F;
        local data_value_scope_invalid = F;
        local alternate_access_present = F;
        local index: count = 0;
        while ( index < member_count )
            {
            local member_name = pending$member_names[index];
            local member_scope = pending$member_scopes[index];
            if ( is_transfer_set_special_member(member_name) )
                {
                if ( member_scope != 1 ||
                     pending$member_domains[index] == "" )
                    special_scope_invalid = T;
                }
            else if ( member_scope != 0 && member_scope != 1 )
                data_value_scope_invalid = T;

            if ( pending$exact_member_access_evidence &&
                 index < |pending$member_alternate_access_counts| &&
                 pending$member_alternate_access_counts[index] > 0 )
                alternate_access_present = T;
            ++index;
            }
        if ( special_scope_invalid )
            reasons = add_transfer_profile_reason(
                reasons, "create_special_member_not_domain_specific");
        if ( data_value_scope_invalid )
            reasons = add_transfer_profile_reason(
                reasons, "create_data_value_invalid_scope");
        if ( alternate_access_present )
            reasons = add_transfer_profile_reason(
                reasons, "create_member_alternate_access");
        return reasons;
        }

    if ( pending$action != "delete" || pending$delete_scope != 0 ||
         pending$name_count == 0 ||
         |pending$member_scopes| != pending$name_count ||
         |pending$member_domains| != pending$name_count ||
         |pending$member_names| != pending$name_count )
        return "delete_not_specific_domain_vector";
    local delete_index: count = 0;
    while ( delete_index < pending$name_count )
        {
        if ( pending$member_scopes[delete_index] != 1 ||
             ! valid_tase2_object_identifier(
                 pending$member_scopes[delete_index],
                 pending$member_domains[delete_index],
                 pending$member_names[delete_index]) )
            return "delete_not_specific_domain_vector";
        ++delete_index;
        }
    if ( pending$scope != pending$member_scopes[0] ||
         pending$domain != pending$member_domains[0] ||
         pending$name != pending$member_names[0] )
        return "delete_not_specific_domain_vector";
    return "";
    }

function valid_pending_transfer_identifiers(pending: PendingTransferSet): bool
    {
    if ( pending$action == "inspect" )
        return valid_tase2_object_identifier(
            pending$scope, pending$domain, pending$name);
    if ( pending$action == "delete" && pending$delete_scope != 0 )
        return T;
    if ( pending$action != "define" && pending$action != "delete" )
        return F;
    if ( ! valid_tase2_object_identifier(
             pending$scope, pending$domain, pending$name) ) return F;
    if ( |pending$member_scopes| != |pending$member_domains| ||
         |pending$member_scopes| != |pending$member_names| ||
         (pending$action == "delete" &&
          |pending$member_names| != pending$name_count) ) return F;

    local index: count = 0;
    while ( index < |pending$member_names| )
        {
        if ( ! valid_tase2_object_identifier(
                 pending$member_scopes[index], pending$member_domains[index],
                 pending$member_names[index]) ) return F;
        ++index;
        }
    return T;
    }

type TransferMembership: record {
    scopes: vector of count;
    domains: vector of string;
    names: vector of string;
};

type KnownTransferKey: record {
    server_is_orig: bool;
    scope: count;
    domain: string;
    name: string;
};

type InformationReportResultIdentity: record {
    known: bool;
    scope: count;
    domain: string;
    name: string;
};

global information_report_pairing_status: function(
    c: connection, server_is_orig: bool,
    evidence: InformationReportResultsEvidence): string;

global pending_transfer_sets: table[string, bool, count] of PendingTransferSet
    &read_expire=association_state_timeout;
global known_transfer_sets:
    table[string, bool, count, string, string] of TransferMembership
    &read_expire=association_state_timeout;

type DSTransferParameters: record {
    data_set_scope: count &optional;
    data_set_domain: string &optional;
    data_set_name: string &optional;
    start_time: int &optional;
    transfer_interval: int &optional;
    tle: int &optional;
    buffer_time: int &optional;
    integrity_check: int &optional;
    conditions: string &optional;
    condition_mask: count &optional;
    block_data: bool &optional;
    critical: bool &optional;
    report_by_exception: bool &optional;
    all_changes_reported: bool &optional;
    enabled: bool &optional;
    event_code_requested: int &optional;
    conformance: string;
    conformance_reasons: string &optional;
};

type PendingTransferControl: record {
    action: string;
    request_is_orig: bool;
    scope: count;
    domain: string;
    name: string;
    parameters: DSTransferParameters &optional;
};

type ActiveDSTransfer: record {
    request_is_orig: bool;
    scope: count;
    domain: string;
    name: string;
    parameters: DSTransferParameters;
    state: string;
};

type PendingTransferSupport: record {
    request_is_orig: bool;
    scope: count;
    domain: string;
    name: string;
};

global pending_transfer_support:
    table[string, bool, count] of PendingTransferSupport
    &read_expire=association_state_timeout;

global pending_transfer_controls:
    table[string, bool, count] of PendingTransferControl
    &read_expire=association_state_timeout;
global active_ds_transfers:
    table[string, bool, count, string, string] of ActiveDSTransfer
    &read_expire=association_state_timeout;

global transfer_scope_name: function(scope: count): string;
global decode_ds_conditions: function(bits: count): string;
global append_feature: function(current: string, feature: string): string;

function add_ds_transfer_parameters(rec: TransferInfo,
                                    parameters: DSTransferParameters): TransferInfo
    {
    if ( parameters?$data_set_scope )
        rec$data_set_scope = transfer_scope_name(parameters$data_set_scope);
    if ( parameters?$data_set_domain && parameters$data_set_domain != "" )
        rec$data_set_domain = parameters$data_set_domain;
    if ( parameters?$data_set_name )
        rec$data_set_name = parameters$data_set_name;
    if ( parameters?$start_time ) rec$start_time = parameters$start_time;
    if ( parameters?$transfer_interval )
        rec$transfer_interval = parameters$transfer_interval;
    if ( parameters?$tle ) rec$tle = parameters$tle;
    if ( parameters?$buffer_time ) rec$buffer_time = parameters$buffer_time;
    if ( parameters?$integrity_check )
        rec$integrity_check = parameters$integrity_check;
    if ( parameters?$conditions ) rec$conditions = parameters$conditions;
    if ( parameters?$condition_mask )
        rec$condition_mask = parameters$condition_mask;
    if ( parameters?$block_data ) rec$block_data = parameters$block_data;
    if ( parameters?$critical ) rec$critical = parameters$critical;
    if ( parameters?$report_by_exception )
        rec$report_by_exception = parameters$report_by_exception;
    if ( parameters?$all_changes_reported )
        rec$all_changes_reported = parameters$all_changes_reported;
    if ( parameters?$enabled ) rec$enabled = parameters$enabled;
    if ( parameters?$event_code_requested )
        rec$event_code_requested = parameters$event_code_requested;
    rec$conformance = parameters$conformance;
    if ( parameters?$conformance_reasons )
        rec$conformance_reasons = parameters$conformance_reasons;
    return rec;
    }

type PendingVariableType: record {
    request_is_orig: bool;
    server: addr;
    peer: addr;
    scope: count;
    domain: string;
    name: string;
};

global pending_variable_types:
    table[string, bool, count] of PendingVariableType
    &read_expire=association_state_timeout;
global invalid_variable_type_invokes: table[string, bool, count] of bool
    &read_expire=association_state_timeout;
global known_variable_types:
    table[string, bool, count, string, string] of string
    &read_expire=association_state_timeout;

# Return true when a specialized request handler may retain correlation state.
# The aggregate event purges additive state on a newly detected global limit;
# this predicate prevents a deferred/additive hook from recreating state after
# the aggregate hook has already marked same-direction reuse.
function confirmed_request_tracking_allowed(
    c: connection, is_orig: bool, invoke_id: int): bool
    {
    if ( invoke_id < 0 ) return F;
    local key = int_to_count(invoke_id);
    if ( [c$uid, is_orig, key] in invalid_confirmed_invokes )
        return F;

    # The aggregate MMS hook and additive service hooks may be delivered in
    # either order.  Preserve an invoke already admitted by the aggregate
    # hook; otherwise let an early additive hook retain state only while the
    # association-wide confirmed-request budget still has room.  This keeps a
    # cap-rejected request from recreating specialized state in either order.
    if ( [c$uid, is_orig, key] in pending_confirmed )
        return T;
    return pending_confirmed_count(c$uid) < max_pending_confirmed;
    }

# A response from one endpoint can consume only the other endpoint's request.
# An invalid marker in the response sender's namespace is deliberately ignored:
# it may coexist with a valid request from the peer using the same numeric ID.
function confirmed_response_is_ambiguous(
    c: connection, is_orig: bool, invoke_id: int): bool
    {
    if ( invoke_id < 0 ) return F;
    return [c$uid, ! is_orig, int_to_count(invoke_id)] in
        invalid_confirmed_invokes;
    }

# Remove every higher-level interpretation of one invalid/rejected confirmed
# request.  The evidence-policy tables perform the analogous transition in
# iccp_evidence's low-priority aggregate-event handler.
function purge_confirmed_request_state(
    c: connection, request_is_orig: bool, invoke_id: int)
    {
    if ( invoke_id < 0 ) return;
    local key = int_to_count(invoke_id);

    delete pending_controls[c$uid, request_is_orig, key];
    delete pending_control_reads[c$uid, request_is_orig, key];
    delete invalid_control_read_invokes[c$uid, request_is_orig, key];
    delete pending_transfer_sets[c$uid, request_is_orig, key];
    delete pending_transfer_support[c$uid, request_is_orig, key];
    delete pending_transfer_controls[c$uid, request_is_orig, key];
    delete pending_variable_types[c$uid, request_is_orig, key];
    delete invalid_variable_type_invokes[c$uid, request_is_orig, key];

    # Read identity also lives in the association state used by the aggregate
    # logger.  Do not let an overwritten request supply an object identity to a
    # later ambiguous response.
    if ( c$uid in associations )
        {
        local state = associations[c$uid];
        delete state$pending_reads[request_is_orig, key];
        delete state$invalid_read_invokes[request_is_orig, key];
        associations[c$uid] = state;
        }

    clear_control_read_shapes(c$uid, ! request_is_orig, key);
    clear_control_value_shapes_for_invoke(
        c$uid, request_is_orig, key);
    }

# Run the authoritative invoke lifecycle synchronously on the aggregate parser
# event.  The logging path may be deferred while waiting for additive evidence;
# correlation state must not be, or another PDU at the same timestamp could
# observe/consume stale state before the scheduled callback executes.
function track_confirmed_request(
    c: connection, is_orig: bool, recognized: bool, pdu_type: count,
    semantic_decoded: bool, invoke_id: int, service_tag: count,
    candidate_operation: count)
    {
    if ( ! recognized || ! semantic_decoded || pdu_type != 0 ||
         invoke_id < 0 )
        return;

    local request_key = int_to_count(invoke_id);
    if ( [c$uid, is_orig, request_key] in invalid_confirmed_invokes )
        {
        # Keep a tombstone until one direction-correct terminal response.
        # Further reuse cannot make an already ambiguous invoke resolvable.
        delete pending_confirmed[c$uid, is_orig, request_key];
        purge_confirmed_request_state(c, is_orig, invoke_id);
        return;
        }

    if ( [c$uid, is_orig, request_key] in pending_confirmed )
        {
        # MMS invoke IDs are unique among one caller's outstanding confirmed
        # requests, across all services.  Never replace the old identity:
        # neither a response nor ConfirmedError can then be safely attributed.
        delete pending_confirmed[c$uid, is_orig, request_key];
        add invalid_confirmed_invokes[c$uid, is_orig, request_key];
        purge_confirmed_request_state(c, is_orig, invoke_id);
        return;
        }

    if ( pending_confirmed_count(c$uid) < max_pending_confirmed )
        {
        pending_confirmed[c$uid, is_orig, request_key] = [
            $service_tag=service_tag, $operation=candidate_operation,
            $request_is_orig=is_orig
        ];
        return;
        }

    # An additive service hook may have run before this aggregate hook.  Do not
    # allow it to bypass the authoritative global cap.
    purge_confirmed_request_state(c, is_orig, invoke_id);
    event ICCP::resource_limit_exceeded(
        c, is_orig, "pending_confirmed", max_pending_confirmed,
        pending_confirmed_count(c$uid), invoke_id);
    }

type KnownVariableTypeKey: record {
    server_is_orig: bool;
    scope: count;
    domain: string;
    name: string;
};

function pending_variable_type_count(uid: string): count
    {
    local total: count = 0;
    for ( [entry_uid, request_is_orig, invoke] in pending_variable_types )
        if ( entry_uid == uid ) ++total;
    for ( [invalid_uid, request_is_orig, invalid_invoke] in
          invalid_variable_type_invokes )
        if ( invalid_uid == uid ) ++total;
    return total;
    }

function known_variable_type_count(uid: string): count
    {
    local total: count = 0;
    for ( [entry_uid, server_is_orig, scope, domain, name] in
          known_variable_types )
        if ( entry_uid == uid ) ++total;
    return total;
    }

function supported_tase2_variable_type(name: string): bool
    {
    return name == "DSTransferSet" || name == "DSConditions" ||
           name == "Control_Command" ||
           name == "Control_Setpoint_Real" ||
           name == "Control_Setpoint_Discrete" ||
           name == "SBO_CheckBackName" || name == "Tag_Value" ||
           name == "Data_Real" || name == "Data_Discrete" ||
           name == "Data_State" ||
           name == "Data_StateSupplemental" ||
           name == "Data_RealQ" ||
           name == "Data_StateQ" ||
           name == "Data_StateSupplementalQ" ||
           name == "Data_DiscreteQ" ||
           name == "Data_RealQTimeTag" ||
           name == "Data_StateQTimeTag" ||
           name == "Data_StateSupplementalQTimeTag" ||
           name == "Data_DiscreteQTimeTag" ||
           name == "Data_RealExtended" ||
           name == "Data_StateExtended" ||
           name == "Data_StateSupplementalExtended" ||
           name == "Data_DiscreteExtended" ||
           name == "Data_RealQTimeTagExtended" ||
           name == "Data_StateQTimeTagExtended" ||
           name == "Data_StateSupplementalQTimeTagExtended" ||
           name == "Data_DiscreteQTimeTagExtended";
    }

function configured_tase2_type_scope_valid(
    name: string, scope: count, domain: string,
    object_name: string): bool
    {
    if ( ! valid_tase2_object_identifier(scope, domain, object_name) )
        return F;
    if ( name == "DSTransferSet" )
        return scope == 1;
    if ( name == "DSConditions" )
        return scope == 1 && object_name == "DSConditions_Detected";
    # IEC 60870-6-802 point/control variables and the associated IEC 503
    # SBO/Tag variables are VMD- or Domain-specific, never AA-specific.
    return standardized_point_control_scope(scope, domain);
    }

type TypeDescriptionSignature: record {
    choices: vector of count;
    primary: vector of int;
    secondary: vector of int;
    child_counts: vector of count;
    packed: vector of bool;
};

function empty_type_description_signature(): TypeDescriptionSignature
    {
    local choices: vector of count = vector();
    local primary: vector of int = vector();
    local secondary: vector of int = vector();
    local child_counts: vector of count = vector();
    local packed: vector of bool = vector();
    return [$choices=choices, $primary=primary, $secondary=secondary,
            $child_counts=child_counts, $packed=packed];
    }

function append_type_description_node(
    signature: TypeDescriptionSignature, choice: count,
    primary: int, secondary: int, child_count: count,
    packed: bool): TypeDescriptionSignature
    {
    local index = |signature$choices|;
    signature$choices[index] = choice;
    signature$primary[index] = primary;
    signature$secondary[index] = secondary;
    signature$child_counts[index] = child_count;
    signature$packed[index] = packed;
    return signature;
    }

function append_type_integer(
    signature: TypeDescriptionSignature, width: int): TypeDescriptionSignature
    {
    return append_type_description_node(signature, 5, width, 0, 0, F);
    }

function append_type_unsigned(
    signature: TypeDescriptionSignature, width: int): TypeDescriptionSignature
    {
    return append_type_description_node(signature, 6, width, 0, 0, F);
    }

function append_type_bits(
    signature: TypeDescriptionSignature, width: int): TypeDescriptionSignature
    {
    return append_type_description_node(signature, 4, width, 0, 0, F);
    }

function append_type_visible(
    signature: TypeDescriptionSignature, width: int): TypeDescriptionSignature
    {
    return append_type_description_node(signature, 10, width, 0, 0, F);
    }

function append_type_real(signature: TypeDescriptionSignature):
    TypeDescriptionSignature
    {
    return append_type_description_node(signature, 7, 32, 8, 0, F);
    }

function append_type_boolean(signature: TypeDescriptionSignature):
    TypeDescriptionSignature
    {
    return append_type_description_node(signature, 3, 0, 0, 0, F);
    }

function append_type_structure(
    signature: TypeDescriptionSignature,
    component_count: count): TypeDescriptionSignature
    {
    return append_type_description_node(
        signature, 2, 0, 0, component_count, F);
    }

function append_type_extended_timestamp(signature: TypeDescriptionSignature):
    TypeDescriptionSignature
    {
    signature = append_type_integer(signature, 32);
    signature = append_type_integer(signature, 16);
    return append_type_structure(signature, 2);
    }

function append_type_object_name(signature: TypeDescriptionSignature):
    TypeDescriptionSignature
    {
    signature = append_type_unsigned(signature, 8);
    # A negative MMS TypeDescription string width means variable length with
    # the absolute value as its maximum, as required for IEC 503 Identifier.
    signature = append_type_visible(signature, -32);
    signature = append_type_visible(signature, -32);
    return append_type_structure(signature, 3);
    }

function expected_tase2_type_signature(name: string): TypeDescriptionSignature
    {
    local signature = empty_type_description_signature();

    if ( name == "Data_Real" || name == "Control_Setpoint_Real" )
        return append_type_real(signature);
    if ( name == "Data_Discrete" )
        return append_type_integer(signature, 32);
    if ( name == "Data_State" || name == "Data_StateSupplemental" )
        return append_type_bits(signature, 8);
    if ( name == "DSConditions" )
        return append_type_bits(signature, 5);
    if ( name == "Control_Command" ||
         name == "Control_Setpoint_Discrete" ||
         name == "SBO_CheckBackName" )
        return append_type_integer(signature, 16);
    if ( name == "Tag_Value" )
        {
        signature = append_type_bits(signature, 3);
        signature = append_type_visible(signature, -255);
        return append_type_structure(signature, 2);
        }

    if ( name == "Data_RealQ" )
        signature = append_type_real(signature);
    else if ( name == "Data_DiscreteQ" )
        signature = append_type_integer(signature, 32);
    else if ( name == "Data_StateQ" ||
              name == "Data_StateSupplementalQ" )
        signature = append_type_bits(signature, 8);
    if ( name == "Data_RealQ" || name == "Data_DiscreteQ" ||
         name == "Data_StateQ" || name == "Data_StateSupplementalQ" )
        {
        signature = append_type_bits(signature, 8);
        return append_type_structure(signature, 2);
        }

    if ( name == "Data_RealQTimeTag" )
        signature = append_type_real(signature);
    else if ( name == "Data_DiscreteQTimeTag" )
        signature = append_type_integer(signature, 32);
    else if ( name == "Data_StateSupplementalQTimeTag" )
        signature = append_type_bits(signature, 8);
    if ( name == "Data_RealQTimeTag" ||
         name == "Data_DiscreteQTimeTag" ||
         name == "Data_StateSupplementalQTimeTag" )
        {
        signature = append_type_integer(signature, 32);
        signature = append_type_bits(signature, 8);
        return append_type_structure(signature, 3);
        }
    if ( name == "Data_StateQTimeTag" )
        {
        signature = append_type_integer(signature, 32);
        signature = append_type_bits(signature, 8);
        return append_type_structure(signature, 2);
        }

    if ( name == "Data_RealExtended" )
        signature = append_type_real(signature);
    else if ( name == "Data_DiscreteExtended" )
        signature = append_type_integer(signature, 32);
    else if ( name == "Data_StateSupplementalExtended" )
        signature = append_type_bits(signature, 8);
    if ( name == "Data_RealExtended" || name == "Data_DiscreteExtended" ||
         name == "Data_StateSupplementalExtended" )
        {
        signature = append_type_integer(signature, 32);
        signature = append_type_bits(signature, 8);
        signature = append_type_unsigned(signature, 16);
        return append_type_structure(signature, 4);
        }
    if ( name == "Data_StateExtended" )
        {
        signature = append_type_integer(signature, 32);
        signature = append_type_bits(signature, 8);
        signature = append_type_unsigned(signature, 16);
        return append_type_structure(signature, 3);
        }

    if ( name == "Data_RealQTimeTagExtended" )
        signature = append_type_real(signature);
    else if ( name == "Data_DiscreteQTimeTagExtended" )
        signature = append_type_integer(signature, 32);
    else if ( name == "Data_StateSupplementalQTimeTagExtended" )
        signature = append_type_bits(signature, 8);
    if ( name == "Data_RealQTimeTagExtended" ||
         name == "Data_DiscreteQTimeTagExtended" ||
         name == "Data_StateSupplementalQTimeTagExtended" )
        {
        signature = append_type_extended_timestamp(signature);
        signature = append_type_bits(signature, 8);
        return append_type_structure(signature, 3);
        }
    if ( name == "Data_StateQTimeTagExtended" )
        {
        signature = append_type_extended_timestamp(signature);
        signature = append_type_bits(signature, 8);
        return append_type_structure(signature, 2);
        }

    if ( name == "DSTransferSet" )
        {
        signature = append_type_object_name(signature);
        local interval_index: count = 0;
        while ( interval_index < 5 )
            {
            signature = append_type_integer(signature, 32);
            ++interval_index;
            }
        signature = append_type_bits(signature, 5);
        local boolean_index: count = 0;
        while ( boolean_index < 5 )
            {
            signature = append_type_boolean(signature);
            ++boolean_index;
            }
        signature = append_type_integer(signature, 16);
        return append_type_structure(signature, 13);
        }

    return signature;
    }

function valid_type_description_signature(
    signature: TypeDescriptionSignature): bool
    {
    local size = |signature$choices|;
    if ( size == 0 || size > 4096 || |signature$primary| != size ||
         |signature$secondary| != size ||
         |signature$child_counts| != size || |signature$packed| != size )
        return F;

    local available: count = 0;
    local index: count = 0;
    while ( index < size )
        {
        local choice = signature$choices[index];
        local primary = signature$primary[index];
        local secondary = signature$secondary[index];
        local children = signature$child_counts[index];
        local packed = signature$packed[index];

        if ( choice == 1 )
            {
            if ( primary < 0 || secondary != 0 || children != 1 ) return F;
            }
        else if ( choice == 2 )
            {
            if ( primary != 0 || secondary != 0 || children == 0 ) return F;
            }
        else
            {
            if ( children != 0 || packed ) return F;
            if ( choice == 3 || choice == 11 || choice == 15 )
                {
                if ( primary != 0 || secondary != 0 ) return F;
                }
            else if ( choice == 4 || choice == 9 || choice == 10 ||
                      choice == 16 )
                {
                if ( secondary != 0 ) return F;
                }
            else if ( choice == 5 || choice == 6 || choice == 13 )
                {
                if ( primary < 0 || primary > 127 || secondary != 0 )
                    return F;
                }
            else if ( choice == 7 )
                {
                if ( primary < 0 || primary > 127 || secondary < 0 ||
                     secondary > 127 ) return F;
                }
            else if ( choice == 12 )
                {
                if ( (primary != 0 && primary != 1) || secondary != 0 )
                    return F;
                }
            else
                return F;
            }

        if ( children > available ) return F;
        available = available - children + 1;
        ++index;
        }
    return available == 1;
    }

function type_description_signatures_equal(
    observed: TypeDescriptionSignature,
    expected: TypeDescriptionSignature): bool
    {
    local size = |observed$choices|;
    if ( size != |expected$choices| || |observed$primary| != size ||
         |observed$secondary| != size ||
         |observed$child_counts| != size || |observed$packed| != size )
        return F;
    local index: count = 0;
    while ( index < size )
        {
        if ( observed$choices[index] != expected$choices[index] ||
             observed$primary[index] != expected$primary[index] ||
             observed$secondary[index] != expected$secondary[index] ||
             observed$child_counts[index] != expected$child_counts[index] ||
             observed$packed[index] != expected$packed[index] )
            return F;
        ++index;
        }
    return T;
    }

function exact_eight_bit_string(raw: string): bool
    {
    return |raw| == 2 &&
        bytestring_to_count(sub_bytes(raw, 1, 1)) == 0;
    }

function exact_extended_timestamp(shape: PointValueShapeEvidence,
                                  component_index: count): bool
    {
    if ( ! shape?$nested_component_index ||
         shape$nested_component_index != component_index ||
         ! shape?$nested_choices || ! shape?$nested_raws ||
         ! shape?$nested_integer_values ||
         |shape$nested_choices| != 2 || |shape$nested_raws| != 2 ||
         |shape$nested_integer_values| != 2 )
        return F;
    return shape$nested_choices[0] == 5 &&
           shape$nested_choices[1] == 5 &&
           |shape$nested_raws[0]| > 0 && |shape$nested_raws[0]| <= 4 &&
           |shape$nested_raws[1]| > 0 && |shape$nested_raws[1]| <= 2 &&
           shape$nested_integer_values[0] >= 0 &&
           shape$nested_integer_values[1] >= 0 &&
           shape$nested_integer_values[1] <= 999;
    }

function learned_variable_type_name(
    c: connection, server_is_orig: bool,
    scope: count, domain: string, name: string): string
    {
    if ( [c$uid, server_is_orig, scope, domain, name] in
         known_variable_types )
        return known_variable_types[
            c$uid, server_is_orig, scope, domain, name];
    return "";
    }

function classify_control_write(
    c: connection, server_is_orig: bool,
    scope: count, domain: string, name: string,
    variable_count: count, data_count: count,
    shape: ControlValueShapeEvidence): string
    {
    if ( association_kind(c) != "tase2" )
        return "write_candidate";

    if ( ! valid_tase2_object_identifier(scope, domain, name) )
        return "write_candidate";

    local named_type = learned_variable_type_name(
        c, server_is_orig, scope, domain, name);
    local tag_candidate = tag_name_candidate(name) ||
                          named_type == "Tag_Value";
    if ( tag_candidate )
        {
        local valid_scope = standardized_point_control_scope(scope, domain);
        if ( valid_scope && variable_count == 1 && data_count == 1 &&
             tag_name_candidate(name) && named_type == "Tag_Value" &&
             control_tag_value_shape(shape) )
            return "set_tag";
        return "set_tag_candidate";
        }

    if ( name == "" || variable_count != 1 || data_count != 1 )
        return "write_candidate";

    if ( ! standardized_point_control_scope(scope, domain) )
        return "write_candidate";

    if ( named_type == "Control_Command" && shape$choice == 5 &&
         |shape$raw| > 0 && |shape$raw| <= 2 &&
         shape$integer_value >= -32768 && shape$integer_value <= 32767 )
        return "operate_command";
    if ( named_type == "Control_Setpoint_Discrete" && shape$choice == 5 &&
         |shape$raw| > 0 && |shape$raw| <= 2 &&
         shape$integer_value >= -32768 && shape$integer_value <= 32767 )
        return "operate_setpoint_discrete";
    if ( named_type == "Control_Setpoint_Real" && shape$choice == 7 &&
         |shape$raw| == 5 )
        return "operate_setpoint_real";
    return "write_candidate";
    }

function pending_transfer_control_count(uid: string): count
    {
    local total: count = 0;
    for ( [entry_uid, request_is_orig, invoke] in pending_transfer_controls )
        if ( entry_uid == uid ) ++total;
    return total;
    }

function active_ds_transfer_count(uid: string): count
    {
    local total: count = 0;
    for ( [entry_uid, client_is_orig, transfer_scope, transfer_domain,
           transfer_name] in active_ds_transfers )
        if ( entry_uid == uid ) ++total;
    return total;
    }

function transfer_member_matches(membership: TransferMembership,
                                 scope: count, domain: string,
                                 name: string): bool
    {
    local index: count = 0;
    while ( index < |membership$names| )
        {
        local member_scope: count = index < |membership$scopes| ?
            membership$scopes[index] : 0;
        local member_domain = index < |membership$domains| ?
            membership$domains[index] : "";
        if ( membership$names[index] == name && member_scope == scope &&
             (scope != 1 || member_domain == domain) )
            return T;
        ++index;
        }
    return F;
    }

function block_data_special_name(name: string): bool
    {
    return name == "Transfer_Set_Name" ||
           name == "DSConditions_Detected" ||
           name == "Event_Code_Detected" ||
           name == "Transfer_Set_Time_Stamp";
    }

type BlockDataAssessment: record {
    outcome: string;
    correlation: string;
    reason: string;
};

function block_data_deviation(reason: string): BlockDataAssessment
    {
    return [$outcome="standards_deviation",
            $correlation=fmt("block_data_%s", reason), $reason=reason];
    }

function block_data_special_value_valid(
    evidence: InformationReportResultsEvidence, index: count,
    name: string): bool
    {
    if ( index >= |evidence$result_choices| ||
         index >= |evidence$result_raws| ||
         index >= |evidence$result_integer_values| )
        return F;

    local choice = evidence$result_choices[index];
    local raw = evidence$result_raws[index];
    local value = evidence$result_integer_values[index];
    if ( name == "Transfer_Set_Name" )
        # Per-result nested structure is not available in this bounded event;
        # require the exact outer MMS Structure shape and retain an explicitly
        # unverified-content result below.
        return choice == 2 && |raw| > 0;
    if ( name == "DSConditions_Detected" )
        return choice == 4 && |raw| == 2 &&
            bytestring_to_count(sub_bytes(raw, 1, 1)) == 3 &&
            (bytestring_to_count(sub_bytes(raw, 2, 1)) & 0x07) == 0;
    if ( name == "Event_Code_Detected" )
        return choice == 5 && |raw| >= 1 && |raw| <= 2 &&
            value >= -32768 && value <= 32767;
    if ( name == "Transfer_Set_Time_Stamp" )
        return choice == 5 && |raw| == 4 && value >= 0;
    return F;
    }

function assess_block_data_report(
    c: connection, server_is_orig: bool,
    evidence: InformationReportResultsEvidence,
    active: ActiveDSTransfer): BlockDataAssessment
    {
    if ( evidence$access_choice != 0 )
        return block_data_deviation("named_access");
    if ( information_report_pairing_status(c, server_is_orig, evidence) !=
         "explicit_complete" )
        return block_data_deviation("incomplete_pairing");
    if ( evidence$failure_count != 0 )
        return block_data_deviation("failed_result");

    if ( ! active$parameters?$data_set_scope ||
         ! active$parameters?$data_set_name )
        return [$outcome="unresolved",
                $correlation="block_data_uncorrelatable",
                $reason="block_data_uncorrelatable"];
    local data_set_scope = active$parameters$data_set_scope;
    local data_set_domain = data_set_scope == 1 &&
        active$parameters?$data_set_domain ?
            active$parameters$data_set_domain : "";
    local data_set_name = active$parameters$data_set_name;
    if ( [c$uid, server_is_orig, data_set_scope, data_set_domain,
          data_set_name] !in known_transfer_sets )
        return [$outcome="unresolved",
                $correlation="block_data_uncorrelatable",
                $reason="block_data_uncorrelatable"];
    local membership = known_transfer_sets[
        c$uid, server_is_orig, data_set_scope, data_set_domain,
        data_set_name];

    local payload_count: count = 0;
    local payload_index: count = 0;
    local index: count = 0;
    while ( index < evidence$result_count )
        {
        if ( evidence$result_choices[index] == 0 ||
             evidence$result_errors[index] >= 0 )
            return block_data_deviation("failed_result");
        local scope = evidence$variable_scopes[index];
        local domain = evidence$variable_domains[index];
        local name = evidence$variable_names[index];
        if ( ! valid_tase2_object_identifier(scope, domain, name) )
            return block_data_deviation("invalid_identity");
        if ( block_data_special_name(name) )
            {
            if ( ! transfer_member_matches(
                     membership, scope, domain, name) )
                return block_data_deviation("special_not_member");
            if ( ! block_data_special_value_valid(
                     evidence, index, name) )
                return block_data_deviation("invalid_special_value");
            }
        else
            {
            ++payload_count;
            payload_index = index;
            }
        ++index;
        }

    if ( payload_count == 0 )
        return block_data_deviation("missing_payload");
    if ( payload_count != 1 )
        return block_data_deviation("multiple_payloads");
    if ( evidence$result_choices[payload_index] != 9 )
        return block_data_deviation("payload_not_octet_string");
    local payload = evidence$result_raws[payload_index];
    if ( |payload| == 0 )
        return block_data_deviation("empty_payload");
    local rule = bytestring_to_count(sub_bytes(payload, 1, 1));
    if ( rule > 2 )
        return block_data_deviation("invalid_rule");
    local rbe = active$parameters?$report_by_exception &&
        active$parameters$report_by_exception;
    if ( (rule == 0 && rbe) || (rule > 0 && ! rbe) )
        return block_data_deviation("rule_rbe_mismatch");

    return [$outcome="correlated_context_only",
            $correlation="block_data_header_valid_contents_unverified",
            $reason=""];
    }

function report_matches_active_data_set(
    c: connection, server_is_orig: bool,
    evidence: InformationReportResultsEvidence,
    active: ActiveDSTransfer): bool
    {
    if ( ! active$parameters?$data_set_scope ||
         ! active$parameters?$data_set_name )
        return F;
    local scope = active$parameters$data_set_scope;
    local domain = scope == 1 && active$parameters?$data_set_domain ?
        active$parameters$data_set_domain : "";
    local name = active$parameters$data_set_name;

    local blocked = active$parameters?$block_data &&
        active$parameters$block_data;

    if ( evidence$access_choice == 1 )
        return evidence$list_scope == scope && evidence$list_name == name &&
            (scope != 1 || evidence$list_domain == domain);

    if ( blocked && evidence$access_choice == 0 )
        {
        local block_server_is_orig = ! active$request_is_orig;
        if ( [c$uid, block_server_is_orig, scope, domain, name] !in
             known_transfer_sets )
            return F;
        local block_membership = known_transfer_sets[
            c$uid, block_server_is_orig, scope, domain, name];
        local block_index: count = 0;
        while ( block_index < |evidence$variable_names| )
            {
            if ( block_data_special_name(
                     evidence$variable_names[block_index]) &&
                 block_index < |evidence$variable_scopes| &&
                 block_index < |evidence$variable_domains| &&
                 transfer_member_matches(
                     block_membership,
                     evidence$variable_scopes[block_index],
                     evidence$variable_domains[block_index],
                     evidence$variable_names[block_index]) )
                return T;
            ++block_index;
            }
        return F;
        }

    if ( evidence$access_choice != 0 || evidence$result_count == 0 ||
         information_report_pairing_status(c, server_is_orig, evidence) !=
             "explicit_complete" ||
         [c$uid, server_is_orig, scope, domain, name] !in
             known_transfer_sets )
        return F;

    local membership = known_transfer_sets[
        c$uid, server_is_orig, scope, domain, name];
    local index: count = 0;
    while ( index < evidence$result_count )
        {
        if ( ! transfer_member_matches(
                 membership, evidence$variable_scopes[index],
                 evidence$variable_domains[index],
                 evidence$variable_names[index]) )
            return F;
        ++index;
        }
    return T;
    }

function active_report_correlation(evidence: InformationReportResultsEvidence,
                                   active: ActiveDSTransfer): string
    {
    local rbe = active$parameters?$report_by_exception &&
        active$parameters$report_by_exception;
    local blocked = active$parameters?$block_data &&
        active$parameters$block_data;
    if ( evidence$access_choice == 1 )
        {
        if ( blocked ) return "unexpected_named_block_data";
        return rbe ? "rbe_full_list_fallback" : "exact_data_set";
        }
    if ( blocked ) return "block_data_uncorrelatable";
    return rbe ? "rbe_subset" : "unexpected_explicit_non_rbe";
    }

function write_active_report(c: connection, is_orig: bool,
                             evidence: InformationReportResultsEvidence,
                             active: ActiveDSTransfer,
                             correlation: string, outcome: string)
    {
    local rec: TransferInfo = [
        $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
        $action="active_report", $outcome=outcome,
        $result_count=evidence$result_count,
        $failure_count=evidence$failure_count,
        $transfer_set_scope=transfer_scope_name(active$scope),
        $transfer_set_name=active$name, $transfer_state=active$state,
        $report_access=evidence$access_choice == 1 ?
            "named_list" : "explicit_variables",
        $report_correlation=correlation,
        $ack_required=active$parameters?$critical &&
            active$parameters$critical
    ];
    if ( active$domain != "" ) rec$transfer_set_domain = active$domain;
    rec = add_ds_transfer_parameters(rec, active$parameters);
    write_transfer_record(c, is_orig, rec);
    }

function emit_transfer_report_anomaly(c: connection, is_orig: bool,
                                      active: ActiveDSTransfer,
                                      correlation: string, reason: string)
    {
    event ICCP::transfer_report_anomaly(
        c, is_orig, association_kind(c), endpoint_role(c, is_orig),
        transfer_scope_name(active$scope), active$domain, active$name,
        correlation, reason);
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
    provenance: count) &priority=5
    {
    if ( association_kind(c) != "tase2" ) return;
    local sequence = mms_parser_sequence(c, is_orig);
    if ( ! information_report_results_available(
            c, is_orig, sequence) ) return;
    local evidence = information_report_results_evidence[
        c$uid, is_orig, sequence];
    local matches: count = 0;
    local wrong_direction: count = 0;
    local selected_name = "";
    local selected_client_is_orig = F;
    local selected_scope: count = 0;
    local selected_domain = "";
    for ( [uid, client_is_orig, transfer_scope, transfer_domain,
           transfer_name] in active_ds_transfers )
        {
        if ( uid != c$uid ) next;
        local active = active_ds_transfers[
            uid, client_is_orig, transfer_scope, transfer_domain,
            transfer_name];
        if ( ! report_matches_active_data_set(
                 c, is_orig, evidence, active) ) next;
        if ( is_orig == active$request_is_orig )
            ++wrong_direction;
        else
            {
            ++matches;
            selected_name = transfer_name;
            selected_client_is_orig = client_is_orig;
            selected_scope = transfer_scope;
            selected_domain = transfer_domain;
            }
        }

    if ( matches == 0 )
        {
        if ( wrong_direction == 1 )
            {
            for ( [wrong_uid, wrong_client_is_orig, wrong_scope,
                   wrong_domain, wrong_name] in active_ds_transfers )
                {
                if ( wrong_uid != c$uid ) next;
                local wrong = active_ds_transfers[
                    wrong_uid, wrong_client_is_orig, wrong_scope,
                    wrong_domain, wrong_name];
                if ( report_matches_active_data_set(
                         c, is_orig, evidence, wrong) &&
                     is_orig == wrong$request_is_orig )
                    {
                    write_active_report(c, is_orig, evidence, wrong,
                        "direction_mismatch", "standards_deviation");
                    emit_transfer_report_anomaly(c, is_orig, wrong,
                        "direction_mismatch", "report_direction_mismatch");
                    return;
                    }
                }
            }
        if ( access_choice == 0 )
            {
            local blocked_candidates: count = 0;
            for ( [candidate_uid, candidate_client_is_orig,
                   candidate_scope, candidate_domain,
                   candidate_name] in active_ds_transfers )
                {
                if ( candidate_uid != c$uid ||
                     is_orig == candidate_client_is_orig ) next;
                local candidate = active_ds_transfers[
                    candidate_uid, candidate_client_is_orig,
                    candidate_scope, candidate_domain, candidate_name];
                if ( candidate$parameters?$block_data &&
                     candidate$parameters$block_data )
                    ++blocked_candidates;
                }
            if ( blocked_candidates > 0 )
                {
                local unresolved_block: TransferInfo = [
                    $ts=network_time(), $uid=c$uid, $id=c$id,
                    $is_orig=is_orig, $action="active_report",
                    $outcome="unresolved", $result_count=result_count,
                    $failure_count=failure_count,
                    $report_access="explicit_variables",
                    $report_correlation="block_data_uncorrelatable"
                ];
                write_transfer_record(c, is_orig, unresolved_block);
                }
            }
        return;
        }

    if ( matches > 1 )
        {
        local ambiguous: TransferInfo = [
            $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
            $action="active_report", $outcome="unresolved",
            $result_count=result_count, $failure_count=failure_count,
            $report_access=access_choice == 1 ?
                "named_list" : "explicit_variables",
            $report_correlation="ambiguous_active_transfer"
        ];
        write_transfer_record(c, is_orig, ambiguous);
        return;
        }

    local selected = active_ds_transfers[
        c$uid, selected_client_is_orig, selected_scope, selected_domain,
        selected_name];
    local selected_blocked = selected$parameters?$block_data &&
        selected$parameters$block_data;
    if ( selected_blocked )
        {
        local assessment = assess_block_data_report(
            c, is_orig, evidence, selected);
        if ( assessment$outcome == "standards_deviation" )
            emit_transfer_report_anomaly(
                c, is_orig, selected, assessment$correlation,
                assessment$reason);
        write_active_report(c, is_orig, evidence, selected,
                            assessment$correlation, assessment$outcome);
        return;
        }
    local correlation = active_report_correlation(evidence, selected);
    local outcome = failure_count == 0 ? "correlated" :
        "correlated_partial_or_failed";
    if ( selected$state == "stopped" )
        {
        # 503 requires a client to accept at least one report after issuing
        # Stop and does not give this passive observer a safe maximum. Keep
        # later reports attributable, but do not call their count a violation.
        correlation = "post_stop_observed";
        outcome = "correlated_context_only";
        }
    else if ( correlation == "unexpected_explicit_non_rbe" ||
              correlation == "unexpected_named_block_data" )
        {
        outcome = "standards_deviation";
        emit_transfer_report_anomaly(c, is_orig, selected, correlation,
                                     correlation);
        }
    write_active_report(c, is_orig, evidence, selected, correlation, outcome);
    active_ds_transfers[
        c$uid, selected_client_is_orig, selected_scope, selected_domain,
        selected_name] = selected;
    }

function pending_transfer_support_count(uid: string): count
    {
    local total: count = 0;
    for ( [entry_uid, request_is_orig, invoke] in pending_transfer_support )
        if ( entry_uid == uid ) ++total;
    return total;
    }


function pending_transfer_count(uid: string): count
    {
    local total: count = 0;
    for ( [entry_uid, request_is_orig, invoke] in pending_transfer_sets )
        if ( entry_uid == uid ) ++total;
    return total;
    }

function known_transfer_count(uid: string): count
    {
    local total: count = 0;
    for ( [entry_uid, server_is_orig, scope, domain, name] in
          known_transfer_sets )
        if ( entry_uid == uid ) ++total;
    return total;
    }

function transfer_scope_name(scope: count): string
    {
    if ( scope == 0 ) return "vcc";
    if ( scope == 1 ) return "icc";
    if ( scope == 2 ) return "aa";
    return "unknown";
    }

function information_report_result_limit(): count
    {
    # Preserve the historical first-result observation even when a deployment
    # attempts to set the additive per-report limit to zero.
    return max_logged_information_report_results == 0 ?
        1 : max_logged_information_report_results;
    }

function information_report_result_identity(
    c: connection, server_is_orig: bool,
    evidence: InformationReportResultsEvidence,
    index: count): InformationReportResultIdentity
    {
    local identity: InformationReportResultIdentity = [
        $known=F, $scope=0, $domain="", $name=""
    ];

    local pairing_status = information_report_pairing_status(
        c, server_is_orig, evidence);
    if ( pairing_status != "explicit_complete" &&
         pairing_status != "known_list_complete" )
        return identity;

    if ( evidence$access_choice == 0 )
        {
        if ( index >= |evidence$variable_names| ||
             evidence$variable_names[index] == "" )
            return identity;
        identity$known = T;
        identity$name = evidence$variable_names[index];
        if ( index < |evidence$variable_scopes| )
            identity$scope = evidence$variable_scopes[index];
        if ( index < |evidence$variable_domains| )
            identity$domain = evidence$variable_domains[index];
        return identity;
        }

    if ( evidence$access_choice != 1 || evidence$list_name == "" ||
         [c$uid, server_is_orig,
          evidence$list_scope, evidence$list_domain,
          evidence$list_name] !in known_transfer_sets )
        return identity;

    local membership = known_transfer_sets[
        c$uid, server_is_orig,
        evidence$list_scope, evidence$list_domain,
        evidence$list_name];
    if ( index >= |membership$names| || membership$names[index] == "" )
        return identity;
    identity$known = T;
    identity$name = membership$names[index];
    if ( index < |membership$scopes| )
        identity$scope = membership$scopes[index];
    if ( index < |membership$domains| )
        identity$domain = membership$domains[index];
    return identity;
    }

function information_report_pairing_status(
    c: connection, server_is_orig: bool,
    evidence: InformationReportResultsEvidence): string
    {
    if ( evidence$result_count != |evidence$result_choices| ||
         evidence$result_count != |evidence$result_errors| ||
         evidence$result_count != |evidence$result_raws| ||
         evidence$result_count != |evidence$result_integer_values| ||
         evidence$result_count != |evidence$result_floating_values| ||
         evidence$result_count != |evidence$result_boolean_values| ||
         evidence$result_count != |evidence$result_string_values| )
        return "count_mismatch";

    if ( evidence$access_choice == 0 )
        {
        if ( |evidence$variable_scopes| != evidence$result_count ||
             |evidence$variable_domains| != evidence$result_count ||
             |evidence$variable_names| != evidence$result_count )
            return "count_mismatch";
        local explicit_index: count = 0;
        while ( explicit_index < |evidence$variable_names| )
            {
            if ( evidence$variable_names[explicit_index] == "" )
                return "identity_incomplete";
            ++explicit_index;
            }
        return "explicit_complete";
        }

    if ( evidence$access_choice != 1 || evidence$list_name == "" ||
         [c$uid, server_is_orig,
          evidence$list_scope, evidence$list_domain,
          evidence$list_name] !in known_transfer_sets )
        return "untracked_list";

    local membership = known_transfer_sets[
        c$uid, server_is_orig,
        evidence$list_scope, evidence$list_domain,
        evidence$list_name];
    if ( |membership$scopes| != evidence$result_count ||
         |membership$domains| != evidence$result_count ||
         |membership$names| != evidence$result_count )
        return "count_mismatch";
    local membership_index: count = 0;
    while ( membership_index < |membership$names| )
        {
        if ( membership$names[membership_index] == "" )
            return "identity_incomplete";
        ++membership_index;
        }
    return "known_list_complete";
    }

function information_report_loggable_result_count(
    c: connection, server_is_orig: bool,
    evidence: InformationReportResultsEvidence): count
    {
    local logged: count = 0;
    local index: count = 0;
    local limit = information_report_result_limit();
    while ( index < |evidence$result_choices| && logged < limit )
        {
        if ( information_report_result_identity(
                 c, server_is_orig, evidence, index)$known )
            ++logged;
        ++index;
        }
    return logged;
    }

function information_buffer_capacity(name: string): count
    {
    # Supported Information Message buffers encode their capacity in the
    # Info_Buff_XX suffix. Bound the suffix before
    # conversion and reject capacities beyond the parser's 16 MiB value cap.
    if ( ! ( /^Info_Buff_[1-9][0-9]{0,7}$/ in name ) ) return 0;
    local capacity = to_count(sub_bytes(name, 11, |name| - 10));
    return capacity <= 16777216 ? capacity : 0;
    }

function information_message_candidate(
    c: connection, server_is_orig: bool,
    evidence: InformationReportResultsEvidence): bool
    {
    local pairing = information_report_pairing_status(
        c, server_is_orig, evidence);
    if ( association_kind(c) != "tase2" || evidence$result_count != 2 ||
         (pairing != "known_list_complete" &&
          pairing != "explicit_complete") )
        return F;
    local header = information_report_result_identity(
        c, server_is_orig, evidence, 0);
    local buffer = information_report_result_identity(
        c, server_is_orig, evidence, 1);
    return header$known && buffer$known &&
           valid_tase2_object_identifier(
               header$scope, header$domain, header$name) &&
           valid_tase2_object_identifier(
               buffer$scope, buffer$domain, buffer$name) &&
           (header$scope == 0 || header$scope == 1) &&
           header$name == "Info_Mess_Header" &&
           buffer$scope == header$scope && buffer$domain == header$domain &&
           information_buffer_capacity(buffer$name) > 0;
    }

function write_information_message_observation(
    c: connection, is_orig: bool,
    evidence: InformationReportResultsEvidence,
    shape: PointValueShapeEvidence, provenance: string)
    {
    if ( ! information_message_candidate(c, is_orig, evidence) ) return;

    local header = information_report_result_identity(
        c, is_orig, evidence, 0);
    local buffer = information_report_result_identity(
        c, is_orig, evidence, 1);
    local capacity = information_buffer_capacity(buffer$name);
    local header_valid = evidence$failure_count == 0 &&
        |evidence$result_choices| == 2 &&
        evidence$result_choices[0] == 2 &&
        shape?$component_choices && shape?$component_raws &&
        shape?$component_integer_values &&
        |shape$component_choices| == 4 &&
        |shape$component_raws| == 4 &&
        |shape$component_integer_values| == 4;
    local component_index: count = 0;
    while ( header_valid && component_index < 4 )
        {
        if ( shape$component_choices[component_index] != 5 ||
             |shape$component_raws[component_index]| == 0 ||
             |shape$component_raws[component_index]| > 4 )
            header_valid = F;
        ++component_index;
        }

    local buffer_valid = evidence$failure_count == 0 &&
        |evidence$result_choices| == 2 &&
        |evidence$result_raws| == 2 &&
        evidence$result_choices[1] == 9 &&
        |evidence$result_raws[1]| == capacity;
    local size_valid = header_valid &&
        shape$component_integer_values[3] >= 0 &&
        int_to_count(shape$component_integer_values[3]) <= capacity;

    local rec: TransferInfo = [
        $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
        $action="information_message",
        $outcome=! header_valid ? "invalid_header" :
            ! buffer_valid ? "invalid_buffer" :
            ! size_valid ? "size_mismatch" : "delivered",
        $first_variable_scope=transfer_scope_name(header$scope),
        $first_variable_name=header$name,
        $result_count=evidence$result_count,
        $failure_count=evidence$failure_count,
        $pairing_status=information_report_pairing_status(
            c, is_orig, evidence),
        $buffer_capacity=capacity,
        $buffer_length=|evidence$result_raws| > 1 ?
            |evidence$result_raws[1]| : 0
    ];
    if ( header$domain != "" ) rec$first_variable_domain = header$domain;
    if ( evidence$access_choice == 1 )
        {
        rec$list_scope = transfer_scope_name(evidence$list_scope);
        rec$list_name = evidence$list_name;
        if ( evidence$list_domain != "" )
            rec$list_domain = evidence$list_domain;
        }
    if ( header_valid )
        {
        rec$info_reference = shape$component_integer_values[0];
        rec$local_reference = shape$component_integer_values[1];
        rec$message_id = shape$component_integer_values[2];
        if ( shape$component_integer_values[3] >= 0 )
            rec$message_size = int_to_count(
                shape$component_integer_values[3]);
        }
    write_transfer_record_with_provenance(c, is_orig, rec, provenance);
    }

function bounded_information_report_result_raw(raw: string): string
    {
    local bounded = raw;
    if ( |bounded| > max_logged_result_raw_bytes )
        bounded = sub_bytes(bounded, 0, max_logged_result_raw_bytes);
    return bytestring_to_hexstr(bounded);
    }

function add_information_report_result_to_info(
    rec: Info, evidence: InformationReportResultsEvidence,
    index: count): Info
    {
    rec$result_index = index;
    rec$result_count = evidence$result_count;
    if ( index < |evidence$result_choices| )
        rec$result_type = evidence$result_choices[index];
    if ( index < |evidence$result_errors| &&
         evidence$result_errors[index] >= 0 )
        rec$result_error = evidence$result_errors[index];
    if ( index < |evidence$result_raws| &&
         evidence$result_raws[index] != "" )
        {
        rec$result_raw = bounded_information_report_result_raw(
            evidence$result_raws[index]);
        rec$result_raw_truncated =
            |evidence$result_raws[index]| > max_logged_result_raw_bytes;
        }
    if ( index < |evidence$result_choices| )
        {
        local choice = evidence$result_choices[index];
        if ( (choice == 5 || choice == 6 || choice == 13 || choice == 17) &&
             index < |evidence$result_integer_values| )
            rec$integer_value = evidence$result_integer_values[index];
        else if ( choice == 7 &&
                  index < |evidence$result_floating_values| )
            rec$floating_value = evidence$result_floating_values[index];
        else if ( choice == 3 &&
                  index < |evidence$result_boolean_values| )
            rec$boolean_value = evidence$result_boolean_values[index];
        else if ( (choice == 10 || choice == 16) &&
                  index < |evidence$result_string_values| )
            rec$string_value = bounded_detail(
                evidence$result_string_values[index]);
        else if ( choice == 15 &&
                  index < |evidence$result_string_values| )
            rec$object_identifier_value = bounded_detail(
                evidence$result_string_values[index]);
        }
    return rec;
    }

function write_additional_information_report_results(
    c: connection, is_orig: bool,
    evidence: InformationReportResultsEvidence,
    skip_first: bool, provenance: string)
    {
    local emitted: count = 0;
    local index: count = 0;
    local limit = information_report_result_limit();
    local pairing_status = information_report_pairing_status(
        c, is_orig, evidence);
    local standardized_information_message =
        information_message_candidate(c, is_orig, evidence);
    while ( index < |evidence$result_choices| && emitted < limit )
        {
        local identity = information_report_result_identity(
            c, is_orig, evidence, index);
        if ( identity$known )
            {
            if ( ! (skip_first && index == 0) )
                {
                local result: ObjectInfo = [
                    $ts=network_time(), $uid=c$uid, $id=c$id,
                    $is_orig=is_orig,
                    $association_kind=association_kind(c),
                    $association_phase=association_phase(c),
                    $endpoint_role=endpoint_role(c, is_orig),
                    $observation_kind="information_report_result",
                    $operation="information_report",
                    $object_scope=transfer_scope_name(identity$scope),
                    $object_name=identity$name,
                    $name_model=standardized_information_message ?
                        "standardized" : identity$scope == 1 &&
                        is_bilateral_domain_for_server(
                            c, is_orig, identity$domain) ?
                            "agreement_defined" : "private_unknown",
                    $domain_kind=identity$scope == 0 ? "vcc" :
                        identity$scope == 1 ?
                            (is_bilateral_domain_for_server(
                                 c, is_orig, identity$domain) ?
                                "bilateral" : "icc") :
                        identity$scope == 2 ? "aa" : "unknown",
                    $bilateral_domain=is_bilateral_domain_for_server(
                        c, is_orig, identity$domain),
                    $result_count=evidence$result_count,
                    $result_pairing_status=pairing_status,
                    $result_index=index,
                    $result_type=evidence$result_choices[index],
                    $provenance=provenance,
                    $stream_completeness=output_completeness(c, is_orig)
                ];
                if ( identity$domain != "" )
                    result$object_domain = identity$domain;
                if ( index < |evidence$result_errors| &&
                     evidence$result_errors[index] >= 0 )
                    result$result_error = evidence$result_errors[index];
                if ( index < |evidence$result_raws| &&
                     evidence$result_raws[index] != "" &&
                     information_buffer_capacity(identity$name) == 0 )
                    {
                    result$result_raw =
                        bounded_information_report_result_raw(
                            evidence$result_raws[index]);
                    result$result_raw_truncated =
                        |evidence$result_raws[index]| >
                            max_logged_result_raw_bytes;
                    }
                local choice = evidence$result_choices[index];
                if ( (choice == 5 || choice == 6 || choice == 13 ||
                      choice == 17) &&
                     index < |evidence$result_integer_values| )
                    result$integer_value =
                        evidence$result_integer_values[index];
                else if ( choice == 7 &&
                          index < |evidence$result_floating_values| )
                    result$floating_value =
                        evidence$result_floating_values[index];
                else if ( choice == 3 &&
                          index < |evidence$result_boolean_values| )
                    result$boolean_value =
                        evidence$result_boolean_values[index];
                else if ( (choice == 10 || choice == 16) &&
                          index < |evidence$result_string_values| )
                    result$string_value = bounded_detail(
                        evidence$result_string_values[index]);
                else if ( choice == 15 &&
                          index < |evidence$result_string_values| )
                    result$object_identifier_value = bounded_detail(
                        evidence$result_string_values[index]);
                Log::write(ICCP::OBJECT_LOG, result);
                }
            ++emitted;
            }
        ++index;
        }
    }

function process_gva_message(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    object_scope: count, object_domain: string, object_name: string,
    deletable_present: bool, mms_deletable: bool, type_resolved: bool,
    unresolved_type_name_count: count,
    observed: TypeDescriptionSignature, type_raw: string,
    type_node_count: count, type_maximum_depth: count,
    provenance: count, legacy_compatibility: bool)
    {
    # Recovered/inferred parser output remains available through evidence
    # events, but it cannot create, contradict, or revoke trusted exact state.
    # A terminal response still retires an opposite-direction verified request
    # so truncated recovery cannot leak correlation state or poison invoke
    # reuse.
    if ( ! legacy_compatibility && provenance != 1 )
        {
        if ( pdu_type == 1 && invoke_id >= 0 )
            {
            local untrusted_key = int_to_count(invoke_id);
            local untrusted_request_is_orig = ! is_orig;
            delete pending_variable_types[
                c$uid, untrusted_request_is_orig, untrusted_key];
            delete invalid_variable_type_invokes[
                c$uid, untrusted_request_is_orig, untrusted_key];
            }
        return;
        }
    if ( association_kind(c) != "tase2" || invoke_id < 0 )
        return;
    if ( pdu_type == 0 &&
         ! confirmed_request_tracking_allowed(c, is_orig, invoke_id) )
        return;
    if ( pdu_type == 1 &&
         confirmed_response_is_ambiguous(c, is_orig, invoke_id) )
        return;
    local key = int_to_count(invoke_id);
    if ( pdu_type == 0 )
        {
        if ( ! valid_tase2_object_identifier(
                 object_scope, object_domain, object_name) ) return;
        if ( [c$uid, is_orig, key] in invalid_variable_type_invokes ) return;
        if ( [c$uid, is_orig, key] in pending_variable_types )
            {
            local reused = pending_variable_types[c$uid, is_orig, key];
            delete pending_variable_types[c$uid, is_orig, key];
            invalid_variable_type_invokes[c$uid, is_orig, key] =
                reused$request_is_orig;
            return;
            }
        if ( pending_variable_type_count(c$uid) >=
             max_pending_transfer_sets )
            {
            event ICCP::resource_limit_exceeded(
                c, is_orig, "pending_variable_types",
                max_pending_transfer_sets,
                pending_variable_type_count(c$uid), invoke_id);
            return;
            }
        pending_variable_types[c$uid, is_orig, key] = [
            $request_is_orig=is_orig,
            $server=is_orig ? c$id$resp_h : c$id$orig_h,
            $peer=is_orig ? c$id$orig_h : c$id$resp_h,
            $scope=object_scope,
            $domain=object_domain, $name=object_name
        ];
        return;
        }
    if ( pdu_type != 1 ) return;
    local request_is_orig = ! is_orig;
    if ( [c$uid, request_is_orig, key] !in pending_variable_types )
        {
        if ( [c$uid, request_is_orig, key] in
             invalid_variable_type_invokes )
            delete invalid_variable_type_invokes[
                c$uid, request_is_orig, key];
        return;
        }
    local prior = pending_variable_types[c$uid, request_is_orig, key];
    delete pending_variable_types[c$uid, request_is_orig, key];
    local configured_type = "";
    if ( [prior$server, prior$peer, prior$scope, prior$domain, prior$name] in
         configured_variable_types )
        configured_type = configured_variable_types[
            prior$server, prior$peer, prior$scope, prior$domain, prior$name];

    local discovery: TransferInfo = [
        $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
        $action="type_discovery", $outcome="unmapped",
        $invoke_id=invoke_id,
        $list_scope=transfer_scope_name(prior$scope),
        $list_name=prior$name
    ];
    if ( prior$domain != "" ) discovery$list_domain = prior$domain;

    # GetVariableAccessAttributes-Response carries an inline TypeDescription,
    # never a standardized type name. Exact names therefore come only from
    # explicit operator configuration; legacy event parameters are retained
    # for ABI compatibility but are deliberately not trusted here.
    if ( ! supported_tase2_variable_type(configured_type) )
        {
        if ( configured_type != "" )
            discovery$outcome = "invalid_configuration";
        write_transfer_record(c, is_orig, discovery);
        return;
        }

    discovery$named_type = configured_type;
    if ( ! configured_tase2_type_scope_valid(
             configured_type, prior$scope, prior$domain, prior$name) )
        {
        delete known_variable_types[
            c$uid, is_orig, prior$scope, prior$domain, prior$name];
        discovery$outcome = "invalid_configuration";
        discovery$conformance = "standards_deviation";
        discovery$conformance_reasons = "invalid_standardized_scope";
        write_transfer_record(c, is_orig, discovery);
        return;
        }

    local expected = expected_tase2_type_signature(configured_type);
    if ( legacy_compatibility )
        {
        # Direct script tests historically supplied no recursive response
        # evidence. This explicit, test-only mode models a conformant response;
        # packet-driven parser delivery never enters this path.
        observed = expected;
        deletable_present = T;
        mms_deletable = F;
        type_resolved = T;
        unresolved_type_name_count = 0;
        }

    discovery$deletable = mms_deletable;
    discovery$type_node_count = type_node_count;
    discovery$type_maximum_depth = type_maximum_depth;
    if ( type_raw != "" )
        {
        discovery$type_raw = bounded_information_report_result_raw(type_raw);
        discovery$type_raw_truncated =
            |type_raw| > max_logged_result_raw_bytes;
        }
    if ( |observed$choices| > 0 &&
         |observed$primary| == |observed$choices| &&
         |observed$secondary| == |observed$choices| &&
         |observed$child_counts| == |observed$choices| &&
         |observed$packed| == |observed$choices| )
        {
        local root_index = |observed$choices| - 1;
        local root_choice = observed$choices[root_index];
        discovery$type_choice = root_choice;
        discovery$type_constructed =
            root_choice == 1 || root_choice == 2 || root_choice == 7 ||
            root_choice == 16;
        discovery$type_packed = observed$packed[root_index];
        if ( root_choice == 1 )
            discovery$type_number_of_elements = observed$primary[root_index];
        else if ( root_choice == 2 )
            discovery$type_component_count =
                observed$child_counts[root_index];
        else if ( root_choice == 7 )
            {
            discovery$type_format_width = observed$primary[root_index];
            discovery$type_exponent_width = observed$secondary[root_index];
            }
        else if ( root_choice == 12 )
            discovery$type_boolean_value = observed$primary[root_index] != 0;
        else if ( root_choice == 4 || root_choice == 5 ||
                  root_choice == 6 || root_choice == 9 ||
                  root_choice == 10 || root_choice == 13 ||
                  root_choice == 16 )
            discovery$type_signed_value = observed$primary[root_index];
        }

    local mismatch_reasons = "";
    if ( ! deletable_present )
        mismatch_reasons = append_feature(
            mismatch_reasons, "mms_deletable_missing");
    else if ( mms_deletable )
        mismatch_reasons = append_feature(
            mismatch_reasons, "mms_deletable_true");
    if ( ! type_resolved || unresolved_type_name_count > 0 )
        mismatch_reasons = append_feature(
            mismatch_reasons, "unresolved_type_name");
    if ( ! valid_type_description_signature(observed) )
        mismatch_reasons = append_feature(
            mismatch_reasons, "invalid_type_signature");
    else if ( ! type_description_signatures_equal(observed, expected) )
        mismatch_reasons = append_feature(
            mismatch_reasons, "type_signature_mismatch");

    if ( mismatch_reasons != "" )
        {
        # A later contradictory response revokes stale trust for the exact
        # endpoint-owned object instead of leaving an earlier learned type live.
        delete known_variable_types[
            c$uid, is_orig, prior$scope, prior$domain, prior$name];
        discovery$outcome = "type_mismatch";
        discovery$conformance = "standards_deviation";
        discovery$conformance_reasons = mismatch_reasons;
        write_transfer_record(c, is_orig, discovery);
        return;
        }

    # The responder is the endpoint that owns the discovered Named Variable.
    # Keep identical ObjectNames from opposite endpoints independent.
    local already_known = [c$uid, is_orig, prior$scope, prior$domain,
                           prior$name] in known_variable_types;
    if ( ! already_known && known_variable_type_count(c$uid) >=
         max_known_transfer_sets )
        {
        event ICCP::resource_limit_exceeded(
            c, is_orig, "known_variable_types", max_known_transfer_sets,
            known_variable_type_count(c$uid), invoke_id);
        return;
        }
    known_variable_types[
        c$uid, is_orig, prior$scope, prior$domain, prior$name] =
            configured_type;
    discovery$outcome = "configured";
    write_transfer_record(c, is_orig, discovery);
    }

event ICCP::mms_gva_message_v3(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    object_scope: count, object_domain: string, object_name: string,
    deletable_present: bool, mms_deletable: bool, type_resolved: bool,
    unresolved_type_name_count: count,
    type_choices: vector of count, type_primary: vector of int,
    type_secondary: vector of int, type_child_counts: vector of count,
    type_packed: vector of bool, type_raw: string,
    type_node_count: count, type_maximum_depth: count, provenance: count)
    {
    local observed: TypeDescriptionSignature = [
        $choices=type_choices, $primary=type_primary,
        $secondary=type_secondary, $child_counts=type_child_counts,
        $packed=type_packed
    ];
    process_gva_message(
        c, is_orig, pdu_type, invoke_id, object_scope, object_domain,
        object_name, deletable_present, mms_deletable, type_resolved,
        unresolved_type_name_count, observed, type_raw, type_node_count,
        type_maximum_depth, provenance, F);
    }

event ICCP::mms_variable_type_message(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    service_tag: count, object_scope: count, object_domain: string,
    object_name: string, type_choice: count, named_type_scope: count,
    named_type_domain: string, named_type_name: string)
    {
    if ( ! legacy_gva_direct_event_compatibility || service_tag != 6 ) return;
    local observed = empty_type_description_signature();
    process_gva_message(
        c, is_orig, pdu_type, invoke_id, object_scope, object_domain,
        object_name, pdu_type == 1, F, T, 0, observed, "", 0, 0, 0, T);
    }

function is_transfer_support_value(name: string): bool
    {
    return name == "Next_DSTransfer_Set" ||
           name == "Transfer_Set_Name" ||
           name == "Event_Code_Detected" ||
           name == "Transfer_Set_Time_Stamp" ||
           name == "Transfer_Report_ACK" ||
           name == "Transfer_Report_NACK";
    }

function transfer_support_action(name: string): string
    {
    if ( name == "Next_DSTransfer_Set" ) return "next_transfer_set";
    if ( name == "Transfer_Set_Name" ) return "transfer_set_name";
    if ( name == "Event_Code_Detected" ) return "event_code_detected";
    if ( name == "Transfer_Set_Time_Stamp" ) return "transfer_timestamp";
    if ( name == "Transfer_Report_ACK" )
        return "read_report_ack_value";
    if ( name == "Transfer_Report_NACK" )
        return "read_report_nack_value";
    return "support_value";
    }

function begin_transfer_support_read_request(
    c: connection, is_orig: bool, invoke_id: int,
    object_scope: count, object_domain: string, object_name: string)
    {
    if ( object_scope != 1 ||
         ! valid_tase2_object_identifier(
             object_scope, object_domain, object_name) ||
         ! is_transfer_support_value(object_name) )
        return;

    local key = int_to_count(invoke_id);
    local reused = [c$uid, is_orig, key] in pending_transfer_support;
    if ( ! reused && pending_transfer_support_count(c$uid) >=
         max_pending_transfer_sets )
        {
        event ICCP::resource_limit_exceeded(
            c, is_orig, "pending_transfer_support",
            max_pending_transfer_sets,
            pending_transfer_support_count(c$uid), invoke_id);
        return;
        }

    pending_transfer_support[c$uid, is_orig, key] = [
        $request_is_orig=is_orig, $scope=object_scope,
        $domain=object_domain, $name=object_name
    ];
    }

# Authoritative packet Read request policy.  Unlike the two compatibility
# events below, v3 carries access_choice, so only an explicit variable list can
# supply a first-variable identity for control or transfer-support semantics.
event ICCP::mms_read_message_v3(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    access_choice: count, variable_count: count,
    first_variable_scope: count, first_variable_domain: string,
    first_variable_name: string, first_variable_category: count,
    result_count: count, failure_count: count,
    first_result_type: count, first_result_raw: string,
    result_integer_count: count, result_first_integer: int,
    result_second_integer: int, result_component_count: count,
    result_first_choice: count, result_second_choice: count,
    provenance: count) &priority=5
    {
    if ( pdu_type != 0 || invoke_id < 0 ) return;

    mark_parser_read_delivery(c, is_orig, invoke_id);
    if ( access_choice != 0 || association_kind(c) != "tase2" ||
         ! confirmed_request_tracking_allowed(c, is_orig, invoke_id) )
        return;

    begin_control_read_request(
        c, is_orig, invoke_id, first_variable_scope,
        first_variable_domain, first_variable_name, variable_count);
    begin_transfer_support_read_request(
        c, is_orig, invoke_id, first_variable_scope,
        first_variable_domain, first_variable_name);
    }

event ICCP::mms_transfer_support_value_message(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    service_tag: count, object_scope: count, object_domain: string,
    object_name: string, result_count: count, failure_count: count,
    first_result_choice: count, first_result_raw: string,
    component_count: count, first_component_choice: count,
    second_component_choice: count, third_component_choice: count,
    first_integer_value: int, second_component_raw: string,
    third_component_raw: string)
    {
    if ( association_kind(c) != "tase2" || service_tag != 4 ||
         invoke_id < 0 ) return;
    if ( pdu_type == 0 &&
         parser_read_delivery_is_current(c, is_orig, invoke_id) )
        return;
    if ( pdu_type == 0 &&
         ! confirmed_request_tracking_allowed(c, is_orig, invoke_id) )
        return;
    if ( pdu_type == 1 &&
         confirmed_response_is_ambiguous(c, is_orig, invoke_id) )
        return;
    if ( pdu_type == 1 )
        {
        local read_key = int_to_count(invoke_id);
        local read_request_is_orig = ! is_orig;
        local read_direction_valid = T;
        if ( [c$uid, read_request_is_orig, read_key] !in
             pending_control_reads )
            {
            read_request_is_orig = is_orig;
            read_direction_valid = F;
            }
        local tag_read = [c$uid, read_request_is_orig, read_key] in
                pending_control_reads &&
            (pending_control_reads[
                 c$uid, read_request_is_orig, read_key]$classification ==
                 "get_tag" ||
             pending_control_reads[
                 c$uid, read_request_is_orig, read_key]$classification ==
                 "get_tag_candidate");
        if ( tag_read )
            {
            local read_pending = pending_control_reads[
                c$uid, read_request_is_orig, read_key];
            local read_context: MMSControlReadProcessingContext = [
                $parser_sequence=mms_parser_sequence(c, is_orig),
                $policy_generation=mms_policy_generation(c),
                $provenance=mms_provenance(c, is_orig),
                $request_is_orig=read_request_is_orig,
                $direction_valid=read_direction_valid,
                $scope=read_pending$scope, $domain=read_pending$domain,
                $name=read_pending$name,
                $variable_count=read_pending$variable_count,
                $classification=read_pending$classification,
                $named_type=read_pending$named_type
            ];
            if ( read_direction_valid )
                delete pending_control_reads[
                    c$uid, read_request_is_orig, read_key];
            schedule 0secs {
                ICCP::mms_control_read_response_deferred_v2(
                    c, is_orig, invoke_id, result_count, failure_count,
                    first_result_choice, first_result_raw,
                    first_integer_value, read_context)
            };
            }
        else
            finish_control_read_response(
                c, is_orig, invoke_id, result_count, failure_count,
                first_result_choice, first_result_raw,
                first_integer_value);
        }
    local key = int_to_count(invoke_id);
    if ( pdu_type == 0 )
        {
        begin_transfer_support_read_request(
            c, is_orig, invoke_id, object_scope, object_domain,
            object_name);
        return;
        }
    if ( pdu_type != 1 ) return;
    local request_is_orig = ! is_orig;
    if ( [c$uid, request_is_orig, key] !in pending_transfer_support )
        {
        # A same-direction response is observable but cannot consume the
        # request; its peer may still return the valid response later.
        request_is_orig = is_orig;
        if ( [c$uid, request_is_orig, key] !in pending_transfer_support )
            return;
        local mismatch_prior = pending_transfer_support[
            c$uid, request_is_orig, key];
        local mismatch: TransferInfo = [
            $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
            $action=transfer_support_action(mismatch_prior$name),
            $outcome="direction_mismatch", $invoke_id=invoke_id,
            $list_scope=transfer_scope_name(mismatch_prior$scope),
            $list_domain=mismatch_prior$domain,
            $list_name=mismatch_prior$name,
            $result_count=result_count, $failure_count=failure_count
        ];
        write_transfer_record(c, is_orig, mismatch);
        return;
        }
    local prior = pending_transfer_support[c$uid, request_is_orig, key];
    delete pending_transfer_support[c$uid, request_is_orig, key];

    local decoded = result_count == 1 && failure_count == 0;
    local is_timestamp = prior$name == "Transfer_Set_Time_Stamp";
    local is_event_code = prior$name == "Event_Code_Detected";
    if ( is_timestamp )
        decoded = decoded && first_result_choice == 5 &&
            |first_result_raw| == 4 && first_integer_value >= 0;
    else if ( is_event_code )
        decoded = decoded && first_result_choice == 5 &&
            |first_result_raw| >= 1 && |first_result_raw| <= 2 &&
            first_integer_value >= -32768 && first_integer_value <= 32767;
    else
        decoded = decoded && first_result_choice == 2 &&
            component_count == 3 && first_component_choice == 6 &&
            second_component_choice == 10 && third_component_choice == 10 &&
            first_integer_value == 1 &&
            |second_component_raw| >= 1 && |second_component_raw| <= 32 &&
            |third_component_raw| >= 1 && |third_component_raw| <= 32 &&
            valid_tase2_visible_identifier(second_component_raw) &&
            valid_tase2_visible_identifier(third_component_raw) &&
            second_component_raw == prior$domain;

    local rec: TransferInfo = [
        $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
        $action=transfer_support_action(prior$name),
        $outcome=decoded ? "decoded" : "invalid_value",
        $invoke_id=invoke_id, $list_scope=transfer_scope_name(prior$scope),
        $list_domain=prior$domain, $list_name=prior$name,
        $result_count=result_count, $failure_count=failure_count
    ];
    if ( decoded && is_timestamp )
        rec$timestamp_value = first_integer_value;
    else if ( decoded && is_event_code )
        rec$event_code_detected = first_integer_value;
    else if ( decoded )
        {
        rec$first_variable_scope = "icc";
        rec$first_variable_domain = second_component_raw;
        rec$first_variable_name = third_component_raw;
        }
    else if ( first_result_raw != "" )
        {
        rec$result_raw = bounded_information_report_result_raw(
            first_result_raw);
        rec$result_raw_truncated =
            |first_result_raw| > max_logged_result_raw_bytes;
        }
    write_transfer_record(c, is_orig, rec);
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
    provenance: count)
    {
    if ( association_kind(c) != "tase2" || pdu_type != 0 ||
         invoke_id < 0 || service_tag != 5 || object_name == "" ||
         [c$uid, ! is_orig, object_scope, object_domain, object_name] !in
            known_variable_types ||
         known_variable_types[
            c$uid, ! is_orig,
            object_scope, object_domain, object_name] !=
            "DSTransferSet" )
        return;
    if ( ! confirmed_request_tracking_allowed(c, is_orig, invoke_id) )
        return;

    local deviation = F;
    local reasons = "";
    local parameters: DSTransferParameters = [
        $conformance="parameters_conformant"
    ];

    if ( access_choice != 0 )
        {
        deviation = T;
        reasons = append_feature(reasons, "invalid_access_selection");
        }
    # IEC 60870-6-503 maps Transfer Set named variables to the MMS Domain for
    # the client control centre.  The transfer variable itself is therefore
    # Domain-specific even though its embedded DataSetName may be either VMD-
    # or Domain-specific.
    if ( object_scope != 1 )
        {
        deviation = T;
        reasons = append_feature(reasons, "invalid_transfer_variable_scope");
        }
    if ( object_scope == 1 &&
         ! valid_tase2_identifier(object_domain) )
        {
        deviation = T;
        reasons = append_feature(reasons, "invalid_transfer_variable_domain");
        }
    if ( ! valid_tase2_identifier(object_name) )
        {
        deviation = T;
        reasons = append_feature(reasons, "invalid_transfer_variable_name");
        }
    if ( variable_count != 1 )
        {
        deviation = T;
        reasons = append_feature(reasons, "invalid_variable_count");
        }
    if ( data_count != 1 )
        {
        deviation = T;
        reasons = append_feature(reasons, "invalid_data_count");
        }
    if ( first_data_choice != 2 )
        {
        deviation = T;
        reasons = append_feature(reasons, "invalid_value_choice");
        }

    local component_evidence = |component_choices| == 13 &&
        |component_raws| == 13 && |component_integer_values| == 13;
    if ( ! component_evidence )
        {
        deviation = T;
        reasons = append_feature(reasons, "invalid_component_count");
        }

    if ( component_evidence )
        {
        local data_set_evidence = component_choices[0] == 2 &&
            |data_set_component_choices| == 3 &&
            |data_set_component_raws| == 3 &&
            |data_set_component_integer_values| == 3;
        if ( ! data_set_evidence )
            {
            deviation = T;
            reasons = append_feature(
                reasons, "invalid_data_set_name_structure");
            }
        else
            {
            if ( data_set_component_choices[0] == 6 &&
                 |data_set_component_raws[0]| == 1 &&
                 (data_set_component_integer_values[0] == 0 ||
                  data_set_component_integer_values[0] == 1) )
                parameters$data_set_scope = int_to_count(
                    data_set_component_integer_values[0]);
            else
                {
                deviation = T;
                reasons = append_feature(
                    reasons, "invalid_data_set_scope");
                }

            if ( data_set_component_choices[1] == 10 &&
                 |data_set_component_raws[1]| >= 1 &&
                 |data_set_component_raws[1]| <= 32 &&
                 valid_tase2_visible_identifier(
                     data_set_component_raws[1]) )
                parameters$data_set_domain = data_set_component_raws[1];
            else
                {
                deviation = T;
                reasons = append_feature(
                    reasons, "invalid_data_set_domain");
                }

            if ( data_set_component_choices[2] == 10 &&
                 |data_set_component_raws[2]| >= 1 &&
                 |data_set_component_raws[2]| <= 32 &&
                 valid_tase2_visible_identifier(
                     data_set_component_raws[2]) )
                parameters$data_set_name = data_set_component_raws[2];
            else
                {
                deviation = T;
                reasons = append_feature(reasons, "invalid_data_set_name");
                }

            }

        if ( component_choices[1] == 5 &&
             |component_raws[1]| >= 1 && |component_raws[1]| <= 4 &&
             component_integer_values[1] >= 0 &&
             component_integer_values[1] <= 2147483647 )
            parameters$start_time = component_integer_values[1];
        else
            {
            deviation = T;
            reasons = append_feature(reasons, "invalid_start_time");
            }
        if ( component_choices[2] == 5 &&
             |component_raws[2]| >= 1 && |component_raws[2]| <= 4 &&
             component_integer_values[2] >= 0 &&
             component_integer_values[2] <= 2147483647 )
            parameters$transfer_interval = component_integer_values[2];
        else
            {
            deviation = T;
            reasons = append_feature(reasons, "invalid_transfer_interval");
            }
        if ( component_choices[3] == 5 &&
             |component_raws[3]| >= 1 && |component_raws[3]| <= 4 &&
             component_integer_values[3] >= 0 &&
             component_integer_values[3] <= 2147483647 )
            parameters$tle = component_integer_values[3];
        else
            {
            deviation = T;
            reasons = append_feature(reasons, "invalid_tle");
            }
        if ( component_choices[4] == 5 &&
             |component_raws[4]| >= 1 && |component_raws[4]| <= 4 &&
             component_integer_values[4] >= 0 &&
             component_integer_values[4] <= 2147483647 )
            parameters$buffer_time = component_integer_values[4];
        else
            {
            deviation = T;
            reasons = append_feature(reasons, "invalid_buffer_time");
            }
        if ( component_choices[5] == 5 &&
             |component_raws[5]| >= 1 && |component_raws[5]| <= 4 &&
             component_integer_values[5] >= 0 &&
             component_integer_values[5] <= 2147483647 )
            parameters$integrity_check = component_integer_values[5];
        else
            {
            deviation = T;
            reasons = append_feature(reasons, "invalid_integrity_check");
            }

        local conditions_valid = T;
        if ( component_choices[6] != 4 )
            {
            conditions_valid = F;
            reasons = append_feature(
                reasons, "invalid_ds_conditions_choice");
            }
        else if ( |component_raws[6]| != 2 )
            {
            conditions_valid = F;
            reasons = append_feature(
                reasons, "invalid_ds_conditions_width");
            }
        else if ( bytestring_to_count(
                      sub_bytes(component_raws[6], 1, 1)) != 3 )
            {
            conditions_valid = F;
            reasons = append_feature(
                reasons, "invalid_ds_conditions_unused_bits");
            }
        else if ( (bytestring_to_count(
                       sub_bytes(component_raws[6], 2, 1)) & 0x07) != 0 )
            {
            conditions_valid = F;
            reasons = append_feature(
                reasons, "invalid_ds_conditions_reserved_bits");
            }
        local condition_flags: count = 0;
        if ( conditions_valid )
            {
            condition_flags = bytestring_to_count(
                sub_bytes(component_raws[6], 2, 1));
            parameters$conditions = decode_ds_conditions(condition_flags);
            parameters$condition_mask = condition_flags / 8;
            }
        else
            {
            deviation = T;
            }

        if ( component_choices[7] == 3 && |component_raws[7]| == 1 )
            parameters$block_data =
                bytestring_to_count(component_raws[7]) != 0;
        else
            {
            deviation = T;
            reasons = append_feature(reasons, "invalid_block_data");
            }
        if ( component_choices[8] == 3 && |component_raws[8]| == 1 )
            parameters$critical = bytestring_to_count(component_raws[8]) != 0;
        else
            {
            deviation = T;
            reasons = append_feature(reasons, "invalid_critical");
            }
        if ( component_choices[9] == 3 && |component_raws[9]| == 1 )
            parameters$report_by_exception =
                bytestring_to_count(component_raws[9]) != 0;
        else
            {
            deviation = T;
            reasons = append_feature(reasons, "invalid_rbe");
            }
        if ( component_choices[10] == 3 && |component_raws[10]| == 1 )
            parameters$all_changes_reported =
                bytestring_to_count(component_raws[10]) != 0;
        else
            {
            deviation = T;
            reasons = append_feature(reasons, "invalid_all_changes_reported");
            }
        if ( component_choices[11] == 3 && |component_raws[11]| == 1 )
            parameters$enabled = bytestring_to_count(component_raws[11]) != 0;
        else
            {
            deviation = T;
            reasons = append_feature(reasons, "invalid_status");
            }

        local event_code_valid = component_choices[12] == 5 &&
            |component_raws[12]| >= 1 && |component_raws[12]| <= 2 &&
            component_integer_values[12] >= -32768 &&
            component_integer_values[12] <= 32767;
        if ( ! event_code_valid )
            {
            deviation = T;
            reasons = append_feature(reasons, "invalid_event_code");
            }
        else if ( conditions_valid && (condition_flags & 0x08) != 0 )
            parameters$event_code_requested = component_integer_values[12];
        }

    if ( deviation )
        parameters$conformance = "standards_deviation";
    if ( reasons != "" ) parameters$conformance_reasons = reasons;

    local enabled = parameters?$enabled && parameters$enabled;
    local action = enabled ? "start" : "stop";
    if ( deviation )
        {
        local invalid: TransferInfo = [
            $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
            $action="transfer_candidate", $outcome="invalid_parameters",
            $invoke_id=invoke_id,
            $list_scope=transfer_scope_name(object_scope),
            $list_name=object_name, $named_type="DSTransferSet",
            $variable_count=variable_count
        ];
        if ( object_domain != "" ) invalid$list_domain = object_domain;
        invalid = add_ds_transfer_parameters(invalid, parameters);
        write_transfer_record(c, is_orig, invalid);
        event ICCP::dst_transfer_set_anomaly(
            c, is_orig, association_kind(c), endpoint_role(c, is_orig),
            invoke_id, transfer_scope_name(object_scope), object_domain,
            object_name, "transfer_candidate", parameters$conformance,
            reasons);
        return;
        }

    local key = int_to_count(invoke_id);
    local reused = [c$uid, is_orig, key] in pending_transfer_controls;
    local state_full = ! reused &&
        pending_transfer_control_count(c$uid) >= max_pending_transfer_sets;
    if ( ! state_full )
        pending_transfer_controls[c$uid, is_orig, key] = [
            $action=action, $request_is_orig=is_orig,
            $scope=object_scope, $domain=object_domain, $name=object_name,
            $parameters=parameters
        ];
    else
        event ICCP::resource_limit_exceeded(
            c, is_orig, "pending_transfer_controls",
            max_pending_transfer_sets,
            pending_transfer_control_count(c$uid), invoke_id);

    local request: TransferInfo = [
        $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
        $action=action,
        $outcome=state_full ? "state_limit" :
            reused ? "invoke_reused" : "requested",
        $invoke_id=invoke_id,
        $list_scope=transfer_scope_name(object_scope),
        $list_name=object_name,
        $named_type="DSTransferSet", $variable_count=variable_count
    ];
    if ( object_domain != "" ) request$list_domain = object_domain;
    request = add_ds_transfer_parameters(request, parameters);
    write_transfer_record(c, is_orig, request);
    }

event ICCP::mms_transfer_control_message(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    service_tag: count, access_choice: count, object_scope: count,
    object_domain: string, object_name: string, variable_count: count,
    data_count: count, first_data_choice: count,
    first_data_boolean: bool, first_data_child_count: count,
    first_data_twelfth_choice: count,
    first_data_twelfth_boolean: bool,
    first_data_dst_transfer_set_shape: bool, result_count: count,
    success_count: count, failure_count: count)
    {
    if ( association_kind(c) != "tase2" || invoke_id < 0 ||
         service_tag != 5 )
        return;

    if ( pdu_type == 0 &&
         ! confirmed_request_tracking_allowed(c, is_orig, invoke_id) )
        return;
    if ( pdu_type == 1 &&
         confirmed_response_is_ambiguous(c, is_orig, invoke_id) )
        return;

    local key = int_to_count(invoke_id);
    if ( pdu_type == 0 )
        {
        local fixed_im = access_choice == 0 && object_scope == 2 &&
            object_domain == "" && object_name == "IM_Transfer_Set" &&
            variable_count == 1 && data_count == 1 &&
            first_data_choice == 3;
        if ( ! fixed_im )
            return;

        local enabled = first_data_boolean;
        local action = enabled ? "start" : "stop";
        local reused = [c$uid, is_orig, key] in pending_transfer_controls;
        local state_full = ! reused &&
            pending_transfer_control_count(c$uid) >= max_pending_transfer_sets;
        if ( ! state_full )
            pending_transfer_controls[c$uid, is_orig, key] = [
                $action=action, $request_is_orig=is_orig,
                $scope=object_scope, $domain=object_domain,
                $name=object_name
            ];
        else
            event ICCP::resource_limit_exceeded(
                c, is_orig, "pending_transfer_controls",
                max_pending_transfer_sets,
                pending_transfer_control_count(c$uid), invoke_id);
        local request: TransferInfo = [
            $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
            $action=action,
            $outcome=state_full ? "state_limit" :
                reused ? "invoke_reused" : "requested",
            $invoke_id=invoke_id,
            $list_scope=transfer_scope_name(object_scope),
            $list_name=object_name, $variable_count=variable_count
        ];
        if ( object_domain != "" ) request$list_domain = object_domain;
        write_transfer_record(c, is_orig, request);
        return;
        }

    if ( pdu_type != 1 )
        return;
    local response_request_is_orig = ! is_orig;
    local response_direction_valid = T;
    if ( [c$uid, response_request_is_orig, key] !in
         pending_transfer_controls )
        {
        response_request_is_orig = is_orig;
        response_direction_valid = F;
        }
    if ( [c$uid, response_request_is_orig, key] !in
         pending_transfer_controls ) return;

    local prior = pending_transfer_controls[
        c$uid, response_request_is_orig, key];
    if ( ! response_direction_valid )
        {
        local mismatch: TransferInfo = [
            $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
            $action=prior$action, $outcome="direction_mismatch",
            $invoke_id=invoke_id, $list_scope=transfer_scope_name(prior$scope),
            $list_name=prior$name
        ];
        if ( prior$domain != "" ) mismatch$list_domain = prior$domain;
        if ( prior?$parameters )
            {
            mismatch$named_type = "DSTransferSet";
            mismatch = add_ds_transfer_parameters(
                mismatch, prior$parameters);
            }
        write_transfer_record(c, is_orig, mismatch);
        return;
        }

    local response: TransferInfo = [
        $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
        $action=prior$action,
        $outcome=(result_count == 1 && success_count == 1 &&
                  failure_count == 0) ? "confirmed" : "partial_or_failed",
        $invoke_id=invoke_id, $list_scope=transfer_scope_name(prior$scope),
        $list_name=prior$name, $result_count=result_count,
        $failure_count=failure_count
    ];
    if ( prior$domain != "" ) response$list_domain = prior$domain;
    if ( prior?$parameters )
        {
        response$named_type = "DSTransferSet";
        response = add_ds_transfer_parameters(response, prior$parameters);
        }
    if ( response$outcome == "confirmed" && prior?$parameters )
        {
        if ( prior$action == "start" )
            {
            local existing = [c$uid, prior$request_is_orig, prior$scope,
                              prior$domain, prior$name] in active_ds_transfers;
            local already_active = F;
            if ( existing )
                already_active = active_ds_transfers[
                    c$uid, prior$request_is_orig, prior$scope, prior$domain,
                    prior$name]$state == "active";
            if ( already_active )
                {
                response$outcome = "confirmed_duplicate_start";
                response$conformance = "standards_deviation";
                local duplicate_reasons = "";
                if ( response?$conformance_reasons )
                    duplicate_reasons = response$conformance_reasons;
                response$conformance_reasons = append_feature(
                    duplicate_reasons, "duplicate_start_confirmed");
                event ICCP::dst_transfer_set_anomaly(
                    c, is_orig, association_kind(c), endpoint_role(c, is_orig),
                    invoke_id, transfer_scope_name(prior$scope), prior$domain,
                    prior$name, "start", "standards_deviation",
                    "duplicate_start_confirmed");
                }
            else if ( existing || active_ds_transfer_count(c$uid) <
                      max_active_transfer_sets )
                active_ds_transfers[
                    c$uid, prior$request_is_orig, prior$scope, prior$domain,
                    prior$name] = [
                    $request_is_orig=prior$request_is_orig,
                    $scope=prior$scope, $domain=prior$domain,
                    $name=prior$name, $parameters=prior$parameters,
                    $state="active"
                ];
            else
                {
                response$outcome = "confirmed_state_limit";
                event ICCP::resource_limit_exceeded(
                    c, is_orig, "active_ds_transfers",
                    max_active_transfer_sets,
                    active_ds_transfer_count(c$uid), invoke_id);
                }
            }
        else if ( prior$action == "stop" &&
                  [c$uid, prior$request_is_orig, prior$scope, prior$domain,
                   prior$name] in
                    active_ds_transfers )
            {
            local active = active_ds_transfers[
                c$uid, prior$request_is_orig, prior$scope, prior$domain,
                prior$name];
            if ( active$request_is_orig == prior$request_is_orig )
                {
                active$state = "stopped";
                active_ds_transfers[
                    c$uid, prior$request_is_orig, prior$scope, prior$domain,
                    prior$name] = active;
                }
            }
        }
    delete pending_transfer_controls[c$uid, response_request_is_orig, key];
    write_transfer_record(c, is_orig, response);
    }

event ICCP::mms_error_message(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    modifier_position: int, error_class: count, error_code: int,
    additional_code: int, additional_description: string)
    {
    if ( pdu_type != 2 || invoke_id < 0 ) return;
    if ( confirmed_response_is_ambiguous(c, is_orig, invoke_id) ) return;
    local key = int_to_count(invoke_id);
    local error_request_is_orig = ! is_orig;
    if ( [c$uid, error_request_is_orig, key] in pending_variable_types )
        delete pending_variable_types[c$uid, error_request_is_orig, key];
    if ( [c$uid, error_request_is_orig, key] in
         invalid_variable_type_invokes )
        delete invalid_variable_type_invokes[
            c$uid, error_request_is_orig, key];

    local set_request_is_orig = ! is_orig;
    local set_direction_valid = T;
    if ( [c$uid, set_request_is_orig, key] !in pending_transfer_sets )
        {
        set_request_is_orig = is_orig;
        set_direction_valid = F;
        }
    if ( [c$uid, set_request_is_orig, key] in pending_transfer_sets )
        {
        local set_prior = pending_transfer_sets[
            c$uid, set_request_is_orig, key];
        local set_error: TransferInfo = [
            $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
            $action=set_prior$action,
            $outcome=set_direction_valid ? "rejected" :
                "direction_mismatch", $invoke_id=invoke_id
        ];
        if ( set_prior$name != "" )
            {
            set_error$list_scope = transfer_scope_name(set_prior$scope);
            set_error$list_name = set_prior$name;
            if ( set_prior$domain != "" )
                set_error$list_domain = set_prior$domain;
            }
        if ( set_direction_valid )
            delete pending_transfer_sets[
                c$uid, set_request_is_orig, key];
        write_transfer_record(c, is_orig, set_error);
        }

    local support_request_is_orig = ! is_orig;
    local support_direction_valid = T;
    if ( [c$uid, support_request_is_orig, key] !in pending_transfer_support )
        {
        support_request_is_orig = is_orig;
        support_direction_valid = F;
        }
    if ( [c$uid, support_request_is_orig, key] in pending_transfer_support )
        {
        local support_prior = pending_transfer_support[
            c$uid, support_request_is_orig, key];
        local support_error: TransferInfo = [
            $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
            $action=transfer_support_action(support_prior$name),
            $outcome=support_direction_valid ? "rejected" :
                "direction_mismatch",
            $invoke_id=invoke_id,
            $list_scope=transfer_scope_name(support_prior$scope),
            $list_domain=support_prior$domain,
            $list_name=support_prior$name
        ];
        if ( support_direction_valid )
            delete pending_transfer_support[
                c$uid, support_request_is_orig, key];
        write_transfer_record(c, is_orig, support_error);
        }

    local control_request_is_orig = ! is_orig;
    local control_direction_valid = T;
    if ( [c$uid, control_request_is_orig, key] !in
         pending_transfer_controls )
        {
        control_request_is_orig = is_orig;
        control_direction_valid = F;
        }
    if ( [c$uid, control_request_is_orig, key] !in
         pending_transfer_controls ) return;
    local prior = pending_transfer_controls[
        c$uid, control_request_is_orig, key];
    local rejected: TransferInfo = [
        $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
        $action=prior$action,
        $outcome=control_direction_valid ? "rejected" :
            "direction_mismatch",
        $invoke_id=invoke_id, $list_scope=transfer_scope_name(prior$scope),
        $list_name=prior$name
    ];
    if ( prior$domain != "" ) rejected$list_domain = prior$domain;
    if ( prior?$parameters )
        {
        rejected$named_type = "DSTransferSet";
        rejected = add_ds_transfer_parameters(rejected, prior$parameters);
        }
    if ( control_direction_valid )
        delete pending_transfer_controls[c$uid, control_request_is_orig, key];
    write_transfer_record(c, is_orig, rejected);
    }

function process_transfer_set_message(
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
    member_alternate_access_counts: vector of count,
    exact_member_access_evidence: bool)
    {
    if ( association_kind(c) != "tase2" )
        return;

    if ( pdu_type == 0 && invoke_id >= 0 &&
         ! confirmed_request_tracking_allowed(c, is_orig, invoke_id) )
        return;
    if ( pdu_type == 1 && invoke_id >= 0 &&
         confirmed_response_is_ambiguous(c, is_orig, invoke_id) )
        return;

    if ( pdu_type == 0 && invoke_id >= 0 &&
         (service_tag == 11 || service_tag == 12 || service_tag == 13) )
        {
        local action = service_tag == 11 ? "define" :
                       service_tag == 12 ? "inspect" : "delete";
        local request_pending_key = int_to_count(invoke_id);
        local invoke_reused = [c$uid, is_orig, request_pending_key] in
                              pending_transfer_sets;
        local prior_known = list_name != "" &&
            [c$uid, ! is_orig, list_scope, list_domain, list_name] in
                known_transfer_sets;
        local pending: PendingTransferSet = [
            $action=action, $scope=list_scope, $domain=list_domain,
            $name=list_name, $variable_count=variable_count,
            $first_variable_scope=first_variable_scope,
            $first_variable_domain=first_variable_domain,
            $first_variable_name=first_variable_name,
            $prior_known=prior_known,
            $delete_scope=delete_scope, $name_count=name_count,
            $profile_valid=F,
            $member_scopes=member_scopes, $member_domains=member_domains,
            $member_names=member_names,
            $member_alternate_access_counts=
                member_alternate_access_counts,
            $exact_member_access_evidence=exact_member_access_evidence,
            $profile_reasons=""
        ];
        local identifiers_valid = valid_pending_transfer_identifiers(pending);
        pending$profile_reasons = transfer_set_profile_reasons(pending);
        pending$profile_valid = identifiers_valid &&
            pending$profile_reasons == "";
        local state_full = identifiers_valid && ! invoke_reused &&
            pending_transfer_count(c$uid) >= max_pending_transfer_sets;
        if ( identifiers_valid && ! state_full )
            pending_transfer_sets[
                c$uid, is_orig, request_pending_key] = pending;
        else if ( state_full )
            event ICCP::resource_limit_exceeded(
                c, is_orig, "pending_transfer_sets",
                max_pending_transfer_sets, pending_transfer_count(c$uid),
                invoke_id);

        local request: TransferInfo = [
            $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
            $action=action,
            $outcome=! identifiers_valid ? "invalid_identifier" :
                state_full ? "state_limit" :
                invoke_reused ? "invoke_reused" : "requested",
            $invoke_id=invoke_id
        ];
        if ( list_name != "" )
            {
            request$list_scope = transfer_scope_name(list_scope);
            request$list_name = list_name;
            if ( list_domain != "" ) request$list_domain = list_domain;
            request$known_list = prior_known;
            }
        if ( service_tag == 11 ) request$variable_count = variable_count;
        if ( service_tag == 13 ) request$delete_scope = delete_scope;
        if ( identifiers_valid && action != "inspect" &&
             ! pending$profile_valid )
            {
            request$conformance = "standards_deviation";
            request$conformance_reasons = pending$profile_reasons;
            }
        write_transfer_record(c, is_orig, request);
        return;
        }

    if ( pdu_type == 1 && invoke_id >= 0 &&
         (service_tag == 11 || service_tag == 12 || service_tag == 13) )
        {
        local response_pending_key = int_to_count(invoke_id);
        local response_request_is_orig = ! is_orig;
        local response_direction_valid = T;
        if ( [c$uid, response_request_is_orig, response_pending_key] !in
             pending_transfer_sets )
            {
            response_request_is_orig = is_orig;
            response_direction_valid = F;
            }
        if ( [c$uid, response_request_is_orig, response_pending_key] !in
             pending_transfer_sets )
            {
            local unexpected: TransferInfo = [
                $ts=network_time(), $uid=c$uid, $id=c$id,
                $is_orig=is_orig,
                $action=service_tag == 11 ? "define" :
                    service_tag == 12 ? "inspect" : "delete",
                $outcome="unexpected_response", $invoke_id=invoke_id
            ];
            write_transfer_record(c, is_orig, unexpected);
            return;
            }
        local prior = pending_transfer_sets[
            c$uid, response_request_is_orig, response_pending_key];
        if ( ! response_direction_valid )
            {
            local wrong_direction: TransferInfo = [
                $ts=network_time(), $uid=c$uid, $id=c$id,
                $is_orig=is_orig, $action=prior$action,
                $outcome="direction_mismatch", $invoke_id=invoke_id
            ];
            write_transfer_record(c, is_orig, wrong_direction);
            return;
            }
        local response_action = service_tag == 11 ? "define" :
                                service_tag == 12 ? "inspect" : "delete";
        if ( prior$action != response_action )
            {
            # Define/Get/DeleteNamedVariableList share one pending family, but
            # a response from a different service must never mutate the prior
            # list lifecycle.  Leave the request available for a valid reply.
            local wrong_service: TransferInfo = [
                $ts=network_time(), $uid=c$uid, $id=c$id,
                $is_orig=is_orig, $action=prior$action,
                $outcome="service_mismatch", $invoke_id=invoke_id
            ];
            if ( prior$name != "" )
                {
                wrong_service$list_scope = transfer_scope_name(prior$scope);
                wrong_service$list_name = prior$name;
                if ( prior$domain != "" )
                    wrong_service$list_domain = prior$domain;
                }
            write_transfer_record(c, is_orig, wrong_service);
            return;
            }
        local response: TransferInfo = [
            $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
            $action=prior$action, $outcome="confirmed", $invoke_id=invoke_id
        ];
        if ( prior$name != "" )
            {
            response$list_scope = transfer_scope_name(prior$scope);
            response$list_name = prior$name;
            if ( prior$domain != "" ) response$list_domain = prior$domain;
            }
        if ( prior$action != "inspect" && ! prior$profile_valid )
            {
            response$conformance = "standards_deviation";
            response$conformance_reasons = prior$profile_reasons;
            }
        if ( service_tag == 11 )
            {
            # Re-check at response time as well as using the request snapshot:
            # two outstanding definitions for one previously unknown name can
            # confirm out of order.
            local existing_definition = prior$prior_known ||
                (prior$name != "" &&
                 [c$uid, is_orig, prior$scope, prior$domain, prior$name] in
                     known_transfer_sets);
            response$variable_count = prior$variable_count;
            if ( prior$first_variable_name != "" )
                {
                response$first_variable_scope =
                    transfer_scope_name(prior$first_variable_scope);
                response$first_variable_name = prior$first_variable_name;
                if ( prior$first_variable_domain != "" )
                    response$first_variable_domain =
                        prior$first_variable_domain;
                }
            # A successful duplicate definition is a peer deviation, not a
            # valid update operation.  Preserve the membership learned from
            # the original confirmed definition.
            if ( prior$profile_valid && ! existing_definition &&
                 prior$name != "" &&
                 known_transfer_count(c$uid) < max_known_transfer_sets )
                known_transfer_sets[c$uid, is_orig, prior$scope,
                                    prior$domain, prior$name] = [
                    $scopes=prior$member_scopes,
                    $domains=prior$member_domains,
                    $names=prior$member_names
                ];
            if ( existing_definition )
                {
                response$conformance = "standards_deviation";
                response$conformance_reasons = add_transfer_profile_reason(
                    response?$conformance_reasons ?
                        response$conformance_reasons : "",
                    "define_existing_name_confirmed");
                }
            response$known_list = prior$name != "" &&
                [c$uid, is_orig, prior$scope, prior$domain, prior$name] in
                known_transfer_sets;
            response$outcome = existing_definition ?
                "confirmed_existing_name" :
                ! prior$profile_valid ? "confirmed_profile_deviation" :
                    response$known_list ? "confirmed" : "state_limit";
            if ( prior$profile_valid && ! existing_definition &&
                 prior$name != "" &&
                 ! response$known_list )
                event ICCP::resource_limit_exceeded(
                    c, is_orig, "known_transfer_sets",
                    max_known_transfer_sets, known_transfer_count(c$uid),
                    invoke_id);
            }
        else if ( service_tag == 12 )
            {
            response$variable_count = variable_count;
            response$deletable = deletable;
            response$known_list = prior$name != "" &&
                [c$uid, is_orig, prior$scope, prior$domain, prior$name] in
                known_transfer_sets;
            }
        else
            {
            response$number_matched = number_matched;
            response$number_deleted = number_deleted;
            if ( ! prior$profile_valid )
                response$outcome = "confirmed_profile_deviation";
            else
                {
                # The TASE.2 Delete Data Set profile requires a positive
                # response only after every specifically named Data Set was
                # found and deleted.  Keep the wire-level aggregate counts
                # observable, but do not treat a partial positive result as a
                # conforming confirmation.
                local delete_count_reasons = "";
                if ( number_matched != prior$name_count )
                    delete_count_reasons = add_transfer_profile_reason(
                        delete_count_reasons,
                        "matched_count_differs_requested_names");
                if ( number_deleted != prior$name_count )
                    delete_count_reasons = add_transfer_profile_reason(
                        delete_count_reasons,
                        "deleted_count_differs_requested_names");
                if ( delete_count_reasons != "" )
                    {
                    response$outcome = "confirmed_count_deviation";
                    response$conformance = "standards_deviation";
                    response$conformance_reasons = delete_count_reasons;
                    }

                if ( number_deleted > 0 )
                    {
                    # DeleteNamedVariableList returns only aggregate counts. A
                    # positive partial result cannot identify which requested
                    # names were deleted, so invalidate every requested
                    # identity.
                    local delete_index: count = 0;
                    while ( delete_index < |prior$member_names| )
                        {
                        delete known_transfer_sets[
                            c$uid, is_orig,
                            prior$member_scopes[delete_index],
                            prior$member_domains[delete_index],
                            prior$member_names[delete_index]];
                        ++delete_index;
                        }
                    }
                }
            response$known_list = prior$name != "" &&
                [c$uid, is_orig, prior$scope, prior$domain, prior$name] in
                    known_transfer_sets;
            }
        delete pending_transfer_sets[
            c$uid, response_request_is_orig, response_pending_key];
        write_transfer_record(c, is_orig, response);
        return;
        }

    if ( pdu_type == 3 && unconfirmed_service_tag == 0 &&
         access_choice == 1 && list_name != "" )
        {
        local report: TransferInfo = [
            $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
            $action="report", $outcome=failure_count == 0 ?
                "delivered" : "partial_or_failed",
            $list_scope=transfer_scope_name(list_scope),
            $list_name=list_name, $result_count=result_count,
            $failure_count=failure_count,
            $known_list=[c$uid, is_orig,
                         list_scope, list_domain, list_name] in
                known_transfer_sets
        ];
        if ( list_domain != "" ) report$list_domain = list_domain;

        if ( [c$uid, is_orig, list_scope, list_domain, list_name] in
             known_transfer_sets )
            {
            local membership = known_transfer_sets[
                c$uid, is_orig, list_scope, list_domain, list_name];
            report$pairing_status = |membership$names| == |result_choices| ?
                "complete" : "count_mismatch";
            local pair_count = |membership$names| < |result_choices| ?
                |membership$names| : |result_choices|;
            local row_limit = information_report_result_limit();
            if ( pair_count > row_limit )
                pair_count = row_limit;
            report$logged_result_count = pair_count;
            report$omitted_result_count = result_count > pair_count ?
                result_count - pair_count : 0;
            write_transfer_record(c, is_orig, report);
            local index: count = 0;
            while ( index < pair_count )
                {
                local paired: TransferInfo = [
                    $ts=network_time(), $uid=c$uid, $id=c$id,
                    $is_orig=is_orig, $action="report_value",
                    $outcome=result_choices[index] == 0 ? "failed" :
                        "delivered", $list_scope=transfer_scope_name(list_scope),
                    $list_name=list_name, $known_list=T,
                    $result_index=index, $result_type=result_choices[index]
                ];
                if ( list_domain != "" ) paired$list_domain = list_domain;
                if ( index < |membership$scopes| )
                    paired$first_variable_scope =
                        transfer_scope_name(membership$scopes[index]);
                if ( index < |membership$domains| &&
                     membership$domains[index] != "" )
                    paired$first_variable_domain = membership$domains[index];
                paired$first_variable_name = membership$names[index];
                if ( index < |result_errors| && result_errors[index] >= 0 )
                    paired$result_error = result_errors[index];
                if ( index < |result_raws| && result_raws[index] != "" &&
                     information_buffer_capacity(membership$names[index]) == 0 )
                    {
                    paired$result_raw = bounded_information_report_result_raw(
                        result_raws[index]);
                    paired$result_raw_truncated =
                        |result_raws[index]| > max_logged_result_raw_bytes;
                    }
                write_transfer_record(c, is_orig, paired);
                ++index;
                }
            }
        else
            {
            report$pairing_status = "untracked_list";
            write_transfer_record(c, is_orig, report);
            }
        }
    }

event ICCP::mms_transfer_set_message(
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
    result_errors: vector of int, result_raws: vector of string)
    {
    if ( (pdu_type == 0 || pdu_type == 1) &&
         (service_tag == 11 || service_tag == 12 || service_tag == 13) &&
         parser_transfer_delivery_is_current(
             c, is_orig, pdu_type, invoke_id, service_tag,
             unconfirmed_service_tag) )
        return;

    process_transfer_set_message(
        c, is_orig, pdu_type, invoke_id, service_tag,
        unconfirmed_service_tag, access_choice, list_scope, list_domain,
        list_name, variable_count, first_variable_scope,
        first_variable_domain, first_variable_name, deletable, delete_scope,
        name_count, number_matched, number_deleted, result_count,
        failure_count, member_scopes, member_domains, member_names,
        result_choices, result_errors, result_raws, vector(), F);
    }

event ICCP::mms_transfer_set_message_v3(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    service_tag: count, unconfirmed_service_tag: count,
    access_choice: count, list_scope: count, list_domain: string,
    list_name: string, variable_count: count,
    first_variable_scope: count, first_variable_domain: string,
    first_variable_name: string, deletable: bool, delete_scope: int,
    name_count: count, number_matched: int, number_deleted: int,
    result_count: count, failure_count: count,
    member_scopes: vector of count, member_domains: vector of string,
    member_names: vector of string,
    member_alternate_access_counts: vector of count,
    result_choices: vector of count, result_errors: vector of int,
    result_raws: vector of string, provenance: count) &priority=5
    {
    set_mms_provenance(c, is_orig, provenance);
    mark_parser_transfer_delivery(
        c, is_orig, pdu_type, invoke_id, service_tag,
        unconfirmed_service_tag);
    process_transfer_set_message(
        c, is_orig, pdu_type, invoke_id, service_tag,
        unconfirmed_service_tag, access_choice, list_scope, list_domain,
        list_name, variable_count, first_variable_scope,
        first_variable_domain, first_variable_name, deletable, delete_scope,
        name_count, number_matched, number_deleted, result_count,
        failure_count, member_scopes, member_domains, member_names,
        result_choices, result_errors, result_raws,
        member_alternate_access_counts, T);
    }

function clear_transfer_processing_state(uid_to_clear: string)
    {
    local pending_keys: vector of count;
    local pending_directions: vector of bool;
    for ( [uid, request_is_orig, invoke] in pending_transfer_sets )
        if ( uid == uid_to_clear )
            {
            pending_keys[|pending_keys|] = invoke;
            pending_directions[|pending_directions|] = request_is_orig;
            }
    for ( index in pending_keys )
        delete pending_transfer_sets[
            uid_to_clear, pending_directions[index], pending_keys[index]];

    local control_keys: vector of count;
    local control_directions: vector of bool;
    for ( [control_uid, control_is_orig, control_invoke] in
          pending_transfer_controls )
        if ( control_uid == uid_to_clear )
            {
            control_keys[|control_keys|] = control_invoke;
            control_directions[|control_directions|] = control_is_orig;
            }
    for ( control_index in control_keys )
        delete pending_transfer_controls[
            uid_to_clear, control_directions[control_index],
            control_keys[control_index]];

    local active_keys: vector of string;
    local active_directions: vector of bool;
    local active_scopes: vector of count;
    local active_domains: vector of string;
    for ( [active_uid, active_is_orig, active_scope, active_domain,
           active_name] in active_ds_transfers )
        if ( active_uid == uid_to_clear )
            {
            active_keys[|active_keys|] = active_name;
            active_directions[|active_directions|] = active_is_orig;
            active_scopes[|active_scopes|] = active_scope;
            active_domains[|active_domains|] = active_domain;
            }
    for ( active_index in active_keys )
        delete active_ds_transfers[
            uid_to_clear, active_directions[active_index],
            active_scopes[active_index], active_domains[active_index],
            active_keys[active_index]];

    local support_keys: vector of count;
    local support_directions: vector of bool;
    for ( [support_uid, support_is_orig, support_invoke] in
          pending_transfer_support )
        if ( support_uid == uid_to_clear )
            {
            support_keys[|support_keys|] = support_invoke;
            support_directions[|support_directions|] = support_is_orig;
            }
    for ( support_index in support_keys )
        delete pending_transfer_support[
            uid_to_clear, support_directions[support_index],
            support_keys[support_index]];

    local type_pending_keys: vector of count;
    local type_pending_directions: vector of bool;
    for ( [type_uid, type_is_orig, type_invoke] in pending_variable_types )
        if ( type_uid == uid_to_clear )
            {
            type_pending_keys[|type_pending_keys|] = type_invoke;
            type_pending_directions[|type_pending_directions|] = type_is_orig;
            }
    for ( type_pending_index in type_pending_keys )
        delete pending_variable_types[
            uid_to_clear, type_pending_directions[type_pending_index],
            type_pending_keys[type_pending_index]];

    local invalid_type_keys: vector of count;
    local invalid_type_directions: vector of bool;
    for ( [invalid_type_uid, invalid_type_is_orig, invalid_type_invoke] in
          invalid_variable_type_invokes )
        if ( invalid_type_uid == uid_to_clear )
            {
            invalid_type_keys[|invalid_type_keys|] = invalid_type_invoke;
            invalid_type_directions[|invalid_type_directions|] =
                invalid_type_is_orig;
            }
    for ( invalid_type_index in invalid_type_keys )
        delete invalid_variable_type_invokes[
            uid_to_clear, invalid_type_directions[invalid_type_index],
            invalid_type_keys[invalid_type_index]];

    local type_known_keys: vector of KnownVariableTypeKey;
    for ( [type_known_uid, type_server_is_orig, type_scope, type_domain,
           known_type_name] in known_variable_types )
        if ( type_known_uid == uid_to_clear )
            type_known_keys[|type_known_keys|] = [
                $server_is_orig=type_server_is_orig,
                $scope=type_scope, $domain=type_domain,
                $name=known_type_name
            ];
    for ( type_known_index in type_known_keys )
        {
        local type_key = type_known_keys[type_known_index];
        delete known_variable_types[
            uid_to_clear, type_key$server_is_orig, type_key$scope,
            type_key$domain, type_key$name];
        }

    local known_keys: vector of KnownTransferKey;
    for ( [uid, server_is_orig, scope, domain, name] in
          known_transfer_sets )
        if ( uid == uid_to_clear )
            known_keys[|known_keys|] = [
                $server_is_orig=server_is_orig,
                $scope=scope, $domain=domain, $name=name
            ];
    for ( known_index in known_keys )
        {
        local known_key = known_keys[known_index];
        delete known_transfer_sets[
            uid_to_clear, known_key$server_is_orig, known_key$scope,
            known_key$domain, known_key$name];
        }
    }

event connection_state_remove(c: connection)
    {
    clear_transfer_processing_state(c$uid);
    }

function bounded_detail(value: string): string
    {
    if ( |value| <= 256 )
        return value;

    return sub_bytes(value, 0, 256);
    }

global supported_features_value_is_valid: function(raw: string): bool;

function clear_failed_mms_pdu_evidence(c: connection, is_orig: bool)
    {
    # The unconsumed %init marker identifies the current incomplete PDU and its
    # sequence. Evidence from completed earlier PDUs uses older sequence keys.
    if ( [c$uid, is_orig] !in pending_mms_parser_markers )
        return;

    local sequence = mms_parser_sequence(c, is_orig);
    local identify_pdus: vector of count;
    local identify_invokes: vector of count;
    for ( [uid, direction, entry_sequence, pdu_type, invoke] in
          identify_evidence )
        if ( uid == c$uid && direction == is_orig &&
             entry_sequence == sequence )
            {
            identify_pdus[|identify_pdus|] = pdu_type;
            identify_invokes[|identify_invokes|] = invoke;
            }
    for ( index in identify_pdus )
        delete identify_evidence[
            c$uid, is_orig, sequence, identify_pdus[index],
            identify_invokes[index]];

    delete information_report_results_evidence[c$uid, is_orig, sequence];
    delete point_value_shape_evidence[c$uid, is_orig, sequence];
    delete control_value_shape_evidence[c$uid, is_orig, sequence];
    delete control_value_shape_invokes[c$uid, is_orig, sequence];

    local read_invokes: vector of count;
    for ( [read_uid, read_direction, read_sequence, read_invoke] in
          control_read_value_shape_evidence )
        if ( read_uid == c$uid && read_direction == is_orig &&
             read_sequence == sequence )
            read_invokes[|read_invokes|] = read_invoke;
    for ( read_index in read_invokes )
        delete control_read_value_shape_evidence[
            c$uid, is_orig, sequence, read_invokes[read_index]];
    }

event ICCP::parser_error(c: connection, reason: string)
    {
    # A directionless parser failure cannot identify the failed PDU's evidence
    # direction, but each unconsumed parser marker identifies an incomplete PDU
    # and its exact sequence. Preserve completed-PDU evidence whose callbacks
    # may still be queued while removing evidence owned by incomplete PDUs.
    clear_failed_mms_pdu_evidence(c, T);
    clear_failed_mms_pdu_evidence(c, F);
    delete processing_acse_lifecycle_spdu[c$uid, T];
    delete processing_acse_lifecycle_spdu[c$uid, F];
    delete processing_session_cleanup_spdu[c$uid, T];
    delete processing_session_cleanup_spdu[c$uid, F];
    event ICCP::malformed_structure(c, bounded_detail(reason));
    }

function append_feature(current: string, feature: string): string
    {
    if ( current == "" )
        return feature;

    return fmt("%s,%s", current, feature);
    }

function decode_supported_features(raw: string): string
    {
    if ( ! supported_features_value_is_valid(raw) )
        return "";

    local unused = bytestring_to_count(sub_bytes(raw, 1, 1));
    local width = (|raw| - 1) * 8;
    local used = width - unused;

    local result = "";
    local position: count = 0;
    while ( position < used )
        {
        local octet_offset = position / 8;
        local bit_offset = position % 8;
        local octet = bytestring_to_count(
            sub_bytes(raw, 2 + octet_offset, 1));
        local mask: count = 1 << (7 - bit_offset);
        if ( (octet & mask) != 0 )
            {
            if ( position == 0 )
                result = append_feature(result, "block1");
            else if ( position == 1 )
                result = append_feature(result, "block2");
            else if ( position == 3 )
                result = append_feature(result, "block4");
            else if ( position == 4 )
                result = append_feature(result, "block5");
            else if ( position == 10 )
                result = append_feature(result, "block11");
            else if ( position == 11 )
                result = append_feature(result, "block12");
            else
                result = append_feature(
                    result, fmt("reserved-bit-%d", position));
            }
        ++position;
        }

    return result;
    }

function supported_features_value_is_valid(raw: string): bool
    {
    # SupportedFeatures defines named bits 0 through 11. BER may omit trailing
    # zero named bits, so accept one or two payload octets, but never pass an
    # arbitrary-width value to a Zeek integer conversion.
    if ( |raw| < 2 || |raw| > 3 )
        return F;

    local unused = bytestring_to_count(sub_bytes(raw, 1, 1));
    if ( unused > 7 )
        return F;

    local width = (|raw| - 1) * 8;
    if ( unused >= width || width - unused > 12 )
        return F;

    local last = bytestring_to_count(sub_bytes(raw, |raw|, 1));
    if ( unused > 0 )
        {
        local unused_mask: count = (1 << unused) - 1;
        if ( (last & unused_mask) != 0 )
            return F;
        }

    # Block 1 is mandatory for a TASE.2 server.
    return (bytestring_to_count(sub_bytes(raw, 2, 1)) & 0x80) != 0;
    }

function decode_ds_conditions(bits: count): string
    {
    local result = "";
    if ( (bits & 0x80) != 0 )
        result = append_feature(result, "interval_timeout");
    if ( (bits & 0x40) != 0 )
        result = append_feature(result, "integrity_timeout");
    if ( (bits & 0x20) != 0 )
        result = append_feature(result, "object_change");
    if ( (bits & 0x10) != 0 )
        result = append_feature(result, "operator_request");
    if ( (bits & 0x08) != 0 )
        result = append_feature(result, "other_external_event");
    return result;
    }

function data_flags_validity(flags: count): string
    {
    switch ( (flags & 0x30) / 16 )
        {
        case 0: return "valid";
        case 1: return "held";
        case 2: return "suspect";
        default: return "invalid";
        }
    }

function data_flags_source(flags: count): string
    {
    switch ( (flags & 0x0c) / 4 )
        {
        case 0: return "telemetered";
        case 1: return "calculated";
        case 2: return "entered";
        default: return "estimated";
        }
    }

function object_domain_kind(c: connection, server_is_orig: bool,
                            scope: count, domain: string): string
    {
    if ( scope == 0 )
        return "vcc";

    if ( scope == 2 )
        return "aa";

    if ( scope == 1 &&
         is_bilateral_domain_for_server(c, server_is_orig, domain) )
        return "bilateral";

    if ( scope == 1 )
        return "icc";

    return "unknown";
    }

function object_name_model(c: connection, server_is_orig: bool,
                           scope: count, domain: string, name: string,
                           category: count): string
    {
    # IEC fixes the Information Message buffer name even though its decimal
    # capacity suffix makes it impractical to enumerate in objectCategory().
    # It is standardized only at the permitted VMD/Domain scopes and only
    # when the suffix is canonical, positive, and within the supported cap.
    if ( (scope == 0 || scope == 1) &&
         information_buffer_capacity(name) > 0 &&
         valid_tase2_object_identifier(scope, domain, name) )
        return "standardized";

    if ( scope == 1 && name == "Event_Code_Detected" &&
         valid_tase2_object_identifier(scope, domain, name) )
        return "standardized";
    if ( category > 0 &&
         valid_tase2_object_identifier(scope, domain, name) )
        return "standardized";

    # Data Value and Transfer Set ObjectNames are selected by the bilateral or
    # site agreement rather than fixed by IEC.  A complete, direction-correct
    # GVA exchange can nevertheless establish that exact endpoint-owned object
    # as one of the configured TASE.2 types.  Preserve that stronger evidence
    # for VMD objects and for Domain objects whose Domain was not independently
    # learned from Bilateral_Table_ID; otherwise later accesses to an already
    # verified object are falsely reported as private/unknown.
    if ( valid_tase2_object_identifier(scope, domain, name) &&
         [c$uid, server_is_orig, scope, domain, name] in
             known_variable_types )
        return "agreement_defined";

    if ( scope == 1 && valid_tase2_identifier(name) &&
         is_bilateral_domain_for_server(c, server_is_orig, domain) )
        return "agreement_defined";

    return "private_unknown";
    }

function base_record(c: connection, is_orig: bool, layer: string,
                     message_type: string, status: string,
                     payload_length: count): Info
    {
    return [$ts=network_time(), $uid=c$uid, $id=c$id,
            $is_orig=is_orig, $layer=layer, $message_type=message_type,
            $status=status, $payload_length=payload_length,
            $authentication_present=F, $authentication_length=0,
            $is_opaque=F, $association_kind=association_kind(c),
            $association_phase=association_phase(c),
            $endpoint_role=endpoint_role(c, is_orig),
            $provenance="not_applicable",
            $stream_completeness=output_completeness(c, is_orig)];
    }

function write_object_observation(rec: Info)
    {
    if ( ! rec?$object_name || ! rec?$object_scope )
        return;

    local object_rec: ObjectInfo = [
        $ts=rec$ts, $uid=rec$uid, $id=rec$id, $is_orig=rec$is_orig,
        $association_kind=rec$association_kind,
        $association_phase=rec$association_phase,
        $endpoint_role=rec$endpoint_role,
        $observation_kind=rec?$transfer_kind ? rec$transfer_kind : "reference",
        $object_scope=rec$object_scope, $object_name=rec$object_name,
        $provenance=rec$provenance,
        $stream_completeness=rec$stream_completeness
    ];
    if ( rec?$operation ) object_rec$operation = rec$operation;
    if ( rec?$invoke_id ) object_rec$invoke_id = rec$invoke_id;
    if ( rec?$object_domain ) object_rec$object_domain = rec$object_domain;
    if ( rec?$object_category ) object_rec$object_category = rec$object_category;
    if ( rec?$name_model ) object_rec$name_model = rec$name_model;
    if ( rec?$domain_kind ) object_rec$domain_kind = rec$domain_kind;
    if ( rec?$bilateral_domain )
        object_rec$bilateral_domain = rec$bilateral_domain;
    if ( rec?$value_type ) object_rec$value_type = rec$value_type;
    if ( rec?$standardized_value )
        object_rec$standardized_value = rec$standardized_value;
    if ( rec?$conformance_blocks )
        object_rec$conformance_blocks = rec$conformance_blocks;
    if ( rec?$conditions ) object_rec$conditions = rec$conditions;
    if ( rec?$condition_mask )
        object_rec$condition_mask = rec$condition_mask;
    if ( rec?$point_type ) object_rec$point_type = rec$point_type;
    if ( rec?$state_value ) object_rec$state_value = rec$state_value;
    if ( rec?$tag_value ) object_rec$tag_value = rec$tag_value;
    if ( rec?$expected_state_value )
        object_rec$expected_state_value = rec$expected_state_value;
    if ( rec?$supplemental_reserved )
        object_rec$supplemental_reserved = rec$supplemental_reserved;
    if ( rec?$integer_value ) object_rec$integer_value = rec$integer_value;
    if ( rec?$floating_value ) object_rec$floating_value = rec$floating_value;
    if ( rec?$validity ) object_rec$validity = rec$validity;
    if ( rec?$value_source ) object_rec$value_source = rec$value_source;
    if ( rec?$normal_value ) object_rec$normal_value = rec$normal_value;
    if ( rec?$timestamp_quality )
        object_rec$timestamp_quality = rec$timestamp_quality;
    if ( rec?$timestamp_value ) object_rec$timestamp_value = rec$timestamp_value;
    if ( rec?$cov_value ) object_rec$cov_value = rec$cov_value;
    if ( rec?$result_count ) object_rec$result_count = rec$result_count;
    if ( rec?$result_pairing_status )
        object_rec$result_pairing_status = rec$result_pairing_status;
    if ( rec?$result_index ) object_rec$result_index = rec$result_index;
    if ( rec?$result_type ) object_rec$result_type = rec$result_type;
    if ( rec?$result_error ) object_rec$result_error = rec$result_error;
    if ( rec?$result_raw ) object_rec$result_raw = rec$result_raw;
    if ( rec?$result_raw_truncated )
        object_rec$result_raw_truncated = rec$result_raw_truncated;
    if ( rec?$boolean_value ) object_rec$boolean_value = rec$boolean_value;
    if ( rec?$string_value ) object_rec$string_value = rec$string_value;
    if ( rec?$object_identifier_value )
        object_rec$object_identifier_value = rec$object_identifier_value;

    Log::write(ICCP::OBJECT_LOG, object_rec);
    }

event ICCP::connection_message(c: connection, is_orig: bool)
    {
    local rec = base_record(c, is_orig, "stream", "complete", "parsed", 0);
    Log::write(ICCP::LOG, rec);
    }

event ICCP::stream_finished(
    c: connection, is_orig: bool, status: string,
    terminal_completeness: string)
    {
    local rec = base_record(
        c, is_orig, "stream", "direction_summary", status, 0);
    rec$stream_completeness = terminal_completeness;
    rec$detail = status == "non_exhaustive" ?
        "capture gaps, parser recovery, or an incomplete record prevent an exhaustive direction-level output claim" :
        "direction-level observation verdict";
    Log::write(ICCP::LOG, rec);
    }

event ICCP::presentation_message_v2(
    c: connection, is_orig: bool, recognized: bool, ppdu_type: count,
    context_id: count, abstract_syntax: string, transfer_syntax: string,
    dispatch_acse: bool, dispatch_mms: bool, inferred_mms: bool,
    payload_length: count)
    {
    local status = "decoded";
    local detail = "";

    if ( ! recognized )
        {
        status = "unsupported";
        detail = "unrecognized presentation value preserved";
        }
    else if ( inferred_mms )
        {
        status = "inferred";
        detail = "MMS decoded without observed Presentation negotiation";
        }
    else if ( context_id > 0 && payload_length > 0 &&
              ! dispatch_acse && ! dispatch_mms )
        {
        status = "recognized_not_dispatched";
        detail = "context is unknown, rejected, unsupported, or not ACSE/MMS with supported BER";
        }

    local rec = base_record(c, is_orig, "presentation",
                            fmt("%d", ppdu_type), status, payload_length);
    if ( inferred_mms ) rec$provenance = "inferred";
    else if ( dispatch_mms ) rec$provenance = "verified";
    if ( context_id > 0 )
        rec$context_id = context_id;
    if ( abstract_syntax != "" )
        rec$abstract_syntax = abstract_syntax;
    if ( transfer_syntax != "" )
        rec$transfer_syntax = transfer_syntax;
    if ( detail != "" )
        rec$detail = bounded_detail(detail);

    Log::write(ICCP::LOG, rec);
    }

# Preserve the established parser-to-Zeek event for downstream consumers while
# policy uses the versioned event's direct-MMS and inference metadata.
event ICCP::presentation_message_v2(
    c: connection, is_orig: bool, recognized: bool, ppdu_type: count,
    context_id: count, abstract_syntax: string, transfer_syntax: string,
    dispatch_acse: bool, dispatch_mms: bool, inferred_mms: bool,
    payload_length: count) &priority=-20
    {
    event ICCP::presentation_message(
        c, is_orig, recognized, ppdu_type, context_id, abstract_syntax,
        transfer_syntax, dispatch_acse, payload_length);
    }

event ICCP::acse_message(
    c: connection, is_orig: bool, recognized: bool, apdu_type: count,
    application_context: string, association_result: int, reason: int,
    diagnostic_code: int, authentication_present: bool,
    authentication_length: count, is_opaque: bool, dispatch_mms: bool,
    payload_length: count)
    {
    local status = "decoded";
    local detail = "";

    if ( ! recognized )
        {
        status = "unsupported";
        detail = "unrecognized ACSE APDU preserved";
        }
    else if ( is_opaque )
        {
        status = "opaque";
        detail = "ACSE user information uses an unsupported or opaque encoding";
        }
    else if ( payload_length > 0 && ! dispatch_mms )
        {
        status = "recognized_not_dispatched";
        detail = "ACSE user information was not eligible for MMS dispatch";
        }

    local rec = base_record(c, is_orig, "acse", fmt("%d", apdu_type),
                            status, payload_length);
    if ( application_context != "" )
        rec$application_context = application_context;
    if ( association_result >= 0 )
        rec$association_result = association_result;
    if ( reason >= 0 )
        rec$reason = reason;
    if ( diagnostic_code >= 0 )
        rec$diagnostic_code = diagnostic_code;
    rec$authentication_present = authentication_present;
    rec$authentication_length = authentication_length;
    rec$is_opaque = is_opaque;
    if ( detail != "" )
        rec$detail = bounded_detail(detail);

    Log::write(ICCP::LOG, rec);
    }

function capture_mms_processing_context(
    c: connection, is_orig: bool, recognized: bool, pdu_type: count,
    semantic_decoded: bool, invoke_id: int, service_tag: count):
    MMSProcessingContext
    {
    local context: MMSProcessingContext = [
        $parser_sequence=mms_parser_sequence(c, is_orig),
        $policy_generation=mms_policy_generation(c),
        $provenance=mms_provenance(c, is_orig),
        $request_invoke_reused=F, $request_state_full=F,
        $response_correlation="", $read_scope=0, $read_domain="",
        $read_name="", $read_category=0
    ];

    if ( ! recognized || ! semantic_decoded || invoke_id < 0 )
        return context;

    local key = int_to_count(invoke_id);
    if ( pdu_type == 0 )
        {
        context$request_invoke_reused =
            [c$uid, is_orig, key] in invalid_confirmed_invokes;
        context$request_state_full = ! context$request_invoke_reused &&
            [c$uid, is_orig, key] !in pending_confirmed;
        return context;
        }

    if ( pdu_type != 1 && pdu_type != 6 )
        return context;

    local request_is_orig = ! is_orig;
    if ( [c$uid, request_is_orig, key] in invalid_confirmed_invokes )
        context$response_correlation = "ambiguous_response";
    else if ( [c$uid, request_is_orig, key] in pending_confirmed )
        {
        local pending = pending_confirmed[c$uid, request_is_orig, key];
        context$response_correlation =
            (pdu_type == 6 || service_tag == pending$service_tag) ?
                "matched_response" : "service_mismatch";
        }
    else if ( [c$uid, is_orig, key] in invalid_confirmed_invokes ||
              [c$uid, is_orig, key] in pending_confirmed )
        context$response_correlation = "direction_mismatch";
    else
        context$response_correlation = "unmatched_response";

    if ( pdu_type == 1 && service_tag == 4 )
        {
        local read_identity = pending_read_for_response(
            c, is_orig, invoke_id);
        context$read_scope = read_identity$scope;
        context$read_domain = read_identity$domain;
        context$read_name = read_identity$name;
        context$read_category = read_identity$category;
        }

    return context;
    }

function process_mms_message(
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
    context: MMSProcessingContext)
    {
    local shape_applicable = recognized && semantic_decoded &&
        ((pdu_type == 1 && service_tag == 4) ||
         (pdu_type == 3 && unconfirmed_service_tag == 0));
    local shape_available = shape_applicable &&
        point_value_shape_available(
            c, is_orig, context$parser_sequence);
    local first_result_length: count = 0;
    local first_component_length: count = 0;
    local second_component_length: count = 0;
    local third_component_length: count = 0;
    local point_shape: PointValueShapeEvidence = [
        $first_result_length=0, $first_component_length=0,
        $second_component_length=0, $third_component_length=0
    ];
    if ( shape_available )
        {
        local shape = point_value_shape_evidence[
            c$uid, is_orig, context$parser_sequence];
        point_shape = shape;
        first_result_length = shape$first_result_length;
        first_component_length = shape$first_component_length;
        second_component_length = shape$second_component_length;
        third_component_length = shape$third_component_length;
        delete point_value_shape_evidence[
            c$uid, is_orig, context$parser_sequence];
        }
    local request_invoke_reused = context$request_invoke_reused;
    local request_state_full = context$request_state_full;
    local response_correlation = context$response_correlation;

    local status = "decoded";
    local detail = "";

    if ( ! recognized )
        {
        status = "unsupported";
        detail = "unrecognized MMS top-level PDU preserved";
        }
    else if ( ! semantic_decoded )
        {
        status = "raw";
        detail = "recognized MMS top-level PDU body preserved for semantic decoding";
        }
    else if ( request_invoke_reused )
        {
        status = "invoke_reused";
        detail = "caller reused an outstanding confirmed-request invoke ID";
        }
    else if ( response_correlation == "ambiguous_response" ||
              response_correlation == "direction_mismatch" ||
              response_correlation == "service_mismatch" )
        {
        status = response_correlation;
        detail = response_correlation == "ambiguous_response" ?
            "response cannot be attributed after invoke-ID reuse" :
            response_correlation == "direction_mismatch" ?
                "response direction does not match the pending caller" :
                "response service does not match the pending request";
        }

    local rec = base_record(c, is_orig, "mms", fmt("%d", pdu_type),
                            status, body_length);
    rec$provenance = context$provenance;
    if ( invoke_id >= 0 )
        rec$invoke_id = invoke_id;
    if ( pdu_type == 0 || pdu_type == 1 )
        rec$service_tag = service_tag;
    else if ( pdu_type == 3 )
        rec$service_tag = unconfirmed_service_tag;
    if ( candidate_operation > 0 )
        rec$operation = operation_name(candidate_operation);

    if ( invoke_id >= 0 && (pdu_type == 0 || pdu_type == 1) &&
         identify_evidence_available(
             c, is_orig, context$parser_sequence, pdu_type,
             int_to_count(invoke_id)) )
        {
        local identify_key = int_to_count(invoke_id);
        local identity = identify_evidence[
            c$uid, is_orig, context$parser_sequence, pdu_type,
            identify_key];
        if ( pdu_type == 0 )
            rec$identify_outcome = request_invoke_reused ? "invoke_reused" :
                request_state_full ? "state_limit" : "requested";
        else
            rec$identify_outcome = response_correlation;

        if ( identity$vendor_name != "" )
            rec$vendor_name = bounded_detail(identity$vendor_name);
        if ( identity$model_name != "" )
            rec$model_name = bounded_detail(identity$model_name);
        if ( identity$revision != "" )
            rec$revision = bounded_detail(identity$revision);
        rec$abstract_syntax_count = identity$abstract_syntax_count;
        if ( identity$first_abstract_syntax != "" )
            rec$first_abstract_syntax = identity$first_abstract_syntax;
        delete identify_evidence[
            c$uid, is_orig, context$parser_sequence, pdu_type,
            identify_key];
        }

    if ( pdu_type == 3 && unconfirmed_service_tag == 0 &&
         information_report_results_available(
             c, is_orig, context$parser_sequence) )
        {
        local report_evidence =
            information_report_results_evidence[
                c$uid, is_orig, context$parser_sequence];
        local logged_results = information_report_loggable_result_count(
            c, is_orig, report_evidence);
        rec$result_count = report_evidence$result_count;
        rec$failure_count = report_evidence$failure_count;
        rec$logged_result_count = logged_results;
        rec$omitted_result_count =
            report_evidence$result_count > logged_results ?
                report_evidence$result_count - logged_results : 0;
        rec$result_pairing_status = information_report_pairing_status(
            c, is_orig, report_evidence);

        if ( |report_evidence$result_choices| > 0 )
            {
            local first_identity = information_report_result_identity(
                c, is_orig, report_evidence, 0);
            if ( first_identity$known )
                {
                # Preserve the established first-result label. Additional
                # ordered result rows use information_report_result.
                rec$transfer_kind = "information_report";
                rec$object_scope = transfer_scope_name(first_identity$scope);
                rec$object_name = first_identity$name;
                if ( first_identity$domain != "" )
                    rec$object_domain = first_identity$domain;
                rec$name_model = object_name_model(
                    c, is_orig, first_identity$scope, first_identity$domain,
                    first_identity$name, 0);
                if ( information_message_candidate(
                         c, is_orig, report_evidence) )
                    rec$name_model = "standardized";
                rec$domain_kind = object_domain_kind(
                    c, is_orig, first_identity$scope,
                    first_identity$domain);
                rec$bilateral_domain = is_bilateral_domain_for_server(
                    c, is_orig, first_identity$domain);
                rec = add_information_report_result_to_info(
                    rec, report_evidence, 0);
                rec$result_pairing_status =
                    information_report_pairing_status(
                        c, is_orig, report_evidence);
                }
            }
        write_information_message_observation(
            c, is_orig, report_evidence, point_shape,
            context$provenance);
        }

    if ( first_result_type > 0 &&
         ((pdu_type == 1 && service_tag == 4 && invoke_id >= 0) ||
          (pdu_type == 3 && unconfirmed_service_tag == 0 &&
           object_name != "" && association_kind(c) == "tase2")) )
        {
        local transfer_object: PendingRead;
        if ( pdu_type == 3 )
            {
            transfer_object = [$scope=object_scope,
                               $domain=object_domain,
                               $name=object_name,
                               $category=object_category];
            rec$transfer_kind = "information_report";
            }
        else
            {
            transfer_object = [
                $scope=context$read_scope, $domain=context$read_domain,
                $name=context$read_name, $category=context$read_category
            ];
            rec$transfer_kind = "read_response";
            }

        if ( transfer_object$name != "" )
            {
            rec$object_scope = transfer_object$scope == 0 ? "vcc" :
                               transfer_object$scope == 1 ? "icc" : "aa";
            rec$object_name = transfer_object$name;
            if ( transfer_object$domain != "" )
                rec$object_domain = transfer_object$domain;
            rec$value_type = first_result_type;
            local learned_point_type = learned_variable_type_name(
                c, is_orig,
                transfer_object$scope, transfer_object$domain,
                transfer_object$name);
            # 802 IndicationPoint values are never AA-specific.  Keep a
            # configured AA-specific Data_* variable observable as generic MMS
            # data instead of promoting it to an exact TASE.2 point.
            if ( /^Data_/ in learned_point_type &&
                 ! standardized_point_control_scope(
                     transfer_object$scope, transfer_object$domain) )
                learned_point_type = "";

            if ( transfer_object$category == 1 && first_result_type == 4 &&
                 |first_result_raw| >= 2 )
                {
                rec$object_category = "supported_features";
                rec$standardized_value =
                    bounded_information_report_result_raw(first_result_raw);
                if ( supported_features_value_is_valid(first_result_raw) )
                    rec$conformance_blocks = fmt(
                        "unused=%d,bits=%s,enabled=%s",
                        bytestring_to_count(sub_bytes(
                            first_result_raw, 1, 1)),
                        bytestring_to_hexstr(sub_bytes(
                            first_result_raw, 2, |first_result_raw| - 1)),
                        decode_supported_features(first_result_raw));
                else
                    rec$conformance_blocks = "invalid_bit_string";
                }
            else if ( transfer_object$category == 2 &&
                      first_result_type == 10 )
                {
                rec$object_category = "bilateral_table";
                rec$standardized_value =
                    bounded_detail(first_result_raw);
                }
            else if ( transfer_object$category == 5 &&
                      first_result_type == 2 &&
                      result_integer_count >= 2 )
                {
                rec$object_category = "tase2_version";
                rec$standardized_value = fmt(
                    "%d.%02d",
                    result_first_integer,
                    result_second_integer);
                }
            else if ( association_kind(c) == "tase2" &&
                      first_result_type == 4 &&
                      |first_result_raw| == 2 &&
                      bytestring_to_count(
                          sub_bytes(first_result_raw, 1, 1)) == 3 &&
                      transfer_object$scope == 1 &&
                      transfer_object$name == "DSConditions_Detected" &&
                      valid_tase2_object_identifier(
                          transfer_object$scope, transfer_object$domain,
                          transfer_object$name) )
                {
                local condition_bits = bytestring_to_count(
                    sub_bytes(first_result_raw, 2, 1));
                rec$object_category = "transfer_support";
                rec$point_type = "ds_conditions";
                rec$standardized_value =
                    bytestring_to_hexstr(first_result_raw);
                rec$condition_mask = condition_bits / 8;
                rec$conditions = decode_ds_conditions(condition_bits);
                }
            else if ( association_kind(c) == "tase2" &&
                      learned_point_type == "Data_Real" &&
                      first_result_type == 7 && shape_available &&
                      first_result_length == 5 )
                {
                rec$point_type = "real";
                rec$floating_value = result_floating_value;
                }
            else if ( association_kind(c) == "tase2" &&
                      learned_point_type == "Data_Discrete" &&
                      first_result_type == 5 && shape_available &&
                      first_result_length > 0 && first_result_length <= 4 )
                {
                rec$point_type = "discrete";
                rec$integer_value = result_integer_value;
                }
            else if ( association_kind(c) == "tase2" &&
                      learned_point_type == "Data_State" &&
                      first_result_type == 4 &&
                      shape_available && first_result_length == 2 &&
                      |first_result_raw| == 2 &&
                      bytestring_to_count(
                          sub_bytes(first_result_raw, 1, 1)) == 0 )
                {
                local state_flags = bytestring_to_count(
                    sub_bytes(first_result_raw, 2, 1));
                rec$point_type = "state";
                rec$state_value = (state_flags & 0xc0) / 64;
                rec$validity = data_flags_validity(state_flags);
                rec$value_source = data_flags_source(state_flags);
                rec$normal_value = (state_flags & 0x02) != 0;
                rec$timestamp_quality = (state_flags & 0x01) != 0;
                }
            else if ( association_kind(c) == "tase2" &&
                      learned_point_type == "Data_StateSupplemental" &&
                      first_result_type == 4 && shape_available &&
                      first_result_length == 2 &&
                      exact_eight_bit_string(first_result_raw) )
                {
                local supplemental = bytestring_to_count(
                    sub_bytes(first_result_raw, 2, 1));
                rec$point_type = "state_supplemental";
                rec$state_value = (supplemental & 0xc0) / 64;
                rec$tag_value = (supplemental & 0x30) / 16;
                rec$expected_state_value = (supplemental & 0x0c) / 4;
                rec$supplemental_reserved = supplemental & 0x03;
                }
            else if ( association_kind(c) == "tase2" &&
                      learned_point_type == "Data_StateQ" &&
                      first_result_type == 2 && shape_available &&
                      point_shape?$component_choices &&
                      point_shape?$component_raws &&
                      |point_shape$component_choices| == 2 &&
                      |point_shape$component_raws| == 2 &&
                      point_shape$component_choices[0] == 4 &&
                      exact_eight_bit_string(
                          point_shape$component_raws[0]) &&
                      point_shape$component_choices[1] == 4 &&
                      exact_eight_bit_string(
                          point_shape$component_raws[1]) )
                {
                local state_q = bytestring_to_count(
                    sub_bytes(point_shape$component_raws[0], 2, 1));
                local state_q_flags = bytestring_to_count(
                    sub_bytes(point_shape$component_raws[1], 2, 1));
                rec$point_type = "state_q";
                rec$state_value = (state_q & 0xc0) / 64;
                rec$validity = data_flags_validity(state_q_flags);
                rec$value_source = data_flags_source(state_q_flags);
                rec$normal_value = (state_q_flags & 0x02) != 0;
                rec$timestamp_quality = (state_q_flags & 0x01) != 0;
                }
            else if ( association_kind(c) == "tase2" &&
                      learned_point_type == "Data_StateSupplementalQ" &&
                      first_result_type == 2 && shape_available &&
                      point_shape?$component_choices &&
                      point_shape?$component_raws &&
                      |point_shape$component_choices| == 2 &&
                      |point_shape$component_raws| == 2 &&
                      point_shape$component_choices[0] == 4 &&
                      exact_eight_bit_string(
                          point_shape$component_raws[0]) &&
                      point_shape$component_choices[1] == 4 &&
                      exact_eight_bit_string(
                          point_shape$component_raws[1]) )
                {
                local supplemental_q = bytestring_to_count(
                    sub_bytes(point_shape$component_raws[0], 2, 1));
                local supplemental_q_flags = bytestring_to_count(
                    sub_bytes(point_shape$component_raws[1], 2, 1));
                rec$point_type = "state_supplemental_q";
                rec$state_value = (supplemental_q & 0xc0) / 64;
                rec$tag_value = (supplemental_q & 0x30) / 16;
                rec$expected_state_value = (supplemental_q & 0x0c) / 4;
                rec$supplemental_reserved = supplemental_q & 0x03;
                rec$validity = data_flags_validity(supplemental_q_flags);
                rec$value_source = data_flags_source(supplemental_q_flags);
                rec$normal_value = (supplemental_q_flags & 0x02) != 0;
                rec$timestamp_quality =
                    (supplemental_q_flags & 0x01) != 0;
                }
            else if ( association_kind(c) == "tase2" &&
                      first_result_type == 2 &&
                      result_component_count == 2 &&
                      shape_available &&
                      ((learned_point_type == "Data_RealQ" &&
                        result_first_choice == 7 &&
                        first_component_length == 5) ||
                       (learned_point_type == "Data_DiscreteQ" &&
                        result_first_choice == 5 &&
                        first_component_length > 0 &&
                        first_component_length <= 4)) &&
                      result_second_choice == 4 &&
                      second_component_length == 2 &&
                      |result_flags_raw| == 2 &&
                      bytestring_to_count(
                          sub_bytes(result_flags_raw, 1, 1)) == 0 )
                {
                local flags = bytestring_to_count(
                    sub_bytes(result_flags_raw, 2, 1));
                rec$point_type = learned_point_type == "Data_RealQ" ?
                    "real_q" : "discrete_q";
                if ( learned_point_type == "Data_RealQ" )
                    rec$floating_value = result_floating_value;
                else
                    rec$integer_value = result_integer_value;
                rec$validity = data_flags_validity(flags);
                rec$value_source = data_flags_source(flags);
                rec$normal_value = (flags & 0x02) != 0;
                rec$timestamp_quality = (flags & 0x01) != 0;
                }
            else if ( association_kind(c) == "tase2" &&
                      first_result_type == 2 &&
                      result_component_count == 3 &&
                      shape_available &&
                      ((learned_point_type == "Data_RealQTimeTag" &&
                        result_first_choice == 7 &&
                        first_component_length == 5) ||
                       (learned_point_type == "Data_DiscreteQTimeTag" &&
                        result_first_choice == 5 &&
                        first_component_length > 0 &&
                        first_component_length <= 4)) &&
                      result_second_choice == 5 &&
                      second_component_length > 0 &&
                      second_component_length <= 4 &&
                      result_third_choice == 4 &&
                      third_component_length == 2 &&
                      |result_flags_raw| == 2 &&
                      bytestring_to_count(
                          sub_bytes(result_flags_raw, 1, 1)) == 0 &&
                      result_timestamp_value >= 0 )
                {
                local time_flags = bytestring_to_count(
                    sub_bytes(result_flags_raw, 2, 1));
                rec$point_type =
                    learned_point_type == "Data_RealQTimeTag" ?
                        "real_q_time" : "discrete_q_time";
                if ( learned_point_type == "Data_RealQTimeTag" )
                    rec$floating_value = result_floating_value;
                else
                    rec$integer_value = result_integer_value;
                rec$validity = data_flags_validity(time_flags);
                rec$value_source = data_flags_source(time_flags);
                rec$normal_value = (time_flags & 0x02) != 0;
                rec$timestamp_quality = (time_flags & 0x01) != 0;
                rec$timestamp_value = result_timestamp_value;
                }
            else if ( association_kind(c) == "tase2" &&
                      learned_point_type == "Data_StateQTimeTag" &&
                      first_result_type == 2 && shape_available &&
                      point_shape?$component_choices &&
                      point_shape?$component_raws &&
                      point_shape?$component_integer_values &&
                      |point_shape$component_choices| == 2 &&
                      |point_shape$component_raws| == 2 &&
                      |point_shape$component_integer_values| == 2 &&
                      point_shape$component_choices[0] == 5 &&
                      |point_shape$component_raws[0]| > 0 &&
                      |point_shape$component_raws[0]| <= 4 &&
                      point_shape$component_integer_values[0] >= 0 &&
                      point_shape$component_choices[1] == 4 &&
                      exact_eight_bit_string(
                          point_shape$component_raws[1]) )
                {
                local state_time_flags = bytestring_to_count(
                    sub_bytes(point_shape$component_raws[1], 2, 1));
                rec$point_type = "state_q_time";
                rec$state_value = (state_time_flags & 0xc0) / 64;
                rec$validity = data_flags_validity(state_time_flags);
                rec$value_source = data_flags_source(state_time_flags);
                rec$normal_value = (state_time_flags & 0x02) != 0;
                rec$timestamp_quality = (state_time_flags & 0x01) != 0;
                rec$timestamp_value =
                    point_shape$component_integer_values[0];
                }
            else if ( association_kind(c) == "tase2" &&
                      learned_point_type ==
                          "Data_StateSupplementalQTimeTag" &&
                      first_result_type == 2 && shape_available &&
                      point_shape?$component_choices &&
                      point_shape?$component_raws &&
                      point_shape?$component_integer_values &&
                      |point_shape$component_choices| == 3 &&
                      |point_shape$component_raws| == 3 &&
                      |point_shape$component_integer_values| == 3 &&
                      point_shape$component_choices[0] == 4 &&
                      exact_eight_bit_string(
                          point_shape$component_raws[0]) &&
                      point_shape$component_choices[1] == 5 &&
                      |point_shape$component_raws[1]| > 0 &&
                      |point_shape$component_raws[1]| <= 4 &&
                      point_shape$component_integer_values[1] >= 0 &&
                      point_shape$component_choices[2] == 4 &&
                      exact_eight_bit_string(
                          point_shape$component_raws[2]) )
                {
                local supplemental_time = bytestring_to_count(
                    sub_bytes(point_shape$component_raws[0], 2, 1));
                local supplemental_time_flags = bytestring_to_count(
                    sub_bytes(point_shape$component_raws[2], 2, 1));
                rec$point_type = "state_supplemental_q_time";
                rec$state_value = (supplemental_time & 0xc0) / 64;
                rec$tag_value = (supplemental_time & 0x30) / 16;
                rec$expected_state_value =
                    (supplemental_time & 0x0c) / 4;
                rec$supplemental_reserved = supplemental_time & 0x03;
                rec$validity = data_flags_validity(
                    supplemental_time_flags);
                rec$value_source = data_flags_source(
                    supplemental_time_flags);
                rec$normal_value =
                    (supplemental_time_flags & 0x02) != 0;
                rec$timestamp_quality =
                    (supplemental_time_flags & 0x01) != 0;
                rec$timestamp_value =
                    point_shape$component_integer_values[1];
                }
            else if ( association_kind(c) == "tase2" &&
                      first_result_type == 2 && shape_available &&
                      point_shape?$component_choices &&
                      point_shape?$component_raws &&
                      point_shape?$component_integer_values &&
                      |point_shape$component_raws| ==
                          |point_shape$component_choices| &&
                      |point_shape$component_integer_values| ==
                          |point_shape$component_choices| &&
                      ((learned_point_type == "Data_RealExtended" &&
                        |point_shape$component_choices| == 4 &&
                        point_shape$component_choices[0] == 7 &&
                        |point_shape$component_raws[0]| == 5) ||
                       (learned_point_type == "Data_DiscreteExtended" &&
                        |point_shape$component_choices| == 4 &&
                        point_shape$component_choices[0] == 5 &&
                        |point_shape$component_raws[0]| > 0 &&
                        |point_shape$component_raws[0]| <= 4) ||
                       (learned_point_type ==
                            "Data_StateSupplementalExtended" &&
                        |point_shape$component_choices| == 4 &&
                        point_shape$component_choices[0] == 4 &&
                        exact_eight_bit_string(
                            point_shape$component_raws[0])) ||
                       (learned_point_type == "Data_StateExtended" &&
                        |point_shape$component_choices| == 3)) )
                {
                local extended_is_state =
                    learned_point_type == "Data_StateExtended";
                local timestamp_index: count = extended_is_state ? 0 : 1;
                local flags_index: count = extended_is_state ? 1 : 2;
                local cov_index: count = extended_is_state ? 2 : 3;
                local extended_valid =
                    |point_shape$component_raws| ==
                        |point_shape$component_choices| &&
                    |point_shape$component_integer_values| ==
                        |point_shape$component_choices| &&
                    point_shape$component_choices[timestamp_index] == 5 &&
                    |point_shape$component_raws[timestamp_index]| > 0 &&
                    |point_shape$component_raws[timestamp_index]| <= 4 &&
                    point_shape$component_integer_values[timestamp_index] >= 0 &&
                    point_shape$component_choices[flags_index] == 4 &&
                    exact_eight_bit_string(
                        point_shape$component_raws[flags_index]) &&
                    point_shape$component_choices[cov_index] == 6 &&
                    |point_shape$component_raws[cov_index]| > 0 &&
                    |point_shape$component_raws[cov_index]| <= 3 &&
                    point_shape$component_integer_values[cov_index] >= 0 &&
                    point_shape$component_integer_values[cov_index] <= 65535;
                if ( extended_valid )
                    {
                    local extended_flags = bytestring_to_count(
                        sub_bytes(point_shape$component_raws[flags_index], 2, 1));
                    rec$point_type = learned_point_type == "Data_RealExtended" ?
                        "real_extended" :
                        learned_point_type == "Data_DiscreteExtended" ?
                            "discrete_extended" :
                        learned_point_type ==
                            "Data_StateSupplementalExtended" ?
                            "state_supplemental_extended" :
                            "state_extended";
                    if ( learned_point_type == "Data_RealExtended" )
                        rec$floating_value = result_floating_value;
                    else if ( learned_point_type == "Data_DiscreteExtended" )
                        rec$integer_value = result_integer_value;
                    else if ( learned_point_type ==
                              "Data_StateSupplementalExtended" )
                        {
                        local supplemental_extended = bytestring_to_count(
                            sub_bytes(point_shape$component_raws[0], 2, 1));
                        rec$state_value =
                            (supplemental_extended & 0xc0) / 64;
                        rec$tag_value =
                            (supplemental_extended & 0x30) / 16;
                        rec$expected_state_value =
                            (supplemental_extended & 0x0c) / 4;
                        rec$supplemental_reserved =
                            supplemental_extended & 0x03;
                        }
                    else
                        rec$state_value = (extended_flags & 0xc0) / 64;
                    rec$validity = data_flags_validity(extended_flags);
                    rec$value_source = data_flags_source(extended_flags);
                    rec$normal_value = (extended_flags & 0x02) != 0;
                    rec$timestamp_quality = (extended_flags & 0x01) != 0;
                    rec$timestamp_value =
                        point_shape$component_integer_values[timestamp_index];
                    rec$cov_value = int_to_count(
                        point_shape$component_integer_values[cov_index]);
                    }
                else
                    rec$standardized_value =
                        bounded_information_report_result_raw(first_result_raw);
                }
            else if ( association_kind(c) == "tase2" &&
                      first_result_type == 2 && shape_available &&
                      point_shape?$component_choices &&
                      point_shape?$component_raws &&
                      point_shape?$component_integer_values &&
                      |point_shape$component_raws| ==
                          |point_shape$component_choices| &&
                      |point_shape$component_integer_values| ==
                          |point_shape$component_choices| &&
                      ((learned_point_type == "Data_RealQTimeTagExtended" &&
                        |point_shape$component_choices| == 3 &&
                        point_shape$component_choices[0] == 7 &&
                        |point_shape$component_raws[0]| == 5 &&
                        point_shape$component_choices[1] == 2 &&
                        point_shape$component_choices[2] == 4 &&
                        exact_extended_timestamp(point_shape, 2) &&
                        exact_eight_bit_string(
                            point_shape$component_raws[2])) ||
                       (learned_point_type == "Data_DiscreteQTimeTagExtended" &&
                        |point_shape$component_choices| == 3 &&
                        point_shape$component_choices[0] == 5 &&
                        |point_shape$component_raws[0]| > 0 &&
                        |point_shape$component_raws[0]| <= 4 &&
                        point_shape$component_choices[1] == 2 &&
                        point_shape$component_choices[2] == 4 &&
                        exact_extended_timestamp(point_shape, 2) &&
                        exact_eight_bit_string(
                            point_shape$component_raws[2])) ||
                       (learned_point_type == "Data_StateQTimeTagExtended" &&
                        |point_shape$component_choices| == 2 &&
                        point_shape$component_choices[0] == 2 &&
                        point_shape$component_choices[1] == 4 &&
                        exact_extended_timestamp(point_shape, 1) &&
                        exact_eight_bit_string(
                            point_shape$component_raws[1])) ||
                       (learned_point_type ==
                            "Data_StateSupplementalQTimeTagExtended" &&
                        |point_shape$component_choices| == 3 &&
                        point_shape$component_choices[0] == 4 &&
                        exact_eight_bit_string(
                            point_shape$component_raws[0]) &&
                        point_shape$component_choices[1] == 2 &&
                        point_shape$component_choices[2] == 4 &&
                        exact_extended_timestamp(point_shape, 2) &&
                        exact_eight_bit_string(
                            point_shape$component_raws[2]))) )
                {
                local extended_time_flags_index: count =
                    learned_point_type == "Data_StateQTimeTagExtended" ? 1 : 2;
                local extended_time_flags = bytestring_to_count(
                    sub_bytes(
                        point_shape$component_raws[extended_time_flags_index],
                        2, 1));
                rec$point_type =
                    learned_point_type == "Data_RealQTimeTagExtended" ?
                        "real_q_time_extended" :
                    learned_point_type == "Data_DiscreteQTimeTagExtended" ?
                        "discrete_q_time_extended" :
                    learned_point_type ==
                        "Data_StateSupplementalQTimeTagExtended" ?
                        "state_supplemental_q_time_extended" :
                        "state_q_time_extended";
                if ( learned_point_type == "Data_RealQTimeTagExtended" )
                    rec$floating_value = result_floating_value;
                else if ( learned_point_type ==
                          "Data_DiscreteQTimeTagExtended" )
                    rec$integer_value = result_integer_value;
                else if ( learned_point_type ==
                          "Data_StateSupplementalQTimeTagExtended" )
                    {
                    local supplemental_time_extended = bytestring_to_count(
                        sub_bytes(point_shape$component_raws[0], 2, 1));
                    rec$state_value =
                        (supplemental_time_extended & 0xc0) / 64;
                    rec$tag_value =
                        (supplemental_time_extended & 0x30) / 16;
                    rec$expected_state_value =
                        (supplemental_time_extended & 0x0c) / 4;
                    rec$supplemental_reserved =
                        supplemental_time_extended & 0x03;
                    }
                else
                    rec$state_value = (extended_time_flags & 0xc0) / 64;
                rec$validity = data_flags_validity(extended_time_flags);
                rec$value_source = data_flags_source(extended_time_flags);
                rec$normal_value = (extended_time_flags & 0x02) != 0;
                rec$timestamp_quality = (extended_time_flags & 0x01) != 0;
                rec$timestamp_value =
                    point_shape$nested_integer_values[0] * 1000 +
                    point_shape$nested_integer_values[1];
                }
            else
                rec$standardized_value =
                    bounded_information_report_result_raw(first_result_raw);

            rec$name_model = object_name_model(
                c, is_orig, transfer_object$scope, transfer_object$domain,
                transfer_object$name, transfer_object$category);
            rec$domain_kind = object_domain_kind(
                c, is_orig, transfer_object$scope, transfer_object$domain);
            rec$bilateral_domain =
                is_bilateral_domain_for_server(
                    c, is_orig, transfer_object$domain);
            }
        }
    if ( object_name != "" )
        {
        rec$object_scope = object_scope == 0 ? "vcc" :
                           object_scope == 1 ? "icc" : "aa";
        rec$object_name = object_name;
        if ( object_domain != "" )
            rec$object_domain = object_domain;

        switch ( object_category )
            {
            case 1: rec$object_category = "supported_features"; break;
            case 2: rec$object_category = "bilateral_table"; break;
            case 3: rec$object_category = "transfer_support"; break;
            case 4: rec$object_category = "information_message"; break;
            case 5: rec$object_category = "tase2_version"; break;
            default: rec$object_category = "unknown"; break;
            }
        if ( object_category == 0 && object_scope == 1 &&
             object_name == "Event_Code_Detected" &&
             valid_tase2_object_identifier(
                 object_scope, object_domain, object_name) )
            rec$object_category = "transfer_support";
        if ( object_category == 0 &&
             (object_scope == 0 || object_scope == 1) &&
             information_buffer_capacity(object_name) > 0 &&
             valid_tase2_object_identifier(
                 object_scope, object_domain, object_name) )
            rec$object_category = "information_message";
        local object_server_is_orig = pdu_type == 0 ? ! is_orig : is_orig;
        rec$name_model = object_name_model(
            c, object_server_is_orig, object_scope, object_domain,
            object_name, object_category);
        rec$domain_kind = object_domain_kind(
            c, object_server_is_orig, object_scope, object_domain);
        rec$bilateral_domain = is_bilateral_domain_for_server(
            c, object_server_is_orig, object_domain);
        }
    if ( detail != "" )
        rec$detail = bounded_detail(detail);

    Log::write(ICCP::LOG, rec);
    write_object_observation(rec);
    if ( pdu_type == 3 && unconfirmed_service_tag == 0 &&
         information_report_results_available(
             c, is_orig, context$parser_sequence) )
        {
        local remaining_report_evidence =
            information_report_results_evidence[
                c$uid, is_orig, context$parser_sequence];
        local first_remaining_identity =
            information_report_result_identity(
                c, is_orig, remaining_report_evidence, 0);
        local skip_first_result =
            |remaining_report_evidence$result_choices| > 0 &&
            first_remaining_identity$known;
        write_additional_information_report_results(
            c, is_orig, remaining_report_evidence, skip_first_result,
            context$provenance);
        delete information_report_results_evidence[
            c$uid, is_orig, context$parser_sequence];
        }
    if ( recognized && semantic_decoded && pdu_type == 0 &&
         rec?$object_name && rec?$object_scope && rec?$name_model &&
         rec$name_model == "private_unknown" )
        {
        event ICCP::legacy_alert_provenance_marker_v1(
            c, is_orig, "unknown_object_access", context$provenance);
        event ICCP::unknown_object_access(
            c, is_orig, rec$association_kind, rec$endpoint_role,
            rec?$operation ? rec$operation : "unknown",
            rec?$invoke_id ? rec$invoke_id : -1,
            rec$object_scope,
            rec?$object_domain ? rec$object_domain : "",
            rec$object_name, rec$name_model);
        }

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
    result_flags_raw: string, result_timestamp_value: int)
    {
    local parser_delivery = consume_mms_parser_marker(c, is_orig);
    if ( parser_delivery && recognized && semantic_decoded &&
         pdu_type == 0 && service_tag == 4 && invoke_id >= 0 )
        mark_parser_read_delivery(c, is_orig, invoke_id);
    if ( parser_delivery && recognized && semantic_decoded &&
         (pdu_type == 0 || pdu_type == 1) &&
         (service_tag == 11 || service_tag == 12 ||
          service_tag == 13) )
        mark_parser_transfer_delivery(
            c, is_orig, pdu_type, invoke_id, service_tag,
            unconfirmed_service_tag);
    track_confirmed_request(
        c, is_orig, recognized, pdu_type, semantic_decoded, invoke_id,
        service_tag, candidate_operation);
    local context = capture_mms_processing_context(
        c, is_orig, recognized, pdu_type, semantic_decoded, invoke_id,
        service_tag);

    # Parser hook delivery places the aggregate event before some additive
    # evidence events. Always defer these marked parser families and correlate
    # their evidence by the immutable per-PDU sequence; testing for a populated
    # direction-wide slot would let a later PDU steal an earlier PDU's data.
    # Direct script callers have no marker and retain synchronous behavior.
    if ( recognized && parser_delivery &&
         ((service_tag == 2 && (pdu_type == 0 || pdu_type == 1) &&
           invoke_id >= 0) ||
          (pdu_type == 3 && unconfirmed_service_tag == 0) ||
          (pdu_type == 1 && service_tag == 4)) )
        {
        schedule 0secs { ICCP::mms_message_evidence_deferred(
            c, is_orig, recognized, pdu_type, semantic_decoded, body_length,
            invoke_id, service_tag, unconfirmed_service_tag,
            iccp_required_service, candidate_operation, parameter_cbb,
            services, object_scope, object_domain, object_name,
            object_category, tase2_object_evidence, first_variable_scope,
            first_variable_domain, first_variable_name,
            first_variable_category, first_result_type, first_result_raw,
            result_integer_count, result_first_integer,
            result_second_integer, result_component_count,
            result_first_choice, result_second_choice, result_third_choice,
            result_integer_value, result_floating_value, result_flags_raw,
            result_timestamp_value, context) };
        return;
        }

    process_mms_message(
        c, is_orig, recognized, pdu_type, semantic_decoded, body_length,
        invoke_id, service_tag, unconfirmed_service_tag,
        iccp_required_service, candidate_operation, parameter_cbb, services,
        object_scope, object_domain, object_name, object_category,
        tase2_object_evidence, first_variable_scope, first_variable_domain,
        first_variable_name, first_variable_category, first_result_type,
        first_result_raw, result_integer_count, result_first_integer,
        result_second_integer, result_component_count, result_first_choice,
        result_second_choice, result_third_choice, result_integer_value,
        result_floating_value, result_flags_raw, result_timestamp_value,
        context);

    # The specialized tag callback, when present, was queued by a later
    # sibling parser event. Queue cleanup behind it so non-tag/invalid Read
    # shapes cannot accumulate while tag classification can still consume its
    # exact sequence-keyed evidence.
    if ( recognized && semantic_decoded && pdu_type == 1 &&
         service_tag == 4 && invoke_id >= 0 )
        schedule 0secs { ICCP::mms_control_read_shape_cleanup(
            c, is_orig, context$parser_sequence, invoke_id) };

    }

event ICCP::mms_message_evidence_deferred(
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
    context: MMSProcessingContext)
    {
    if ( ! mms_policy_generation_is_current(
             c, context$policy_generation) )
        return;

    process_mms_message(
        c, is_orig, recognized, pdu_type, semantic_decoded, body_length,
        invoke_id, service_tag, unconfirmed_service_tag,
        iccp_required_service, candidate_operation, parameter_cbb, services,
        object_scope, object_domain, object_name, object_category,
        tase2_object_evidence, first_variable_scope, first_variable_domain,
        first_variable_name, first_variable_category, first_result_type,
        first_result_raw, result_integer_count, result_first_integer,
        result_second_integer, result_component_count, result_first_choice,
        result_second_choice, result_third_choice, result_integer_value,
        result_floating_value, result_flags_raw, result_timestamp_value,
        context);
    if ( recognized && semantic_decoded && pdu_type == 1 &&
         service_tag == 4 && invoke_id >= 0 )
        schedule 0secs { ICCP::mms_control_read_shape_cleanup(
            c, is_orig, context$parser_sequence, invoke_id) };
    }

# Retire terminal correlation state after normal-priority direct-event
# consumers have inspected it, but before Zeek dispatches the next queued PDU.
# Deferred policy callbacks carry immutable correlation and Read snapshots, so
# they no longer need live state to survive until the scheduler runs.
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
    result_flags_raw: string, result_timestamp_value: int) &priority=-25
    {
    if ( ! recognized || ! semantic_decoded || invoke_id < 0 )
        return;

    local key = int_to_count(invoke_id);
    if ( pdu_type == 1 || pdu_type == 6 )
        {
        local request_is_orig = ! is_orig;
        if ( [c$uid, request_is_orig, key] in invalid_confirmed_invokes )
            delete invalid_confirmed_invokes[
                c$uid, request_is_orig, key];
        else if ( [c$uid, request_is_orig, key] in pending_confirmed )
            {
            local pending = pending_confirmed[
                c$uid, request_is_orig, key];
            if ( pdu_type == 6 || service_tag == pending$service_tag )
                {
                delete pending_confirmed[c$uid, request_is_orig, key];
                if ( pdu_type == 6 )
                    purge_confirmed_request_state(
                        c, request_is_orig, invoke_id);
                }
            }
        }

    }

function clear_mms_deferred_evidence(uid_to_clear: string)
    {
    local identify_directions: vector of bool;
    local identify_sequences: vector of count;
    local identify_pdus: vector of count;
    local identify_invokes: vector of count;
    for ( [uid, is_orig, sequence, pdu_type, invoke] in identify_evidence )
        if ( uid == uid_to_clear )
            {
            identify_directions[|identify_directions|] = is_orig;
            identify_sequences[|identify_sequences|] = sequence;
            identify_pdus[|identify_pdus|] = pdu_type;
            identify_invokes[|identify_invokes|] = invoke;
            }
    for ( index in identify_sequences )
        delete identify_evidence[
            uid_to_clear, identify_directions[index],
            identify_sequences[index], identify_pdus[index],
            identify_invokes[index]];

    local report_directions: vector of bool;
    local report_sequences: vector of count;
    for ( [report_uid, report_is_orig, report_sequence] in
          information_report_results_evidence )
        if ( report_uid == uid_to_clear )
            {
            report_directions[|report_directions|] = report_is_orig;
            report_sequences[|report_sequences|] = report_sequence;
            }
    for ( report_index in report_sequences )
        delete information_report_results_evidence[
            uid_to_clear, report_directions[report_index],
            report_sequences[report_index]];

    local point_directions: vector of bool;
    local point_sequences: vector of count;
    for ( [point_uid, point_is_orig, point_sequence] in
          point_value_shape_evidence )
        if ( point_uid == uid_to_clear )
            {
            point_directions[|point_directions|] = point_is_orig;
            point_sequences[|point_sequences|] = point_sequence;
            }
    for ( point_index in point_sequences )
        delete point_value_shape_evidence[
            uid_to_clear, point_directions[point_index],
            point_sequences[point_index]];

    local read_directions: vector of bool;
    local read_sequences: vector of count;
    local read_invokes: vector of count;
    for ( [read_uid, read_is_orig, read_sequence, read_invoke] in
          control_read_value_shape_evidence )
        if ( read_uid == uid_to_clear )
            {
            read_directions[|read_directions|] = read_is_orig;
            read_sequences[|read_sequences|] = read_sequence;
            read_invokes[|read_invokes|] = read_invoke;
            }
    for ( read_index in read_sequences )
        delete control_read_value_shape_evidence[
            uid_to_clear, read_directions[read_index],
            read_sequences[read_index], read_invokes[read_index]];
    clear_control_value_shapes(uid_to_clear, T);
    clear_control_value_shapes(uid_to_clear, F);
    }

function clear_confirmed_processing_state(uid_to_clear: string)
    {
    local confirmed_keys: vector of count;
    local confirmed_directions: vector of bool;
    for ( [uid, request_is_orig, invoke] in pending_confirmed )
        if ( uid == uid_to_clear )
            {
            confirmed_keys[|confirmed_keys|] = invoke;
            confirmed_directions[|confirmed_directions|] = request_is_orig;
            }
    for ( index in confirmed_keys )
        delete pending_confirmed[
            uid_to_clear, confirmed_directions[index], confirmed_keys[index]];

    local invalid_keys: vector of count;
    local invalid_directions: vector of bool;
    for ( [invalid_uid, invalid_is_orig, invalid_invoke] in
          invalid_confirmed_invokes )
        if ( invalid_uid == uid_to_clear )
            {
            invalid_keys[|invalid_keys|] = invalid_invoke;
            invalid_directions[|invalid_directions|] = invalid_is_orig;
            }
    for ( invalid_index in invalid_keys )
        delete invalid_confirmed_invokes[
            uid_to_clear, invalid_directions[invalid_index],
            invalid_keys[invalid_index]];

    clear_mms_deferred_evidence(uid_to_clear);
    }

event connection_state_remove(c: connection)
    {
    clear_confirmed_processing_state(c$uid);
    delete processing_acse_lifecycle_spdu[c$uid, T];
    delete processing_acse_lifecycle_spdu[c$uid, F];
    delete processing_session_cleanup_spdu[c$uid, T];
    delete processing_session_cleanup_spdu[c$uid, F];
    }

event ICCP::session_spdu_marker_v1(
    c: connection, is_orig: bool, spdu_type: count) &priority=-30
    {
    # A CONNECT replaces any stale association on the transport connection;
    # REFUSE, DISCONNECT, ABORT, and ABORT-ACCEPT are terminal even if nested
    # Presentation/ACSE decoding later fails. Remember the cleanup so a nested
    # legacy ACSE event does not repeat it.
    delete processing_acse_lifecycle_spdu[c$uid, is_orig];
    delete processing_session_cleanup_spdu[c$uid, is_orig];
    if ( spdu_type != 10 && spdu_type != 12 && spdu_type != 13 &&
         spdu_type != 25 && spdu_type != 26 )
        return;
    clear_transfer_processing_state(c$uid);
    clear_confirmed_processing_state(c$uid);
    clear_control_processing_state(c$uid);
    processing_session_cleanup_spdu[c$uid, is_orig] = spdu_type;
    }

event ICCP::cotp_lifecycle_v1(
    c: connection, is_orig: bool, tpdu_type: count) &priority=-30
    {
    if ( tpdu_type != 0xe0 && tpdu_type != 0xd0 &&
         tpdu_type != 0x80 &&
         tpdu_type != 0xc0 && tpdu_type != 0x70 )
        return;

    delete processing_acse_lifecycle_spdu[c$uid, T];
    delete processing_acse_lifecycle_spdu[c$uid, F];
    delete processing_session_cleanup_spdu[c$uid, T];
    delete processing_session_cleanup_spdu[c$uid, F];
    clear_transfer_processing_state(c$uid);
    clear_confirmed_processing_state(c$uid);
    clear_control_processing_state(c$uid);
    }

function clear_processing_after_observation_gap(c: connection)
    {
    delete processing_acse_lifecycle_spdu[c$uid, T];
    delete processing_acse_lifecycle_spdu[c$uid, F];
    delete processing_session_cleanup_spdu[c$uid, T];
    delete processing_session_cleanup_spdu[c$uid, F];
    clear_transfer_processing_state(c$uid);
    clear_confirmed_processing_state(c$uid);
    clear_control_processing_state(c$uid);
    }

event ICCP::stream_gap(
    c: connection, is_orig: bool, length: count) &priority=-30
    {
    clear_processing_after_observation_gap(c);
    }

event content_gap(
    c: connection, is_orig: bool, seq: count, length: count) &priority=-30
    {
    if ( lookup_connection_analyzer_id(
             c$id, Analyzer::ANALYZER_ICCP_TCP) == 0 )
        return;

    clear_processing_after_observation_gap(c);
    }

event ICCP::acse_lifecycle_v1(
    c: connection, is_orig: bool, apdu_type: count,
    spdu_type: count) &priority=-30
    {
    # The following compatibility acse_message supplies result details.  Save
    # only the Session envelope here and consume it exactly once there.
    processing_acse_lifecycle_spdu[c$uid, is_orig] = spdu_type;
    }

event ICCP::acse_message(
    c: connection, is_orig: bool, recognized: bool, apdu_type: count,
    application_context: string, association_result: int, reason: int,
    diagnostic_code: int, authentication_present: bool,
    authentication_length: count, is_opaque: bool, dispatch_mms: bool,
    payload_length: count) &priority=-30
    {
    local parser_lifecycle =
        [c$uid, is_orig] in processing_acse_lifecycle_spdu;
    local spdu_type: count = 0;
    if ( parser_lifecycle )
        {
        spdu_type = processing_acse_lifecycle_spdu[c$uid, is_orig];
        delete processing_acse_lifecycle_spdu[c$uid, is_orig];
        }
    local session_already_cleared = parser_lifecycle &&
        [c$uid, is_orig] in processing_session_cleanup_spdu &&
        processing_session_cleanup_spdu[c$uid, is_orig] == spdu_type;
    delete processing_session_cleanup_spdu[c$uid, is_orig];

    # Direct compatibility-event callers retain the historical terminal RLRE
    # behavior.  Parser callers carry Session context: NOT-FINISHED (8)
    # rejects a release and retains state, while DISCONNECT (10) completes it.
    local terminal = recognized &&
        ((apdu_type == 1 && association_result != 0) ||
         apdu_type == 4 ||
         (apdu_type == 3 && (! parser_lifecycle || spdu_type == 10)));
    if ( terminal && ! session_already_cleared )
        {
        clear_transfer_processing_state(c$uid);
        clear_confirmed_processing_state(c$uid);
        clear_control_processing_state(c$uid);
        }
    }

event ICCP::mms_error_message(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    modifier_position: int, error_class: count, error_code: int,
    additional_code: int, additional_description: string) &priority=-30
    {
    if ( pdu_type == 2 && invoke_id >= 0 )
        delete invalid_confirmed_invokes[
            c$uid, ! is_orig, int_to_count(invoke_id)];
    }

event ICCP::mms_conclude_result_v1(
    c: connection, response_is_orig: bool, request_is_orig: bool,
    accepted: bool)
    {
    if ( accepted )
        {
        clear_transfer_processing_state(c$uid);
        clear_confirmed_processing_state(c$uid);
        clear_control_processing_state(c$uid);
        }
    }
