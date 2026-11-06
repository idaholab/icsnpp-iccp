# Copyright 2026, Battelle Energy Alliance, LLC. All Rights Reserved.

################################################################################
##
## ICSNPP - ICCP
##
## This file preserves bounded MMS evidence used by ICCP policy processing.
##
## Christopher B. Peterson and Christian J Weelborg
## Idaho National Lab, November 2026
##
################################################################################

module ICCP;

# Policy consumers for the parser's complete bounded vector/shape evidence.
# Keep these tables independent of higher-level TASE.2 classification state:
# they preserve generic MMS facts without promoting them to protocol claims.

type PendingNameList: record {
    object_class_choice: count;
    object_class: int;
    scope: count;
    domain: string;
    continue_after: string;
};

global pending_name_lists: table[string, bool, count] of PendingNameList
    &read_expire=association_state_timeout;
global invalid_name_list_invokes: set[string, bool, count]
    &read_expire=association_state_timeout;

type PendingWriteEvidence: record {
    access_choice: count;
    selector_scope: count;
    selector_domain: string;
    selector_name: string;
    target_count_known: bool;
    target_count: count;
    value_count: count;
    pairing_status: string;
    target_scopes: vector of count;
    target_domains: vector of string;
    target_names: vector of string;
    value_choices: vector of count;
    value_raws: vector of string;
    value_raw_truncated: vector of bool;
    value_integer_values: vector of int;
    value_floating_values: vector of double;
    value_boolean_values: vector of bool;
    value_string_values: vector of string;
};

global pending_write_evidence:
    table[string, bool, count] of PendingWriteEvidence
    &read_expire=association_state_timeout;
global invalid_write_evidence_invokes: set[string, bool, count]
    &read_expire=association_state_timeout;
global evidence_acse_lifecycle_spdu: table[string, bool] of count
    &read_expire=association_state_timeout;
global evidence_session_cleanup_spdu: table[string, bool] of count
    &read_expire=association_state_timeout;

function evidence_provenance_name(code: count): string
    {
    if ( code == 1 ) return "verified";
    if ( code == 2 ) return "inferred";
    return "unknown";
    }

function evidence_scope_name(scope: count): string
    {
    if ( scope == 0 ) return "vcc";
    if ( scope == 1 ) return "icc";
    if ( scope == 2 ) return "aa";
    return "unknown";
    }

function evidence_bounded_text(value: string): string
    {
    if ( |value| <= 256 ) return value;
    return sub_bytes(value, 0, 256);
    }

function evidence_bounded_raw(raw: string): string
    {
    local retained = raw;
    if ( |retained| > max_logged_result_raw_bytes )
        retained = sub_bytes(retained, 0, max_logged_result_raw_bytes);
    return bytestring_to_hexstr(retained);
    }

function evidence_raw_prefix(raw: string): string
    {
    if ( |raw| <= max_logged_result_raw_bytes ) return raw;
    return sub_bytes(raw, 0, max_logged_result_raw_bytes);
    }

function pending_name_list_count(uid: string): count
    {
    local total: count = 0;
    for ( [entry_uid, request_is_orig, invoke] in pending_name_lists )
        if ( entry_uid == uid ) ++total;
    for ( [invalid_uid, invalid_is_orig, invalid_invoke] in
          invalid_name_list_invokes )
        if ( invalid_uid == uid ) ++total;
    return total;
    }

function pending_write_evidence_count(uid: string): count
    {
    local total: count = 0;
    for ( [entry_uid, request_is_orig, invoke] in pending_write_evidence )
        if ( entry_uid == uid ) ++total;
    for ( [invalid_uid, invalid_is_orig, invalid_invoke] in
          invalid_write_evidence_invokes )
        if ( invalid_uid == uid ) ++total;
    return total;
    }

function generic_confirmed_service_conflicts(
    c: connection, is_orig: bool, invoke: count, service_tag: count): bool
    {
    if ( [c$uid, is_orig, invoke] !in pending_confirmed ) return F;
    return pending_confirmed[c$uid, is_orig, invoke]$service_tag !=
        service_tag;
    }

function base_name_list_record(
    c: connection, is_orig: bool, invoke_id: int,
    observation_kind: string, provenance: count): ObjectInfo
    {
    return [
        $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
        $association_kind=association_kind(c),
        $association_phase=association_phase(c),
        $endpoint_role=endpoint_role(c, is_orig),
        $observation_kind=observation_kind,
        $operation="get_name_list", $invoke_id=invoke_id,
        $object_scope="unknown", $object_name="",
        $provenance=evidence_provenance_name(provenance),
        $stream_completeness=output_completeness(c, is_orig)
    ];
    }

function add_name_list_request(
    rec: ObjectInfo, pending: PendingNameList): ObjectInfo
    {
    rec$object_class_choice = pending$object_class_choice;
    rec$object_class = pending$object_class;
    rec$object_scope = evidence_scope_name(pending$scope);
    if ( pending$domain != "" ) rec$object_domain = pending$domain;
    if ( pending$continue_after != "" )
        rec$continue_after = pending$continue_after;
    return rec;
    }

event ICCP::mms_get_name_list_evidence_v1(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    object_class_choice: count, object_class: int,
    object_scope: count, object_domain: string,
    continue_after: string, identifier_count: count,
    identifiers: vector of string, more_follows: bool,
    provenance: count)
    {
    if ( invoke_id < 0 || (pdu_type != 0 && pdu_type != 1) ) return;
    local key = int_to_count(invoke_id);

    if ( pdu_type == 0 )
        {
        local name_request_state: PendingNameList = [
            $object_class_choice=object_class_choice,
            $object_class=object_class, $scope=object_scope,
            $domain=object_domain, $continue_after=continue_after
        ];
        local outcome = "requested";
        local other_service_reused =
            [c$uid, is_orig, key] in pending_write_evidence ||
            [c$uid, is_orig, key] in invalid_write_evidence_invokes ||
            generic_confirmed_service_conflicts(c, is_orig, key, 1) ||
            [c$uid, is_orig, key] in invalid_confirmed_invokes;
        if ( other_service_reused )
            {
            # Invoke IDs are unique across confirmed services for one MMS
            # user.  Invalidate any evidence-family request already using it
            # instead of allowing a later response to pick one arbitrarily.
            delete pending_write_evidence[c$uid, is_orig, key];
            add invalid_write_evidence_invokes[c$uid, is_orig, key];
            add invalid_name_list_invokes[c$uid, is_orig, key];
            outcome = "invoke_reused";
            }
        else if ( [c$uid, is_orig, key] in pending_name_lists )
            {
            delete pending_name_lists[c$uid, is_orig, key];
            add invalid_name_list_invokes[c$uid, is_orig, key];
            outcome = "invoke_reused";
            }
        else if ( [c$uid, is_orig, key] in invalid_name_list_invokes )
            outcome = "invoke_reused";
        else if ( [c$uid, is_orig, key] !in pending_confirmed &&
                  pending_confirmed_count(c$uid) >= max_pending_confirmed )
            {
            # Respect the association-wide confirmed-request budget in either
            # completion-hook order.  If the aggregate hook ran first, the
            # current key is present only when generic admission succeeded.
            outcome = "state_limit";
            }
        else if ( pending_name_list_count(c$uid) >= max_pending_confirmed )
            {
            outcome = "state_limit";
            event ICCP::resource_limit_exceeded(
                c, is_orig, "pending_name_lists", max_pending_confirmed,
                pending_name_list_count(c$uid), invoke_id);
            }
        else
            pending_name_lists[c$uid, is_orig, key] = name_request_state;

        local request_log = base_name_list_record(
            c, is_orig, invoke_id, "name_list_request", provenance);
        request_log = add_name_list_request(request_log, name_request_state);
        request_log$result_pairing_status = outcome;
        Log::write(ICCP::OBJECT_LOG, request_log);
        return;
        }

    local response_request_is_orig = ! is_orig;
    local response_status = "unexpected_response";
    local have_request = F;
    local matched_name_request: PendingNameList;
    if ( [c$uid, response_request_is_orig, key] in pending_name_lists )
        {
        have_request = T;
        matched_name_request =
            pending_name_lists[c$uid, response_request_is_orig, key];
        response_status = "matched_response";
        }
    else if ( [c$uid, response_request_is_orig, key] in
              invalid_name_list_invokes )
        response_status = "ambiguous_response";
    else if ( [c$uid, is_orig, key] in pending_name_lists ||
              [c$uid, is_orig, key] in invalid_name_list_invokes )
        response_status = "direction_mismatch";

    if ( identifier_count != |identifiers| )
        response_status = "evidence_mismatch";

    local logged = identifier_count < max_logged_information_report_results ?
        identifier_count : max_logged_information_report_results;
    if ( logged > |identifiers| ) logged = |identifiers|;
    local omitted = identifier_count >= logged ? identifier_count - logged : 0;

    local summary = base_name_list_record(
        c, is_orig, invoke_id, "name_list_response", provenance);
    if ( have_request )
        summary = add_name_list_request(summary, matched_name_request);
    summary$result_count = identifier_count;
    summary$logged_result_count = logged;
    summary$omitted_result_count = omitted;
    summary$more_follows = more_follows;
    summary$result_pairing_status = response_status;
    Log::write(ICCP::OBJECT_LOG, summary);

    local index: count = 0;
    while ( index < logged )
        {
        local item = base_name_list_record(
            c, is_orig, invoke_id, "name_list_identifier", provenance);
        if ( have_request )
            item = add_name_list_request(item, matched_name_request);
        item$object_name = identifiers[index];
        item$result_count = identifier_count;
        item$result_index = index;
        item$more_follows = more_follows;
        item$result_pairing_status = response_status;
        Log::write(ICCP::OBJECT_LOG, item);
        ++index;
        }

    if ( response_status != "direction_mismatch" )
        {
        delete pending_name_lists[c$uid, response_request_is_orig, key];
        delete invalid_name_list_invokes[
            c$uid, response_request_is_orig, key];
        }
    }

function base_write_record(
    c: connection, is_orig: bool, invoke_id: int,
    classification: string, outcome: string,
    provenance: count): ControlInfo
    {
    return [
        $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
        $association_kind=association_kind(c),
        $association_phase=association_phase(c),
        $endpoint_role=endpoint_role(c, is_orig),
        $classification=classification, $outcome=outcome,
        $invoke_id=invoke_id,
        $provenance=evidence_provenance_name(provenance),
        $stream_completeness=output_completeness(c, is_orig)
    ];
    }

function add_write_identity(
    rec: ControlInfo, pending: PendingWriteEvidence,
    index: count): ControlInfo
    {
    rec$access_choice = pending$access_choice;
    rec$target_count_known = pending$target_count_known;
    rec$target_count = pending$target_count;
    rec$value_count = pending$value_count;
    rec$pairing_status = pending$pairing_status;
    if ( pending$access_choice == 0 &&
         index < |pending$target_scopes| &&
         index < |pending$target_domains| &&
         index < |pending$target_names| )
        {
        rec$object_scope = evidence_scope_name(pending$target_scopes[index]);
        if ( pending$target_domains[index] != "" )
            rec$object_domain = pending$target_domains[index];
        rec$object_name = pending$target_names[index];
        }
    else if ( pending$selector_name != "" )
        {
        rec$object_scope = evidence_scope_name(pending$selector_scope);
        if ( pending$selector_domain != "" )
            rec$object_domain = pending$selector_domain;
        rec$object_name = pending$selector_name;
        }
    return rec;
    }

function add_write_value(
    rec: ControlInfo, pending: PendingWriteEvidence,
    index: count): ControlInfo
    {
    if ( index >= |pending$value_choices| ) return rec;
    local choice = pending$value_choices[index];
    rec$value_type = choice;
    if ( index < |pending$value_raws| )
        rec$value_raw = evidence_bounded_raw(pending$value_raws[index]);
    if ( index < |pending$value_raw_truncated| )
        rec$value_raw_truncated = pending$value_raw_truncated[index];
    if ( (choice == 5 || choice == 6 || choice == 13 || choice == 17) &&
         index < |pending$value_integer_values| )
        rec$integer_value = pending$value_integer_values[index];
    else if ( choice == 7 && index < |pending$value_floating_values| )
        rec$floating_value = pending$value_floating_values[index];
    else if ( choice == 3 && index < |pending$value_boolean_values| )
        rec$boolean_value = pending$value_boolean_values[index];
    else if ( (choice == 10 || choice == 16) &&
              index < |pending$value_string_values| )
        rec$string_value = evidence_bounded_text(
            pending$value_string_values[index]);
    return rec;
    }

event ICCP::mms_write_evidence_v1(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    access_choice: count, selector_scope: count,
    selector_domain: string, selector_name: string,
    target_count_known: bool, target_count: count, value_count: count,
    target_scopes: vector of count,
    target_domains: vector of string,
    target_names: vector of string,
    value_choices: vector of count,
    value_raws: vector of string,
    value_integer_values: vector of int,
    value_floating_values: vector of double,
    value_boolean_values: vector of bool,
    value_string_values: vector of string,
    result_count: count,
    result_successes: vector of bool,
    result_errors: vector of int,
    provenance: count)
    {
    if ( invoke_id < 0 || (pdu_type != 0 && pdu_type != 1) ) return;
    local key = int_to_count(invoke_id);

    if ( pdu_type == 0 )
        {
        local values_complete =
            value_count == |value_choices| &&
            value_count == |value_raws| &&
            value_count == |value_integer_values| &&
            value_count == |value_floating_values| &&
            value_count == |value_boolean_values| &&
            value_count == |value_string_values|;
        local targets_complete =
            (access_choice == 0 && target_count_known &&
             target_count == value_count &&
             target_count == |target_scopes| &&
             target_count == |target_domains| &&
             target_count == |target_names|) ||
            (access_choice == 1 && ! target_count_known &&
             |target_scopes| == 0 && |target_domains| == 0 &&
             |target_names| == 0 && selector_name != "");
        local request_pairing = ! values_complete || ! targets_complete ?
            "evidence_mismatch" : access_choice == 0 ?
                "explicit_complete" : "named_list_ordered";
        local request_logged_count = value_count <
            max_logged_information_report_results ? value_count :
                max_logged_information_report_results;
        if ( request_logged_count > |value_choices| )
            request_logged_count = |value_choices|;
        if ( ! values_complete || ! targets_complete )
            request_logged_count = 0;

        local retained_target_scopes: vector of count;
        local retained_target_domains: vector of string;
        local retained_target_names: vector of string;
        local retained_choices: vector of count;
        local retained_raws: vector of string;
        local retained_raw_truncated: vector of bool;
        local retained_integers: vector of int;
        local retained_floats: vector of double;
        local retained_booleans: vector of bool;
        local retained_strings: vector of string;
        local index: count = 0;
        while ( index < request_logged_count )
            {
            if ( index < |target_scopes| )
                retained_target_scopes[index] = target_scopes[index];
            if ( index < |target_domains| )
                retained_target_domains[index] = target_domains[index];
            if ( index < |target_names| )
                retained_target_names[index] = target_names[index];
            retained_choices[index] = value_choices[index];
            retained_raws[index] = evidence_raw_prefix(value_raws[index]);
            retained_raw_truncated[index] =
                |value_raws[index]| > max_logged_result_raw_bytes;
            retained_integers[index] = value_integer_values[index];
            retained_floats[index] = value_floating_values[index];
            retained_booleans[index] = value_boolean_values[index];
            retained_strings[index] = evidence_bounded_text(
                value_string_values[index]);
            ++index;
            }

        local request_evidence: PendingWriteEvidence = [
            $access_choice=access_choice,
            $selector_scope=selector_scope,
            $selector_domain=selector_domain, $selector_name=selector_name,
            $target_count_known=target_count_known,
            $target_count=target_count, $value_count=value_count,
            $pairing_status=request_pairing,
            $target_scopes=retained_target_scopes,
            $target_domains=retained_target_domains,
            $target_names=retained_target_names,
            $value_choices=retained_choices,
            $value_raws=retained_raws,
            $value_raw_truncated=retained_raw_truncated,
            $value_integer_values=retained_integers,
            $value_floating_values=retained_floats,
            $value_boolean_values=retained_booleans,
            $value_string_values=retained_strings
        ];

        local request_outcome = request_pairing == "evidence_mismatch" ?
            "evidence_mismatch" : "requested";
        local other_service_reused =
            [c$uid, is_orig, key] in pending_name_lists ||
            [c$uid, is_orig, key] in invalid_name_list_invokes ||
            generic_confirmed_service_conflicts(c, is_orig, key, 5) ||
            [c$uid, is_orig, key] in invalid_confirmed_invokes;
        if ( other_service_reused )
            {
            delete pending_name_lists[c$uid, is_orig, key];
            add invalid_name_list_invokes[c$uid, is_orig, key];
            add invalid_write_evidence_invokes[c$uid, is_orig, key];
            request_outcome = "invoke_reused";
            }
        else if ( [c$uid, is_orig, key] in pending_write_evidence )
            {
            delete pending_write_evidence[c$uid, is_orig, key];
            add invalid_write_evidence_invokes[c$uid, is_orig, key];
            request_outcome = "invoke_reused";
            }
        else if ( [c$uid, is_orig, key] in
                  invalid_write_evidence_invokes )
            request_outcome = "invoke_reused";
        else if ( [c$uid, is_orig, key] !in pending_confirmed &&
                  pending_confirmed_count(c$uid) >= max_pending_confirmed )
            {
            request_outcome = "state_limit";
            }
        else if ( request_pairing != "evidence_mismatch" &&
                  pending_write_evidence_count(c$uid) >=
                      max_pending_controls )
            {
            request_outcome = "state_limit";
            event ICCP::resource_limit_exceeded(
                c, is_orig, "pending_write_evidence", max_pending_controls,
                pending_write_evidence_count(c$uid), invoke_id);
            }
        else if ( request_pairing != "evidence_mismatch" )
            pending_write_evidence[c$uid, is_orig, key] = request_evidence;

        local request_summary = base_write_record(
            c, is_orig, invoke_id, "write_evidence", request_outcome,
            provenance);
        request_summary = add_write_identity(
            request_summary, request_evidence, 0);
        request_summary$logged_item_count = request_logged_count;
        request_summary$omitted_item_count =
            value_count >= request_logged_count ?
                value_count - request_logged_count : 0;
        Log::write(ICCP::CONTROL_LOG, request_summary);

        index = 0;
        while ( index < request_logged_count )
            {
            local request_item = base_write_record(
                c, is_orig, invoke_id, "write_value", "observed",
                provenance);
            request_item$item_index = index;
            request_item = add_write_identity(
                request_item, request_evidence, index);
            request_item = add_write_value(
                request_item, request_evidence, index);
            Log::write(ICCP::CONTROL_LOG, request_item);
            ++index;
            }
        return;
        }

    local results_complete =
        result_count == |result_successes| &&
        result_count == |result_errors|;
    local request_is_orig = ! is_orig;
    local have_request = F;
    local direction_valid = T;
    local ambiguous = F;
    local matched_write: PendingWriteEvidence;
    if ( [c$uid, request_is_orig, key] in pending_write_evidence )
        {
        have_request = T;
        matched_write =
            pending_write_evidence[c$uid, request_is_orig, key];
        }
    else if ( [c$uid, request_is_orig, key] in
              invalid_write_evidence_invokes )
        ambiguous = T;
    else if ( [c$uid, is_orig, key] in pending_write_evidence )
        {
        request_is_orig = is_orig;
        have_request = T;
        direction_valid = F;
        matched_write =
            pending_write_evidence[c$uid, request_is_orig, key];
        }
    else if ( [c$uid, is_orig, key] in invalid_write_evidence_invokes )
        {
        request_is_orig = is_orig;
        ambiguous = T;
        direction_valid = F;
        }

    local failure_count: count = 0;
    local result_index: count = 0;
    local observed_result_count = result_count < |result_successes| ?
        result_count : |result_successes|;
    while ( result_index < observed_result_count )
        {
        if ( ! result_successes[result_index] ) ++failure_count;
        ++result_index;
        }

    local pairing = ! results_complete ? "evidence_mismatch" :
        ! have_request ? ambiguous ? "ambiguous_response" :
            "unmatched_response" :
        ! direction_valid ? "direction_mismatch" :
        result_count != matched_write$value_count ? "count_mismatch" :
            matched_write$pairing_status;
    local outcome = pairing == "direction_mismatch" ?
        "direction_mismatch" : pairing == "ambiguous_response" ?
        "ambiguous_response" : pairing == "unmatched_response" ?
        "unexpected_response" : pairing == "evidence_mismatch" ?
        "evidence_mismatch" : pairing == "count_mismatch" ?
        "count_mismatch" : failure_count == 0 ?
        "confirmed" : "partial_or_failed";
    local retained_count = result_count <
        max_logged_information_report_results ? result_count :
            max_logged_information_report_results;
    if ( retained_count > |result_successes| )
        retained_count = |result_successes|;

    local summary = base_write_record(
        c, is_orig, invoke_id, "write_evidence", outcome, provenance);
    summary$result_count = result_count;
    # A declared count cannot be partitioned into successes/failures unless
    # both result vectors are complete.  Keep those optional fields absent on
    # malformed public-event input instead of manufacturing impossible totals.
    if ( results_complete )
        {
        summary$success_count = result_count - failure_count;
        summary$failure_count = failure_count;
        }
    summary$logged_item_count = retained_count;
    summary$omitted_item_count = result_count >= retained_count ?
        result_count - retained_count : 0;
    if ( have_request )
        summary = add_write_identity(summary, matched_write, 0);
    summary$pairing_status = pairing;
    Log::write(ICCP::CONTROL_LOG, summary);

    result_index = 0;
    while ( result_index < retained_count )
        {
        local item_outcome = result_successes[result_index] ?
            "succeeded" : "failed";
        local item = base_write_record(
            c, is_orig, invoke_id, "write_result", item_outcome,
            provenance);
        item$item_index = result_index;
        item$result_count = result_count;
        item$result_success = result_successes[result_index];
        item$pairing_status = pairing;
        if ( ! result_successes[result_index] &&
             result_index < |result_errors| )
            item$result_error = result_errors[result_index];
        if ( have_request && direction_valid &&
             (pairing == "explicit_complete" ||
              pairing == "named_list_ordered") )
            {
            item = add_write_identity(item, matched_write, result_index);
            item = add_write_value(item, matched_write, result_index);
            item$pairing_status = pairing;
            }
        Log::write(ICCP::CONTROL_LOG, item);
        ++result_index;
        }

    if ( direction_valid )
        {
        delete pending_write_evidence[c$uid, request_is_orig, key];
        delete invalid_write_evidence_invokes[
            c$uid, request_is_orig, key];
        }
    }

event ICCP::mms_type_description_evidence_v1(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    type_choice: count, constructed: bool, signed_value: int,
    boolean_value: bool, format_width: int, exponent_width: int,
    raw: string, packed: bool, number_of_elements: int,
    component_count: count, node_count: count,
    maximum_depth: count, provenance: count)
    {
    if ( pdu_type != 1 || invoke_id < 0 ) return;
    local rec: TransferInfo = [
        $ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
        $action="type_description", $outcome="observed",
        $invoke_id=invoke_id, $type_choice=type_choice,
        $type_constructed=constructed,
        $type_raw=evidence_bounded_raw(raw),
        $type_raw_truncated=|raw| > max_logged_result_raw_bytes,
        $type_node_count=node_count,
        $type_maximum_depth=maximum_depth,
        $provenance=evidence_provenance_name(provenance),
        $stream_completeness=output_completeness(c, is_orig)
    ];
    if ( type_choice == 4 || type_choice == 5 || type_choice == 6 ||
         type_choice == 9 || type_choice == 10 || type_choice == 13 ||
         type_choice == 16 )
        rec$type_signed_value = signed_value;
    else if ( type_choice == 7 )
        {
        rec$type_format_width = format_width;
        rec$type_exponent_width = exponent_width;
        }
    else if ( type_choice == 12 )
        rec$type_boolean_value = boolean_value;
    if ( type_choice == 1 )
        {
        rec$type_packed = packed;
        rec$type_number_of_elements = number_of_elements;
        }
    else if ( type_choice == 2 )
        {
        rec$type_packed = packed;
        rec$type_component_count = component_count;
        }
    # This event carries its own provenance.  Do not route through the legacy
    # helper, which intentionally derives provenance from aggregate-event
    # state for unversioned hooks.
    Log::write(ICCP::TRANSFER_LOG, rec);
    }

event ICCP::mms_error_message(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    modifier_position: int, error_class: count, error_code: int,
    additional_code: int, additional_description: string)
    {
    if ( pdu_type != 2 || invoke_id < 0 ) return;
    local key = int_to_count(invoke_id);
    local request_is_orig = ! is_orig;
    delete pending_name_lists[c$uid, request_is_orig, key];
    delete invalid_name_list_invokes[c$uid, request_is_orig, key];
    delete pending_write_evidence[c$uid, request_is_orig, key];
    delete invalid_write_evidence_invokes[c$uid, request_is_orig, key];
    }

event ICCP::mms_reject_message_v1(
    c: connection, is_orig: bool, invoke_id: int,
    reason_tag: count, reason: int, provenance: count)
    {
    if ( invoke_id < 0 || reason_tag != 1 ) return;
    local key = int_to_count(invoke_id);
    local request_is_orig = ! is_orig;
    delete pending_name_lists[c$uid, request_is_orig, key];
    delete invalid_name_list_invokes[c$uid, request_is_orig, key];
    delete pending_write_evidence[c$uid, request_is_orig, key];
    delete invalid_write_evidence_invokes[c$uid, request_is_orig, key];
    }

function clear_evidence_state(uid_to_clear: string)
    {
    local name_keys: vector of count;
    local name_directions: vector of bool;
    for ( [uid, direction, invoke] in pending_name_lists )
        if ( uid == uid_to_clear )
            {
            name_keys[|name_keys|] = invoke;
            name_directions[|name_directions|] = direction;
            }
    for ( index in name_keys )
        delete pending_name_lists[
            uid_to_clear, name_directions[index], name_keys[index]];

    local invalid_name_keys: vector of count;
    local invalid_name_directions: vector of bool;
    for ( [invalid_uid, invalid_direction, invalid_invoke] in
          invalid_name_list_invokes )
        if ( invalid_uid == uid_to_clear )
            {
            invalid_name_keys[|invalid_name_keys|] = invalid_invoke;
            invalid_name_directions[|invalid_name_directions|] =
                invalid_direction;
            }
    for ( invalid_index in invalid_name_keys )
        delete invalid_name_list_invokes[
            uid_to_clear, invalid_name_directions[invalid_index],
            invalid_name_keys[invalid_index]];

    local write_keys: vector of count;
    local write_directions: vector of bool;
    for ( [write_uid, write_direction, write_invoke] in
          pending_write_evidence )
        if ( write_uid == uid_to_clear )
            {
            write_keys[|write_keys|] = write_invoke;
            write_directions[|write_directions|] = write_direction;
            }
    for ( write_index in write_keys )
        delete pending_write_evidence[
            uid_to_clear, write_directions[write_index],
            write_keys[write_index]];

    local invalid_write_keys: vector of count;
    local invalid_write_directions: vector of bool;
    for ( [invalid_write_uid, invalid_write_direction,
           invalid_write_invoke] in invalid_write_evidence_invokes )
        if ( invalid_write_uid == uid_to_clear )
            {
            invalid_write_keys[|invalid_write_keys|] = invalid_write_invoke;
            invalid_write_directions[|invalid_write_directions|] =
                invalid_write_direction;
            }
    for ( invalid_write_index in invalid_write_keys )
        delete invalid_write_evidence_invokes[
            uid_to_clear, invalid_write_directions[invalid_write_index],
            invalid_write_keys[invalid_write_index]];
    }

event connection_state_remove(c: connection)
    {
    clear_evidence_state(c$uid);
    delete evidence_acse_lifecycle_spdu[c$uid, T];
    delete evidence_acse_lifecycle_spdu[c$uid, F];
    delete evidence_session_cleanup_spdu[c$uid, T];
    delete evidence_session_cleanup_spdu[c$uid, F];
    }

event ICCP::session_spdu_marker_v1(
    c: connection, is_orig: bool, spdu_type: count) &priority=-30
    {
    delete evidence_acse_lifecycle_spdu[c$uid, is_orig];
    delete evidence_session_cleanup_spdu[c$uid, is_orig];
    if ( spdu_type != 10 && spdu_type != 12 && spdu_type != 13 &&
         spdu_type != 25 && spdu_type != 26 )
        return;
    clear_evidence_state(c$uid);
    evidence_session_cleanup_spdu[c$uid, is_orig] = spdu_type;
    }

event ICCP::cotp_lifecycle_v1(
    c: connection, is_orig: bool, tpdu_type: count) &priority=-30
    {
    if ( tpdu_type != 0xe0 && tpdu_type != 0xd0 &&
         tpdu_type != 0x80 &&
         tpdu_type != 0xc0 && tpdu_type != 0x70 )
        return;

    delete evidence_acse_lifecycle_spdu[c$uid, T];
    delete evidence_acse_lifecycle_spdu[c$uid, F];
    delete evidence_session_cleanup_spdu[c$uid, T];
    delete evidence_session_cleanup_spdu[c$uid, F];
    clear_evidence_state(c$uid);
    }

function clear_evidence_after_observation_gap(c: connection)
    {
    delete evidence_acse_lifecycle_spdu[c$uid, T];
    delete evidence_acse_lifecycle_spdu[c$uid, F];
    delete evidence_session_cleanup_spdu[c$uid, T];
    delete evidence_session_cleanup_spdu[c$uid, F];
    clear_evidence_state(c$uid);
    }

event ICCP::stream_gap(
    c: connection, is_orig: bool, length: count) &priority=-30
    {
    clear_evidence_after_observation_gap(c);
    }

event content_gap(
    c: connection, is_orig: bool, seq: count, length: count) &priority=-30
    {
    if ( lookup_connection_analyzer_id(
             c$id, Analyzer::ANALYZER_ICCP_TCP) == 0 )
        return;

    clear_evidence_after_observation_gap(c);
    }

event ICCP::acse_lifecycle_v1(
    c: connection, is_orig: bool, apdu_type: count,
    spdu_type: count) &priority=-30
    {
    evidence_acse_lifecycle_spdu[c$uid, is_orig] = spdu_type;
    }

event ICCP::parser_error(c: connection, reason: string) &priority=-30
    {
    # A failed nested ACSE parse has no following compatibility event to
    # consume its Session context.  Retain long-lived request evidence, but
    # discard these one-shot envelope tokens so they cannot affect a later
    # direct or recovered parser event.
    delete evidence_acse_lifecycle_spdu[c$uid, T];
    delete evidence_acse_lifecycle_spdu[c$uid, F];
    delete evidence_session_cleanup_spdu[c$uid, T];
    delete evidence_session_cleanup_spdu[c$uid, F];
    }

event ICCP::acse_message(
    c: connection, is_orig: bool, recognized: bool, apdu_type: count,
    application_context: string, association_result: int, reason: int,
    diagnostic_code: int, authentication_present: bool,
    authentication_length: count, is_opaque: bool, dispatch_mms: bool,
    payload_length: count) &priority=-30
    {
    local parser_lifecycle =
        [c$uid, is_orig] in evidence_acse_lifecycle_spdu;
    local spdu_type: count = 0;
    if ( parser_lifecycle )
        {
        spdu_type = evidence_acse_lifecycle_spdu[c$uid, is_orig];
        delete evidence_acse_lifecycle_spdu[c$uid, is_orig];
        }
    local session_already_cleared = parser_lifecycle &&
        [c$uid, is_orig] in evidence_session_cleanup_spdu &&
        evidence_session_cleanup_spdu[c$uid, is_orig] == spdu_type;
    delete evidence_session_cleanup_spdu[c$uid, is_orig];
    local terminal = recognized &&
        ((apdu_type == 1 && association_result != 0) ||
         apdu_type == 4 ||
         (apdu_type == 3 && (! parser_lifecycle || spdu_type == 10)));
    if ( terminal && ! session_already_cleared )
        clear_evidence_state(c$uid);
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
    result_flags_raw: string, result_timestamp_value: int) &priority=-30
    {
    if ( recognized && semantic_decoded && pdu_type == 0 && invoke_id >= 0 )
        {
        local request_key = int_to_count(invoke_id);
        if ( [c$uid, is_orig, request_key] in invalid_confirmed_invokes )
            {
            local had_name =
                [c$uid, is_orig, request_key] in pending_name_lists;
            local had_write =
                [c$uid, is_orig, request_key] in pending_write_evidence;
            delete pending_name_lists[c$uid, is_orig, request_key];
            delete pending_write_evidence[c$uid, is_orig, request_key];
            if ( had_name || service_tag == 1 )
                add invalid_name_list_invokes[
                    c$uid, is_orig, request_key];
            if ( had_write || service_tag == 5 )
                add invalid_write_evidence_invokes[
                    c$uid, is_orig, request_key];
            }
        else if ( [c$uid, is_orig, request_key] !in pending_confirmed )
            {
            # The generic confirmed-request tracker owns the association-wide
            # cap.  A specialized hook may have run first and tentatively
            # retained this request; discard it when generic admission fails.
            delete pending_name_lists[c$uid, is_orig, request_key];
            delete invalid_name_list_invokes[c$uid, is_orig, request_key];
            delete pending_write_evidence[c$uid, is_orig, request_key];
            delete invalid_write_evidence_invokes[
                c$uid, is_orig, request_key];
            }
        }
    if ( recognized && semantic_decoded && invoke_id >= 0 &&
         pdu_type == 6 )
        {
        # A successful Cancel-Response is terminal for the peer-originated
        # confirmed request named by this invoke ID.  Reject cannot be
        # retired here: its direction depends on rejectReasonTag, which this
        # aggregate event intentionally does not carry.
        local terminal_key = int_to_count(invoke_id);
        local terminal_request_is_orig = ! is_orig;
        delete pending_name_lists[
            c$uid, terminal_request_is_orig, terminal_key];
        delete invalid_name_list_invokes[
            c$uid, terminal_request_is_orig, terminal_key];
        delete pending_write_evidence[
            c$uid, terminal_request_is_orig, terminal_key];
        delete invalid_write_evidence_invokes[
            c$uid, terminal_request_is_orig, terminal_key];
        }
    }

event ICCP::mms_conclude_result_v1(
    c: connection, response_is_orig: bool, request_is_orig: bool,
    accepted: bool)
    {
    if ( accepted ) clear_evidence_state(c$uid);
    }
