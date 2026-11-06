# Copyright 2026, Battelle Energy Alliance, LLC. All Rights Reserved.

################################################################################
##
## ICSNPP - ICCP
##
## This file manages ICCP association lifecycle and connection state.
##
## Christopher B. Peterson and Christian J Weelborg
## Idaho National Lab, November 2026
##
################################################################################

module ICCP;

export {
    type PendingRead: record {
        scope: count;
        domain: string;
        name: string;
        category: count;
        # This implementation conservatively promotes only from a verified,
        # single-item explicit-variable Read.  The single-item condition is a
        # confidence boundary, not a claim that IEC forbids batched Reads.
        bootstrap_eligible: bool &default=F;
    };

    type AssociationState: record {
        association_generation: count;
        phase: string;
        presentation_profile: bool;
        acse_association: bool;
        mms_negotiation: bool;
        tase2_evidence: bool;
        originator_known: bool;
        originator_is_orig: bool;
        association_request_pending: bool;
        association_request_has_mms: bool;
        association_request_context: string;
        authentication_offered: bool;
        authentication_length: count;
        authentication_request_is_orig: bool;
        presentation_context_id: count;
        abstract_syntax: string;
        transfer_syntax: string;
        application_context: string;
        parameter_cbb: string;
        services_supported: string;
        # Compatibility union of the currently trusted bilateral domains from
        # either serving endpoint.  Internal policy must use
        # bilateral_domains_by_server so identically spelled Domains in the
        # two endpoint VCCs cannot contaminate one another.
        bilateral_domains: set[string];
        bilateral_domains_by_server: table[bool] of string;
        # IEC 60870-6-503 permits both peers to serve on one association, but
        # each serving VCC has exactly one Domain for the peer control centre.
        # Conflicting successful bootstrap observations make only that
        # endpoint's identity untrustworthy until the association is reset.
        ambiguous_bilateral_domain_servers: set[bool];
        # Invoke IDs are scoped to the request sender.  Both endpoints may
        # therefore have an outstanding request with the same numeric ID.
        pending_reads: table[bool, count] of PendingRead;
        # Reusing an outstanding Read invoke ID makes its response identity
        # ambiguous.  Retain that fact until a terminal response/error rather
        # than allowing a later request to recreate trusted correlation.
        invalid_read_invokes: set[bool, count];
        # A response is terminal immediately, but aggregate logging may be a
        # sibling parser event delivered in either order.  Retain its identity
        # until a zero-delay cleanup while preventing duplicate promotion or a
        # following request from being mistaken for invoke-ID reuse.
        completed_read_invokes: set[bool, count];
        # Conclude has no invoke ID, so retain the requesting endpoint itself.
        # A response/error is terminal only for the peer's outstanding request.
        pending_concludes: set[bool];
    };

    const association_state_timeout = 1hr &redef;
    const max_bilateral_domains = 64 &redef;
    const max_pending_reads = 128 &redef;

    global association_kind: function(c: connection): string;
    global association_phase: function(c: connection): string;
    global endpoint_role: function(c: connection, is_orig: bool): string;
    global operation_name: function(operation: count): string;
    global is_bilateral_domain: function(c: connection, domain: string): bool;
    global is_bilateral_domain_for_server: function(
        c: connection, server_is_orig: bool, domain: string): bool;
    global pending_read: function(c: connection, invoke_id: int): PendingRead;
    global pending_read_for_response: function(
        c: connection, response_is_orig: bool,
        invoke_id: int): PendingRead;
    global retire_pending_read_for_response: function(
        c: connection, response_is_orig: bool, invoke_id: int);
}

global associations: table[string] of AssociationState
    &read_expire=association_state_timeout;
global state_acse_lifecycle_spdu: table[string, bool] of count
    &read_expire=association_state_timeout;
global state_presentation_spdu: table[string, bool] of count
    &read_expire=association_state_timeout;
global retire_completed_read_v1: event(
    c: connection, request_is_orig: bool, invoke_id: count,
    association_generation: count);
# One-event token for legacy script callers that emit only mms_message.  The
# high-priority state handler can still see whether the parser marker exists;
# a low-priority handler then retires after all normal policy consumers.
global direct_read_response_retirements: set[string, bool, count]
    &read_expire=association_state_timeout;

function initial_state(): AssociationState
    {
    local bilateral_domains: set[string] = set();
    local bilateral_domains_by_server: table[bool] of string = table();
    local ambiguous_bilateral_domain_servers: set[bool] = set();
    local pending_reads: table[bool, count] of PendingRead = table();
    local invalid_read_invokes: set[bool, count] = set();
    local completed_read_invokes: set[bool, count] = set();
    local pending_concludes: set[bool] = set();

    return [
        $association_generation=1,
        $phase="new",
        $presentation_profile=F,
        $acse_association=F,
        $mms_negotiation=F,
        $tase2_evidence=F,
        $originator_known=F,
        $originator_is_orig=F,
        $association_request_pending=F,
        $association_request_has_mms=F,
        $association_request_context="",
        $authentication_offered=F,
        $authentication_length=0,
        $authentication_request_is_orig=F,
        $presentation_context_id=0,
        $abstract_syntax="",
        $transfer_syntax="",
        $application_context="",
        $parameter_cbb="",
        $services_supported="",
        $bilateral_domains=bilateral_domains,
        $bilateral_domains_by_server=bilateral_domains_by_server,
        $ambiguous_bilateral_domain_servers=
            ambiguous_bilateral_domain_servers,
        $pending_reads=pending_reads,
        $invalid_read_invokes=invalid_read_invokes,
        $completed_read_invokes=completed_read_invokes,
        $pending_concludes=pending_concludes
    ];
    }

function clear_association_semantics(state: AssociationState): AssociationState
    {
    local bilateral_domains: set[string] = set();
    local bilateral_domains_by_server: table[bool] of string = table();
    local ambiguous_bilateral_domain_servers: set[bool] = set();
    local pending_reads: table[bool, count] of PendingRead = table();
    local invalid_read_invokes: set[bool, count] = set();
    local completed_read_invokes: set[bool, count] = set();
    local pending_concludes: set[bool] = set();
    state$association_generation += 1;
    state$acse_association = F;
    state$mms_negotiation = F;
    state$tase2_evidence = F;
    state$parameter_cbb = "";
    state$services_supported = "";
    state$authentication_offered = F;
    state$authentication_length = 0;
    state$association_request_pending = F;
    state$association_request_has_mms = F;
    state$association_request_context = "";
    state$bilateral_domains = bilateral_domains;
    state$bilateral_domains_by_server = bilateral_domains_by_server;
    state$ambiguous_bilateral_domain_servers =
        ambiguous_bilateral_domain_servers;
    state$pending_reads = pending_reads;
    state$invalid_read_invokes = invalid_read_invokes;
    state$completed_read_invokes = completed_read_invokes;
    state$pending_concludes = pending_concludes;
    return state;
    }

function clear_session_association(
    state: AssociationState, phase: string): AssociationState
    {
    state = clear_association_semantics(state);
    state$phase = phase;
    state$presentation_profile = F;
    state$originator_known = F;
    state$originator_is_orig = F;
    state$presentation_context_id = 0;
    state$abstract_syntax = "";
    state$transfer_syntax = "";
    state$application_context = "";
    return state;
    }

function current_state(c: connection): AssociationState
    {
    if ( c$uid !in associations )
        associations[c$uid] = initial_state();

    return associations[c$uid];
    }

function association_kind(c: connection): string
    {
    local state = current_state(c);

    if ( ! state$presentation_profile ||
         ! state$acse_association ||
         ! state$mms_negotiation )
        return "unknown";

    if ( state$tase2_evidence )
        return "tase2";

    return "mms";
    }

function association_phase(c: connection): string
    {
    return current_state(c)$phase;
    }

function endpoint_role(c: connection, is_orig: bool): string
    {
    local state = current_state(c);

    if ( ! state$originator_known )
        return "unknown";

    if ( state$originator_is_orig == is_orig )
        return "originator";

    return "responder";
    }

function operation_name(operation: count): string
    {
    switch ( operation )
        {
        case 1: return "get_name_list";
        case 2: return "read";
        case 3: return "write";
        case 4: return "get_variable_access_attributes";
        case 5: return "define_named_variable_list";
        case 6: return "get_named_variable_list_attributes";
        case 7: return "delete_named_variable_list";
        case 8: return "information_report";
        case 9: return "service_error";
        case 10: return "identify";
        case 11: return "device_action";
        default: return "unknown";
        }
    }

function is_bilateral_domain(c: connection, domain: string): bool
    {
    local state = current_state(c);
    return domain != "" && domain in state$bilateral_domains;
    }

function is_bilateral_domain_for_server(
    c: connection, server_is_orig: bool, domain: string): bool
    {
    local state = current_state(c);
    return domain != "" &&
           server_is_orig !in state$ambiguous_bilateral_domain_servers &&
           server_is_orig in state$bilateral_domains_by_server &&
           state$bilateral_domains_by_server[server_is_orig] == domain;
    }

function rebuild_bilateral_domain_union(
    state: AssociationState): AssociationState
    {
    local bilateral_domains: set[string] = set();
    for ( server_is_orig in state$bilateral_domains_by_server )
        add bilateral_domains[
            state$bilateral_domains_by_server[server_is_orig]];
    state$bilateral_domains = bilateral_domains;
    return state;
    }

function valid_tase2_state_identifier(name: string): bool
    {
    # Generic MMS parsing owns repertoire/length validation.  TASE.2 adds only
    # the rule that an Identifier cannot begin with a digit.
    return name != "" && ! ( /^[0-9]/ in name );
    }

function pending_read(c: connection, invoke_id: int): PendingRead
    {
    local state = current_state(c);
    if ( invoke_id >= 0 )
        {
        local key = int_to_count(invoke_id);
        local orig_pending = [T, key] in state$pending_reads &&
            [T, key] !in state$invalid_read_invokes;
        local resp_pending = [F, key] in state$pending_reads &&
            [F, key] !in state$invalid_read_invokes;
        # Keep this compatibility helper useful for callers that do not have a
        # response direction, but never guess when both endpoints reused the
        # same numeric invoke ID concurrently.
        if ( orig_pending != resp_pending )
            return orig_pending ? state$pending_reads[T, key] :
                                  state$pending_reads[F, key];
        }

    return [$scope=0, $domain="", $name="", $category=0];
    }

function pending_read_for_response(c: connection, response_is_orig: bool,
                                   invoke_id: int): PendingRead
    {
    local state = current_state(c);
    if ( invoke_id >= 0 )
        {
        local key = int_to_count(invoke_id);
        local request_is_orig = ! response_is_orig;
        if ( [request_is_orig, key] in state$pending_reads &&
             [request_is_orig, key] !in state$invalid_read_invokes )
            return state$pending_reads[request_is_orig, key];
        }

    return [$scope=0, $domain="", $name="", $category=0];
    }

function retire_pending_read_for_response(
    c: connection, response_is_orig: bool, invoke_id: int)
    {
    if ( invoke_id < 0 ) return;
    local state = current_state(c);
    local request_is_orig = ! response_is_orig;
    local key = int_to_count(invoke_id);
    delete state$pending_reads[request_is_orig, key];
    delete state$invalid_read_invokes[request_is_orig, key];
    delete state$completed_read_invokes[request_is_orig, key];
    associations[c$uid] = state;
    }

event retire_completed_read_v1(
    c: connection, request_is_orig: bool, invoke_id: count,
    association_generation: count)
    {
    # A connection-removal callback must not recreate state, and a timer from a
    # replaced association must not delete correlation in its successor.
    if ( c$uid !in associations ||
         associations[c$uid]$association_generation !=
             association_generation )
        return;
    local state = associations[c$uid];
    # A following request may already have consumed the completion marker and
    # installed a new identity under this numeric invoke ID.  In that case the
    # deferred retirement belongs to the old transaction and must do nothing.
    if ( [request_is_orig, invoke_id] !in state$completed_read_invokes )
        return;

    delete state$pending_reads[request_is_orig, invoke_id];
    delete state$invalid_read_invokes[request_is_orig, invoke_id];
    delete state$completed_read_invokes[request_is_orig, invoke_id];
    associations[c$uid] = state;
    }

function state_supported_features_value_is_valid(raw: string): bool
    {
    # SupportedFeatures has named bits zero through eleven.  The first octet
    # is the BER unused-bit count; one or two payload octets are sufficient
    # when trailing zero named bits are omitted.
    if ( |raw| < 2 || |raw| > 3 ) return F;

    local unused = bytestring_to_count(sub_bytes(raw, 1, 1));
    if ( unused > 7 ) return F;

    local width = (|raw| - 1) * 8;
    if ( unused >= width || width - unused > 12 ) return F;

    local last = bytestring_to_count(sub_bytes(raw, |raw|, 1));
    if ( unused > 0 )
        {
        local unused_mask: count = (1 << unused) - 1;
        if ( (last & unused_mask) != 0 ) return F;
        }

    # Building Block 1 is mandatory for a TASE.2 server.
    return (bytestring_to_count(sub_bytes(raw, 2, 1)) & 0x80) != 0;
    }

function valid_bootstrap_read_response(
    request: PendingRead, first_result_type: count,
    first_result_raw: string, result_integer_count: count,
    result_first_integer: int, result_second_integer: int,
    result_component_count: count, result_first_choice: count,
    result_second_choice: count, result_count: count,
    failure_count: count): bool
    {
    if ( ! request$bootstrap_eligible || result_count != 1 ||
         failure_count != 0 )
        return F;

    if ( request$category == 1 )
        return request$scope == 0 && request$domain == "" &&
            request$name == "Supported_Features" &&
            first_result_type == 4 &&
            state_supported_features_value_is_valid(first_result_raw);

    if ( request$category == 2 )
        return request$scope == 1 &&
            valid_tase2_state_identifier(request$domain) &&
            request$name == "Bilateral_Table_ID" &&
            first_result_type == 10 && |first_result_raw| > 0 &&
            |first_result_raw| <= 32;

    if ( request$category == 5 )
        return request$scope == 0 && request$domain == "" &&
            request$name == "TASE.2_Version" &&
            first_result_type == 2 && result_component_count == 2 &&
            result_integer_count == 2 && result_first_choice == 5 &&
            result_second_choice == 5 &&
            result_first_integer == 2000 && result_second_integer == 8;

    return F;
    }

function track_read_request_identity(
    c: connection, state: AssociationState, is_orig: bool, invoke_id: int,
    can_retain_identity: bool, first_variable_scope: count,
    first_variable_domain: string, first_variable_name: string,
    first_variable_category: count,
    bootstrap_eligible: bool): AssociationState
    {
    if ( invoke_id < 0 ) return state;
    local key = int_to_count(invoke_id);

    # A direction-correct response made the previous use terminal.  Aggregate
    # logging retains its identity only until a zero-delay callback, so a new
    # request seen first must explicitly consume that stale completion marker.
    if ( [is_orig, key] in state$completed_read_invokes )
        {
        delete state$pending_reads[is_orig, key];
        delete state$invalid_read_invokes[is_orig, key];
        delete state$completed_read_invokes[is_orig, key];
        }

    if ( [is_orig, key] in state$invalid_read_invokes )
        return state;

    if ( [is_orig, key] in state$pending_reads )
        {
        delete state$pending_reads[is_orig, key];
        add state$invalid_read_invokes[is_orig, key];
        return state;
        }

    if ( ! can_retain_identity ) return state;

    if ( |state$pending_reads| + |state$invalid_read_invokes| <
         max_pending_reads )
        state$pending_reads[is_orig, key] = [
            $scope=first_variable_scope,
            $domain=first_variable_domain,
            $name=first_variable_name,
            $category=first_variable_category,
            $bootstrap_eligible=bootstrap_eligible
        ];
    else
        event ICCP::resource_limit_exceeded(
            c, is_orig, "pending_reads", max_pending_reads,
            |state$pending_reads| + |state$invalid_read_invokes|,
            invoke_id);

    return state;
    }

# This self-contained parser event is authoritative for packet-derived Read
# correlation.  In particular, a named-variable-list ObjectName must never be
# treated as the identity of its first result.
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
    provenance: count) &priority=10
    {
    if ( invoke_id < 0 ) return;
    local state = current_state(c);

    if ( pdu_type == 0 )
        {
        local explicit_identity = access_choice == 0 && variable_count > 0 &&
            first_variable_name != "";
        local exact_bootstrap_request = explicit_identity &&
            variable_count == 1 && state$mms_negotiation && provenance == 1;
        state = track_read_request_identity(
            c, state, is_orig, invoke_id, explicit_identity,
            first_variable_scope, first_variable_domain,
            first_variable_name, first_variable_category,
            exact_bootstrap_request);
        associations[c$uid] = state;
        return;
        }

    if ( pdu_type != 1 ) return;

    local key = int_to_count(invoke_id);
    local request_is_orig = ! is_orig;
    if ( [request_is_orig, key] in state$completed_read_invokes )
        return;

    local correlated = [request_is_orig, key] in state$pending_reads ||
        [request_is_orig, key] in state$invalid_read_invokes;
    if ( ! correlated ) return;

    if ( [request_is_orig, key] in state$pending_reads &&
         [request_is_orig, key] !in state$invalid_read_invokes )
        {
        local bootstrap = state$pending_reads[request_is_orig, key];
        if ( state$mms_negotiation && provenance == 1 &&
             valid_bootstrap_read_response(
                 bootstrap, first_result_type, first_result_raw,
                 result_integer_count, result_first_integer,
                 result_second_integer, result_component_count,
                 result_first_choice, result_second_choice,
                 result_count, failure_count) )
            {
            state$tase2_evidence = T;
            if ( bootstrap$category == 2 &&
                 is_orig !in state$ambiguous_bilateral_domain_servers )
                {
                if ( is_orig in state$bilateral_domains_by_server )
                    {
                    if ( state$bilateral_domains_by_server[is_orig] !=
                         bootstrap$domain )
                        {
                        delete state$bilateral_domains_by_server[is_orig];
                        add state$ambiguous_bilateral_domain_servers[is_orig];
                        state = rebuild_bilateral_domain_union(state);
                        }
                    }
                else if ( |state$bilateral_domains_by_server| <
                          max_bilateral_domains )
                    {
                    state$bilateral_domains_by_server[is_orig] =
                        bootstrap$domain;
                    add state$bilateral_domains[bootstrap$domain];
                    }
                else
                    event ICCP::resource_limit_exceeded(
                        c, is_orig, "bilateral_domains",
                        max_bilateral_domains,
                        |state$bilateral_domains_by_server|, invoke_id);
                }
            }
        }

    add state$completed_read_invokes[request_is_orig, key];
    local response_generation = state$association_generation;
    associations[c$uid] = state;
    schedule 0secs {
        ICCP::retire_completed_read_v1(
            c, request_is_orig, key, response_generation)
    };
    }

# MMS serviceSupportOptions uses ASN.1 BIT STRING ordering: service tag zero is
# the most-significant bit of the first content octet. Return -1 when the saved
# advertisement is too short to make a claim, 0 for clear, and 1 for set.
function advertised_service(state: AssociationState, service_tag: count): int
    {
    local byte_offset = service_tag / 8;
    if ( byte_offset >= |state$services_supported| )
        return -1;

    local bit_offset = service_tag % 8;
    local mask = 0x80;
    if ( bit_offset == 1 ) mask = 0x40;
    else if ( bit_offset == 2 ) mask = 0x20;
    else if ( bit_offset == 3 ) mask = 0x10;
    else if ( bit_offset == 4 ) mask = 0x08;
    else if ( bit_offset == 5 ) mask = 0x04;
    else if ( bit_offset == 6 ) mask = 0x02;
    else if ( bit_offset == 7 ) mask = 0x01;

    local octet = bytestring_to_count(
        sub_bytes(state$services_supported, byte_offset, 1));
    return (octet & mask) == 0 ? 0 : 1;
    }

event ICCP::session_spdu_marker_v1(
    c: connection, is_orig: bool, spdu_type: count) &priority=20
    {
    delete state_acse_lifecycle_spdu[c$uid, is_orig];
    state_presentation_spdu[c$uid, is_orig] = spdu_type;

    # A Session CONNECT replaces any association that previously occupied the
    # transport connection. REFUSE, DISCONNECT, ABORT, and ABORT-ACCEPT are
    # terminal even when their optional Presentation value is absent or
    # malformed. NOT-FINISHED deliberately retains the association.
    if ( spdu_type == 13 )
        associations[c$uid] = clear_session_association(
            current_state(c), "presentation_connecting");
    else if ( spdu_type == 10 )
        associations[c$uid] = clear_session_association(
            current_state(c), "released");
    else if ( spdu_type == 12 )
        associations[c$uid] = clear_session_association(
            current_state(c), "refused");
    else if ( spdu_type == 25 || spdu_type == 26 )
        associations[c$uid] = clear_session_association(
            current_state(c), "aborted");
    }

event ICCP::cotp_lifecycle_v1(
    c: connection, is_orig: bool, tpdu_type: count) &priority=20
    {
    if ( tpdu_type != 0xe0 && tpdu_type != 0xd0 &&
         tpdu_type != 0x80 &&
         tpdu_type != 0xc0 && tpdu_type != 0x70 )
        return;

    delete state_acse_lifecycle_spdu[c$uid, T];
    delete state_acse_lifecycle_spdu[c$uid, F];
    delete state_presentation_spdu[c$uid, T];
    delete state_presentation_spdu[c$uid, F];

    local phase = "transport_disconnected";
    if ( tpdu_type == 0xe0 || tpdu_type == 0xd0 )
        phase = "transport_connecting";
    else if ( tpdu_type == 0x70 )
        phase = "transport_error";

    associations[c$uid] = clear_session_association(
        current_state(c), phase);
    }

function clear_state_after_observation_gap(c: connection)
    {
    delete state_acse_lifecycle_spdu[c$uid, T];
    delete state_acse_lifecycle_spdu[c$uid, F];
    delete state_presentation_spdu[c$uid, T];
    delete state_presentation_spdu[c$uid, F];
    associations[c$uid] = clear_session_association(
        current_state(c), "observation_gap");
    }

# Missing TCP sequence space can hide any COTP, Session, Presentation, or ACSE
# lifecycle service. Exact association trust therefore ends at the gap even
# though bounded post-gap records may still be reported as inferred recovery.
event ICCP::stream_gap(
    c: connection, is_orig: bool, length: count) &priority=20
    {
    clear_state_after_observation_gap(c);
    }

event content_gap(
    c: connection, is_orig: bool, seq: count, length: count) &priority=20
    {
    if ( lookup_connection_analyzer_id(
             c$id, Analyzer::ANALYZER_ICCP_TCP) == 0 )
        return;

    clear_state_after_observation_gap(c);
    }

# Envelope markers are one-shot correlation tokens. A nested parser failure
# has no Presentation/ACSE completion event to consume them, and parser_error
# does not carry a reliable direction, so discard both directions here.
event ICCP::parser_error(c: connection, reason: string) &priority=20
    {
    delete state_acse_lifecycle_spdu[c$uid, T];
    delete state_acse_lifecycle_spdu[c$uid, F];
    delete state_presentation_spdu[c$uid, T];
    delete state_presentation_spdu[c$uid, F];
    }

event ICCP::acse_lifecycle_v1(
    c: connection, is_orig: bool, apdu_type: count,
    spdu_type: count) &priority=20
    {
    state_acse_lifecycle_spdu[c$uid, is_orig] = spdu_type;
    }

event ICCP::presentation_message_v2(
    c: connection, is_orig: bool, recognized: bool, ppdu_type: count,
    context_id: count, abstract_syntax: string, transfer_syntax: string,
    dispatch_acse: bool, dispatch_mms: bool, inferred_mms: bool,
    payload_length: count) &priority=10
    {
    local spdu_type: count = 0;
    if ( [c$uid, is_orig] in state_presentation_spdu )
        {
        spdu_type = state_presentation_spdu[c$uid, is_orig];
        delete state_presentation_spdu[c$uid, is_orig];
        }

    # Session abort is terminal at the envelope. An ARU may still emit useful
    # ACSE diagnostics, but its pre-abort context must not be restored here.
    if ( spdu_type == 10 || spdu_type == 12 ||
         spdu_type == 25 || spdu_type == 26 )
        return;

    if ( recognized && ! inferred_mms && (dispatch_acse || dispatch_mms) )
        {
        local state = current_state(c);
        state$presentation_profile = T;
        state$presentation_context_id = context_id;
        state$abstract_syntax = abstract_syntax;
        state$transfer_syntax = transfer_syntax;
        if ( state$phase == "new" ||
             state$phase == "presentation_connecting" )
            state$phase = "presentation_ready";
        associations[c$uid] = state;
        }
    }

event ICCP::acse_message(
    c: connection, is_orig: bool, recognized: bool, apdu_type: count,
    application_context: string, association_result: int, reason: int,
    diagnostic_code: int, authentication_present: bool,
    authentication_length: count, is_opaque: bool, dispatch_mms: bool,
    payload_length: count) &priority=10
    {
    local parser_lifecycle =
        [c$uid, is_orig] in state_acse_lifecycle_spdu;
    local spdu_type: count = 0;
    if ( parser_lifecycle )
        {
        spdu_type = state_acse_lifecycle_spdu[c$uid, is_orig];
        delete state_acse_lifecycle_spdu[c$uid, is_orig];
        }

    if ( ! recognized )
        return;

    local state = current_state(c);

    if ( apdu_type == 0 )
        {
        # A new AARQ supersedes stale application-association semantics, but is
        # only a request. Parser-originated dispatch_mms means its context-bound
        # Association-information carried a valid MMS InitiateRequest.
        state = clear_association_semantics(state);
        state$originator_known = T;
        state$originator_is_orig = is_orig;
        state$association_request_pending = T;
        state$association_request_has_mms = dispatch_mms;
        state$association_request_context = application_context;
        state$application_context = application_context;
        state$authentication_offered = authentication_present;
        state$authentication_length = authentication_length;
        state$authentication_request_is_orig = is_orig;
        state$phase = "association_requested";
        }

    else if ( apdu_type == 1 )
        {
        local response_matches =
            state$association_request_pending &&
            state$originator_known &&
            state$originator_is_orig != is_orig &&
            state$association_request_context != "" &&
            state$association_request_context == application_context;

        if ( association_result == 0 )
            {
            # Establishment requires both context-bound MMS Initiate PDUs. The
            # ACSE parser only reports dispatch_mms for AARQ/InitiateRequest and
            # accepted AARE/InitiateResponse pairs with matching EXTERNAL refs.
            if ( response_matches &&
                 state$association_request_has_mms && dispatch_mms )
                {
                state$acse_association = T;
                state$mms_negotiation = T;
                state$phase = "established";
                state$association_request_pending = F;
                state$association_request_has_mms = F;
                state$authentication_offered = F;
                state$authentication_length = 0;
                state$application_context = application_context;
                }
            else
                {
                # An unmatched ACCEPT never inherits trust from a prior
                # association on a reused transport connection.
                state = clear_association_semantics(state);
                state$phase = "association_unverified";
                }
            }
        else
            {
            if ( response_matches && state$authentication_offered )
                event ICCP::authenticated_association_rejected(
                    c, is_orig, state$authentication_request_is_orig,
                    state$authentication_length, association_result,
                    diagnostic_code);
            if ( response_matches )
                {
                state = clear_association_semantics(state);
                state$phase = "rejected";
                }
            else
                {
                state = clear_association_semantics(state);
                state$phase = "association_unverified";
                }
            }
        }
    else if ( apdu_type == 2 )
        {
        if ( ! parser_lifecycle || spdu_type == 9 )
            state$phase = "release_requested";
        }
    else if ( apdu_type == 3 )
        {
        if ( parser_lifecycle && spdu_type == 8 )
            {
            # NOT-FINISHED is the negative S-RELEASE response. Its RLRE
            # returns the association to data transfer instead of ending it.
            if ( state$acse_association && state$mms_negotiation )
                state$phase = "established";
            else
                state$phase = "association_unverified";
            }
        else
            {
            state = clear_association_semantics(state);
            state$phase = "released";
            }
        }
    else if ( apdu_type == 4 )
        {
        state = clear_association_semantics(state);
        state$phase = "aborted";
        }

    associations[c$uid] = state;
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
    result_flags_raw: string, result_timestamp_value: int) &priority=10
    {
    if ( ! recognized || ! semantic_decoded )
        return;

    local state = current_state(c);

    # Capabilities are detection context, never a parser allowlist. Only an
    # explicit clear bit in a retained Initiate service advertisement produces
    # this event; absent or truncated advertisements remain unknown.
    if ( pdu_type == 0 && invoke_id >= 0 && state$mms_negotiation &&
         advertised_service(state, service_tag) == 0 )
        event ICCP::unexpected_service(
            c, is_orig, association_kind(c), endpoint_role(c, is_orig),
            state$phase, invoke_id, service_tag,
            operation_name(candidate_operation));

    if ( (pdu_type == 8 || pdu_type == 9) &&
         mms_provenance(c, is_orig) != "inferred" )
        {
        state$parameter_cbb = parameter_cbb;
        state$services_supported = services;
        }

    else if ( pdu_type == 11 && state$mms_negotiation )
        {
        add state$pending_concludes[is_orig];
        state$phase = "conclude_requested";
        }
    else if ( pdu_type == 12 && state$mms_negotiation &&
              (! is_orig) in state$pending_concludes )
        {
        event ICCP::mms_conclude_result_v1(c, is_orig, ! is_orig, T);
        state = clear_association_semantics(state);
        state$phase = "concluded";
        }
    else if ( pdu_type == 13 && state$mms_negotiation &&
              (! is_orig) in state$pending_concludes )
        {
        event ICCP::mms_conclude_result_v1(c, is_orig, ! is_orig, F);
        delete state$pending_concludes[! is_orig];
        if ( |state$pending_concludes| == 0 )
            state$phase = "established";
        else
            state$phase = "conclude_requested";
        }

    # Preserve direct script-event compatibility for generic first-result
    # logging. Packet-derived requests always carry the parser marker and are
    # correlated exclusively by mms_read_message_v3, which can distinguish an
    # explicit variable list from a named-list ObjectName. This fallback is
    # deliberately ineligible to promote TASE.2 state.
    if ( pdu_type == 0 && service_tag == 4 && invoke_id >= 0 &&
         first_variable_name != "" &&
         [c$uid, is_orig] !in pending_mms_parser_markers )
        state = track_read_request_identity(
            c, state, is_orig, invoke_id, T, first_variable_scope,
            first_variable_domain, first_variable_name,
            first_variable_category, F);

    if ( pdu_type == 1 && service_tag == 4 && invoke_id >= 0 )
        {
        local response_key = int_to_count(invoke_id);
        if ( [c$uid, is_orig] !in pending_mms_parser_markers )
            add direct_read_response_retirements[
                c$uid, is_orig, response_key];
        else
            delete direct_read_response_retirements[
                c$uid, is_orig, response_key];
        }

    # iccp_required_service alone is intentionally not promoted to evidence:
    # these MMS services may also occur on a non-TASE.2 MMS association.
    associations[c$uid] = state;
    }

# Retire a legacy direct response after same-event consumers have inspected the
# correlated identity. Packet-derived responses never receive this token and
# are retired by the self-contained v3 event independently of sibling order.
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
    if ( invoke_id < 0 ) return;
    local key = int_to_count(invoke_id);
    if ( [c$uid, is_orig, key] !in direct_read_response_retirements )
        return;

    delete direct_read_response_retirements[c$uid, is_orig, key];
    retire_pending_read_for_response(c, is_orig, invoke_id);
    }

event ICCP::mms_error_message(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    modifier_position: int, error_class: count, error_code: int,
    additional_code: int, additional_description: string) &priority=-10
    {
    if ( pdu_type != 2 || invoke_id < 0 ) return;
    local state = current_state(c);
    local request_is_orig = ! is_orig;
    local key = int_to_count(invoke_id);
    delete state$pending_reads[request_is_orig, key];
    delete state$invalid_read_invokes[request_is_orig, key];
    delete state$completed_read_invokes[request_is_orig, key];
    associations[c$uid] = state;
    }

event ICCP::stream_connection_cleanup_v1(uid: string)
    {
    delete associations[uid];
    delete state_acse_lifecycle_spdu[uid, T];
    delete state_acse_lifecycle_spdu[uid, F];
    delete state_presentation_spdu[uid, T];
    delete state_presentation_spdu[uid, F];
    }
