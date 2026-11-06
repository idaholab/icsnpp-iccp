# Copyright 2026, Battelle Energy Alliance, LLC. All Rights Reserved.

################################################################################
##
## ICSNPP - ICCP
##
## This file defines the Zeek log records and public types used by ICCP.
##
## Christopher B. Peterson and Christian J Weelborg
## Idaho National Lab, November 2026
##
################################################################################

module ICCP;

export {
    redef enum Log::ID += {
        LOG, OBJECT_LOG, TRANSFER_LOG, CONTROL_LOG, ERROR_LOG
    };

    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        is_orig: bool &log;
        layer: string &log;
        message_type: string &log;
        status: string &log;
        context_id: count &log &optional;
        abstract_syntax: string &log &optional;
        transfer_syntax: string &log &optional;
        application_context: string &log &optional;
        association_result: int &log &optional;
        reason: int &log &optional;
        diagnostic_code: int &log &optional;
        payload_length: count &log;
        authentication_present: bool &log;
        authentication_length: count &log;
        is_opaque: bool &log;
        association_kind: string &log;
        association_phase: string &log;
        endpoint_role: string &log;
        operation: string &log &optional;
        transfer_kind: string &log &optional;
        invoke_id: int &log &optional;
        service_tag: count &log &optional;
        identify_outcome: string &log &optional;
        vendor_name: string &log &optional;
        model_name: string &log &optional;
        revision: string &log &optional;
        abstract_syntax_count: count &log &optional;
        first_abstract_syntax: string &log &optional;
        object_scope: string &log &optional;
        object_domain: string &log &optional;
        object_name: string &log &optional;
        object_category: string &log &optional;
        name_model: string &log &optional;
        domain_kind: string &log &optional;
        bilateral_domain: bool &log &optional;
        value_type: count &log &optional;
        standardized_value: string &log &optional;
        conformance_blocks: string &log &optional;
        conditions: string &log &optional;
        condition_mask: count &log &optional;
        point_type: string &log &optional;
        state_value: count &log &optional;
        tag_value: count &log &optional;
        expected_state_value: count &log &optional;
        supplemental_reserved: count &log &optional;
        integer_value: int &log &optional;
        floating_value: double &log &optional;
        validity: string &log &optional;
        value_source: string &log &optional;
        normal_value: bool &log &optional;
        timestamp_quality: bool &log &optional;
        timestamp_value: int &log &optional;
        cov_value: count &log &optional;
        result_count: count &log &optional;
        failure_count: count &log &optional;
        logged_result_count: count &log &optional;
        omitted_result_count: count &log &optional;
        result_pairing_status: string &log &optional;
        result_index: count &log &optional;
        result_type: count &log &optional;
        result_error: int &log &optional;
        result_raw: string &log &optional;
        result_raw_truncated: bool &log &optional;
        boolean_value: bool &log &optional;
        string_value: string &log &optional;
        object_identifier_value: string &log &optional;
        detail: string &log &optional;
        provenance: string &log &default="unknown";
        stream_completeness: string &log &default="unknown";
    };

    # Immutable aggregate-event state captured before policy processing may be
    # deferred to await additive parser evidence.  In particular, provenance
    # and invoke correlation must describe this PDU rather than whichever PDU
    # happens to be current when the scheduled callback runs.
    type MMSProcessingContext: record {
        parser_sequence: count;
        policy_generation: count;
        provenance: string;
        request_invoke_reused: bool;
        request_state_full: bool;
        response_correlation: string;
        read_scope: count;
        read_domain: string;
        read_name: string;
        read_category: count;
    };

    type MMSControlReadProcessingContext: record {
        parser_sequence: count;
        policy_generation: count;
        provenance: string;
        request_is_orig: bool;
        direction_valid: bool;
        scope: count;
        domain: string;
        name: string;
        variable_count: count;
        classification: string;
        named_type: string;
    };

    type TransferInfo: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        is_orig: bool &log;
        action: string &log;
        outcome: string &log;
        invoke_id: int &log &optional;
        list_scope: string &log &optional;
        list_domain: string &log &optional;
        list_name: string &log &optional;
        named_type: string &log &optional;
        variable_count: count &log &optional;
        first_variable_scope: string &log &optional;
        first_variable_domain: string &log &optional;
        first_variable_name: string &log &optional;
        deletable: bool &log &optional;
        delete_scope: int &log &optional;
        number_matched: int &log &optional;
        number_deleted: int &log &optional;
        result_count: count &log &optional;
        failure_count: count &log &optional;
        logged_result_count: count &log &optional;
        omitted_result_count: count &log &optional;
        known_list: bool &log &optional;
        result_index: count &log &optional;
        result_type: count &log &optional;
        result_error: int &log &optional;
        result_raw: string &log &optional;
        result_raw_truncated: bool &log &optional;
        pairing_status: string &log &optional;
        timestamp_value: int &log &optional;
        info_reference: int &log &optional;
        local_reference: int &log &optional;
        message_id: int &log &optional;
        message_size: count &log &optional;
        buffer_capacity: count &log &optional;
        buffer_length: count &log &optional;
        data_set_scope: string &log &optional;
        data_set_domain: string &log &optional;
        data_set_name: string &log &optional;
        start_time: int &log &optional;
        transfer_interval: int &log &optional;
        tle: int &log &optional;
        buffer_time: int &log &optional;
        integrity_check: int &log &optional;
        conditions: string &log &optional;
        condition_mask: count &log &optional;
        block_data: bool &log &optional;
        critical: bool &log &optional;
        report_by_exception: bool &log &optional;
        all_changes_reported: bool &log &optional;
        enabled: bool &log &optional;
        event_code_requested: int &log &optional;
        event_code_detected: int &log &optional;
        conformance: string &log &optional;
        conformance_reasons: string &log &optional;
        transfer_set_scope: string &log &optional;
        transfer_set_domain: string &log &optional;
        transfer_set_name: string &log &optional;
        transfer_state: string &log &optional;
        report_access: string &log &optional;
        report_correlation: string &log &optional;
        ack_required: bool &log &optional;
        provenance: string &log &default="unknown";
        stream_completeness: string &log &default="unknown";
        type_choice: count &log &optional;
        type_constructed: bool &log &optional;
        type_signed_value: int &log &optional;
        type_boolean_value: bool &log &optional;
        type_format_width: int &log &optional;
        type_exponent_width: int &log &optional;
        type_raw: string &log &optional;
        type_raw_truncated: bool &log &optional;
        type_packed: bool &log &optional;
        type_number_of_elements: int &log &optional;
        type_component_count: count &log &optional;
        type_node_count: count &log &optional;
        type_maximum_depth: count &log &optional;
    };

    type ObjectInfo: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        is_orig: bool &log;
        association_kind: string &log;
        association_phase: string &log;
        endpoint_role: string &log;
        observation_kind: string &log;
        operation: string &log &optional;
        invoke_id: int &log &optional;
        object_scope: string &log;
        object_domain: string &log &optional;
        object_name: string &log;
        object_category: string &log &optional;
        name_model: string &log &optional;
        domain_kind: string &log &optional;
        bilateral_domain: bool &log &optional;
        value_type: count &log &optional;
        standardized_value: string &log &optional;
        conformance_blocks: string &log &optional;
        conditions: string &log &optional;
        condition_mask: count &log &optional;
        point_type: string &log &optional;
        state_value: count &log &optional;
        tag_value: count &log &optional;
        expected_state_value: count &log &optional;
        supplemental_reserved: count &log &optional;
        integer_value: int &log &optional;
        floating_value: double &log &optional;
        validity: string &log &optional;
        value_source: string &log &optional;
        normal_value: bool &log &optional;
        timestamp_quality: bool &log &optional;
        timestamp_value: int &log &optional;
        cov_value: count &log &optional;
        result_count: count &log &optional;
        result_pairing_status: string &log &optional;
        result_index: count &log &optional;
        result_type: count &log &optional;
        result_error: int &log &optional;
        result_raw: string &log &optional;
        result_raw_truncated: bool &log &optional;
        boolean_value: bool &log &optional;
        string_value: string &log &optional;
        object_identifier_value: string &log &optional;
        provenance: string &log &default="unknown";
        stream_completeness: string &log &default="unknown";
        logged_result_count: count &log &optional;
        omitted_result_count: count &log &optional;
        object_class_choice: count &log &optional;
        object_class: int &log &optional;
        continue_after: string &log &optional;
        more_follows: bool &log &optional;
    };

    type ErrorInfo: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        is_orig: bool &log;
        association_kind: string &log;
        outcome: string &log;
        invoke_id: int &log &optional;
        operation: string &log &optional;
        service_tag: count &log &optional;
        modifier_position: int &log &optional;
        error_class: string &log;
        error_class_code: count &log;
        error_code: int &log;
        additional_code: int &log &optional;
        description: string &log &optional;
        provenance: string &log &default="unknown";
        stream_completeness: string &log &default="unknown";
    };

    type ControlInfo: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        is_orig: bool &log;
        association_kind: string &log;
        association_phase: string &log;
        endpoint_role: string &log;
        classification: string &log;
        named_type: string &log &optional;
        outcome: string &log;
        invoke_id: int &log;
        object_scope: string &log &optional;
        object_domain: string &log &optional;
        object_name: string &log &optional;
        variable_count: count &log &optional;
        data_count: count &log &optional;
        data_node_count: count &log &optional;
        integer_value: int &log &optional;
        floating_value: double &log &optional;
        tag_value: count &log &optional;
        tag_state: string &log &optional;
        tag_reason: string &log &optional;
        result_count: count &log &optional;
        success_count: count &log &optional;
        failure_count: count &log &optional;
        error_class: string &log &optional;
        error_class_code: count &log &optional;
        error_code: int &log &optional;
        event_enrollment_scope: string &log &optional;
        event_enrollment_domain: string &log &optional;
        event_enrollment_name: string &log &optional;
        event_condition_scope: string &log &optional;
        event_condition_domain: string &log &optional;
        severity: int &log &optional;
        current_state: string &log &optional;
        transition_time_kind: string &log &optional;
        transition_time_value: int &log &optional;
        transition_time_raw: string &log &optional;
        notification_lost: bool &log &optional;
        action_result_present: bool &log &optional;
        provenance: string &log &default="unknown";
        stream_completeness: string &log &default="unknown";
        access_choice: count &log &optional;
        target_count_known: bool &log &optional;
        target_count: count &log &optional;
        value_count: count &log &optional;
        logged_item_count: count &log &optional;
        omitted_item_count: count &log &optional;
        item_index: count &log &optional;
        pairing_status: string &log &optional;
        value_type: count &log &optional;
        value_raw: string &log &optional;
        value_raw_truncated: bool &log &optional;
        boolean_value: bool &log &optional;
        string_value: string &log &optional;
        result_success: bool &log &optional;
        result_error: int &log &optional;
    };

    global log_iccp: event(rec: Info);
    global log_iccp_object: event(rec: ObjectInfo);
    global log_iccp_transfer: event(rec: TransferInfo);
    global log_iccp_error: event(rec: ErrorInfo);
    global log_iccp_control: event(rec: ControlInfo);
    global stream_started: event(c: connection, is_orig: bool);
    global stream_gap: event(c: connection, is_orig: bool, length: count);
    global stream_record_started: event(c: connection, is_orig: bool);
    global stream_record_completed: event(c: connection, is_orig: bool);
    global stream_incomplete: event(c: connection, is_orig: bool);
    global stream_recovery_started: event(
        c: connection, is_orig: bool, crossed_gap: bool
    );
    global stream_recovery_candidate: event(
        c: connection, is_orig: bool, crossed_gap: bool
    );
    global stream_recovered: event(
        c: connection, is_orig: bool, crossed_gap: bool
    );
    global stream_finished: event(
        c: connection, is_orig: bool, status: string,
        terminal_completeness: string
    );
    global output_completeness: function(
        c: connection, is_orig: bool
    ): string;
    global parser_error: event(c: connection, reason: string);
    global presentation_message: event(
        c: connection, is_orig: bool, recognized: bool, ppdu_type: count,
        context_id: count, abstract_syntax: string, transfer_syntax: string,
        dispatch_acse: bool, payload_length: count
    );
    global presentation_message_v2: event(
        c: connection, is_orig: bool, recognized: bool, ppdu_type: count,
        context_id: count, abstract_syntax: string, transfer_syntax: string,
        dispatch_acse: bool, dispatch_mms: bool, inferred_mms: bool,
        payload_length: count
    );
    global acse_message: event(
        c: connection, is_orig: bool, recognized: bool, apdu_type: count,
        application_context: string, association_result: int, reason: int,
        diagnostic_code: int, authentication_present: bool,
        authentication_length: count, is_opaque: bool, dispatch_mms: bool,
        payload_length: count
    );
    # Parser-only Session/ACSE lifecycle context.  The Session marker is
    # emitted before child Presentation/ACSE events; the ACSE lifecycle event
    # is emitted at APDU initialization and therefore precedes the
    # compatibility acse_message event independently of completion-hook
    # ordering.  Its apdu_type is UNKNOWN for parser emissions and retained
    # only for source compatibility.  Consumers use the Session SPDU type to
    # distinguish a completed release (DISCONNECT) from a refused release
    # (NOT_FINISHED).
    global session_spdu_marker_v1: event(
        c: connection, is_orig: bool, spdu_type: count
    );
    # Parser-only COTP trust boundary. CR and untrusted CC replace stale
    # transport state; DR/DC release it. ER is handled conservatively as a
    # trust reset even though the transport protocol can permit continuation.
    global cotp_lifecycle_v1: event(
        c: connection, is_orig: bool, tpdu_type: count
    );
    global acse_lifecycle_v1: event(
        c: connection, is_orig: bool, apdu_type: count, spdu_type: count
    );
    global mms_message: event(
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
        result_flags_raw: string, result_timestamp_value: int
    );
    # Parser-only ordering marker emitted when the provenance wrapper begins,
    # before any child MMS completion events are delivered.
    global mms_provenance_marker_v1: event(
        c: connection, is_orig: bool, provenance: count
    );
    # Internal policy-stage delivery used when additive parser evidence for an
    # Identify PDU is emitted after the compatibility event.
    global mms_message_evidence_deferred: event(
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
        context: MMSProcessingContext
    );
    global mms_message_v2: event(
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
        provenance: count
    );
    global mms_point_value_shape_v2: event(
        c: connection, is_orig: bool, first_result_length: count,
        first_component_length: count, second_component_length: count,
        third_component_length: count
    );
    global mms_point_value_shape_v3: event(
        c: connection, is_orig: bool, first_result_length: count,
        component_choices: vector of count,
        component_raws: vector of string,
        component_integer_values: vector of int,
        nested_component_index: count,
        nested_choices: vector of count,
        nested_raws: vector of string,
        nested_integer_values: vector of int
    );
    global mms_control_read_value_shape_v1: event(
        c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
        service_tag: count, first_result_length: count,
        component_choices: vector of count,
        component_raws: vector of string,
        component_integer_values: vector of int
    );
    # Historical script-level response hook and its immutable parser-policy
    # companion.  The latter prevents later PDUs from changing correlation or
    # provenance while the exact response shape is awaiting deferred use.
    global mms_control_read_response_deferred: event(
        c: connection, is_orig: bool, invoke_id: int,
        result_count: count, failure_count: count,
        first_result_choice: count, first_result_raw: string,
        first_integer_value: int
    );
    global mms_control_read_response_deferred_v2: event(
        c: connection, is_orig: bool, invoke_id: int,
        result_count: count, failure_count: count,
        first_result_choice: count, first_result_raw: string,
        first_integer_value: int, context: MMSControlReadProcessingContext
    );
    global mms_identify_message_v2: event(
        c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
        vendor_name: string, model_name: string, revision: string,
        abstract_syntax_count: count, first_abstract_syntax: string,
        provenance: count
    );
    global mms_get_name_list_evidence_v1: event(
        c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
        object_class_choice: count, object_class: int,
        object_scope: count, object_domain: string,
        continue_after: string, identifier_count: count,
        identifiers: vector of string, more_follows: bool,
        provenance: count
    );
    global mms_device_action_message_v1: event(
        c: connection, is_orig: bool,
        enrollment_scope: count, enrollment_domain: string,
        enrollment_name: string, condition_scope: count,
        condition_domain: string, condition_name: string,
        severity: int, current_state_present: bool, current_state: int,
        transition_time_kind: count, transition_time_raw: string,
        transition_time_value: int, notification_lost: bool,
        alarm_ack_rule_present: bool, alarm_ack_rule: int,
        action_result_present: bool, provenance: count
    );
    global mms_information_report_results_v2: event(
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
        provenance: count
    );
    global mms_transfer_set_message: event(
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
        result_errors: vector of int, result_raws: vector of string
    );
    global mms_transfer_set_message_v2: event(
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
        provenance: count
    );
    # Self-contained production evidence for NamedVariableList lifecycle. The
    # per-member AlternateAccess counts are carried in the same event as the
    # identities they qualify, avoiding
    # any dependency on completion-hook delivery order.  The legacy event
    # remains available to direct script callers.
    global mms_transfer_set_message_v3: event(
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
        result_raws: vector of string, provenance: count
    );
    global mms_error_message: event(
        c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
        modifier_position: int, error_class: count, error_code: int,
        additional_code: int, additional_description: string
    );
    global mms_error_message_v2: event(
        c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
        modifier_position: int, error_class: count, error_code: int,
        additional_code: int, additional_description: string,
        provenance: count
    );
    # Reject reason tag 1 (confirmed-requestPDU) identifies a terminal reject
    # of the peer's request. Other reason tags use a different invoke-ID
    # namespace and must not retire confirmed-request correlation state.
    global mms_reject_message_v1: event(
        c: connection, is_orig: bool, invoke_id: int,
        reason_tag: count, reason: int, provenance: count
    );
    global mms_control_message: event(
        c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
        service_tag: count, object_scope: count, object_domain: string,
        object_name: string, variable_count: count, data_count: count,
        data_node_count: count, result_count: count, success_count: count,
        failure_count: count
    );
    global mms_control_message_v2: event(
        c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
        service_tag: count, object_scope: count, object_domain: string,
        object_name: string, variable_count: count, data_count: count,
        data_node_count: count, result_count: count, success_count: count,
        failure_count: count, provenance: count
    );
    global mms_control_value_shape_v3: event(
        c: connection, is_orig: bool, first_data_choice: count,
        first_data_raw: string, first_data_integer_value: int,
        first_data_floating_value: double
    );
    global mms_control_value_shape_v4: event(
        c: connection, is_orig: bool, first_data_choice: count,
        first_data_raw: string, first_data_integer_value: int,
        first_data_floating_value: double,
        component_choices: vector of count,
        component_raws: vector of string,
        component_integer_values: vector of int
    );
    global mms_write_evidence_v1: event(
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
        provenance: count
    );
    # Compatibility entry points used by script-level consumers. Parser
    # delivery uses v3 so deferred processing also carries the immutable
    # association generation that queued it.
    global mms_control_request_deferred: event(
        c: connection, is_orig: bool, invoke_id: int,
        object_scope: count, object_domain: string, object_name: string,
        variable_count: count, data_count: count, data_node_count: count
    );
    global mms_control_request_deferred_v2: event(
        c: connection, is_orig: bool, invoke_id: int,
        object_scope: count, object_domain: string, object_name: string,
        variable_count: count, data_count: count, data_node_count: count,
        parser_sequence: count, provenance: string
    );
    global mms_control_request_deferred_v3: event(
        c: connection, is_orig: bool, invoke_id: int,
        object_scope: count, object_domain: string, object_name: string,
        variable_count: count, data_count: count, data_node_count: count,
        parser_sequence: count, policy_generation: count, provenance: string
    );
    global mms_transfer_control_message: event(
        c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
        service_tag: count, access_choice: count, object_scope: count,
        object_domain: string, object_name: string, variable_count: count,
        data_count: count, first_data_choice: count,
        first_data_boolean: bool, first_data_child_count: count,
        first_data_twelfth_choice: count,
        first_data_twelfth_boolean: bool,
        first_data_dst_transfer_set_shape: bool, result_count: count,
        success_count: count, failure_count: count
    );
    global mms_transfer_control_message_v2: event(
        c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
        service_tag: count, access_choice: count, object_scope: count,
        object_domain: string, object_name: string, variable_count: count,
        data_count: count, first_data_choice: count,
        first_data_boolean: bool, first_data_child_count: count,
        first_data_twelfth_choice: count,
        first_data_twelfth_boolean: bool,
        first_data_dst_transfer_set_shape: bool, result_count: count,
        success_count: count, failure_count: count, provenance: count
    );
    global mms_ds_transfer_set_message_v1: event(
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
        provenance: count
    );
    global mms_variable_type_message: event(
        c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
        service_tag: count, object_scope: count, object_domain: string,
        object_name: string, type_choice: count, named_type_scope: count,
        named_type_domain: string, named_type_name: string
    );
    global mms_variable_type_message_v2: event(
        c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
        service_tag: count, object_scope: count, object_domain: string,
        object_name: string, type_choice: count, named_type_scope: count,
        named_type_domain: string, named_type_name: string, provenance: count
    );
    # Authoritative GetVariableAccessAttributes delivery.  The parallel
    # vectors encode the complete TypeSpecification tree in post-order.
    global mms_gva_message_v3: event(
        c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
        object_scope: count, object_domain: string, object_name: string,
        deletable_present: bool, mms_deletable: bool, type_resolved: bool,
        unresolved_type_name_count: count,
        type_choices: vector of count, type_primary: vector of int,
        type_secondary: vector of int,
        type_child_counts: vector of count,
        type_packed: vector of bool, type_raw: string,
        type_node_count: count, type_maximum_depth: count,
        provenance: count
    );
    global mms_type_description_evidence_v1: event(
        c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
        type_choice: count, constructed: bool, signed_value: int,
        boolean_value: bool, format_width: int, exponent_width: int,
        raw: string, packed: bool, number_of_elements: int,
        component_count: count, node_count: count,
        maximum_depth: count, provenance: count
    );
    # Authoritative, self-contained Read delivery.  Policy must require an
    # explicit variable list (access_choice 0) before trusting first-variable
    # identity; a named-list ObjectName is not a data-variable identity.
    global mms_read_message_v3: event(
        c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
        access_choice: count, variable_count: count,
        first_variable_scope: count, first_variable_domain: string,
        first_variable_name: string, first_variable_category: count,
        result_count: count, failure_count: count,
        first_result_type: count, first_result_raw: string,
        result_integer_count: count, result_first_integer: int,
        result_second_integer: int, result_component_count: count,
        result_first_choice: count, result_second_choice: count,
        provenance: count
    );
    # Parser-policy lifecycle result.  This is emitted only after state has
    # directionally matched a Conclude response or error to the peer's
    # outstanding request; consumers must clean terminal state only when
    # accepted is true.
    global mms_conclude_result_v1: event(
        c: connection, response_is_orig: bool, request_is_orig: bool,
        accepted: bool
    );
    global mms_transfer_support_value_message: event(
        c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
        service_tag: count, object_scope: count, object_domain: string,
        object_name: string, result_count: count, failure_count: count,
        first_result_choice: count, first_result_raw: string,
        component_count: count, first_component_choice: count,
        second_component_choice: count, third_component_choice: count,
        first_integer_value: int, second_component_raw: string,
        third_component_raw: string
    );
    global mms_transfer_support_value_message_v2: event(
        c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
        service_tag: count, object_scope: count, object_domain: string,
        object_name: string, result_count: count, failure_count: count,
        first_result_choice: count, first_result_raw: string,
        component_count: count, first_component_choice: count,
        second_component_choice: count, third_component_choice: count,
        first_integer_value: int, second_component_raw: string,
        third_component_raw: string, provenance: count
    );
    global unknown_object_access: event(
        c: connection, is_orig: bool, association_kind: string,
        endpoint_role: string, operation: string, invoke_id: int,
        object_scope: string, object_domain: string, object_name: string,
        name_model: string
    );
    global unknown_object_access_v2: event(
        c: connection, is_orig: bool, association_kind: string,
        endpoint_role: string, operation: string, invoke_id: int,
        object_scope: string, object_domain: string, object_name: string,
        name_model: string, provenance: string
    );
    global write_attempt: event(
        c: connection, is_orig: bool, association_kind: string,
        endpoint_role: string, invoke_id: int, object_scope: string,
        object_domain: string, object_name: string, variable_count: count,
        data_count: count, data_node_count: count
    );
    global write_attempt_v2: event(
        c: connection, is_orig: bool, association_kind: string,
        endpoint_role: string, invoke_id: int, object_scope: string,
        object_domain: string, object_name: string, variable_count: count,
        data_count: count, data_node_count: count, provenance: string
    );
    global write_failure: event(
        c: connection, is_orig: bool, association_kind: string,
        endpoint_role: string, invoke_id: int, outcome: string,
        object_scope: string, object_domain: string, object_name: string,
        failure_count: count, error_class: string, error_code: int
    );
    global write_failure_v2: event(
        c: connection, is_orig: bool, association_kind: string,
        endpoint_role: string, invoke_id: int, outcome: string,
        object_scope: string, object_domain: string, object_name: string,
        failure_count: count, error_class: string, error_code: int,
        provenance: string
    );
    global control_failure: event(
        c: connection, is_orig: bool, association_kind: string,
        endpoint_role: string, invoke_id: int, classification: string,
        outcome: string, object_scope: string, object_domain: string,
        object_name: string, named_type: string, failure_count: count,
        error_class: string, error_code: int
    );
    global control_failure_v2: event(
        c: connection, is_orig: bool, association_kind: string,
        endpoint_role: string, invoke_id: int, classification: string,
        outcome: string, object_scope: string, object_domain: string,
        object_name: string, named_type: string, failure_count: count,
        error_class: string, error_code: int, provenance: string
    );
    global device_action: event(
        c: connection, is_orig: bool, association_kind: string,
        endpoint_role: string, classification: string, outcome: string,
        enrollment_scope: string, enrollment_domain: string,
        enrollment_name: string, condition_name: string
    );
    global device_action_v2: event(
        c: connection, is_orig: bool, association_kind: string,
        endpoint_role: string, classification: string, outcome: string,
        enrollment_scope: string, enrollment_domain: string,
        enrollment_name: string, condition_name: string,
        provenance: string
    );
    global dst_transfer_set_anomaly: event(
        c: connection, is_orig: bool, association_kind: string,
        endpoint_role: string, invoke_id: int, object_scope: string,
        object_domain: string, object_name: string, classification: string,
        conformance: string, reasons: string
    );
    global dst_transfer_set_anomaly_v2: event(
        c: connection, is_orig: bool, association_kind: string,
        endpoint_role: string, invoke_id: int, object_scope: string,
        object_domain: string, object_name: string, classification: string,
        conformance: string, reasons: string, provenance: string
    );
    global transfer_report_anomaly: event(
        c: connection, is_orig: bool, association_kind: string,
        endpoint_role: string, transfer_set_scope: string,
        transfer_set_domain: string, transfer_set_name: string,
        report_correlation: string, reason: string
    );
    global transfer_report_anomaly_v2: event(
        c: connection, is_orig: bool, association_kind: string,
        endpoint_role: string, transfer_set_scope: string,
        transfer_set_domain: string, transfer_set_name: string,
        report_correlation: string, reason: string, provenance: string
    );
    global unexpected_service: event(
        c: connection, is_orig: bool, association_kind: string,
        endpoint_role: string, association_phase: string, invoke_id: int,
        service_tag: count, operation: string
    );
    global unexpected_service_v2: event(
        c: connection, is_orig: bool, association_kind: string,
        endpoint_role: string, association_phase: string, invoke_id: int,
        service_tag: count, operation: string, provenance: string
    );
    global authenticated_association_rejected: event(
        c: connection, response_is_orig: bool, request_is_orig: bool,
        authentication_length: count, association_result: int,
        diagnostic_code: int
    );
    global authenticated_association_rejected_v2: event(
        c: connection, response_is_orig: bool, request_is_orig: bool,
        authentication_length: count, association_result: int,
        diagnostic_code: int, provenance: string
    );
    global resource_limit_exceeded: event(
        c: connection, is_orig: bool, resource: string, limit: count,
        current: count, invoke_id: int
    );
    global resource_limit_exceeded_v2: event(
        c: connection, is_orig: bool, resource: string, limit: count,
        current: count, invoke_id: int, provenance: string
    );
    global malformed_structure: event(c: connection, reason: string);
    global malformed_structure_v2: event(
        c: connection, reason: string, provenance: string
    );
}
