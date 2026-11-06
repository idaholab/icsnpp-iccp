# @TEST-DOC: Check policy-facing unknown/private object, structural Write, and
# @TEST-DOC: negotiated-service mismatch events remain available when logs are
# @TEST-DOC: disabled.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: test ! -e iccp.log
# @TEST-EXEC: test ! -e iccp_objects.log
# @TEST-EXEC: test ! -e iccp_transfers.log
# @TEST-EXEC: test ! -e iccp_controls.log
# @TEST-EXEC: test ! -e iccp_errors.log

redef ICCP::enable_iccp_log = F;
redef ICCP::enable_iccp_objects_log = F;
redef ICCP::enable_iccp_transfers_log = F;
redef ICCP::enable_iccp_controls_log = F;
redef ICCP::enable_iccp_errors_log = F;

event ICCP::unknown_object_access_v2(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, operation: string, invoke_id: int,
    object_scope: string, object_domain: string, object_name: string,
    name_model: string, provenance: string)
    {
    print fmt("unknown kind=%s role=%s operation=%s invoke=%d object=%s/%s/%s model=%s provenance=%s",
              association_kind, endpoint_role, operation, invoke_id,
              object_scope, object_domain, object_name, name_model,
              provenance);
    }

event ICCP::write_attempt_v2(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, invoke_id: int, object_scope: string,
    object_domain: string, object_name: string, variable_count: count,
    data_count: count, data_node_count: count, provenance: string)
    {
    print fmt("write kind=%s role=%s invoke=%d object=%s/%s/%s variables=%d data=%d nodes=%d provenance=%s",
              association_kind, endpoint_role, invoke_id, object_scope,
              object_domain, object_name, variable_count, data_count,
              data_node_count, provenance);
    }

event ICCP::write_failure_v2(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, invoke_id: int, outcome: string,
    object_scope: string, object_domain: string, object_name: string,
    failure_count: count, error_class: string, error_code: int,
    provenance: string)
    {
    print fmt("write_failure kind=%s role=%s invoke=%d outcome=%s object=%s/%s/%s failures=%d error=%s/%d provenance=%s",
              association_kind, endpoint_role, invoke_id, outcome,
              object_scope, object_domain, object_name, failure_count,
              error_class, error_code, provenance);
    }

event ICCP::unexpected_service_v2(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, association_phase: string, invoke_id: int,
    service_tag: count, operation: string, provenance: string)
    {
    print fmt("unexpected_service kind=%s role=%s phase=%s invoke=%d tag=%d operation=%s provenance=%s",
              association_kind, endpoint_role, association_phase, invoke_id,
              service_tag, operation, provenance);
    }

event ICCP::authenticated_association_rejected_v2(
    c: connection, response_is_orig: bool, request_is_orig: bool,
    authentication_length: count, association_result: int,
    diagnostic_code: int, provenance: string)
    {
    print fmt("authenticated_rejection response_orig=%s request_orig=%s length=%d result=%d diagnostic=%d provenance=%s",
              response_is_orig, request_is_orig, authentication_length,
              association_result, diagnostic_code, provenance);
    }

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.110, $orig_p=49152/tcp,
             $resp_h=192.0.2.120, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs, $service=set("iccp"),
        $history="", $uid="Cdetection"
    ];

    event ICCP::mms_message(
        c, T, T, 0, T, 12, 50, 6, 0, T, 4, "", "",
        0, "", "Vendor_Private", 0, F, 0, "", "", 0, 0, "",
        0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_message(
        c, T, T, 0, T, 12, 51, 6, 0, T, 4, "", "",
        0, "", "Supported_Features", 1, T, 0, "", "", 0, 0, "",
        0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_control_request_deferred(
        c, T, 52, 1, "BILATERAL", "SETPOINT", 1, 1, 3);
    event ICCP::mms_control_message(
        c, F, 1, 52, 5, 0, "", "", 0, 0, 0, 1, 0, 1);
    event ICCP::mms_control_request_deferred(
        c, T, 55, 0, "", "REJECTED_WRITE", 1, 1, 1);
    event ICCP::mms_error_message(c, F, 2, 55, -1, 7, 3, -1, "");

    # A one-octet advertisement with only GetNameList (tag 1) enabled makes a
    # subsequent Read (tag 4) an anomaly. Parsing and normal logging continue.
    event ICCP::presentation_message_v2(
        c, T, T, 2, 3, "2.2.1.0.1", "2.1.1", T, F, F, 32);
    event ICCP::acse_message(
        c, T, T, 0, "1.3.6.1.4.1", -1, -1, -1,
        F, 0, F, T, 24);
    event ICCP::acse_message(
        c, F, T, 1, "1.3.6.1.4.1", 0, -1, 0,
        F, 0, F, T, 24);
    event ICCP::mms_message(
        c, T, T, 8, T, 16, -1, 0, 0, F, 0, "\x00", "\x40",
        0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_message(
        c, T, T, 0, T, 12, 53, 4, 0, T, 2, "", "",
        0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);

    # Tag 1 is explicitly advertised and must not produce a mismatch event.
    event ICCP::mms_message(
        c, T, T, 0, T, 12, 54, 1, 0, T, 1, "", "",
        0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);

    # Only the rejection following an authenticated AARQ emits the event.
    event ICCP::acse_message(c, T, T, 0, "1.3.6.1.4.1", -1, -1, -1,
                            T, 12, F, F, 0);
    event ICCP::acse_message(c, F, T, 1, "1.3.6.1.4.1", 1, -1, 14,
                            F, 0, F, F, 0);
    event ICCP::acse_message(c, T, T, 0, "1.3.6.1.4.1", -1, -1, -1,
                            F, 0, F, F, 0);
    event ICCP::acse_message(c, F, T, 1, "1.3.6.1.4.1", 1, -1, 14,
                            F, 0, F, F, 0);
    }
