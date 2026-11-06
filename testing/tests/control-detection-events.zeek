# @TEST-DOC: Emit control-specific failure events only for exact
# @TEST-DOC: type-discovered Operate or Select requests with direction-valid
# @TEST-DOC: failed responses or ConfirmedError rejections. Generic Write and
# @TEST-DOC: Select candidates and same-direction terminals remain unpromoted.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: test ! -e iccp.log
# @TEST-EXEC: test ! -e iccp_objects.log
# @TEST-EXEC: test ! -e iccp_transfers.log
# @TEST-EXEC: test ! -e iccp_controls.log
# @TEST-EXEC: test ! -e iccp_errors.log

module ICCP;

redef ICCP::legacy_gva_direct_event_compatibility = T;
redef ICCP::enable_iccp_log = F;
redef ICCP::enable_iccp_objects_log = F;
redef ICCP::enable_iccp_transfers_log = F;
redef ICCP::enable_iccp_controls_log = F;
redef ICCP::enable_iccp_errors_log = F;

global control_alerts: count = 0;
global generic_failures: count = 0;

event ICCP::control_failure_v2(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, invoke_id: int, classification: string,
    outcome: string, object_scope: string, object_domain: string,
    object_name: string, named_type: string, failure_count: count,
    error_class: string, error_code: int, provenance: string)
    {
    ++control_alerts;
    print fmt("control_failure kind=%s role=%s invoke=%d classification=%s outcome=%s object=%s/%s/%s type=%s failures=%d error=%s/%d provenance=%s",
              association_kind, endpoint_role, invoke_id, classification,
              outcome, object_scope, object_domain, object_name, named_type,
              failure_count, error_class, error_code, provenance);
    }

event ICCP::write_failure_v2(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, invoke_id: int, outcome: string,
    object_scope: string, object_domain: string, object_name: string,
    failure_count: count, error_class: string, error_code: int,
    provenance: string)
    {
    ++generic_failures;
    }

function learn_control_type(c: connection, invoke_id: int,
                            object_name: string, named_type: string)
    {
    ICCP::configured_variable_types[
        c$id$resp_h, c$id$orig_h, 0, "", object_name] = named_type;
    event ICCP::mms_variable_type_message(
        c, T, 0, invoke_id, 6, 0, "", object_name, 0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, F, 1, invoke_id, 6, 0, "", "", 0, 0, "", named_type);
    }

function control_request(c: connection, invoke_id: int, object_name: string,
                         choice: count, raw: string, integer_value: int,
                         floating_value: double)
    {
    event ICCP::mms_control_value_shape_v3(
        c, T, choice, raw, integer_value, floating_value);
    event ICCP::mms_control_request_deferred(
        c, T, invoke_id, 0, "", object_name, 1, 1, 1);
    }

function control_response(c: connection, is_orig: bool, invoke_id: int,
                          success_count: count, failure_count: count,
                          provenance: count)
    {
    event ICCP::mms_control_message_v2(
        c, is_orig, 1, invoke_id, 5, 0, "", "", 0, 0, 0,
        success_count + failure_count, success_count, failure_count,
        provenance);
    event ICCP::mms_control_message(
        c, is_orig, 1, invoke_id, 5, 0, "", "", 0, 0, 0,
        success_count + failure_count, success_count, failure_count);
    }

function select_request(c: connection, invoke_id: int, object_name: string)
    {
    event ICCP::mms_control_message_v2(
        c, T, 0, invoke_id, 4, 0, "", object_name, 1, 0, 0,
        0, 0, 0, 1);
    event ICCP::mms_control_message(
        c, T, 0, invoke_id, 4, 0, "", object_name, 1, 0, 0,
        0, 0, 0);
    }

function select_response(c: connection, is_orig: bool, invoke_id: int,
                         failure_count: count, choice: count,
                         raw: string, integer_value: int)
    {
    event ICCP::mms_transfer_support_value_message_v2(
        c, is_orig, 1, invoke_id, 4, 0, "", "", 1, failure_count,
        choice, raw, 0, 0, 0, 0, integer_value, "", "", 1);
    event ICCP::mms_transfer_support_value_message(
        c, is_orig, 1, invoke_id, 4, 0, "", "", 1, failure_count,
        choice, raw, 0, 0, 0, 0, integer_value, "", "");
    }

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.130, $orig_p=49152/tcp,
             $resp_h=192.0.2.140, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Ccontrol-alerts"
    ];
    event ICCP::presentation_message_v2(
        c, T, T, 2, 3, "2.2.1.0.1", "2.1.1", T, F, F, 32);
    event ICCP::acse_message(
        c, T, T, 0, "1.3.6.1.4.1", -1, -1, -1,
        F, 0, F, T, 24);
    event ICCP::acse_message(
        c, F, T, 1, "1.3.6.1.4.1", 0, -1, 0,
        F, 0, F, T, 24);
    event ICCP::mms_message(
        c, T, T, 8, T, 16, -1, 0, 0, F, 0, "\x00", "\x01",
        0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_read_message_v3(
        c, T, 0, 8, 0, 1, 0, "", "Supported_Features", 1,
        0, 0, 0, "", 0, 0, 0, 0, 0, 0, 1);
    event ICCP::mms_read_message_v3(
        c, F, 1, 8, 0, 0, 0, "", "", 0,
        1, 0, 4, "\x04\xa0", 0, 0, 0, 0, 0, 0, 1);

    # Exact discrete Operate with a failed Write result: emit both the stable
    # generic Write failure and the additive control-specific alert.
    learn_control_type(c, 100, "TAP", "Control_Setpoint_Discrete");
    control_request(c, 200, "TAP", 5, "\x00\x2a", 42, 0.0);
    control_response(c, F, 200, 0, 1, 1);

    # Exact real Operate rejected by ConfirmedError.
    learn_control_type(c, 101, "MW_SETPOINT", "Control_Setpoint_Real");
    control_request(c, 201, "MW_SETPOINT", 7,
                    "\x08\x41\x48\x00\x00", 0, 12.5);
    event ICCP::mms_error_message_v2(c, F, 2, 201, -1, 7, 3, -1, "", 1);
    event ICCP::mms_error_message(c, F, 2, 201, -1, 7, 3, -1, "");

    # Shape-only generic Write failure: generic alert only.
    control_request(c, 202, "UNKNOWN", 5, "\x01", 1, 0.0);
    control_response(c, F, 202, 0, 1, 1);

    # Same-direction failed response is not a terminal failure alert. The
    # later valid successful response only clears the pending request.
    learn_control_type(c, 102, "BREAKER", "Control_Command");
    control_request(c, 203, "BREAKER", 5, "\x01", 1, 0.0);
    control_response(c, T, 203, 0, 1, 1);
    control_response(c, F, 203, 1, 0, 1);

    # Exact Select failures use the same additive control alert, but never the
    # generic Write-failure event because Select maps to MMS Read.
    learn_control_type(c, 103, "BREAKER_SBO", "SBO_CheckBackName");
    select_request(c, 210, "BREAKER_SBO");
    select_response(c, F, 210, 1, 0, "", 0);

    learn_control_type(c, 104, "PUMP_SBO", "SBO_CheckBackName");
    select_request(c, 211, "PUMP_SBO");
    event ICCP::mms_error_message_v2(c, F, 2, 211, -1, 7, 3, -1, "", 1);
    event ICCP::mms_error_message(c, F, 2, 211, -1, 7, 3, -1, "");

    # Naming without exact type discovery and same-direction failures are not
    # trustworthy Select alerts.
    select_request(c, 212, "UNKNOWN_SBO");
    select_response(c, F, 212, 1, 0, "", 0);
    select_request(c, 213, "BREAKER_SBO");
    select_response(c, T, 213, 1, 0, "", 0);
    select_response(c, F, 213, 0, 5, "\x01", 1);

    # Cross-service invoke reuse makes a later ConfirmedError ambiguous.
    select_request(c, 214, "BREAKER_SBO");
    event ICCP::mms_control_message_v2(
        c, T, 0, 214, 6, 0, "", "OTHER", 1, 0, 0, 0, 0, 0, 1);
    event ICCP::mms_control_message(
        c, T, 0, 214, 6, 0, "", "OTHER", 1, 0, 0, 0, 0, 0);
    event ICCP::mms_error_message_v2(c, F, 2, 214, -1, 7, 3, -1, "", 1);
    event ICCP::mms_error_message(c, F, 2, 214, -1, 7, 3, -1, "");
    }

event zeek_done()
    {
    print fmt("counts control=%d generic=%d", control_alerts,
              generic_failures);
    }
