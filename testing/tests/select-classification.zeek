# @TEST-DOC: Classify Select only when an exact single-variable
# @TEST-DOC: Read of a Device_Name_SBO object is backed by connection-scoped
# @TEST-DOC: SBO_CheckBackName type discovery. Validate success, AccessResult
# @TEST-DOC: failure, ConfirmedError, direction, width, scope, and invoke-reuse
# @TEST-DOC: handling without promoting incomplete evidence.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut classification outcome invoke_id object_scope object_domain object_name named_type variable_count integer_value result_count success_count failure_count error_class error_code < iccp_controls.log > output
# @TEST-EXEC: btest-diff output

module ICCP;

redef ICCP::legacy_gva_direct_event_compatibility = T;
redef ICCP::max_pending_controls = 1;

function learn_select_type(c: connection, invoke_id: int, scope: count,
                           domain: string, object_name: string)
    {
    ICCP::configured_variable_types[
        c$id$resp_h, c$id$orig_h, scope, domain, object_name] =
            "SBO_CheckBackName";
    event ICCP::mms_variable_type_message(
        c, T, 0, invoke_id, 6, scope, domain, object_name, 0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, F, 1, invoke_id, 6, 0, "", "", 0, 0, "",
        "SBO_CheckBackName");
    }

function select_request(c: connection, is_orig: bool, invoke_id: int,
                        scope: count, domain: string, object_name: string,
                        variable_count: count)
    {
    event ICCP::mms_control_message(
        c, is_orig, 0, invoke_id, 4, scope, domain, object_name,
        variable_count, 0, 0, 0, 0, 0);
    }

function select_response(c: connection, is_orig: bool, invoke_id: int,
                         result_count: count, failure_count: count,
                         choice: count, raw: string, integer_value: int)
    {
    event ICCP::mms_transfer_support_value_message(
        c, is_orig, 1, invoke_id, 4, 0, "", "", result_count,
        failure_count, choice, raw, 0, 0, 0, 0, integer_value, "", "");
    }

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.150, $orig_p=49152/tcp,
             $resp_h=192.0.2.160, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Cselect-types"
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
        1, 0, 4, "\x07\x80", 0, 0, 0, 0, 0, 0, 1);

    learn_select_type(c, 100, 0, "", "BREAKER_SBO");
    select_request(c, T, 200, 0, "", "BREAKER_SBO", 1);
    select_response(c, F, 200, 1, 0, 5, "\x2a", 42);

    learn_select_type(c, 101, 0, "", "PUMP_SBO");
    select_request(c, T, 201, 0, "", "PUMP_SBO", 1);
    select_response(c, F, 201, 1, 1, 0, "\x03", 0);

    learn_select_type(c, 102, 0, "", "VALVE_SBO");
    select_request(c, T, 202, 0, "", "VALVE_SBO", 1);
    event ICCP::mms_error_message(c, F, 2, 202, -1, 7, 3, -1, "");

    # Suffix-only and type-only evidence stay candidates.
    select_request(c, T, 203, 0, "", "UNKNOWN_SBO", 1);
    select_response(c, F, 203, 1, 0, 5, "\x01", 1);
    learn_select_type(c, 103, 0, "", "WRONG_NAME");
    select_request(c, T, 204, 0, "", "WRONG_NAME", 1);
    select_response(c, F, 204, 1, 0, 5, "\x01", 1);

    # A three-octet INTEGER violates the width-16 CheckBackID constraint.
    select_request(c, T, 205, 0, "", "BREAKER_SBO", 1);
    select_response(c, F, 205, 1, 0, 5, "\x00\x00\x2a", 42);

    # Same-direction terminals remain non-terminal until the peer responds.
    select_request(c, T, 206, 0, "", "BREAKER_SBO", 1);
    select_response(c, T, 206, 1, 0, 5, "\x2a", 42);
    select_response(c, F, 206, 1, 0, 5, "\x2a", 42);

    # Reused invokes invalidate both candidates and cannot claim a terminal.
    select_request(c, T, 207, 0, "", "BREAKER_SBO", 1);
    select_request(c, T, 207, 0, "", "BREAKER_SBO", 1);
    select_response(c, T, 207, 1, 0, 5, "\x2a", 42);
    select_response(c, F, 207, 1, 0, 5, "\x2a", 42);

    # ICC-scoped objects are valid only with a non-empty domain.
    learn_select_type(c, 104, 1, "STATION1", "TAP_SBO");
    select_request(c, T, 208, 1, "STATION1", "TAP_SBO", 1);
    select_response(c, F, 208, 1, 0, 5, "\x00\x2a", 42);
    learn_select_type(c, 105, 2, "", "AA_SBO");
    select_request(c, T, 209, 2, "", "AA_SBO", 1);
    select_response(c, F, 209, 1, 0, 5, "\x01", 1);

    # A multi-variable Read is never an exact Select.
    select_request(c, T, 210, 0, "", "BREAKER_SBO", 2);
    select_response(c, F, 210, 2, 0, 5, "\x01", 1);

    # Per-connection Select state is bounded independently of request volume.
    learn_select_type(c, 106, 0, "", "FIRST_SBO");
    learn_select_type(c, 107, 0, "", "SECOND_SBO");
    select_request(c, T, 211, 0, "", "FIRST_SBO", 1);
    select_request(c, T, 212, 0, "", "SECOND_SBO", 1);
    select_response(c, F, 211, 1, 0, 5, "\x01", 1);
    select_response(c, F, 212, 1, 0, 5, "\x01", 1);

    # Invoke IDs are association-wide: reuse by another confirmed service
    # invalidates the Select and a later error cannot be assigned to it.
    select_request(c, T, 214, 0, "", "BREAKER_SBO", 1);
    event ICCP::mms_control_message(
        c, T, 0, 214, 6, 0, "", "OTHER", 1, 0, 0, 0, 0, 0);
    event ICCP::mms_error_message(c, F, 2, 214, -1, 7, 3, -1, "");

    # Connection teardown removes pending Select correlation state.
    select_request(c, T, 215, 0, "", "BREAKER_SBO", 1);
    event connection_state_remove(c);
    select_response(c, F, 215, 1, 0, 5, "\x01", 1);
    }
