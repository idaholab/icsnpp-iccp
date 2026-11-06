# @TEST-DOC: Promote only exact type-discovered command and
# @TEST-DOC: setpoint Writes to Operate classifications. Shape-only, wrong
# @TEST-DOC: width, and multi-value writes remain generic candidates.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut classification outcome invoke_id object_name named_type integer_value floating_value < iccp_controls.log > output
# @TEST-EXEC: btest-diff output

module ICCP;

redef ICCP::legacy_gva_direct_event_compatibility = T;

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
                         floating_value: double, variable_count: count,
                         data_count: count)
    {
    event ICCP::mms_control_value_shape_v3(
        c, T, choice, raw, integer_value, floating_value);
    event ICCP::mms_control_request_deferred(
        c, T, invoke_id, 0, "", object_name,
        variable_count, data_count, 1);
    }

function control_response(c: connection, invoke_id: int,
                          success_count: count, failure_count: count)
    {
    event ICCP::mms_control_message(
        c, F, 1, invoke_id, 5, 0, "", "", 0, 0, 0,
        success_count + failure_count, success_count, failure_count);
    }

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.30, $orig_p=49152/tcp,
             $resp_h=192.0.2.40, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Ccontrol-types"
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

    learn_control_type(c, 100, "BREAKER", "Control_Command");
    control_request(c, 200, "BREAKER", 5, "\x01", 1, 0.0, 1, 1);
    control_response(c, 200, 1, 0);

    learn_control_type(c, 101, "MW_SETPOINT", "Control_Setpoint_Real");
    control_request(c, 201, "MW_SETPOINT", 7, "\x08\x41\x48\x00\x00",
                    0, 12.5, 1, 1);
    control_response(c, 201, 1, 0);

    learn_control_type(c, 102, "TAP_SETPOINT", "Control_Setpoint_Discrete");
    control_request(c, 202, "TAP_SETPOINT", 5, "\x00\x2a", 42, 0.0, 1, 1);
    control_response(c, 202, 0, 1);

    # Exact-looking values without all identity/shape requirements stay raw.
    control_request(c, 203, "UNKNOWN_COMMAND", 5, "\x01", 1, 0.0, 1, 1);
    control_response(c, 203, 1, 0);
    control_request(c, 204, "BREAKER", 5, "\x00\x00\x01", 1, 0.0, 1, 1);
    control_response(c, 204, 1, 0);
    control_request(c, 205, "BREAKER", 5, "\x01", 1, 0.0, 2, 2);
    control_response(c, 205, 2, 0);

    control_request(c, 206, "BREAKER", 5, "\x00\x00", 0, 0.0, 1, 1);
    event ICCP::mms_error_message(c, F, 2, 206, -1, 7, 3, -1, "");
    }
