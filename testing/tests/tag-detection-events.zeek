# @TEST-DOC: Emit control-specific failure events only for exact Tag_Value
# @TEST-DOC: Set Tag or Get Tag failures/rejections. Generic Set Tag Write
# @TEST-DOC: failures retain the stable Write alert; candidates do not gain a
# @TEST-DOC: trusted control-specific alert.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT > output
# @TEST-EXEC: btest-diff output

module ICCP;

redef ICCP::legacy_gva_direct_event_compatibility = T;
redef ICCP::enable_iccp_log = F;
redef ICCP::enable_iccp_objects_log = F;
redef ICCP::enable_iccp_transfers_log = F;
redef ICCP::enable_iccp_controls_log = F;
redef ICCP::enable_iccp_errors_log = F;

global tag_control_alerts: count = 0;
global tag_generic_failures: count = 0;

event ICCP::control_failure_v2(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, invoke_id: int, classification: string,
    outcome: string, object_scope: string, object_domain: string,
    object_name: string, named_type: string, failure_count: count,
    error_class: string, error_code: int, provenance: string)
    {
    ++tag_control_alerts;
    print fmt("tag_failure invoke=%d classification=%s outcome=%s object=%s type=%s failures=%d error=%s/%d provenance=%s",
              invoke_id, classification, outcome, object_name, named_type,
              failure_count, error_class, error_code, provenance);
    }

event ICCP::write_failure_v2(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, invoke_id: int, outcome: string,
    object_scope: string, object_domain: string, object_name: string,
    failure_count: count, error_class: string, error_code: int,
    provenance: string)
    {
    ++tag_generic_failures;
    }

function learn_tag_type(c: connection, invoke_id: int, object_name: string)
    {
    ICCP::configured_variable_types[
        c$id$resp_h, c$id$orig_h, 0, "", object_name] = "Tag_Value";
    event ICCP::mms_variable_type_message(
        c, T, 0, invoke_id, 6, 0, "", object_name, 0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, F, 1, invoke_id, 6, 0, "", "", 0, 0, "", "Tag_Value");
    }

function set_tag_request(c: connection, invoke_id: int, object_name: string)
    {
    local integers: vector of int = vector();
    integers[0] = 0;
    integers[1] = 0;
    event ICCP::mms_control_value_shape_v4(
        c, T, 2, "", 0, 0.0, vector(4, 10),
        vector("\x05\x20", "test"), integers);
    event ICCP::mms_control_request_deferred(
        c, T, invoke_id, 0, "", object_name, 1, 1, 3);
    }

function write_failure_result(c: connection, invoke_id: int)
    {
    event ICCP::mms_control_message_v2(
        c, F, 1, invoke_id, 5, 0, "", "", 0, 0, 0, 1, 0, 1, 1);
    event ICCP::mms_control_message(
        c, F, 1, invoke_id, 5, 0, "", "", 0, 0, 0, 1, 0, 1);
    }

function get_tag_request(c: connection, invoke_id: int, object_name: string)
    {
    event ICCP::mms_control_message_v2(
        c, T, 0, invoke_id, 4, 0, "", object_name, 1, 0, 0, 0, 0, 0, 1);
    event ICCP::mms_control_message(
        c, T, 0, invoke_id, 4, 0, "", object_name, 1, 0, 0, 0, 0, 0);
    }

function reject(c: connection, invoke_id: int)
    {
    event ICCP::mms_error_message_v2(
        c, F, 2, invoke_id, -1, 7, 3, -1, "", 1);
    event ICCP::mms_error_message(
        c, F, 2, invoke_id, -1, 7, 3, -1, "");
    }

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.181, $orig_p=49152/tcp,
             $resp_h=192.0.2.182, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Ctag-alerts"
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

    learn_tag_type(c, 100, "BREAKER_TAG");
    set_tag_request(c, 200, "BREAKER_TAG");
    write_failure_result(c, 200);

    get_tag_request(c, 201, "BREAKER_TAG");
    reject(c, 201);

    # Naming evidence without exact type discovery is never promoted.
    set_tag_request(c, 202, "UNKNOWN_TAG");
    write_failure_result(c, 202);
    get_tag_request(c, 203, "UNKNOWN_TAG");
    reject(c, 203);
    }

event zeek_done()
    {
    print fmt("counts control=%d generic=%d", tag_control_alerts,
              tag_generic_failures);
    }
