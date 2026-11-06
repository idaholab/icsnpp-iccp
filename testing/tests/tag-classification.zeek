# @TEST-DOC: Classify Get Tag and Set Tag only when an exact
# @TEST-DOC: single-variable MMS Read/Write of Device_Name_TAG is backed by
# @TEST-DOC: connection-scoped Tag_Value type discovery and the supported
# @TEST-DOC: two-component Tag_Value wire shape. Validate lifecycle failures,
# @TEST-DOC: malformed flags, incomplete evidence, scope, and direction.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut classification outcome invoke_id object_scope object_domain object_name named_type variable_count data_count tag_value tag_state tag_reason result_count success_count failure_count error_class error_code < iccp_controls.log > output
# @TEST-EXEC: btest-diff output

module ICCP;

redef ICCP::legacy_gva_direct_event_compatibility = T;

function learn_tag_type(c: connection, invoke_id: int, scope: count,
                        domain: string, object_name: string)
    {
    ICCP::configured_variable_types[
        c$id$resp_h, c$id$orig_h, scope, domain, object_name] = "Tag_Value";
    event ICCP::mms_variable_type_message(
        c, T, 0, invoke_id, 6, scope, domain, object_name, 0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, F, 1, invoke_id, 6, 0, "", "", 0, 0, "", "Tag_Value");
    }

function set_tag_request(c: connection, invoke_id: int, scope: count,
                         domain: string, object_name: string,
                         variable_count: count, data_count: count,
                         flags_raw: string, reason: string)
    {
    local choices: vector of count = vector(4, 10);
    local raws: vector of string = vector(flags_raw, reason);
    local integers: vector of int = vector();
    integers[0] = 0;
    integers[1] = 0;
    event ICCP::mms_control_value_shape_v4(
        c, T, 2, "", 0, 0.0, choices, raws, integers);
    event ICCP::mms_control_request_deferred(
        c, T, invoke_id, scope, domain, object_name,
        variable_count, data_count, 3);
    }

function write_response(c: connection, is_orig: bool, invoke_id: int,
                        success_count: count, failure_count: count)
    {
    event ICCP::mms_control_message(
        c, is_orig, 1, invoke_id, 5, 0, "", "", 0, 0, 0,
        success_count + failure_count, success_count, failure_count);
    }

function get_tag_request(c: connection, invoke_id: int, scope: count,
                         domain: string, object_name: string,
                         variable_count: count)
    {
    event ICCP::mms_control_message(
        c, T, 0, invoke_id, 4, scope, domain, object_name,
        variable_count, 0, 0, 0, 0, 0);
    }

function get_tag_response(c: connection, is_orig: bool, invoke_id: int,
                          result_count: count, failure_count: count,
                          choice: count, flags_raw: string, reason: string)
    {
    local choices: vector of count = vector(4, 10);
    local raws: vector of string = vector(flags_raw, reason);
    local integers: vector of int = vector();
    integers[0] = 0;
    integers[1] = 0;
    local no_choices: vector of count = vector();
    local no_raws: vector of string = vector();
    local no_integers: vector of int = vector();
    event ICCP::mms_point_value_shape_v3(
        c, is_orig, |flags_raw| + |reason|,
        choices, raws, integers, 0,
        no_choices, no_raws, no_integers);
    event ICCP::mms_control_read_value_shape_v1(
        c, is_orig, 1, invoke_id, 4, |flags_raw| + |reason|,
        choices, raws, integers);
    event ICCP::mms_control_read_response_deferred(
        c, is_orig, invoke_id, result_count, failure_count,
        choice, "", 0);
    }

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.170, $orig_p=49152/tcp,
             $resp_h=192.0.2.180, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Ctag-types"
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

    # Exact Set Tag success, positive Write failure, and ConfirmedError.
    learn_tag_type(c, 100, 0, "", "BREAKER_TAG");
    set_tag_request(c, 200, 0, "", "BREAKER_TAG", 1, 1,
                    "\x05\x60", "maintenance");
    write_response(c, F, 200, 1, 0);
    set_tag_request(c, 201, 0, "", "BREAKER_TAG", 1, 1,
                    "\x05\x80", "remote");
    write_response(c, F, 201, 0, 1);
    set_tag_request(c, 202, 0, "", "BREAKER_TAG", 1, 1,
                    "\x05\x00", "clear");
    event ICCP::mms_error_message(c, F, 2, 202, -1, 7, 3, -1, "");

    # Suffix-only, type-only, invalid TagFlags, and invalid scope stay
    # candidates and never publish decoded tag semantics.
    set_tag_request(c, 203, 0, "", "UNKNOWN_TAG", 1, 1,
                    "\x05\x20", "candidate");
    write_response(c, F, 203, 1, 0);
    learn_tag_type(c, 101, 0, "", "WRONG_NAME");
    set_tag_request(c, 204, 0, "", "WRONG_NAME", 1, 1,
                    "\x05\x20", "candidate");
    write_response(c, F, 204, 1, 0);
    set_tag_request(c, 205, 0, "", "BREAKER_TAG", 1, 1,
                    "\x05\xc0", "reserved-tag");
    write_response(c, F, 205, 1, 0);
    learn_tag_type(c, 102, 2, "", "AA_TAG");
    set_tag_request(c, 206, 2, "", "AA_TAG", 1, 1,
                    "\x05\x20", "bad-scope");
    write_response(c, F, 206, 1, 0);

    # Exact Get Tag success, AccessResult failure, and ConfirmedError.
    get_tag_request(c, 210, 0, "", "BREAKER_TAG", 1);
    get_tag_response(c, F, 210, 1, 0, 2, "\x05\x80", "operator");
    get_tag_request(c, 211, 0, "", "BREAKER_TAG", 1);
    get_tag_response(c, F, 211, 1, 1, 0, "", "");
    get_tag_request(c, 212, 0, "", "BREAKER_TAG", 1);
    event ICCP::mms_error_message(c, F, 2, 212, -1, 7, 3, -1, "");

    # Incomplete type evidence and malformed TagFlags stay visibly
    # untrusted; a same-direction response cannot terminate the request.
    get_tag_request(c, 213, 0, "", "UNKNOWN_TAG", 1);
    get_tag_response(c, F, 213, 1, 0, 2, "\x05\x20", "candidate");
    get_tag_request(c, 214, 0, "", "BREAKER_TAG", 1);
    get_tag_response(c, F, 214, 1, 0, 2, "\x05\xc0", "invalid");
    get_tag_request(c, 215, 0, "", "BREAKER_TAG", 1);
    get_tag_response(c, T, 215, 1, 0, 2, "\x05\x20", "same-side");
    get_tag_response(c, F, 215, 1, 0, 2, "\x05\x20", "peer");

    # ICC-scoped Tag objects require a non-empty domain and exact cardinality.
    learn_tag_type(c, 103, 1, "STATION1", "TAP_TAG");
    get_tag_request(c, 216, 1, "STATION1", "TAP_TAG", 1);
    get_tag_response(c, F, 216, 1, 0, 2, "\x05\x40", "station");
    get_tag_request(c, 217, 0, "", "BREAKER_TAG", 2);
    get_tag_response(c, F, 217, 2, 0, 2, "\x05\x20", "multi");
    }
