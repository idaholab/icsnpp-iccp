# @TEST-DOC: Learned standardized types and named-list membership belong to
# @TEST-DOC: the endpoint that serves the object, not just the association.
# @TEST-DOC: Identical names in both endpoint namespaces remain independent.
# @TEST-DOC: IEC 60870-6-802 point/control objects with AA-specific scope stay
# @TEST-DOC: generic even when an operator configured a matching named type.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut is_orig classification outcome invoke_id object_scope object_name named_type integer_value < iccp_controls.log | awk '$4 >= 40' > controls
# @TEST-EXEC: btest-diff controls
# @TEST-EXEC: zeek-cut is_orig action outcome list_name first_variable_name known_list < iccp_transfers.log | awk '$2 == "report_value"' > lists
# @TEST-EXEC: btest-diff lists
# @TEST-EXEC: zeek-cut is_orig observation_kind object_name result_index result_type integer_value < iccp_objects.log | awk '$3 == "RESP_POINT" || $3 == "ORIG_POINT"' > identities
# @TEST-EXEC: btest-diff identities
# @TEST-EXEC: zeek-cut is_orig object_scope object_name point_type integer_value < iccp_objects.log | awk '$3 == "AA_POINT"' > points
# @TEST-EXEC: btest-diff points

module ICCP;

redef ICCP::legacy_gva_direct_event_compatibility = T;

function establish_tase2(c: connection)
    {
    event ICCP::presentation_message_v2(
        c, T, T, 2, 3, "2.2.1.0.1", "2.1.1", T, F, F, 32);
    event ICCP::acse_message(
        c, T, T, 0, "1.0.9506.2.3", -1, -1, -1,
        F, 0, F, T, 24);
    event ICCP::mms_message(
        c, T, T, 8, T, 16, -1, 0, 0, F, 0, "\x00", "\x01",
        0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::acse_message(
        c, F, T, 1, "1.0.9506.2.3", 0, -1, 0,
        F, 0, F, T, 24);
    event ICCP::mms_read_message_v3(
        c, T, 0, 8, 0, 1, 0, "", "Supported_Features", 1,
        0, 0, 0, "", 0, 0, 0, 0, 0, 0, 1);
    event ICCP::mms_read_message_v3(
        c, F, 1, 8, 0, 0, 0, "", "", 0,
        1, 0, 4, "\x04\xa0", 0, 0, 0, 0, 0, 0, 1);
    }

function learn_named_type(c: connection, request_is_orig: bool,
                          invoke_id: int, scope: count, domain: string,
                          object_name: string, named_type: string)
    {
    local server = request_is_orig ? c$id$resp_h : c$id$orig_h;
    local peer = request_is_orig ? c$id$orig_h : c$id$resp_h;
    ICCP::configured_variable_types[
        server, peer, scope, domain, object_name] = named_type;
    event ICCP::mms_variable_type_message(
        c, request_is_orig, 0, invoke_id, 6,
        scope, domain, object_name, 0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, ! request_is_orig, 1, invoke_id, 6,
        0, "", "", 0, 0, "", named_type);
    }

function control_request(c: connection, request_is_orig: bool,
                         invoke_id: int, scope: count, domain: string,
                         object_name: string, integer_value: int)
    {
    event ICCP::mms_control_value_shape_v3(
        c, request_is_orig, 5, "\x01", integer_value, 0.0);
    event ICCP::mms_control_request_deferred(
        c, request_is_orig, invoke_id, scope, domain, object_name,
        1, 1, 1);
    event ICCP::mms_control_message(
        c, ! request_is_orig, 1, invoke_id, 5, 0, "", "",
        0, 0, 0, 1, 1, 0);
    }

function define_list(c: connection, request_is_orig: bool,
                     invoke_id: int, list_name: string,
                     member_name: string)
    {
    local no_counts: vector of count = vector();
    local no_ints: vector of int = vector();
    local no_strings: vector of string = vector();
    event ICCP::mms_transfer_set_message(
        c, request_is_orig, 0, invoke_id, 11, 0,
        0, 1, "CONTROL_CENTER_B", list_name, 1,
        0, "", member_name, F, 0, 0, 0, 0, 0, 0,
        vector(0), vector(""), vector(member_name),
        no_counts, no_ints, no_strings);
    event ICCP::mms_transfer_set_message(
        c, ! request_is_orig, 1, invoke_id, 11, 0,
        0, 0, "", "", 0,
        0, "", "", F, 0, 0, 0, 0, 0, 0,
        no_counts, no_strings, no_strings,
        no_counts, no_ints, no_strings);
    }

function emit_named_list_report(c: connection, server_is_orig: bool,
                                list_name: string)
    {
    local no_counts: vector of count = vector();
    local no_ints: vector of int = vector();
    local no_strings: vector of string = vector();
    event ICCP::mms_transfer_set_message(
        c, server_is_orig, 3, -1, 0, 0,
        1, 1, "CONTROL_CENTER_B", list_name, 0,
        0, "", "", F, 0, 0, 0, 0, 1, 0,
        no_counts, no_strings, no_strings,
        vector(5), vector(-1), vector("\x2a"));
    }

function emit_evidenced_named_list_report(
    c: connection, server_is_orig: bool, list_name: string,
    integer_value: int)
    {
    event ICCP::mms_information_report_results_v2(
        c, server_is_orig, 1, 1, "CONTROL_CENTER_B", list_name, 1, 0,
        vector(), vector(), vector(), vector(5), vector(-1),
        vector("\x2a"), vector(integer_value), vector(0.0),
        vector(F), vector(""), 1);
    event ICCP::mms_message(
        c, server_is_orig, T, 3, T, 24, -1, 0, 0, F, 0, "", "",
        0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    }

function emit_aa_point_read(c: connection, invoke_id: int,
                            object_name: string)
    {
    event ICCP::mms_message(
        c, T, T, 0, T, 24, invoke_id, 4, 0, T, 2, "", "",
        0, "", "", 0, F, 2, "", object_name, 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_point_value_shape_v2(c, F, 1, 0, 0, 0);
    event ICCP::mms_message(
        c, F, T, 1, T, 24, invoke_id, 4, 0, T, 2, "", "",
        0, "", "", 0, F, 0, "", "", 0, 5, "\x2a", 0, 0, 0,
        0, 0, 0, 0, 42, 0.0, "", 0);
    }

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.10, $orig_p=49152/tcp,
             $resp_h=192.0.2.20, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Cendpoint-state"
    ];
    establish_tase2(c);

    # The same VMD-specific name has a different standardized control type at
    # each serving endpoint.  Each request must use its target server's type.
    learn_named_type(c, T, 10, 0, "", "SHARED_CONTROL",
                     "Control_Command");
    learn_named_type(c, F, 11, 0, "", "SHARED_CONTROL",
                     "Control_Setpoint_Discrete");
    control_request(c, T, 40, 0, "", "SHARED_CONTROL", 1);
    control_request(c, F, 41, 0, "", "SHARED_CONTROL", 2);

    # AA-specific scope is legal MMS naming but is not the 802 mapping for a
    # ControlPoint or IndicationPoint, so neither observation is exact TASE.2.
    learn_named_type(c, T, 12, 2, "", "AA_CONTROL", "Control_Command");
    control_request(c, T, 42, 2, "", "AA_CONTROL", 3);
    learn_named_type(c, T, 13, 2, "", "AA_POINT", "Data_Discrete");
    emit_aa_point_read(c, 43, "AA_POINT");

    # Identically named lists can be hosted by both endpoints with unrelated
    # ordered membership.  Reports must resolve in the sender's namespace.
    define_list(c, T, 20, "SHARED_LIST", "RESP_POINT");
    define_list(c, F, 21, "SHARED_LIST", "ORIG_POINT");
    emit_named_list_report(c, F, "SHARED_LIST");
    emit_named_list_report(c, T, "SHARED_LIST");
    emit_evidenced_named_list_report(c, F, "SHARED_LIST", 10);
    emit_evidenced_named_list_report(c, T, "SHARED_LIST", 20);
    }
