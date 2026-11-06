# @TEST-DOC: Promote only exact ordered Info_Mess_Header / Info_Buff_XX
# @TEST-DOC: InformationReports. Enforce validated header, buffer, and
# @TEST-DOC: declared-size constraints while
# @TEST-DOC: declining near-name and reversed-order lookalikes.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut action outcome first_variable_name result_count failure_count pairing_status info_reference local_reference message_id message_size buffer_capacity buffer_length provenance < iccp_transfers.log | grep '^information_message' > output
# @TEST-EXEC: btest-diff output

module ICCP;

function integer_vector(a: int, b: int, c: int, d: int): vector of int
    {
    local result: vector of int;
    result[0] = a;
    result[1] = b;
    result[2] = c;
    result[3] = d;
    return result;
    }

function define_information_message_list(
    c: connection, invoke_id: int, list_name: string,
    header_name: string, buffer_name: string)
    {
    local member_scopes: vector of count = vector(0, 0);
    local member_domains: vector of string = vector("", "");
    local member_names: vector of string = vector(header_name, buffer_name);
    local no_counts: vector of count;
    local no_ints: vector of int;
    local no_strings: vector of string;
    event ICCP::mms_transfer_set_message(
        c, T, 0, invoke_id, 11, 0, 0, 1, "CONTROL_CENTER_B", list_name, 2,
        0, "", header_name, F, 0, 0, 0, 0, 0, 0,
        member_scopes, member_domains, member_names,
        no_counts, no_ints, no_strings);
    event ICCP::mms_transfer_set_message(
        c, F, 1, invoke_id, 11, 0, 0, 0, "", "", 0,
        0, "", "", F, 0, 0, 0, 0, 0, 0,
        no_counts, no_strings, no_strings,
        no_counts, no_ints, no_strings);
    }

function information_message_report(
    c: connection, list_name: string,
    component_choices: vector of count, component_raws: vector of string,
    component_integers: vector of int, buffer_choice: count,
    buffer: string)
    {
    local no_doubles: vector of double = vector(0.0, 0.0);
    local no_bools: vector of bool = vector(F, F);
    local no_strings: vector of string = vector("", "");
    local normalized_ints: vector of int;
    normalized_ints[0] = 0;
    normalized_ints[1] = 0;
    local no_nested_choices: vector of count;
    local no_nested_raws: vector of string;
    local no_nested_integers: vector of int;
    event ICCP::mms_information_report_results_v2(
        c, F, 1, 1, "CONTROL_CENTER_B", list_name, 2, 0,
        vector(), vector(), vector(),
        vector(2, buffer_choice), vector(-1, -1),
        vector("header", buffer), normalized_ints, no_doubles,
        no_bools, no_strings, 1);
    event ICCP::mms_point_value_shape_v3(
        c, F, 12, component_choices, component_raws,
        component_integers, 0, no_nested_choices, no_nested_raws,
        no_nested_integers);
    event ICCP::mms_message(
        c, F, T, 3, T, 64, -1, 0, 0, T, 8, "", "",
        0, "", "", 0, F,
        0, "", "", 0, 2, "header", 4, 1, 2,
        |component_choices|,
        |component_choices| > 0 ? component_choices[0] : 0,
        |component_choices| > 1 ? component_choices[1] : 0,
        |component_choices| > 2 ? component_choices[2] : 0,
        1, 0.0, "", 0);
    }

function explicit_information_message_report(
    c: connection, component_choices: vector of count,
    component_raws: vector of string,
    component_integers: vector of int, buffer: string)
    {
    local normalized_ints: vector of int;
    normalized_ints[0] = 0; normalized_ints[1] = 0;
    local no_nested_choices: vector of count;
    local no_nested_raws: vector of string;
    local no_nested_integers: vector of int;
    event ICCP::mms_information_report_results_v2(
        c, F, 0, 0, "", "", 2, 0,
        vector(0, 0), vector("", ""),
        vector("Info_Mess_Header", "Info_Buff_8"),
        vector(2, 9), vector(-1, -1), vector("header", buffer),
        normalized_ints, vector(0.0, 0.0), vector(F, F),
        vector("", ""), 1);
    event ICCP::mms_point_value_shape_v3(
        c, F, 12, component_choices, component_raws,
        component_integers, 0, no_nested_choices, no_nested_raws,
        no_nested_integers);
    event ICCP::mms_message(
        c, F, T, 3, T, 64, -1, 0, 0, T, 8, "", "",
        0, "", "", 0, F,
        0, "", "", 0, 2, "header", 4, 1, 2,
        |component_choices|,
        |component_choices| > 0 ? component_choices[0] : 0,
        |component_choices| > 1 ? component_choices[1] : 0,
        |component_choices| > 2 ? component_choices[2] : 0,
        1, 0.0, "", 0);
    }

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.150, $orig_p=49152/tcp,
             $resp_h=192.0.2.160, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Cinformation-message"
    ];
    local state = ICCP::current_state(c);
    state$phase = "established";
    state$presentation_profile = T;
    state$acse_association = T;
    state$mms_negotiation = T;
    state$tase2_evidence = T;
    state$originator_known = T;
    state$originator_is_orig = T;
    ICCP::associations[c$uid] = state;
    local choices = vector(5, 5, 5, 5);
    local raws = vector("\x01", "\x02", "\x03", "\x05");
    local integers = integer_vector(1, 2, 3, 5);
    local buffer = "hello\x00\x00\x00";
    define_information_message_list(
        c, 100, "IM_GOOD", "Info_Mess_Header", "Info_Buff_8");
    information_message_report(
        c, "IM_GOOD", choices, raws,
        integers, 9, buffer);
    explicit_information_message_report(c, choices, raws, integers, buffer);

    define_information_message_list(
        c, 101, "IM_SIZE", "Info_Mess_Header", "Info_Buff_8");
    information_message_report(
        c, "IM_SIZE", choices,
        vector("\x01", "\x02", "\x03", "\x09"),
        integer_vector(1, 2, 4, 9), 9, buffer);

    define_information_message_list(
        c, 102, "IM_HEADER", "Info_Mess_Header", "Info_Buff_8");
    information_message_report(
        c, "IM_HEADER", vector(5, 5, 6, 5),
        raws, integers, 9, buffer);

    define_information_message_list(
        c, 103, "IM_BUFFER", "Info_Mess_Header", "Info_Buff_8");
    information_message_report(
        c, "IM_BUFFER", choices, raws,
        integers, 9, "short");

    # Leading-zero capacity and wrong ordered identity are not standardized
    # Information Message candidates and emit no semantic transfer row.
    define_information_message_list(
        c, 104, "IM_ZERO", "Info_Mess_Header", "Info_Buff_08");
    information_message_report(
        c, "IM_ZERO", choices, raws,
        integers, 9, buffer);
    define_information_message_list(
        c, 105, "IM_REVERSED", "Info_Buff_8", "Info_Mess_Header");
    information_message_report(
        c, "IM_REVERSED", choices, raws,
        integers, 9, buffer);
    }
