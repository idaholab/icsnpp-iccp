# @TEST-DOC: Promote every supported supplemental State family only
# @TEST-DOC: after exact correlated named-type discovery and exact member
# @TEST-DOC: shape validation. Preserve State, Tag, ExpectedState, and reserved
# @TEST-DOC: bits; malformed widths, order, milliseconds, and COV remain raw.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut object_name point_type state_value tag_value expected_state_value supplemental_reserved validity value_source normal_value timestamp_quality timestamp_value cov_value standardized_value < iccp_objects.log | grep -E '^(SUPP_|BAD_SUPP_)' > output
# @TEST-EXEC: btest-diff output

module ICCP;

redef ICCP::legacy_gva_direct_event_compatibility = T;

function integer_vector(a: int, b: int, c: int, d: int,
                        length: count): vector of int
    {
    local result: vector of int;
    if ( length > 0 ) result[0] = a;
    if ( length > 1 ) result[1] = b;
    if ( length > 2 ) result[2] = c;
    if ( length > 3 ) result[3] = d;
    return result;
    }

function learn_type(c: connection, invoke_id: int, object_name: string,
                    named_type: string)
    {
    ICCP::configured_variable_types[
        c$id$resp_h, c$id$orig_h, 0, "", object_name] = named_type;
    event ICCP::mms_variable_type_message(
        c, T, 0, invoke_id, 6, 0, "", object_name, 0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, F, 1, invoke_id, 6, 0, "", "", 0, 0, "", named_type);
    }

function read_request(c: connection, invoke_id: int, object_name: string)
    {
    event ICCP::mms_message(
        c, T, T, 0, T, 24, invoke_id, 4, 0, T, 2, "", "",
        0, "", "", 0, F, 0, "", object_name, 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    }

function read_response(c: connection, invoke_id: int,
                       first_result_type: count,
                       choices: vector of count, raws: vector of string,
                       integers: vector of int, nested_index: count,
                       nested_choices: vector of count,
                       nested_raws: vector of string,
                       nested_integers: vector of int,
                       raw_marker: string)
    {
    event ICCP::mms_point_value_shape_v3(
        c, F, |raw_marker|, choices, raws, integers, nested_index,
        nested_choices, nested_raws, nested_integers);
    event ICCP::mms_message(
        c, F, T, 1, T, 32, invoke_id, 4, 0, T, 2, "", "",
        0, "", "", 0, F, 0, "", "", 0,
        first_result_type, raw_marker, 0, 0, 0, |choices|,
        |choices| > 0 ? choices[0] : 0,
        |choices| > 1 ? choices[1] : 0,
        |choices| > 2 ? choices[2] : 0,
        0, 0.0, "", 0);
    }

function observe(c: connection, type_invoke: int, read_invoke: int,
                 object_name: string, named_type: string,
                 first_result_type: count,
                 choices: vector of count, raws: vector of string,
                 integers: vector of int, nested_index: count,
                 nested_choices: vector of count,
                 nested_raws: vector of string,
                 nested_integers: vector of int,
                 raw_marker: string)
    {
    learn_type(c, type_invoke, object_name, named_type);
    read_request(c, read_invoke, object_name);
    read_response(c, read_invoke, first_result_type, choices, raws, integers,
                  nested_index, nested_choices, nested_raws, nested_integers,
                  raw_marker);
    }

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.30, $orig_p=49152/tcp,
             $resp_h=192.0.2.40, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Csupplemental-state"
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

    local supplemental = "\x00\x6c";
    local flags = "\x00\xaa";
    local seconds = "\x65\x53\xf1\x00";
    local milliseconds = "\x7b";
    local nested = "\x85\x04\x65\x53\xf1\x00\x85\x01\x7b";
    local cov = "\x2a";
    local no_choices: vector of count;
    local no_raws: vector of string;
    local no_integers: vector of int;

    observe(c, 100, 200, "SUPP_SCALAR", "Data_StateSupplemental", 4,
        no_choices, no_raws, no_integers, 0,
        no_choices, no_raws, no_integers, supplemental);
    observe(c, 101, 201, "SUPP_Q", "Data_StateSupplementalQ", 2,
        vector(4, 4), vector(supplemental, flags),
        integer_vector(0, 0, 0, 0, 2), 0,
        no_choices, no_raws, no_integers, "supp-q");
    observe(c, 102, 202, "SUPP_TIME", "Data_StateSupplementalQTimeTag", 2,
        vector(4, 5, 4), vector(supplemental, seconds, flags),
        integer_vector(0, 1700000000, 0, 0, 3), 0,
        no_choices, no_raws, no_integers, "supp-time");
    observe(c, 103, 203, "SUPP_COV", "Data_StateSupplementalExtended", 2,
        vector(4, 5, 4, 6), vector(supplemental, seconds, flags, cov),
        integer_vector(0, 1700000000, 0, 42, 4), 0,
        no_choices, no_raws, no_integers, "supp-cov");
    observe(c, 104, 204, "SUPP_TIME_EXT",
        "Data_StateSupplementalQTimeTagExtended", 2,
        vector(4, 2, 4), vector(supplemental, nested, flags),
        integer_vector(0, 0, 0, 0, 3), 2,
        vector(5, 5), vector(seconds, milliseconds),
        integer_vector(1700000000, 123, 0, 0, 2), "supp-time-ext");

    observe(c, 105, 205, "BAD_SUPP_WIDTH", "Data_StateSupplementalQ", 2,
        vector(4, 4), vector("\x01\x6c", flags),
        integer_vector(0, 0, 0, 0, 2), 0,
        no_choices, no_raws, no_integers, "bad-width");
    observe(c, 106, 206, "BAD_SUPP_ORDER",
        "Data_StateSupplementalQTimeTag", 2,
        vector(5, 4, 4), vector(seconds, supplemental, flags),
        integer_vector(1700000000, 0, 0, 0, 3), 0,
        no_choices, no_raws, no_integers, "bad-order");
    observe(c, 107, 207, "BAD_SUPP_MILLISECONDS",
        "Data_StateSupplementalQTimeTagExtended", 2,
        vector(4, 2, 4), vector(supplemental, nested, flags),
        integer_vector(0, 0, 0, 0, 3), 2,
        vector(5, 5), vector(seconds, "\x03\xe8"),
        integer_vector(1700000000, 1000, 0, 0, 2), "bad-milliseconds");
    observe(c, 108, 208, "BAD_SUPP_COV",
        "Data_StateSupplementalExtended", 2,
        vector(4, 5, 4, 6),
        vector(supplemental, seconds, flags, "\x01\x00\x00"),
        integer_vector(0, 1700000000, 0, 65536, 4), 0,
        no_choices, no_raws, no_integers, "bad-cov");
    }
