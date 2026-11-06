# @TEST-DOC: Verify exact supported StateQTimeTag, structured
# @TEST-DOC: TimeStampExtended, and COV-bearing Real/State/Discrete promotion.
# @TEST-DOC: Malformed, mismatched, and out-of-range values remain raw even
# @TEST-DOC: after exact named-type discovery.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut object_name point_type state_value integer_value floating_value timestamp_value cov_value standardized_value < iccp_objects.log | grep -E '^(STATE_|REAL_|DISCRETE_|BAD_)' > output
# @TEST-EXEC: btest-diff output

module ICCP;

redef ICCP::legacy_gva_direct_event_compatibility = T;

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

function read_response(c: connection, invoke_id: int, object_name: string,
                       choices: vector of count, raws: vector of string,
                       integers: vector of int,
                       nested_index: count,
                       nested_choices: vector of count,
                       nested_raws: vector of string,
                       nested_integers: vector of int,
                       integer_value: int, floating_value: double,
                       raw_marker: string)
    {
    event ICCP::mms_point_value_shape_v3(
        c, F, |raw_marker|, choices, raws, integers, nested_index,
        nested_choices, nested_raws, nested_integers);
    event ICCP::mms_message(
        c, F, T, 1, T, 32, invoke_id, 4, 0, T, 2, "", "",
        0, "", "", 0, F, 0, "", "", 0, 2, raw_marker,
        0, 0, 0, |choices|,
        |choices| > 0 ? choices[0] : 0,
        |choices| > 1 ? choices[1] : 0,
        |choices| > 2 ? choices[2] : 0,
        integer_value, floating_value, "", 0);
    }

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.10, $orig_p=49152/tcp,
             $resp_h=192.0.2.20, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Cpoint-families"
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

    local seconds = "\x65\x53\xf1\x00";
    local flags = "\x00\xaa";
    local real = "\x08\x41\x20\x00\x00";
    local discrete = "\x00\x7b";
    local cov = "\x2a";
    local milliseconds = "\x7b";
    local nested = "\x85\x04\x65\x53\xf1\x00\x85\x01\x7b";
    local no_choices: vector of count;
    local no_raws: vector of string;
    local no_integers: vector of int;

    learn_type(c, 100, "STATE_TIME", "Data_StateQTimeTag");
    read_request(c, 200, "STATE_TIME");
    read_response(c, 200, "STATE_TIME", vector(5, 4),
        vector(seconds, flags), integer_vector(1700000000, 0, 0, 0, 2), 0,
        no_choices, no_raws, no_integers, 1700000000, 0.0, "state-time");

    learn_type(c, 101, "REAL_COV", "Data_RealExtended");
    read_request(c, 201, "REAL_COV");
    read_response(c, 201, "REAL_COV", vector(7, 5, 4, 6),
        vector(real, seconds, flags, cov),
        integer_vector(0, 1700000000, 0, 42, 4), 0,
        no_choices, no_raws, no_integers, 0, 10.0, "real-cov");

    learn_type(c, 102, "STATE_COV", "Data_StateExtended");
    read_request(c, 202, "STATE_COV");
    read_response(c, 202, "STATE_COV", vector(5, 4, 6),
        vector(seconds, flags, cov),
        integer_vector(1700000000, 0, 42, 0, 3), 0,
        no_choices, no_raws, no_integers, 1700000000, 0.0, "state-cov");

    learn_type(c, 103, "DISCRETE_COV", "Data_DiscreteExtended");
    read_request(c, 203, "DISCRETE_COV");
    read_response(c, 203, "DISCRETE_COV", vector(5, 5, 4, 6),
        vector(discrete, seconds, flags, cov),
        integer_vector(123, 1700000000, 0, 42, 4), 0,
        no_choices, no_raws, no_integers, 123, 0.0, "discrete-cov");

    learn_type(c, 104, "REAL_TIME_EXT", "Data_RealQTimeTagExtended");
    read_request(c, 204, "REAL_TIME_EXT");
    read_response(c, 204, "REAL_TIME_EXT", vector(7, 2, 4),
        vector(real, nested, flags), integer_vector(0, 0, 0, 0, 3), 2,
        vector(5, 5), vector(seconds, milliseconds),
        integer_vector(1700000000, 123, 0, 0, 2),
        0, 10.0, "real-time-ext");

    learn_type(c, 105, "STATE_TIME_EXT", "Data_StateQTimeTagExtended");
    read_request(c, 205, "STATE_TIME_EXT");
    read_response(c, 205, "STATE_TIME_EXT", vector(2, 4),
        vector(nested, flags), integer_vector(0, 0, 0, 0, 2), 1,
        vector(5, 5), vector(seconds, milliseconds),
        integer_vector(1700000000, 123, 0, 0, 2),
        0, 0.0, "state-time-ext");

    learn_type(c, 106, "DISCRETE_TIME_EXT",
               "Data_DiscreteQTimeTagExtended");
    read_request(c, 206, "DISCRETE_TIME_EXT");
    read_response(c, 206, "DISCRETE_TIME_EXT", vector(5, 2, 4),
        vector(discrete, nested, flags), integer_vector(123, 0, 0, 0, 3), 2,
        vector(5, 5), vector(seconds, milliseconds),
        integer_vector(1700000000, 123, 0, 0, 2),
        123, 0.0, "discrete-time-ext");

    # Exact named types do not rescue unsupported member evidence.
    learn_type(c, 107, "BAD_ORDER", "Data_RealExtended");
    read_request(c, 207, "BAD_ORDER");
    read_response(c, 207, "BAD_ORDER", vector(7, 4, 5, 6),
        vector(real, flags, seconds, cov),
        integer_vector(0, 0, 1700000000, 42, 4), 0,
        no_choices, no_raws, no_integers, 0, 10.0, "bad-order");

    learn_type(c, 108, "BAD_MILLISECONDS", "Data_RealQTimeTagExtended");
    read_request(c, 208, "BAD_MILLISECONDS");
    read_response(c, 208, "BAD_MILLISECONDS", vector(7, 2, 4),
        vector(real, nested, flags), integer_vector(0, 0, 0, 0, 3), 2,
        vector(5, 5), vector(seconds, "\x03\xe8"),
        integer_vector(1700000000, 1000, 0, 0, 2),
        0, 10.0, "bad-milliseconds");

    learn_type(c, 109, "BAD_COV", "Data_DiscreteExtended");
    read_request(c, 209, "BAD_COV");
    read_response(c, 209, "BAD_COV", vector(5, 5, 4, 6),
        vector(discrete, seconds, flags, "\x01\x00\x00"),
        integer_vector(123, 1700000000, 0, 65536, 4), 0,
        no_choices, no_raws, no_integers, 123, 0.0, "bad-cov");
    }
