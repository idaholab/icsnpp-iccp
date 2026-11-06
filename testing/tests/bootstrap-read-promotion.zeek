# @TEST-DOC: TASE.2 association/domain promotion requires one verified,
# @TEST-DOC: direction-correlated explicit-variable Read and an exact mandatory
# @TEST-DOC: bootstrap value. Names, bad values/scopes/directions, failed or
# @TEST-DOC: ambiguous responses, and named-list Reads cannot promote state.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT > output
# @TEST-EXEC: btest-diff output

module ICCP;

function make_connection(uid: string): connection
    {
    return [
        $id=[$orig_h=192.0.2.91, $orig_p=49152/tcp,
             $resp_h=192.0.2.92, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid=uid
    ];
    }

function establish(c: connection)
    {
    event ICCP::presentation_message_v2(
        c, T, T, 2, 3, "2.2.1.0.1", "2.1.1", T, F, F, 32);
    event ICCP::acse_message(
        c, T, T, 0, "1.0.9506.2.3", -1, -1, -1, F, 0, F, T, 24);
    event ICCP::acse_message(
        c, F, T, 1, "1.0.9506.2.3", 0, -1, 0, F, 0, F, T, 24);
    }

function read_request(
    c: connection, is_orig: bool, invoke_id: int,
    access_choice: count, variable_count: count, scope: count,
    domain: string, name: string, category: count, provenance: count)
    {
    event ICCP::mms_read_message_v3(
        c, is_orig, 0, invoke_id, access_choice, variable_count,
        scope, domain, name, category, 0, 0, 0, "",
        0, 0, 0, 0, 0, 0, provenance);
    }

function read_response(
    c: connection, is_orig: bool, invoke_id: int,
    result_count: count, failure_count: count, result_type: count,
    raw: string, integer_count: count, first_integer: int,
    second_integer: int, component_count: count,
    first_choice: count, second_choice: count, provenance: count)
    {
    event ICCP::mms_read_message_v3(
        c, is_orig, 1, invoke_id, 0, 0, 0, "", "", 0,
        result_count, failure_count, result_type, raw,
        integer_count, first_integer, second_integer, component_count,
        first_choice, second_choice, provenance);
    }

function aggregate_read_request(
    c: connection, is_orig: bool, invoke_id: int,
    scope: count, domain: string, name: string, category: count)
    {
    event ICCP::mms_message(
        c, is_orig, T, 0, T, 24, invoke_id, 4, 0, T, 2, "", "",
        0, "", "", 0, F, scope, domain, name, category,
        0, "", 0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);
    }

function aggregate_read_response(
    c: connection, is_orig: bool, invoke_id: int,
    result_type: count, raw: string)
    {
    event ICCP::mms_message(
        c, is_orig, T, 1, T, 24, invoke_id, 4, 0, T, 2, "", "",
        0, "", "", 0, F, 0, "", "", 0,
        result_type, raw, 0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);
    }

event inspect_bootstrap(c: connection, label: string, domain: string)
    &priority=-20
    {
    local state = current_state(c);
    print fmt("%s kind=%s tase=%s bilateral=%s", label,
              association_kind(c), state$tase2_evidence,
              is_bilateral_domain(c, domain));
    }

event zeek_init()
    {
    local good_features = make_connection("Cbootstrap-good-features");
    establish(good_features);
    read_request(good_features, T, 1, 0, 1, 0, "",
                 "Supported_Features", 1, 1);
    read_response(good_features, F, 1, 1, 0, 4, "\x07\x80",
                  0, 0, 0, 0, 0, 0, 1);
    event inspect_bootstrap(good_features, "good-features", "");

    local good_bilateral = make_connection("Cbootstrap-good-bilateral");
    establish(good_bilateral);
    read_request(good_bilateral, T, 2, 0, 1, 1, "BILATERAL_A",
                 "Bilateral_Table_ID", 2, 1);
    read_response(good_bilateral, F, 2, 1, 0, 10, "AGREEMENT_A",
                  0, 0, 0, 0, 0, 0, 1);
    event inspect_bootstrap(
        good_bilateral, "good-bilateral", "BILATERAL_A");

    local good_version = make_connection("Cbootstrap-good-version");
    establish(good_version);
    read_request(good_version, T, 3, 0, 1, 0, "",
                 "TASE.2_Version", 5, 1);
    read_response(good_version, F, 3, 1, 0, 2, "", 2, 2000, 8,
                  2, 5, 5, 1);
    event inspect_bootstrap(good_version, "good-version", "");

    local bad_value = make_connection("Cbootstrap-bad-value");
    establish(bad_value);
    read_request(bad_value, T, 4, 0, 1, 0, "",
                 "Supported_Features", 1, 1);
    read_response(bad_value, F, 4, 1, 0, 4, "\x07\x00",
                  0, 0, 0, 0, 0, 0, 1);
    event inspect_bootstrap(bad_value, "bad-value", "");

    local bad_scope = make_connection("Cbootstrap-bad-scope");
    establish(bad_scope);
    read_request(bad_scope, T, 5, 0, 1, 1, "WRONG_DOMAIN",
                 "Supported_Features", 1, 1);
    read_response(bad_scope, F, 5, 1, 0, 4, "\x07\x80",
                  0, 0, 0, 0, 0, 0, 1);
    event inspect_bootstrap(bad_scope, "bad-scope", "WRONG_DOMAIN");

    local bad_direction = make_connection("Cbootstrap-bad-direction");
    establish(bad_direction);
    read_request(bad_direction, T, 6, 0, 1, 0, "",
                 "Supported_Features", 1, 1);
    read_response(bad_direction, T, 6, 1, 0, 4, "\x07\x80",
                  0, 0, 0, 0, 0, 0, 1);
    event inspect_bootstrap(bad_direction, "bad-direction", "");

    local failed = make_connection("Cbootstrap-failed");
    establish(failed);
    read_request(failed, T, 7, 0, 1, 0, "",
                 "Supported_Features", 1, 1);
    read_response(failed, F, 7, 1, 1, 0, "",
                  0, 0, 0, 0, 0, 0, 1);
    event inspect_bootstrap(failed, "access-failure", "");

    local reused = make_connection("Cbootstrap-reused");
    establish(reused);
    read_request(reused, T, 8, 0, 1, 0, "",
                 "Supported_Features", 1, 1);
    read_request(reused, T, 8, 0, 1, 0, "",
                 "Supported_Features", 1, 1);
    read_response(reused, F, 8, 1, 0, 4, "\x07\x80",
                  0, 0, 0, 0, 0, 0, 1);
    event inspect_bootstrap(reused, "invoke-reused", "");

    local named_list = make_connection("Cbootstrap-named-list");
    establish(named_list);
    read_request(named_list, T, 9, 1, 0, 0, "",
                 "Supported_Features", 1, 1);
    read_response(named_list, F, 9, 1, 0, 4, "\x07\x80",
                  0, 0, 0, 0, 0, 0, 1);
    event inspect_bootstrap(named_list, "named-list", "");

    local bad_count = make_connection("Cbootstrap-bad-count");
    establish(bad_count);
    read_request(bad_count, T, 10, 0, 1, 0, "",
                 "Supported_Features", 1, 1);
    read_response(bad_count, F, 10, 2, 0, 4, "\x07\x80",
                  0, 0, 0, 0, 0, 0, 1);
    event inspect_bootstrap(bad_count, "bad-result-count", "");

    local inferred = make_connection("Cbootstrap-inferred");
    establish(inferred);
    read_request(inferred, T, 11, 0, 1, 0, "",
                 "Supported_Features", 1, 2);
    read_response(inferred, F, 11, 1, 0, 4, "\x07\x80",
                  0, 0, 0, 0, 0, 0, 2);
    event inspect_bootstrap(inferred, "inferred", "");

    # Parser completion hooks are siblings. Promotion must not depend on
    # whether the self-contained v3 Read or aggregate compatibility event is
    # delivered first for either half of the exchange.
    local v3_first = make_connection("Cbootstrap-v3-first");
    establish(v3_first);
    event ICCP::mms_provenance_marker_v1(v3_first, T, 1);
    read_request(v3_first, T, 12, 0, 1, 0, "",
                 "Supported_Features", 1, 1);
    aggregate_read_request(
        v3_first, T, 12, 0, "", "Supported_Features", 1);
    event ICCP::mms_provenance_marker_v1(v3_first, F, 1);
    read_response(v3_first, F, 12, 1, 0, 4, "\x07\x80",
                  0, 0, 0, 0, 0, 0, 1);
    aggregate_read_response(v3_first, F, 12, 4, "\x07\x80");
    event inspect_bootstrap(v3_first, "v3-before-aggregate", "");

    local aggregate_first = make_connection("Cbootstrap-aggregate-first");
    establish(aggregate_first);
    event ICCP::mms_provenance_marker_v1(aggregate_first, T, 1);
    aggregate_read_request(
        aggregate_first, T, 13, 0, "", "Supported_Features", 1);
    read_request(aggregate_first, T, 13, 0, 1, 0, "",
                 "Supported_Features", 1, 1);
    event ICCP::mms_provenance_marker_v1(aggregate_first, F, 1);
    aggregate_read_response(aggregate_first, F, 13, 4, "\x07\x80");
    read_response(aggregate_first, F, 13, 1, 0, 4, "\x07\x80",
                  0, 0, 0, 0, 0, 0, 1);
    event inspect_bootstrap(
        aggregate_first, "aggregate-before-v3", "");
    }
