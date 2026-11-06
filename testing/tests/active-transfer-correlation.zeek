# @TEST-DOC: Correlate confirmed DSTransferSet state with named, RBE, blocked,
# @TEST-DOC: direction-invalid, and post-Stop InformationReports without
# @TEST-DOC: treating ambiguous or absent capture context as a violation.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut action outcome transfer_set_scope transfer_set_domain transfer_set_name transfer_state report_access report_correlation data_set_scope data_set_domain data_set_name block_data critical report_by_exception ack_required provenance < iccp_transfers.log | grep '^active_report' > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: zeek-cut action outcome list_scope list_domain list_name data_set_name conformance conformance_reasons < iccp_transfers.log | grep '^start.confirmed_duplicate_start' > lifecycle
# @TEST-EXEC: btest-diff lifecycle
# @TEST-EXEC: grep '^report-anomaly' .stdout > anomalies
# @TEST-EXEC: btest-diff anomalies

module ICCP;

redef ICCP::legacy_gva_direct_event_compatibility = T;

event ICCP::transfer_report_anomaly_v2(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, transfer_set_scope: string,
    transfer_set_domain: string, transfer_set_name: string,
    report_correlation: string, reason: string, provenance: string)
    {
    print fmt("report-anomaly transfer=%s/%s/%s correlation=%s reason=%s provenance=%s",
              transfer_set_scope, transfer_set_domain, transfer_set_name,
              report_correlation, reason, provenance);
    }

function seed_tase2(c: connection)
    {
    local state = ICCP::current_state(c);
    state$phase = "established";
    state$presentation_profile = T;
    state$acse_association = T;
    state$mms_negotiation = T;
    state$tase2_evidence = T;
    state$originator_known = T;
    state$originator_is_orig = T;
    ICCP::associations[c$uid] = state;
    }

function define_list(c: connection, invoke_id: int, name: string,
                     members: vector of string)
    {
    local scopes: vector of count = vector();
    local domains: vector of string = vector();
    local index: count = 0;
    while ( index < |members| )
        {
        scopes[index] = 1;
        domains[index] = "GRID";
        ++index;
        }
    event ICCP::mms_transfer_set_message(
        c, T, 0, invoke_id, 11, 0, 0, 1, "GRID", name, |members|,
        1, "GRID", members[0], F, 0, 0, 0, 0, 0, 0,
        scopes, domains, members, vector(), vector(), vector());
    event ICCP::mms_transfer_set_message(
        c, F, 1, invoke_id, 11, 0, 0, 0, "", "", 0,
        0, "", "", F, 0, 0, 0, 0, 0, 0,
        vector(), vector(), vector(), vector(), vector(), vector());
    }

function learn_transfer_type_in_domain(c: connection, invoke_id: int,
                                       domain: string, name: string)
    {
    ICCP::configured_variable_types[
        c$id$resp_h, c$id$orig_h, 1, domain, name] =
            "DSTransferSet";
    event ICCP::mms_variable_type_message(
        c, T, 0, invoke_id, 6, 1, domain, name,
        0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, F, 1, invoke_id, 6, 0, "", "", 0, 0, "", "DSTransferSet");
    }

function learn_transfer_type(c: connection, invoke_id: int, name: string)
    {
    learn_transfer_type_in_domain(
        c, invoke_id, "CONTROL_CENTER_B", name);
    }

function learn_reverse_transfer_type(c: connection, invoke_id: int,
                                     name: string)
    {
    ICCP::configured_variable_types[
        c$id$orig_h, c$id$resp_h, 1, "CONTROL_CENTER_B", name] =
            "DSTransferSet";
    event ICCP::mms_variable_type_message(
        c, F, 0, invoke_id, 6, 1, "CONTROL_CENTER_B", name,
        0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, T, 1, invoke_id, 6, 0, "", "", 0, 0, "", "DSTransferSet");
    }

function transfer_values(enabled: bool): vector of int
    {
    local values: vector of int = vector();
    values[0] = 0; values[1] = 1700000000; values[2] = 60;
    values[3] = 5; values[4] = 2; values[5] = 3600; values[6] = 0;
    values[7] = 0; values[8] = 0; values[9] = 0; values[10] = 0;
    values[11] = enabled ? 1 : 0; values[12] = 7;
    return values;
    }

function transfer_raws(enabled: bool, rbe: bool,
                       blocked: bool): vector of string
    {
    return vector("", "\x65\x53\xf1\x00", "\x3c", "\x05", "\x02",
                  "\x0e\x10", "\x03\xa0", blocked ? "\xff" : "\x00",
                  "\xff", rbe ? "\xff" : "\x00", "\x00",
                  enabled ? "\xff" : "\x00", "\x07");
    }

function transfer_write_in_domain(
    c: connection, invoke_id: int, transfer_domain: string,
    transfer_name: string, data_set_name: string, enabled: bool, rbe: bool,
    blocked: bool, confirmed: bool)
    {
    local data_set_values: vector of int = vector();
    data_set_values[0] = 1;
    data_set_values[1] = 0;
    data_set_values[2] = 0;
    event ICCP::mms_ds_transfer_set_message_v1(
        c, T, 0, invoke_id, 5, 0, 1, transfer_domain, transfer_name,
        1, 1, 2,
        vector(2, 5, 5, 5, 5, 5, 4, 3, 3, 3, 3, 3, 5),
        transfer_raws(enabled, rbe, blocked), transfer_values(enabled),
        vector(6, 10, 10), vector("\x01", "GRID", data_set_name),
        data_set_values, 1);
    if ( confirmed )
        event ICCP::mms_transfer_control_message(
            c, F, 1, invoke_id, 5, 0, 0, "", "", 0, 0, 0, F,
            0, 0, F, F, 1, 1, 0);
    else
        event ICCP::mms_error_message(
            c, F, 2, invoke_id, -1, 7, 3, -1, "");
    }

function transfer_write(c: connection, invoke_id: int, transfer_name: string,
                        data_set_name: string, enabled: bool, rbe: bool,
                        blocked: bool, confirmed: bool)
    {
    transfer_write_in_domain(
        c, invoke_id, "CONTROL_CENTER_B", transfer_name, data_set_name,
        enabled, rbe, blocked, confirmed);
    }

function reverse_transfer_start(c: connection, invoke_id: int,
                                transfer_name: string,
                                data_set_name: string)
    {
    local data_set_values: vector of int = vector();
    data_set_values[0] = 1; data_set_values[1] = 0;
    data_set_values[2] = 0;
    event ICCP::mms_ds_transfer_set_message_v1(
        c, F, 0, invoke_id, 5, 0, 1, "CONTROL_CENTER_B", transfer_name,
        1, 1, 2,
        vector(2, 5, 5, 5, 5, 5, 4, 3, 3, 3, 3, 3, 5),
        transfer_raws(T, F, F), transfer_values(T),
        vector(6, 10, 10), vector("\x01", "GRID", data_set_name),
        data_set_values, 1);
    event ICCP::mms_transfer_control_message(
        c, T, 1, invoke_id, 5, 0, 0, "", "", 0, 0, 0, F,
        0, 0, F, F, 1, 1, 0);
    }

function named_report(c: connection, is_orig: bool, name: string)
    {
    local integers: vector of int = vector();
    integers[0] = 1;
    integers[1] = 2;
    event ICCP::mms_information_report_results_v2(
        c, is_orig, 1, 1, "GRID", name, 2, 0,
        vector(), vector(), vector(), vector(5, 5), vector(-1, -1),
        vector("\x01", "\x02"), integers, vector(0.0, 0.0),
        vector(F, F), vector("", ""), 1);
    }

function explicit_report(c: connection, is_orig: bool,
                         names: vector of string)
    {
    local scopes: vector of count = vector();
    local domains: vector of string = vector();
    local choices: vector of count = vector();
    local errors: vector of int = vector();
    local raws: vector of string = vector();
    local integers: vector of int = vector();
    local floats: vector of double = vector();
    local booleans: vector of bool = vector();
    local strings: vector of string = vector();
    local index: count = 0;
    while ( index < |names| )
        {
        scopes[index] = 1; domains[index] = "GRID"; choices[index] = 5;
        errors[index] = -1; raws[index] = "\x01"; integers[index] = 1;
        floats[index] = 0.0; booleans[index] = F; strings[index] = "";
        ++index;
        }
    event ICCP::mms_information_report_results_v2(
        c, is_orig, 0, 0, "", "", |names|, 0, scopes, domains, names,
        choices, errors, raws, integers, floats, booleans, strings, 1);
    }

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.10, $orig_p=49152/tcp,
             $resp_h=192.0.2.20, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs, $service=set("iccp"),
        $history="", $uid="CactiveTransfer"
    ];
    seed_tase2(c);
    event ICCP::mms_message(
        c, T, T, 0, T, 24, 20, 6, 0, T, 4, "", "",
        0, "", "Supported_Features", 1, T,
        0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);

    define_list(c, 1, "DS_A", vector("A", "B"));
    define_list(c, 2, "DS_B", vector("C", "D"));
    define_list(c, 3, "DS_C", vector("E", "F"));
    learn_transfer_type(c, 10, "TS_A");
    learn_transfer_type(c, 11, "TS_B");
    learn_transfer_type(c, 12, "TS_C");

    transfer_write(c, 20, "TS_A", "DS_A", T, F, F, T);
    named_report(c, F, "DS_A");
    explicit_report(c, F, vector("A"));
    named_report(c, T, "DS_A");

    # A rejected Stop cannot change the active lifecycle.
    transfer_write(c, 21, "TS_A", "DS_A", F, F, F, F);
    named_report(c, F, "DS_A");
    # A confirmed Stop permits one conservative trailing report.
    transfer_write(c, 22, "TS_A", "DS_A", F, F, F, T);
    named_report(c, F, "DS_A");
    named_report(c, F, "DS_A");

    # The same VCC transfer name can independently be a client-side transfer
    # in the other direction. Discover that serving endpoint's distinct
    # object before using it; direction is part of both learned-type and
    # active-transfer state.
    learn_reverse_transfer_type(c, 14, "TS_A");
    reverse_transfer_start(c, 26, "TS_A", "DS_A");
    named_report(c, T, "DS_A");

    transfer_write(c, 23, "TS_B", "DS_B", T, T, F, T);
    explicit_report(c, F, vector("C"));
    named_report(c, F, "DS_B");

    transfer_write(c, 24, "TS_C", "DS_C", T, T, T, T);
    explicit_report(c, F, vector("E"));
    named_report(c, F, "DS_C");

    # A second active transfer over the same data set makes attribution
    # genuinely ambiguous. It is retained as unresolved, not alerted.
    learn_transfer_type(c, 13, "TS_B2");
    transfer_write(c, 25, "TS_B2", "DS_B", T, T, F, T);
    named_report(c, F, "DS_B");

    # Full Domain identity keeps same-named Transfer Sets independent. A
    # positively confirmed duplicate Start in the first Domain is a peer
    # deviation and must not replace that Domain's original DS_D parameters.
    define_list(c, 4, "DS_D", vector("G", "H"));
    define_list(c, 5, "DS_E", vector("I", "J"));
    define_list(c, 6, "DS_F", vector("K", "L"));
    learn_transfer_type_in_domain(
        c, 15, "CONTROL_CENTER_B", "TS_SHARED");
    learn_transfer_type_in_domain(
        c, 16, "CONTROL_CENTER_C", "TS_SHARED");
    transfer_write_in_domain(
        c, 27, "CONTROL_CENTER_B", "TS_SHARED", "DS_D",
        T, F, F, T);
    transfer_write_in_domain(
        c, 28, "CONTROL_CENTER_B", "TS_SHARED", "DS_F",
        T, F, F, T);
    transfer_write_in_domain(
        c, 29, "CONTROL_CENTER_C", "TS_SHARED", "DS_E",
        T, F, F, T);
    named_report(c, F, "DS_D");
    named_report(c, F, "DS_F");
    named_report(c, F, "DS_E");

    # Teardown removes every full-identity active-state entry; this final
    # report must create no active_report row or anomaly.
    event connection_state_remove(c);
    named_report(c, F, "DS_A");
    }
