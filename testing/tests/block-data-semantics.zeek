# @TEST-DOC: Validate the IEC 60870-6-503 BlockData header/rule matrix without
# @TEST-DOC: claiming that opaque blocked member contents were decoded.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut action outcome transfer_set_name report_access report_correlation < iccp_transfers.log | grep '^active_report' > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: grep '^block-anomaly' .stdout > anomalies
# @TEST-EXEC: btest-diff anomalies

module ICCP;

redef ICCP::legacy_gva_direct_event_compatibility = T;

event ICCP::transfer_report_anomaly_v2(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, transfer_set_scope: string,
    transfer_set_domain: string, transfer_set_name: string,
    report_correlation: string, reason: string, provenance: string)
    {
    print fmt("block-anomaly transfer=%s correlation=%s reason=%s",
              transfer_set_name, report_correlation, reason);
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

function define_block_list(c: connection, invoke: int, domain: string,
                           name: string, include_condition: bool)
    {
    local scopes: vector of count = vector(1);
    local domains: vector of string = vector(domain);
    local names: vector of string = vector("Transfer_Set_Name");
    if ( include_condition )
        {
        scopes[1] = 1;
        domains[1] = domain;
        names[1] = "DSConditions_Detected";
        }
    event ICCP::mms_transfer_set_message(
        c, T, 0, invoke, 11, 0, 0, 1, domain, name, |names|,
        1, domain, names[0], F, 0, 0, 0, 0, 0, 0,
        scopes, domains, names, vector(), vector(), vector());
    event ICCP::mms_transfer_set_message(
        c, F, 1, invoke, 11, 0, 0, 0, "", "", 0,
        0, "", "", F, 0, 0, 0, 0, 0, 0,
        vector(), vector(), vector(), vector(), vector(), vector());
    }

function start_block(c: connection, invoke: int, type_invoke: int,
                     domain: string, transfer: string, data_set: string,
                     rbe: bool)
    {
    ICCP::configured_variable_types[
        c$id$resp_h, c$id$orig_h, 1, domain, transfer] = "DSTransferSet";
    event ICCP::mms_variable_type_message(
        c, T, 0, type_invoke, 6, 1, domain, transfer, 0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, F, 1, type_invoke, 6, 0, "", "", 0, 0, "", "DSTransferSet");

    local values: vector of int;
    values[0] = 1; values[1] = 1700000000; values[2] = 60;
    values[3] = 5; values[4] = 2; values[5] = 3600;
    values[6] = 0; values[7] = 1; values[8] = 1;
    values[9] = rbe ? 1 : 0; values[10] = 0;
    values[11] = 1; values[12] = 0;
    local data_set_values: vector of int;
    data_set_values[0] = 1; data_set_values[1] = 0;
    data_set_values[2] = 0;
    event ICCP::mms_ds_transfer_set_message_v1(
        c, T, 0, invoke, 5, 0, 1, domain, transfer, 1, 1, 2,
        vector(2, 5, 5, 5, 5, 5, 4, 3, 3, 3, 3, 3, 5),
        vector("", "\x65\x53\xf1\x00", "\x3c", "\x05", "\x02",
               "\x0e\x10", "\x03\xa0", "\xff", "\xff",
               rbe ? "\xff" : "\x00", "\x00", "\xff", "\x00"),
        values, vector(6, 10, 10), vector("\x01", domain, data_set),
        data_set_values, 1);
    event ICCP::mms_transfer_control_message(
        c, F, 1, invoke, 5, 0, 0, "", "", 0, 0, 0, F,
        0, 0, F, F, 1, 1, 0);
    }

function block_report(c: connection, is_orig: bool, domain: string,
                      names: vector of string, choices: vector of count,
                      raws: vector of string, errors: vector of int,
                      failure_count: count, shorten_names: bool)
    {
    local scopes: vector of count;
    local domains: vector of string;
    local emitted_names: vector of string;
    local integers: vector of int;
    local floats: vector of double;
    local booleans: vector of bool;
    local strings: vector of string;
    local index: count = 0;
    while ( index < |choices| )
        {
        integers[index] = 0; floats[index] = 0.0;
        booleans[index] = F; strings[index] = "";
        if ( index < |names| )
            {
            scopes[index] = 1; domains[index] = domain;
            if ( ! shorten_names || index + 1 < |names| )
                emitted_names[index] = names[index];
            }
        ++index;
        }
    event ICCP::mms_information_report_results_v2(
        c, is_orig, 0, 0, "", "", |choices|, failure_count,
        scopes, domains, emitted_names, choices, errors, raws, integers,
        floats, booleans, strings, 1);
    }

function prepare(c: connection, ordinal: int, domain: string,
                 transfer: string, data_set: string, rbe: bool,
                 include_condition: bool)
    {
    define_block_list(c, ordinal, domain, data_set, include_condition);
    start_block(c, 100 + ordinal, 200 + ordinal, domain, transfer,
                data_set, rbe);
    }

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.31, $orig_p=49152/tcp,
             $resp_h=192.0.2.32, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Cblock-data"
    ];
    seed_tase2(c);

    prepare(c, 1, "D1", "TS1", "DS1", F, F);
    block_report(c, F, "D1", vector("Transfer_Set_Name", "P"),
                 vector(2, 9), vector("name", "\x00x"),
                 vector(-1, -1), 0, F);
    prepare(c, 2, "D2", "TS2", "DS2", T, F);
    block_report(c, F, "D2", vector("Transfer_Set_Name", "P"),
                 vector(2, 9), vector("name", "\x01x"),
                 vector(-1, -1), 0, F);
    prepare(c, 3, "D3", "TS3", "DS3", T, F);
    block_report(c, F, "D3", vector("Transfer_Set_Name", "P"),
                 vector(2, 9), vector("name", "\x02x"),
                 vector(-1, -1), 0, F);

    prepare(c, 4, "D4", "TS4", "DS4", F, F);
    block_report(c, F, "D4", vector("Transfer_Set_Name", "P"),
                 vector(2, 9), vector("name", ""), vector(-1, -1), 0, F);
    prepare(c, 5, "D5", "TS5", "DS5", F, F);
    block_report(c, F, "D5", vector("Transfer_Set_Name", "P"),
                 vector(2, 5), vector("name", "\x00"),
                 vector(-1, -1), 0, F);
    prepare(c, 6, "D6", "TS6", "DS6", F, F);
    block_report(c, F, "D6", vector("Transfer_Set_Name", "P"),
                 vector(2, 9), vector("name", "\x01"),
                 vector(-1, -1), 0, F);
    prepare(c, 7, "D7", "TS7", "DS7", T, F);
    block_report(c, F, "D7", vector("Transfer_Set_Name", "P"),
                 vector(2, 9), vector("name", "\x00"),
                 vector(-1, -1), 0, F);
    prepare(c, 8, "D8", "TS8", "DS8", T, F);
    block_report(c, F, "D8", vector("Transfer_Set_Name", "P"),
                 vector(2, 9), vector("name", "\x03"),
                 vector(-1, -1), 0, F);
    prepare(c, 9, "D9", "TS9", "DS9", F, F);
    block_report(c, F, "D9", vector("Transfer_Set_Name", "P", "Q"),
                 vector(2, 9, 9), vector("name", "\x00", "\x00"),
                 vector(-1, -1, -1), 0, F);
    prepare(c, 10, "D10", "TS10", "DS10", F, F);
    block_report(c, F, "D10", vector("Transfer_Set_Name"),
                 vector(2), vector("name"), vector(-1), 0, F);
    prepare(c, 11, "D11", "TS11", "DS11", F, F);
    block_report(c, F, "D11", vector("Transfer_Set_Name", "P"),
                 vector(2, 0), vector("name", ""), vector(-1, 7), 1, F);
    prepare(c, 12, "D12", "TS12", "DS12", F, T);
    block_report(c, F, "D12",
                 vector("Transfer_Set_Name", "DSConditions_Detected", "P"),
                 vector(2, 5, 9), vector("name", "\x00", "\x00"),
                 vector(-1, -1, -1), 0, F);
    prepare(c, 13, "D13", "TS13", "DS13", F, F);
    block_report(c, F, "D13",
                 vector("Transfer_Set_Name", "DSConditions_Detected", "P"),
                 vector(2, 4, 9), vector("name", "\x03\xa0", "\x00"),
                 vector(-1, -1, -1), 0, F);
    prepare(c, 14, "D14", "TS14", "DS14", F, F);
    block_report(c, F, "D14", vector("Transfer_Set_Name", "P"),
                 vector(2, 9), vector("name", "\x00"),
                 vector(-1, -1), 0, T);
    prepare(c, 15, "D15", "TS15", "DS15", F, F);
    block_report(c, F, "D15", vector("P"), vector(9),
                 vector("\x00"), vector(-1), 0, F);
    prepare(c, 16, "D16", "TS16", "DS16", F, F);
    block_report(c, T, "D16", vector("Transfer_Set_Name", "P"),
                 vector(2, 9), vector("name", "\x00"),
                 vector(-1, -1), 0, F);

    local named_integers: vector of int;
    named_integers[0] = 0;
    event ICCP::mms_information_report_results_v2(
        c, F, 1, 1, "D1", "DS1", 1, 0,
        vector(), vector(), vector(), vector(2), vector(-1),
        vector("name"), named_integers, vector(0.0), vector(F),
        vector(""), 1);
    }
