# @TEST-DOC: Verify metadata-aware MMS evidence events retain bounded raw
# @TEST-DOC: prefixes together with exact original lengths and truncation.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT > output
# @TEST-EXEC: btest-diff output

module ICCP;

global test_uid = "CdataEvidence";

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.10, $orig_p=49152/tcp,
             $resp_h=192.0.2.20, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid=test_uid
    ];
    local write_integers: vector of int;
    write_integers[0] = 0;
    local no_successes: vector of bool;
    local no_errors: vector of int;

    event ICCP::mms_write_evidence_v2(
        c, T, 0, 42, 0, 1, "DOMAIN", "VALUE", T, 1, 1,
        vector(1), vector("DOMAIN"), vector("VALUE"),
        vector(10), vector("AB"), vector(10), vector(T),
        write_integers, vector(0.0), vector(F), vector("ABCDEFGHIJ"),
        0, no_successes, no_errors, 1);

    local report_errors: vector of int;
    report_errors[0] = -1;
    local report_integers: vector of int;
    report_integers[0] = 258;

    event ICCP::mms_information_report_results_v3(
        c, F, 0, 0, "", "", 1, 0,
        vector(0), vector(""), vector("POINT"),
        vector(5), report_errors, vector("\x01\x02"), vector(9),
        vector(T), report_integers, vector(0.0), vector(F), vector(""), 1);

    event ICCP::mms_first_result_evidence_v1(
        c, F, 1, 99, 4, 5, "\x01", 4, T, 1, 0.0, 1);
    }

event zeek_done()
    {
    for ( [uid, is_orig, invoke] in pending_write_evidence )
        {
        if ( uid != test_uid ) next;
        local write_value = pending_write_evidence[
            uid, is_orig, invoke]$values[0];
        print fmt("write %s %s %d %d %s %d %s",
            uid, is_orig, invoke, write_value$choice,
            write_value$raw_prefix, write_value$raw_length,
            write_value$raw_truncated);
        }

    for ( [uid, is_orig, sequence] in
          information_report_results_evidence )
        {
        if ( uid != test_uid ) next;
        local report = information_report_results_evidence[
            uid, is_orig, sequence];
        local report_value = report$results[0];
        print fmt("report %s %s %d %s %d %s %s",
            uid, is_orig, report_value$choice,
            report_value$raw_prefix, report_value$raw_length,
            report_value$raw_truncated, report$exact_raw_metadata);
        }

    for ( [uid, is_orig, sequence, invoke] in first_result_evidence )
        {
        if ( uid != test_uid ) next;
        local read_value = first_result_evidence[
            uid, is_orig, sequence, invoke];
        print fmt("read %s %s %d %d %s %d %s",
            uid, is_orig, invoke, read_value$choice,
            read_value$raw_prefix, read_value$raw_length,
            read_value$raw_truncated);
        }
    }
