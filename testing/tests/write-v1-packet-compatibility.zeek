# @TEST-DOC: Packet-derived Write request and response evidence reaches legacy
# @TEST-DOC: mms_write_evidence_v1 subscribers exactly once with bounded raw
# @TEST-DOC: prefixes while v2 remains the authoritative processing path.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap input.pcap direct-mms-control-classification > /dev/null
# @TEST-EXEC: zeek -Cr input.pcap ${PACKAGE}/__load__.zeek %INPUT > output
# @TEST-EXEC: btest-diff output

module ICCP;

event ICCP::mms_write_evidence_v1(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    access_choice: count, selector_scope: count,
    selector_domain: string, selector_name: string,
    target_count_known: bool, target_count: count, value_count: count,
    target_scopes: vector of count,
    target_domains: vector of string,
    target_names: vector of string,
    value_choices: vector of count,
    value_raws: vector of string,
    value_integer_values: vector of int,
    value_floating_values: vector of double,
    value_boolean_values: vector of bool,
    value_string_values: vector of string,
    result_count: count,
    result_successes: vector of bool,
    result_errors: vector of int,
    provenance: count) &priority=-20
    {
    local first_raw_length: count = 0;
    if ( |value_raws| > 0 ) first_raw_length = |value_raws[0]|;
    print fmt("v1 dir=%s pdu=%d invoke=%d targets=%d values=%d raw=%d results=%d provenance=%d",
              is_orig, pdu_type, invoke_id, target_count,
              value_count, first_raw_length, result_count, provenance);
    }

event zeek_done()
    {
    print fmt("bridges v1_to_v2=%d v2_to_v1=%d",
              |write_v1_to_v2_adapters|, |write_v2_to_v1_adapters|);
    }
