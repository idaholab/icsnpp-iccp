# @TEST-DOC: Check that malformed COTP and unsafe upper-layer ICCP streams each
# @TEST-DOC: emit one bounded detection event while a valid stream emits none.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-malformed-pcap cotp-li malformed.pcap
# @TEST-EXEC: bash ${SCRIPTS}/generate-malformed-pcap session-length unsafe-upper.pcap
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap valid.pcap
# @TEST-EXEC: zeek -Cr malformed.pcap ${PACKAGE}/__load__.zeek %INPUT > output
# @TEST-EXEC: test "$(zeek-cut message_type status stream_completeness < iccp.log | grep -c '^direction_summary[[:space:]]non_exhaustive[[:space:]]direction_non_exhaustive_after_parse_error$' || true)" -eq 1
# @TEST-EXEC: zeek -Cr unsafe-upper.pcap ${PACKAGE}/__load__.zeek %INPUT >> output
# @TEST-EXEC: zeek -Cr valid.pcap ${PACKAGE}/__load__.zeek %INPUT >> output
# @TEST-EXEC: btest-diff output

event ICCP::malformed_structure_v2(
    c: connection, reason: string, provenance: string)
    {
    print fmt("malformed bounded=%s reason_present=%s provenance=%s",
              |reason| <= 256, |reason| > 0, provenance);
    }
