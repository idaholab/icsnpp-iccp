# @TEST-DOC: Verify Zeek's partial-stream one-byte initial-ACK behavior. An
# @TEST-DOC: originator ACK establishes its sequence baseline, a peer ACK then
# @TEST-DOC: advances one byte, and later payload overlaps that acknowledged
# @TEST-DOC: prefix while carrying a complete Identify TPKT in its suffix.
# @TEST-DOC: Without a later ACK the suffix remains unavailable at EOF and must
# @TEST-DOC: produce no MMS record. A paired fixture adds only the final ACK and
# @TEST-DOC: proves bounded recovery of that same complete suffix.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap initial-ack.pcap direct-mms-partial-initial-ack
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap initial-ack-copy.pcap direct-mms-partial-initial-ack
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap released.pcap direct-mms-partial-initial-ack-release
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap released-copy.pcap direct-mms-partial-initial-ack-release
# @TEST-EXEC: cmp initial-ack.pcap initial-ack-copy.pcap
# @TEST-EXEC: cmp released.pcap released-copy.pcap
# @TEST-EXEC: mkdir initial-run released-run
# @TEST-EXEC: cd initial-run && zeek -Cr ../initial-ack.pcap ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: cd released-run && zeek -Cr ../released.pcap ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: if test -e initial-run/iccp.log; then test "$(zeek-cut layer < initial-run/iccp.log | grep -c '^mms$' || true)" -eq 0; fi
# @TEST-EXEC: test "$(zeek-cut is_orig layer invoke_id operation stream_completeness < released-run/iccp.log | grep -c '^T[[:space:]]mms[[:space:]]7[[:space:]]identify[[:space:]]verified_recovery_after_gap$' || true)" -eq 1
# @TEST-EXEC: test "$(zeek-cut is_orig message_type status stream_completeness < released-run/iccp.log | grep -c '^T[[:space:]]direction_summary[[:space:]]non_exhaustive[[:space:]]direction_non_exhaustive_after_gap$' || true)" -eq 1
# @TEST-EXEC: test ! -e initial-run/iccp_errors.log
# @TEST-EXEC: test ! -e released-run/iccp_errors.log
# @TEST-EXEC: if test -e initial-run/iccp.log; then zeek-cut layer < initial-run/iccp.log | awk 'BEGIN { n = 0 } $1 == "mms" { ++n } END { print "initial_mms", n }' > output; else printf 'initial_mms\t0\n' > output; fi
# @TEST-EXEC: zeek-cut is_orig layer message_type status invoke_id operation provenance stream_completeness < released-run/iccp.log | awk 'BEGIN { OFS="\t" } { print "released", $0 }' >> output
# @TEST-EXEC: btest-diff output
