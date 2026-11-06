# @TEST-DOC: Verify partial-capture recovery when a peer ACK establishes that
# @TEST-DOC: the first later-seen originator TPKT is already old sequence
# @TEST-DOC: space. The late InformationReport must not be fabricated as
# @TEST-DOC: delivered data; the next in-order TPKT must decode after an
# @TEST-DOC: explicit gap, with a durable non-exhaustive direction verdict.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap prebaseline.pcap direct-mms-prebaseline-ack
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap prebaseline-copy.pcap direct-mms-prebaseline-ack
# @TEST-EXEC: cmp prebaseline.pcap prebaseline-copy.pcap
# @TEST-EXEC: mkdir run
# @TEST-EXEC: cd run && zeek -Cr ../prebaseline.pcap ${PACKAGE}/__load__.zeek
# @TEST-EXEC: test ! -e run/iccp_errors.log
# @TEST-EXEC: test "$(zeek-cut layer operation < run/iccp.log | grep -c '^mms[[:space:]]information_report$' || true)" -eq 0
# @TEST-EXEC: test "$(zeek-cut is_orig layer invoke_id operation stream_completeness < run/iccp.log | grep -c '^T[[:space:]]mms[[:space:]]7[[:space:]]identify[[:space:]]verified_recovery_after_gap$' || true)" -eq 1
# @TEST-EXEC: test "$(zeek-cut is_orig message_type status stream_completeness < run/iccp.log | grep -c '^T[[:space:]]direction_summary[[:space:]]non_exhaustive[[:space:]]direction_non_exhaustive_after_gap$' || true)" -eq 1
# @TEST-EXEC: zeek-cut is_orig layer message_type status invoke_id operation provenance stream_completeness < run/iccp.log > output
# @TEST-EXEC: btest-diff output
