# @TEST-DOC: Verify bounded ordered InformationReport result propagation for
# @TEST-DOC: complete explicit variables, rejection of structurally invalid
# @TEST-DOC: result cardinality, and an untracked named list without inventing
# @TEST-DOC: object association.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap explicit.pcap direct-mms-multi-result
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap mismatch.pcap direct-mms-result-mismatch
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap incomplete.pcap direct-mms-incomplete-identity
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap untracked.pcap direct-mms-untracked-list
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap explicit-copy.pcap direct-mms-multi-result
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap mismatch-copy.pcap direct-mms-result-mismatch
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap incomplete-copy.pcap direct-mms-incomplete-identity
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap untracked-copy.pcap direct-mms-untracked-list
# @TEST-EXEC: cmp explicit.pcap explicit-copy.pcap
# @TEST-EXEC: cmp mismatch.pcap mismatch-copy.pcap
# @TEST-EXEC: cmp incomplete.pcap incomplete-copy.pcap
# @TEST-EXEC: cmp untracked.pcap untracked-copy.pcap
# @TEST-EXEC: mkdir explicit-run mismatch-run incomplete-run untracked-run
# @TEST-EXEC: cd explicit-run && zeek -Cr ../explicit.pcap ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: cd mismatch-run && zeek -Cr ../mismatch.pcap ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: cd incomplete-run && zeek -Cr ../incomplete.pcap ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: cd untracked-run && zeek -Cr ../untracked.pcap ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut result_count failure_count logged_result_count omitted_result_count result_pairing_status result_index result_type result_error result_raw result_raw_truncated integer_value boolean_value string_value provenance < explicit-run/iccp.log | awk 'BEGIN { OFS="\t" } $1 != "-" { print "explicit", $0 }' > summary
# @TEST-EXEC: zeek-cut result_count failure_count logged_result_count omitted_result_count result_pairing_status result_index result_type result_error result_raw result_raw_truncated integer_value boolean_value string_value provenance < mismatch-run/iccp.log | awk 'BEGIN { OFS="\t" } $1 != "-" { print "mismatch", $0 }' >> summary
# @TEST-EXEC: zeek-cut result_count failure_count logged_result_count omitted_result_count result_pairing_status result_index result_type result_error result_raw result_raw_truncated integer_value boolean_value string_value provenance < incomplete-run/iccp.log | awk 'BEGIN { OFS="\t" } $1 != "-" { print "incomplete", $0 }' >> summary
# @TEST-EXEC: zeek-cut result_count failure_count logged_result_count omitted_result_count result_pairing_status result_index result_type result_error result_raw result_raw_truncated integer_value boolean_value string_value provenance < untracked-run/iccp.log | awk 'BEGIN { OFS="\t" } $1 != "-" { print "untracked", $0 }' >> summary
# @TEST-EXEC: btest-diff summary
# @TEST-EXEC: zeek-cut observation_kind object_scope object_domain object_name result_count result_pairing_status result_index result_type result_error result_raw result_raw_truncated integer_value boolean_value string_value provenance < explicit-run/iccp_objects.log | awk '$7 != "-"' > objects
# @TEST-EXEC: btest-diff objects
# @TEST-EXEC: test ! -e mismatch-run/iccp_objects.log
# @TEST-EXEC: test "$(zeek-cut message_type status stream_completeness < mismatch-run/iccp.log | grep -c '^direction_summary[[:space:]]non_exhaustive[[:space:]]direction_non_exhaustive_after_parse_error$' || true)" -eq 1
# @TEST-EXEC: test "$(zeek-cut result_count < mismatch-run/iccp.log | grep -cv '^-$' || true)" -eq 0
# @TEST-EXEC: test ! -e incomplete-run/iccp_objects.log
# @TEST-EXEC: test ! -e untracked-run/iccp_objects.log
