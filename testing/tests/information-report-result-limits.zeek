# @TEST-DOC: Verify the configurable per-report row cap and raw-value byte cap
# @TEST-DOC: while normalized values, omission counts, and provenance remain.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap input.pcap direct-mms-multi-result
# @TEST-EXEC: mkdir replay
# @TEST-EXEC: cd replay && zeek -Cr ../input.pcap ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut result_count failure_count logged_result_count omitted_result_count result_pairing_status result_index result_type result_error result_raw result_raw_truncated integer_value provenance < replay/iccp.log | awk '$1 != "-"' > summary
# @TEST-EXEC: zeek-cut observation_kind object_name result_index result_type result_error result_raw result_raw_truncated integer_value provenance < replay/iccp_objects.log | awk '$3 != "-"' > objects
# @TEST-EXEC: btest-diff summary
# @TEST-EXEC: btest-diff objects

redef ICCP::max_logged_information_report_results = 2;
redef ICCP::max_logged_result_raw_bytes = 0;
