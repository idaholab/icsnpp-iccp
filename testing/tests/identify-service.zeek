# @TEST-DOC: Verify bounded MMS Identify request/response decoding, matched,
# @TEST-DOC: unmatched, and same-direction correlation, privacy-bounded device
# @TEST-DOC: identity fields, and verified parser provenance through TCP.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap matched.pcap identify > /dev/null
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap matched-copy.pcap identify > /dev/null
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap unmatched.pcap identify-unmatched > /dev/null
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap mismatch.pcap identify-direction-mismatch > /dev/null
# @TEST-EXEC: cmp matched.pcap matched-copy.pcap
# @TEST-EXEC: mkdir matched-run unmatched-run mismatch-run
# @TEST-EXEC: cd matched-run && zeek -Cr ../matched.pcap ${PACKAGE}/__load__.zeek
# @TEST-EXEC: cd unmatched-run && zeek -Cr ../unmatched.pcap ${PACKAGE}/__load__.zeek
# @TEST-EXEC: cd mismatch-run && zeek -Cr ../mismatch.pcap ${PACKAGE}/__load__.zeek
# @TEST-EXEC: zeek-cut is_orig operation invoke_id identify_outcome vendor_name model_name revision abstract_syntax_count first_abstract_syntax provenance < matched-run/iccp.log | awk '$2 == "identify"' > output
# @TEST-EXEC: zeek-cut is_orig operation invoke_id identify_outcome vendor_name model_name revision abstract_syntax_count first_abstract_syntax provenance < unmatched-run/iccp.log | awk '$2 == "identify"' >> output
# @TEST-EXEC: zeek-cut is_orig operation invoke_id identify_outcome vendor_name model_name revision abstract_syntax_count first_abstract_syntax provenance < mismatch-run/iccp.log | awk '$2 == "identify"' >> output
# @TEST-EXEC: btest-diff output
