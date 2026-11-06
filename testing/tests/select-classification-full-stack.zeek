# @TEST-DOC: Exercise verified TASE.2 association, exact
# @TEST-DOC: SBO_CheckBackName discovery, Select Read classification,
# @TEST-DOC: CheckBackID decoding, and provenance through the production TCP
# @TEST-DOC: analyzer.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap input.pcap direct-mms-select-classification
# @TEST-EXEC: zeek -Cr input.pcap ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut classification outcome object_scope object_name named_type integer_value result_count failure_count provenance stream_completeness < iccp_controls.log > output
# @TEST-EXEC: btest-diff output

redef ICCP::configured_variable_types += {
    [10.2.2.2, 10.1.1.1, 0, "", "BREAKER_SBO"] = "SBO_CheckBackName"
};
