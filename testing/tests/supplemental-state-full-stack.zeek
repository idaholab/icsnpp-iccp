# @TEST-DOC: Exercise exact supplemental State type discovery and a correlated
# @TEST-DOC: extended-timestamp Read through negotiated CP/CPA, ACSE, and MMS.
# @TEST-DOC: Verify normalized supplemental fields and verified provenance.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap input.pcap direct-mms-supplemental-classification
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap input-copy.pcap direct-mms-supplemental-classification
# @TEST-EXEC: cmp input.pcap input-copy.pcap
# @TEST-EXEC: zeek -Cr input.pcap ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut object_name point_type state_value tag_value expected_state_value supplemental_reserved validity value_source normal_value timestamp_quality timestamp_value provenance stream_completeness < iccp_objects.log | grep 'state_supplemental' > output
# @TEST-EXEC: btest-diff output

redef ICCP::configured_variable_types += {
    [10.2.2.2, 10.1.1.1, 0, "", "Point1"] =
        "Data_StateSupplementalQTimeTagExtended"
};
