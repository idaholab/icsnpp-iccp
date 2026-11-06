# @TEST-DOC: Establish TASE.2 from a mandatory standardized-object Read, then
# @TEST-DOC: exercise exact Data_RealQTimeTagExtended discovery and value
# @TEST-DOC: promotion through negotiated Presentation, direct MMS, GVA, Read,
# @TEST-DOC: nested TimeStampExtended extraction, logs, and provenance.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap input.pcap direct-mms-extended-classification
# @TEST-EXEC: zeek -Cr input.pcap ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut object_name point_type floating_value timestamp_value provenance stream_completeness < iccp_objects.log | grep '^Point1' > output
# @TEST-EXEC: btest-diff output

redef ICCP::configured_variable_types += {
    [10.2.2.2, 10.1.1.1, 0, "", "Point1"] =
        "Data_RealQTimeTagExtended"
};
