# @TEST-DOC: Exercise verified TASE.2 association, exact Control_Command type
# @TEST-DOC: discovery, Operate Write classification, response correlation,
# @TEST-DOC: value logging, and provenance through the production TCP analyzer.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap input.pcap direct-mms-control-classification
# @TEST-EXEC: zeek -Cr input.pcap ${PACKAGE}/__load__.zeek %INPUT
# Generic Write evidence and the classified-control view are emitted by
# independent sibling hooks for the same MMS PDU.  Preserve the exact rows and
# each view's internal order while normalizing their unspecified interleaving.
# @TEST-EXEC: zeek-cut classification outcome object_name named_type integer_value provenance stream_completeness < iccp_controls.log > output.raw
# @TEST-EXEC: awk '($1 == "write_evidence" || $1 == "write_value" || $1 == "write_result") { generic[++generic_count] = $0; next } { classified[++classified_count] = $0 } END { for (i = 1; i <= generic_count; ++i) print generic[i]; for (i = 1; i <= classified_count; ++i) print classified[i] }' output.raw > output
# @TEST-EXEC: btest-diff output

redef ICCP::configured_variable_types += {
    [10.2.2.2, 10.1.1.1, 0, "", "BREAKER"] = "Control_Command"
};
