# @TEST-DOC: Exercise verified TASE.2 association, exact Tag_Value type
# @TEST-DOC: discovery, Set Tag Write and Get Tag Read classification,
# @TEST-DOC: TagFlags/Reason decoding, and provenance through the production
# @TEST-DOC: TCP analyzer.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap input.pcap direct-mms-tag-classification
# @TEST-EXEC: zeek -Cr input.pcap ${PACKAGE}/__load__.zeek %INPUT
# Generic Write evidence and the classified-control view are emitted by
# independent sibling hooks for the same MMS PDU.  Preserve the exact rows and
# each view's internal order while normalizing their unspecified interleaving.
# @TEST-EXEC: zeek-cut classification outcome object_scope object_name named_type tag_value tag_state tag_reason result_count failure_count provenance stream_completeness < iccp_controls.log > output.raw
# @TEST-EXEC: awk '($1 == "write_evidence" || $1 == "write_value" || $1 == "write_result") { generic[++generic_count] = $0; next } { classified[++classified_count] = $0 } END { for (i = 1; i <= generic_count; ++i) print generic[i]; for (i = 1; i <= classified_count; ++i) print classified[i] }' output.raw > output
# @TEST-EXEC: btest-diff output

redef ICCP::configured_variable_types += {
    [10.2.2.2, 10.1.1.1, 0, "", "BREAKER_TAG"] = "Tag_Value"
};
