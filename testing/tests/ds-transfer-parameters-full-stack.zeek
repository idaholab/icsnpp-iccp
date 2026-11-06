# @TEST-DOC: Replay a negotiated packet-level DSTransferSet type discovery,
# @TEST-DOC: full Start Transfer Write, correlated confirmation, confirmed
# @TEST-DOC: referenced data set, and active named-list report correlation.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap input.pcap direct-mms-ds-transfer-parameters
# @TEST-EXEC: zeek -Cr input.pcap ${PACKAGE}/__load__.zeek %INPUT
# TypeDescription evidence and type-discovery correlation are independent
# sibling hooks for one response.  Retain every row and each projection's order
# while normalizing only their unspecified cross-hook interleaving.
# @TEST-EXEC: zeek-cut action outcome invoke_id list_scope list_name named_type data_set_scope data_set_domain data_set_name start_time transfer_interval tle buffer_time integrity_check conditions condition_mask block_data critical report_by_exception all_changes_reported enabled event_code_requested conformance conformance_reasons provenance stream_completeness < iccp_transfers.log | grep -v '^active_report' > output.raw
# @TEST-EXEC: awk '$1 == "type_description" { descriptions[++description_count] = $0; next } $1 == "type_discovery" { discoveries[++discovery_count] = $0; next } { remaining[++remaining_count] = $0 } END { for (i = 1; i <= description_count; ++i) print descriptions[i]; for (i = 1; i <= discovery_count; ++i) print discoveries[i]; for (i = 1; i <= remaining_count; ++i) print remaining[i] }' output.raw > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: zeek-cut action outcome transfer_set_name transfer_state report_access report_correlation data_set_scope data_set_domain data_set_name critical report_by_exception ack_required provenance stream_completeness < iccp_transfers.log | grep '^active_report' > active
# @TEST-EXEC: btest-diff active
# @TEST-EXEC: grep '^anomaly' .stdout > anomalies
# @TEST-EXEC: btest-diff anomalies

redef ICCP::configured_variable_types += {
    [10.2.2.2, 10.1.1.1, 1, "CONTROL_CENTER_B", "TS_TYPED"] =
        "DSTransferSet"
};

event ICCP::dst_transfer_set_anomaly_v2(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, invoke_id: int, object_scope: string,
    object_domain: string, object_name: string, classification: string,
    conformance: string, reasons: string, provenance: string)
    {
    print fmt("anomaly invoke=%d role=%s object=%s/%s/%s classification=%s conformance=%s reasons=%s provenance=%s",
              invoke_id, endpoint_role, object_scope, object_domain,
              object_name, classification, conformance, reasons, provenance);
    }
