# @TEST-DOC: Packet-derived Bilateral_Table_ID evidence is owned by the MMS
# @TEST-DOC: endpoint that served the successful Read, even when one negotiated
# @TEST-DOC: association carries requests in both directions. The opposite
# @TEST-DOC: server remains private/unknown until it independently serves the
# @TEST-DOC: same Domain spelling.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap input.pcap direct-mms-bilateral-domain-ownership
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap input-copy.pcap direct-mms-bilateral-domain-ownership
# @TEST-EXEC: cmp input.pcap input-copy.pcap
# @TEST-EXEC: zeek -Cr input.pcap ${PACKAGE}/__load__.zeek %INPUT > alerts
# @TEST-EXEC: zeek-cut is_orig invoke_id object_domain object_name name_model domain_kind bilateral_domain provenance < iccp.log | grep 'Vendor_Probe' > classifications
# @TEST-EXEC: btest-diff alerts
# @TEST-EXEC: btest-diff classifications

redef ICCP::enable_iccp_objects_log = F;
redef ICCP::enable_iccp_transfers_log = F;
redef ICCP::enable_iccp_controls_log = F;
redef ICCP::enable_iccp_errors_log = F;

event ICCP::unknown_object_access_v2(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, operation: string, invoke_id: int,
    object_scope: string, object_domain: string, object_name: string,
    name_model: string, provenance: string)
    {
    if ( object_name != "Vendor_Probe" )
        return;

    print fmt("unknown request_is_orig=%s invoke=%d domain=%s object=%s " +
              "model=%s provenance=%s",
              is_orig, invoke_id, object_domain, object_name,
              name_model, provenance);
    }
