# @TEST-DOC: Packet-derived TASE.2 Data Set verification accepts ordinary
# @TEST-DOC: VMD members, but rejects AA-scoped members, special transfer
# @TEST-DOC: objects outside Domain scope, and members with AlternateAccess.
# @TEST-DOC: A positive response to a concurrently outstanding duplicate
# @TEST-DOC: Define is a deviation and preserves the original membership.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap input.pcap direct-mms-data-set-validation
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap input-copy.pcap direct-mms-data-set-validation
# @TEST-EXEC: cmp input.pcap input-copy.pcap
# @TEST-EXEC: zeek -Cr input.pcap ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut action outcome invoke_id list_name variable_count known_list conformance conformance_reasons provenance < iccp_transfers.log | grep '^define' > definitions
# @TEST-EXEC: btest-diff definitions
# @TEST-EXEC: zeek-cut action outcome list_name first_variable_scope first_variable_domain first_variable_name pairing_status known_list < iccp_transfers.log | grep -E '^(report|report_value)' > pairing
# @TEST-EXEC: btest-diff pairing
# @TEST-EXEC: zeek-cut operation invoke_id object_name provenance < iccp.log | grep 'define_named_variable_list' > generic
# @TEST-EXEC: btest-diff generic
