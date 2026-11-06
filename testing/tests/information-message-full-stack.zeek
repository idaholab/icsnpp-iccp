# @TEST-DOC: Exercise an exact Information Message through negotiated CP/CPA,
# @TEST-DOC: ACSE/MMS association setup, standardized TASE.2 evidence, and a
# @TEST-DOC: two-result direct-MMS InformationReport without logging its body.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap input.pcap direct-mms-information-message
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap input-copy.pcap direct-mms-information-message
# @TEST-EXEC: cmp input.pcap input-copy.pcap
# @TEST-EXEC: zeek -Cr input.pcap ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut action outcome first_variable_scope first_variable_name info_reference local_reference message_id message_size buffer_capacity buffer_length provenance stream_completeness < iccp_transfers.log | grep '^information_message' > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: zeek-cut object_name name_model result_raw < iccp_objects.log | grep '^Info_Buff_8' > buffer
# @TEST-EXEC: btest-diff buffer
