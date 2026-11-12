# @TEST-DOC: Generate sanitized deterministic traffic and verify that known
# @TEST-DOC: TPKT/COTP/Session/Presentation/ACSE/MMS bytes traverse the real
# @TEST-DOC: Zeek TCP analyzer entry point without injected semantic events.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap synthetic.pcap
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap synthetic-copy.pcap
# @TEST-EXEC: cmp synthetic.pcap synthetic-copy.pcap
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap retransmitted.pcap retransmitted
# @TEST-EXEC: mkdir clean-run retransmitted-run
# @TEST-EXEC: cd clean-run && zeek -Cr ../synthetic.pcap ${PACKAGE}/__load__.zeek
# @TEST-EXEC: cd retransmitted-run && zeek -Cr ../retransmitted.pcap ${PACKAGE}/__load__.zeek
# @TEST-EXEC: zeek-cut layer message_type status context_id application_context association_kind endpoint_role operation invoke_id service_tag < clean-run/iccp.log > output
# @TEST-EXEC: zeek-cut layer message_type status context_id application_context association_kind endpoint_role operation invoke_id service_tag < retransmitted-run/iccp.log > retransmitted-output
# @TEST-EXEC: cmp output retransmitted-output
# @TEST-EXEC: btest-diff output
