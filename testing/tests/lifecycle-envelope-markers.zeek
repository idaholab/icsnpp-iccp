# @TEST-DOC: Verify one envelope-first lifecycle marker for successful COTP
# @TEST-DOC: and Session handshakes, and a marker before late failure of an
# @TEST-DOC: exact CR or structurally safe CONNECT SPDU.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap valid.pcap initiate
# @TEST-EXEC: bash ${SCRIPTS}/generate-malformed-pcap cotp-cr-late-failure malformed-cr.pcap
# @TEST-EXEC: bash ${SCRIPTS}/generate-malformed-pcap session-connect-late-failure malformed-connect.pcap
# @TEST-EXEC: bash ${SCRIPTS}/generate-malformed-pcap cotp-cr-reserved-code reserved-cr.pcap
# @TEST-EXEC: bash ${SCRIPTS}/generate-malformed-pcap cotp-dr-reserved-code reserved-dr.pcap
# @TEST-EXEC: bash ${SCRIPTS}/generate-malformed-pcap cotp-dc-reserved-code reserved-dc.pcap
# @TEST-EXEC: bash ${SCRIPTS}/generate-malformed-pcap cotp-er-reserved-code reserved-er.pcap
# @TEST-EXEC: bash ${SCRIPTS}/generate-malformed-pcap cotp-cc-reserved-code reserved-cc.pcap
# @TEST-EXEC: bash ${SCRIPTS}/generate-malformed-pcap cotp-dr-partial-prefix partial-dr.pcap
# @TEST-EXEC: zeek -Cr valid.pcap ${PACKAGE}/__load__.zeek %INPUT > output
# @TEST-EXEC: zeek -Cr malformed-cr.pcap ${PACKAGE}/__load__.zeek %INPUT >> output
# @TEST-EXEC: zeek -Cr malformed-connect.pcap ${PACKAGE}/__load__.zeek %INPUT >> output
# @TEST-EXEC: zeek -Cr reserved-cr.pcap ${PACKAGE}/__load__.zeek %INPUT >> output
# @TEST-EXEC: zeek -Cr reserved-dr.pcap ${PACKAGE}/__load__.zeek %INPUT >> output
# @TEST-EXEC: zeek -Cr reserved-dc.pcap ${PACKAGE}/__load__.zeek %INPUT >> output
# @TEST-EXEC: zeek -Cr reserved-er.pcap ${PACKAGE}/__load__.zeek %INPUT >> output
# @TEST-EXEC: zeek -Cr reserved-cc.pcap ${PACKAGE}/__load__.zeek %INPUT >> output
# @TEST-EXEC: zeek -Cr partial-dr.pcap ${PACKAGE}/__load__.zeek %INPUT >> output
# @TEST-EXEC: btest-diff output

module ICCP;

event cotp_lifecycle_v1(
    c: connection, is_orig: bool, tpdu_type: count) &priority=-100
    {
    print fmt("cotp type=%d", tpdu_type);
    }

event session_spdu_marker_v1(
    c: connection, is_orig: bool, spdu_type: count) &priority=-100
    {
    print fmt("session type=%d", spdu_type);
    }

# A late failure has no aggregate event to consume its one-shot lifecycle
# token. Keep this assertion silent on success so every malformed envelope in
# this test also guards against state leaking into the next recovered PDU.
event parser_error(c: connection, reason: string) &priority=-100
    {
    if ( [c$uid, T] in state_presentation_spdu ||
         [c$uid, F] in state_presentation_spdu ||
         [c$uid, T] in state_acse_lifecycle_spdu ||
         [c$uid, F] in state_acse_lifecycle_spdu )
        print "lifecycle state token leaked after parser error";
    }
