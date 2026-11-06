# @TEST-DOC: Reject a semantically valid MMS Read embedded in an AARQ before
# @TEST-DOC: the nested MMS event bridge can log it, retain request state, or
# @TEST-DOC: confirm the ICCP analyzer.  The malformed envelope traverses the
# @TEST-DOC: complete TCP/TPKT/COTP/Session/Presentation/ACSE stack.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap malformed.pcap association-wrong-mms
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap malformed-copy.pcap association-wrong-mms
# @TEST-EXEC: cmp malformed.pcap malformed-copy.pcap
# @TEST-EXEC: mkdir run
# @TEST-EXEC: cd run && zeek -Cr ../malformed.pcap ${PACKAGE}/__load__.zeek %INPUT > ../output
# @TEST-EXEC: zeek-cut layer < run/iccp.log | awk '$1 == "mms" { rows++ } END { printf "mms_rows=%d\n", rows + 0 }' >> output
# @TEST-EXEC: btest-diff output

module ICCP;

global saw_parser_error = F;
global leaked_pending_read = F;
global confirmed_protocol = F;

event analyzer_confirmation_info(
    atype: AllAnalyzers::Tag,
    info: AnalyzerConfirmationInfo)
    {
    if ( info?$c && info$c$id$resp_p == 102/tcp )
        confirmed_protocol = T;
    }

event ICCP::parser_error(c: connection, reason: string) &priority=-100
    {
    saw_parser_error = T;
    if ( ICCP::pending_read(c, 2)$name != "" )
        leaked_pending_read = T;
    }

event zeek_done()
    {
    print fmt(
        "parser_error=%s pending_mms_state=%s protocol_confirmed=%s",
        saw_parser_error,
        leaked_pending_read,
        confirmed_protocol);
    }
