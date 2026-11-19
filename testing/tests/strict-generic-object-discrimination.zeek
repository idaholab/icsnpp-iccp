# @TEST-DOC: A semantically valid generic MMS private-object exchange must not
# @TEST-DOC: confirm ICCP or write any ICCP-family log records.
#
# @TEST-EXEC: zeek -Cr ${PACKAGE}/../testing/traces/synthetic/private-object.pcap ${PACKAGE}/__load__.zeek %INPUT > output
# @TEST-EXEC: test "$(zeek-cut service < conn.log | grep -Ec '(^|,)iccp_tcp(,|$)' || true)" -eq 0
# @TEST-EXEC: btest-diff output

module ICCP;

global iccp_rows: count = 0;
global object_rows: count = 0;
global transfer_rows: count = 0;
global control_rows: count = 0;
global error_rows: count = 0;
global protocol_confirmed = F;

event ICCP::log_iccp(rec: Info) { ++iccp_rows; }
event ICCP::log_iccp_object(rec: ObjectInfo) { ++object_rows; }
event ICCP::log_iccp_transfer(rec: TransferInfo) { ++transfer_rows; }
event ICCP::log_iccp_control(rec: ControlInfo) { ++control_rows; }
event ICCP::log_iccp_error(rec: ErrorInfo) { ++error_rows; }

event analyzer_confirmation_info(
    atype: AllAnalyzers::Tag,
    info: AnalyzerConfirmationInfo)
    {
    if ( atype == Analyzer::ANALYZER_ICCP_TCP )
        protocol_confirmed = T;
    }

event zeek_done()
    {
    print fmt(
        "confirmed=%s iccp=%d objects=%d transfers=%d controls=%d errors=%d pending=%d active=%d",
        protocol_confirmed, iccp_rows, object_rows, transfer_rows,
        control_rows, error_rows, |pending_iccp_log_record_counts|,
        |iccp_logging_eligible|);
    }
