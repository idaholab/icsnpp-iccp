# @TEST-DOC: S7comm traffic on the shared 102/tcp port must not qualify for
# @TEST-DOC: ICCP output or produce any ICCP log records.
#
# @TEST-EXEC: zeek -Cr ${PACKAGE}/../testing/traces/non-iccp/s7comm-identification.pcap ${PACKAGE}/__load__.zeek %INPUT > output
# @TEST-EXEC: test "$(zeek-cut service < conn.log | grep -Ec '(^|,)iccp_tcp(,|$)' || true)" -eq 0
# @TEST-EXEC: btest-diff output

module ICCP;

global iccp_rows: count = 0;
global object_rows: count = 0;
global transfer_rows: count = 0;
global control_rows: count = 0;
global error_rows: count = 0;
global protocol_confirmed = F;

event ICCP::log_iccp(rec: Info)
    {
    ++iccp_rows;
    }

event ICCP::log_iccp_object(rec: ObjectInfo)
    {
    ++object_rows;
    }

event ICCP::log_iccp_transfer(rec: TransferInfo)
    {
    ++transfer_rows;
    }

event ICCP::log_iccp_control(rec: ControlInfo)
    {
    ++control_rows;
    }

event ICCP::log_iccp_error(rec: ErrorInfo)
    {
    ++error_rows;
    }

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
