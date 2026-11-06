# Copyright 2026, Battelle Energy Alliance, LLC. All Rights Reserved.

################################################################################
##
## ICSNPP - ICCP
##
## This file registers the ICCP analyzer and creates its Zeek log streams.
##
## Christopher B. Peterson and Christian J Weelborg
## Idaho National Lab, November 2026
##
################################################################################

module ICCP;

export {
    const iccp_ports: set[port] = { 102/tcp } &redef;
    const enable_iccp_log = T &redef;
    const enable_iccp_objects_log = T &redef;
    const enable_iccp_transfers_log = T &redef;
    const enable_iccp_controls_log = T &redef;
    const enable_iccp_errors_log = T &redef;
}

redef likely_server_ports += { iccp_ports };

event zeek_init() &priority=5
    {
    Analyzer::register_for_ports(Analyzer::ANALYZER_ICCP_TCP, iccp_ports);
    Log::create_stream(ICCP::LOG,
                       [$columns=Info, $ev=log_iccp, $path="iccp"]);
    Log::create_stream(ICCP::OBJECT_LOG,
                       [$columns=ObjectInfo, $ev=log_iccp_object,
                        $path="iccp_objects"]);
    Log::create_stream(ICCP::TRANSFER_LOG,
                       [$columns=TransferInfo, $ev=log_iccp_transfer,
                        $path="iccp_transfers"]);
    Log::create_stream(ICCP::CONTROL_LOG,
                       [$columns=ControlInfo, $ev=log_iccp_control,
                        $path="iccp_controls"]);
    Log::create_stream(ICCP::ERROR_LOG,
                       [$columns=ErrorInfo, $ev=log_iccp_error,
                        $path="iccp_errors"]);

    if ( ! enable_iccp_log )
        Log::disable_stream(ICCP::LOG);
    if ( ! enable_iccp_objects_log )
        Log::disable_stream(ICCP::OBJECT_LOG);
    if ( ! enable_iccp_transfers_log )
        Log::disable_stream(ICCP::TRANSFER_LOG);
    if ( ! enable_iccp_controls_log )
        Log::disable_stream(ICCP::CONTROL_LOG);
    if ( ! enable_iccp_errors_log )
        Log::disable_stream(ICCP::ERROR_LOG);
    }
