# @TEST-DOC: Check independent log-stream configuration while parser events
# @TEST-DOC: and association state continue to feed the enabled summary log.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: test -f iccp.log
# @TEST-EXEC: test ! -e iccp_objects.log
# @TEST-EXEC: test ! -e iccp_transfers.log
# @TEST-EXEC: test ! -e iccp_controls.log
# @TEST-EXEC: test ! -e iccp_errors.log
# @TEST-EXEC: zeek-cut layer message_type association_kind operation invoke_id < iccp.log > output
# @TEST-EXEC: btest-diff output

redef ICCP::enable_iccp_transfers_log = F;
redef ICCP::enable_iccp_controls_log = F;
redef ICCP::enable_iccp_errors_log = F;
redef ICCP::enable_iccp_objects_log = F;

event zeek_init() &priority=-5
    {
    local no_counts: vector of count = vector();
    local no_ints: vector of int = vector();
    local no_strings: vector of string = vector();
    local c: connection = [
        $id=[$orig_h=192.0.2.70, $orig_p=49152/tcp,
             $resp_h=192.0.2.80, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs, $service=set("iccp"),
        $history="", $uid="Clogconfig"
    ];

    event ICCP::presentation_message_v2(c, T, T, 2, 3,
                                     "2.2.1.0.1", "2.1.1", T, F, F, 32);
    event ICCP::acse_message(c, T, T, 0, "1.3.6.1.4.1", -1, -1, -1,
                            F, 0, F, T, 24);
    event ICCP::acse_message(c, F, T, 1, "1.3.6.1.4.1", 0, -1, 0,
                            F, 0, F, T, 24);
    event ICCP::mms_message(
        c, T, T, 8, T, 16, -1, 0, 0, F, 0, "\x00", "\x01",
        0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    # Establish TASE.2 only after a complete, direction-correlated Read of
    # the fixed VMD bootstrap object.  The following GVA request is then
    # logged against the established association.
    event ICCP::mms_read_message_v3(
        c, T, 0, 29, 0, 1, 0, "", "Supported_Features", 1,
        0, 0, 0, "", 0, 0, 0, 0, 0, 0, 1);
    event ICCP::mms_read_message_v3(
        c, F, 1, 29, 0, 0, 0, "", "", 0,
        1, 0, 4, "\x04\xa0", 0, 0, 0, 0, 0, 0, 1);
    event ICCP::mms_message(
        c, T, T, 0, T, 24, 30, 6, 0, T, 4, "", "",
        0, "", "Supported_Features", 1, T,
        0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);

    # Both disabled streams receive records through their normal handlers.
    event ICCP::mms_transfer_set_message(
        c, T, 0, 31, 11, 0, 0, 0, "", "TS_DISABLED", 1,
        1, "BILATERAL", "MW_FLOW", F, 0, 0, 0, 0, 0, 0,
        vector(1), vector("BILATERAL"), vector("MW_FLOW"),
        no_counts, no_ints, no_strings);
    event ICCP::mms_error_message(c, F, 2, 99, -1, 2, 1, -1, "disabled");
    event ICCP::mms_control_request_deferred(c, T, 32, 0, "", "WRITE",
                                             1, 1, 1);
    }
