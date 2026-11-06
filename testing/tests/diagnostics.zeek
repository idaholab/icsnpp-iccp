# @TEST-DOC: Check the initial ICCP log schema and bounded upper-layer diagnostics.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut layer message_type status context_id application_context payload_length authentication_present authentication_length is_opaque association_kind endpoint_role operation invoke_id service_tag detail < iccp.log > output
# @TEST-EXEC: btest-diff output

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[
            $orig_h=192.0.2.1,
            $orig_p=49152/tcp,
            $resp_h=192.0.2.2,
            $resp_p=102/tcp
        ],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(),
        $duration=0secs,
        $service=set("iccp"),
        $history="",
        $uid="Cdiagnostic"
    ];

    event ICCP::presentation_message_v2(
        c, T, T, 2, 3, "2.2.1.0.1", "2.1.1", F, F, F, 12);
    event ICCP::acse_message(
        c, F, T, 0, "1.3.6.1.4.1", -1, -1, -1,
        T, 9, T, F, 24);
    event ICCP::mms_message(
        c, T, T, 8, F, 32, -1, 0, 0, F, 0, "", "",
        0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    }
