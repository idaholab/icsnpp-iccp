# @TEST-DOC: Require a directionally matched, context-bound AARQ/AARE MMS
# @TEST-DOC: Initiate pair; distinguish refused and completed release; clear
# @TEST-DOC: association trust on Session/COTP replacement and terminal
# @TEST-DOC: boundaries, including an unobserved TCP interval.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT > output
# @TEST-EXEC: btest-diff output

function make_connection(uid: string, origin_port: port): connection
    {
    return [
        $id=[$orig_h=192.0.2.10, $orig_p=origin_port,
             $resp_h=192.0.2.20, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid=uid
    ];
    }

event snapshot(label: string, c: connection)
    {
    print fmt("%s phase=%s kind=%s", label,
              ICCP::association_phase(c), ICCP::association_kind(c));
    }

function aarq(c: connection, is_orig: bool, dispatch_mms: bool)
    {
    event ICCP::presentation_message_v2(
        c, is_orig, T, 1, 1, "2.2.1.0.1", "2.1.1",
        T, F, F, 56);
    event ICCP::acse_message(
        c, is_orig, T, 0, "1.0.9506.2.3", -1, -1, -1,
        F, 0, F, dispatch_mms, 34);
    }

function aare(c: connection, is_orig: bool, application_context: string,
              dispatch_mms: bool)
    {
    event ICCP::acse_message(
        c, is_orig, T, 1, application_context, 0, -1, 0,
        F, 0, F, dispatch_mms, 41);
    }

event zeek_init() &priority=-5
    {
    local request_only = make_connection("Crequest-only", 49152/tcp);
    aarq(request_only, T, T);
    event snapshot("request-only", request_only);

    local same_direction = make_connection("Csame-direction", 49153/tcp);
    aarq(same_direction, T, T);
    aare(same_direction, T, "1.0.9506.2.3", T);
    event snapshot("same-direction-aare", same_direction);

    local unbound_response = make_connection("Cunbound-response", 49154/tcp);
    aarq(unbound_response, T, T);
    aare(unbound_response, F, "1.0.9506.2.3", F);
    event snapshot("unbound-initiate-response", unbound_response);

    local established = make_connection("Cestablished", 49155/tcp);
    aarq(established, T, T);
    aare(established, F, "1.0.9506.2.3", T);
    event snapshot("matched-initiate-pair", established);

    local wrong_context = make_connection("Cwrong-context", 49156/tcp);
    aarq(wrong_context, T, T);
    aare(wrong_context, F, "1.3.6.1.4.1", T);
    event snapshot("application-context-mismatch", wrong_context);

    local inferred = make_connection("Cinferred-response", 49157/tcp);
    event ICCP::presentation_message_v2(
        inferred, F, T, 2, 3, "", "", F, T, T, 41);
    event ICCP::mms_message(
        inferred, F, T, 9, T, 39, -1, 0, 0, F, 0,
        "\x00", "\x00", 0, "", "", 0, F,
        0, "", "", 0, 0, "", 0, 0, 0, 0, 0, 0, 0, 0,
        0.0, "", 0);
    event snapshot("inferred-initiate-response", inferred);

    local reused = make_connection("Creused", 49158/tcp);
    aarq(reused, T, T);
    aare(reused, F, "1.0.9506.2.3", T);
    event ICCP::session_spdu_marker_v1(reused, T, 13);
    event snapshot("new-connect-clears-old", reused);
    aare(reused, F, "1.0.9506.2.3", T);
    event snapshot("unmatched-accept-stays-untrusted", reused);

    local release = make_connection("Crelease", 49159/tcp);
    aarq(release, T, T);
    aare(release, F, "1.0.9506.2.3", T);
    event ICCP::acse_lifecycle_v1(release, T, 2, 9);
    event ICCP::acse_message(
        release, T, T, 2, "", -1, 30, -1,
        F, 0, F, F, 0);
    event ICCP::acse_lifecycle_v1(release, F, 3, 8);
    event ICCP::acse_message(
        release, F, T, 3, "", -1, 0, -1,
        F, 0, F, F, 0);
    event snapshot("not-finished-retains", release);
    event ICCP::acse_lifecycle_v1(release, T, 2, 9);
    event ICCP::acse_message(
        release, T, T, 2, "", -1, 30, -1,
        F, 0, F, F, 0);
    event ICCP::acse_lifecycle_v1(release, F, 3, 10);
    event ICCP::acse_message(
        release, F, T, 3, "", -1, 0, -1,
        F, 0, F, F, 0);
    event snapshot("disconnect-releases", release);

    local aborted = make_connection("Caborted", 49160/tcp);
    aarq(aborted, T, T);
    aare(aborted, F, "1.0.9506.2.3", T);
    event ICCP::session_spdu_marker_v1(aborted, T, 25);
    event snapshot("session-abort-clears", aborted);

    local refused = make_connection("Crefused", 49161/tcp);
    aarq(refused, T, T);
    aare(refused, F, "1.0.9506.2.3", T);
    event ICCP::session_spdu_marker_v1(refused, F, 12);
    event snapshot("session-refuse-clears", refused);

    local abort_accepted = make_connection("Cabort-accepted", 49162/tcp);
    aarq(abort_accepted, T, T);
    aare(abort_accepted, F, "1.0.9506.2.3", T);
    event ICCP::session_spdu_marker_v1(abort_accepted, F, 26);
    event snapshot("session-abort-accept-clears", abort_accepted);

    local transport_cr = make_connection("Ctransport-cr", 49163/tcp);
    aarq(transport_cr, T, T);
    aare(transport_cr, F, "1.0.9506.2.3", T);
    event ICCP::cotp_lifecycle_v1(transport_cr, T, 0xe0);
    event snapshot("transport-cr-replaces", transport_cr);

    local transport_dr = make_connection("Ctransport-dr", 49164/tcp);
    aarq(transport_dr, T, T);
    aare(transport_dr, F, "1.0.9506.2.3", T);
    event ICCP::cotp_lifecycle_v1(transport_dr, T, 0x80);
    event snapshot("transport-dr-clears", transport_dr);

    local transport_dc = make_connection("Ctransport-dc", 49165/tcp);
    aarq(transport_dc, T, T);
    aare(transport_dc, F, "1.0.9506.2.3", T);
    event ICCP::cotp_lifecycle_v1(transport_dc, F, 0xc0);
    event snapshot("transport-dc-clears", transport_dc);

    local transport_er = make_connection("Ctransport-er", 49166/tcp);
    aarq(transport_er, T, T);
    aare(transport_er, F, "1.0.9506.2.3", T);
    event ICCP::cotp_lifecycle_v1(transport_er, F, 0x70);
    event snapshot("transport-er-clears", transport_er);

    local observed_gap = make_connection("Cgap", 49167/tcp);
    aarq(observed_gap, T, T);
    aare(observed_gap, F, "1.0.9506.2.3", T);
    event ICCP::stream_gap(observed_gap, T, 64);
    event snapshot("tcp-gap-clears", observed_gap);
    }
