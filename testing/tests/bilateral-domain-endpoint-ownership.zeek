# @TEST-DOC: A Bilateral Table Domain belongs to the serving endpoint, not to
# @TEST-DOC: the association as a whole. Opposite endpoint VCCs may use the
# @TEST-DOC: same spelling independently; conflicting evidence invalidates only
# @TEST-DOC: that server until the association is reset. The compatibility
# @TEST-DOC: lookup remains an association-wide union, but policy classification
# @TEST-DOC: and unknown-object alerts use endpoint-owned evidence.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT > state
# @TEST-EXEC: zeek-cut is_orig object_domain object_name name_model domain_kind bilateral_domain < iccp.log | awk '$3 ~ /^PROBE_/' > objects
# @TEST-EXEC: btest-diff state
# @TEST-EXEC: btest-diff objects

module ICCP;

redef ICCP::enable_iccp_objects_log = F;
redef ICCP::enable_iccp_transfers_log = F;
redef ICCP::enable_iccp_controls_log = F;
redef ICCP::enable_iccp_errors_log = F;

global probe_alerts: set[int] = set();

function make_connection(): connection
    {
    return [
        $id=[$orig_h=192.0.2.201, $orig_p=49152/tcp,
             $resp_h=192.0.2.202, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Cbilateral-owner"
    ];
    }

function establish(c: connection)
    {
    event ICCP::presentation_message_v2(
        c, T, T, 2, 3, "2.2.1.0.1", "2.1.1", T, F, F, 32);
    event ICCP::acse_message(
        c, T, T, 0, "1.0.9506.2.3", -1, -1, -1,
        F, 0, F, T, 24);
    event ICCP::acse_message(
        c, F, T, 1, "1.0.9506.2.3", 0, -1, 0,
        F, 0, F, T, 24);
    }

function learn_bilateral_domain(
    c: connection, request_is_orig: bool, invoke_id: int, domain: string)
    {
    event ICCP::mms_read_message_v3(
        c, request_is_orig, 0, invoke_id, 0, 1,
        1, domain, "Bilateral_Table_ID", 2,
        0, 0, 0, "", 0, 0, 0, 0, 0, 0, 1);
    event ICCP::mms_read_message_v3(
        c, ! request_is_orig, 1, invoke_id, 0, 0,
        0, "", "", 0, 1, 0, 10, "VERSION",
        0, 0, 0, 0, 0, 0, 1);
    }

function probe(c: connection, request_is_orig: bool, invoke_id: int,
               object_name: string)
    {
    event ICCP::mms_message(
        c, request_is_orig, T, 0, T, 24, invoke_id, 6, 0,
        T, 4, "", "", 1, "SHARED", object_name, 0, F,
        0, "", "", 0, 0, "", 0, 0, 0, 0, 0, 0, 0, 0,
        0.0, "", 0);
    }

event inspect_domains(c: connection, label: string) &priority=-20
    {
    local state = current_state(c);
    print fmt("%s union_shared=%s union_other=%s " +
              "orig_shared=%s resp_shared=%s orig_other=%s resp_other=%s " +
              "ambiguous_orig=%s ambiguous_resp=%s",
              label,
              is_bilateral_domain(c, "SHARED"),
              is_bilateral_domain(c, "OTHER"),
              is_bilateral_domain_for_server(c, T, "SHARED"),
              is_bilateral_domain_for_server(c, F, "SHARED"),
              is_bilateral_domain_for_server(c, T, "OTHER"),
              is_bilateral_domain_for_server(c, F, "OTHER"),
              T in state$ambiguous_bilateral_domain_servers,
              F in state$ambiguous_bilateral_domain_servers);
    }

event ICCP::unknown_object_access_v2(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, operation: string, invoke_id: int,
    object_scope: string, object_domain: string, object_name: string,
    name_model: string, provenance: string)
    {
    if ( /^PROBE_/ in object_name )
        add probe_alerts[invoke_id];
    }

event zeek_done()
    {
    print fmt("alerts invoke_11=%s invoke_13=%s total=%d",
              11 in probe_alerts, 13 in probe_alerts, |probe_alerts|);
    }

event zeek_init()
    {
    local c = make_connection();
    establish(c);

    # The responder serves SHARED to the originator. The compatibility union
    # sees it, but the originator's VCC does not inherit it.
    learn_bilateral_domain(c, T, 1, "SHARED");
    event inspect_domains(c, "responder_only");
    probe(c, T, 10, "PROBE_RESPONDER");
    probe(c, F, 11, "PROBE_ORIGINATOR_UNLEARNED");

    # The same Domain spelling is valid when independently learned from the
    # originator acting as server.
    learn_bilateral_domain(c, F, 2, "SHARED");
    event inspect_domains(c, "both_same_spelling");
    probe(c, F, 12, "PROBE_ORIGINATOR_LEARNED");

    # A second, different successful bootstrap for the responder contradicts
    # the one-Domain-per-peer model. Only that side becomes untrusted; the
    # originator's independently learned SHARED mapping keeps the union true.
    learn_bilateral_domain(c, T, 3, "OTHER");
    event inspect_domains(c, "responder_conflict");
    probe(c, T, 13, "PROBE_RESPONDER_CONFLICTED");
    learn_bilateral_domain(c, T, 4, "SHARED");
    event inspect_domains(c, "conflict_is_sticky");

    # Association reset clears both endpoint mappings and ambiguity, after
    # which the responder can learn a fresh Domain.
    event ICCP::acse_message(
        c, T, T, 4, "1.0.9506.2.3", -1, -1, -1,
        F, 0, F, F, 0);
    event inspect_domains(c, "after_reset");
    establish(c);
    learn_bilateral_domain(c, T, 5, "OTHER");
    event inspect_domains(c, "relearned_after_reset");
    }
