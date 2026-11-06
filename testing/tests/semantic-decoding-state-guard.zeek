# @TEST-DOC: A recognized MMS top-level tag whose service/body did not decode
# @TEST-DOC: semantically must remain observable without mutating association,
# @TEST-DOC: TASE.2, bilateral-domain, or request-correlation state.  It must
# @TEST-DOC: also leave valid outstanding state intact for a later valid PDU.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT > output
# @TEST-EXEC: btest-diff output

module ICCP;

function emit_mms(
    c: connection, is_orig: bool, pdu_type: count,
    semantic_decoded: bool, invoke_id: int, service_tag: count,
    object_scope: count, object_domain: string, object_name: string,
    object_category: count, tase2_object_evidence: bool,
    first_variable_scope: count, first_variable_domain: string,
    first_variable_name: string, first_variable_category: count)
    {
    event ICCP::mms_message(
        c, is_orig, T, pdu_type, semantic_decoded, 24, invoke_id,
        service_tag, 0, service_tag == 4 || service_tag == 6,
        service_tag == 4 ? 2 : service_tag == 6 ? 4 : 0,
        pdu_type == 8 || pdu_type == 9 ? "\x00" : "",
        pdu_type == 8 || pdu_type == 9 ? "\x01" : "",
        object_scope, object_domain, object_name, object_category,
        tase2_object_evidence, first_variable_scope,
        first_variable_domain, first_variable_name,
        first_variable_category, 0, "", 0, 0, 0, 0, 0, 0, 0,
        0, 0.0, "", 0);
    }

function establish_tase_evidence(c: connection, invoke_id: int)
    {
    event ICCP::mms_read_message_v3(
        c, T, 0, invoke_id, 0, 1, 0, "", "Supported_Features", 1,
        0, 0, 0, "", 0, 0, 0, 0, 0, 0, 1);
    event ICCP::mms_read_message_v3(
        c, F, 1, invoke_id, 0, 0, 0, "", "", 0,
        1, 0, 4, "\x07\x80", 0, 0, 0, 0, 0, 0, 1);
    }

event inspect_state(c: connection, label: string, invoke_id: int)
    {
    local state = current_state(c);
    print fmt("%s phase=%s kind=%s mms=%s tase=%s bilateral=%s " +
              "read=%s confirmed=%d",
              label, association_phase(c), association_kind(c),
              state$mms_negotiation, state$tase2_evidence,
              is_bilateral_domain(c, "BAD_BILATERAL"),
              pending_read(c, invoke_id)$name,
              pending_confirmed_count(c$uid));
    }

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.10, $orig_p=49152/tcp,
             $resp_h=192.0.2.20, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Csemantic-guard"
    ];

    event ICCP::presentation_message_v2(
        c, T, T, 2, 3, "2.2.1.0.1", "2.1.1", T, F, F, 32);
    event ICCP::acse_message(
        c, T, T, 0, "1.3.6.1.4.1", -1, -1, -1,
        F, 0, F, T, 24);

    # Recognized top-level MMS choices alone are not semantic evidence.
    emit_mms(c, T, 8, F, -1, 0, 0, "", "", 0, F,
             0, "", "", 0);
    event inspect_state(c, "raw-initiate", 10);
    emit_mms(c, T, 0, F, 10, 6, 1, "BAD_BILATERAL",
             "Bilateral_Table_ID", 2, T, 0, "", "", 0);
    event inspect_state(c, "raw-tase-bilateral", 10);
    emit_mms(c, T, 0, F, 11, 4, 0, "", "", 0, F,
             1, "BAD_BILATERAL", "BAD_READ", 0);
    event inspect_state(c, "raw-read-request", 11);

    # Establish valid state and retire the setup request before testing an
    # outstanding Read, so both pending stores have an exact expected size.
    event ICCP::acse_message(
        c, F, T, 1, "1.3.6.1.4.1", 0, -1, 0,
        F, 0, F, T, 24);
    emit_mms(c, T, 8, T, -1, 0, 0, "", "", 0, F,
             0, "", "", 0);
    emit_mms(c, T, 0, T, 20, 6, 0, "", "Supported_Features", 1, T,
             0, "", "", 0);
    emit_mms(c, F, 1, T, 20, 6, 0, "", "", 0, F,
             0, "", "", 0);
    establish_tase_evidence(c, 21);
    emit_mms(c, T, 0, T, 77, 4, 0, "", "", 0, F,
             1, "CONTROL_CENTER_B", "KEEP_READ", 0);
    event inspect_state(c, "valid-read-pending", 77);

    # Neither a raw response nor a raw conclude may consume/clear valid state.
    emit_mms(c, F, 1, F, 77, 4, 0, "", "", 0, F,
             0, "", "", 0);
    event inspect_state(c, "raw-read-response", 77);
    emit_mms(c, T, 11, F, -1, 0, 0, "", "", 0, F,
             0, "", "", 0);
    emit_mms(c, F, 12, F, -1, 0, 0, "", "", 0, F,
             0, "", "", 0);
    event inspect_state(c, "raw-conclude", 77);

    # The direction-correct semantic response must still find and consume the
    # original request.  Semantic conclude PDUs then transition normally.
    emit_mms(c, F, 1, T, 77, 4, 0, "", "", 0, F,
             0, "", "", 0);
    event inspect_state(c, "valid-read-response", 77);
    emit_mms(c, T, 11, T, -1, 0, 0, "", "", 0, F,
             0, "", "", 0);
    event inspect_state(c, "valid-conclude-request", 77);
    emit_mms(c, F, 12, T, -1, 0, 0, "", "", 0, F,
             0, "", "", 0);
    event inspect_state(c, "valid-conclude-response", 77);
    }
