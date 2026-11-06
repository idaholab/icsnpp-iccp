# @TEST-DOC: Conclude responses/errors affect association state only when they
# @TEST-DOC: come from the peer of an outstanding Conclude request.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT > output
# @TEST-EXEC: btest-diff output

module ICCP;

function emit_mms(c: connection, is_orig: bool, pdu_type: count)
    {
    event ICCP::mms_message(
        c, is_orig, T, pdu_type, T, 0, -1, 0, 0, F, 0, "", "",
        0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0, 0, 0,
        0, 0, 0, 0.0, "", 0);
    }

function emit_read_request(c: connection, is_orig: bool, invoke_id: int)
    {
    event ICCP::mms_message(
        c, is_orig, T, 0, T, 24, invoke_id, 4, 0, T, 2, "", "",
        0, "", "", 0, F, 1, "KEEP_DOMAIN", "KEEP_READ", 0,
        0, "", 0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);
    }

event ICCP::mms_message(
    c: connection, is_orig: bool, recognized: bool, pdu_type: count,
    semantic_decoded: bool, body_length: count, invoke_id: int,
    service_tag: count, unconfirmed_service_tag: count,
    iccp_required_service: bool, candidate_operation: count,
    parameter_cbb: string, services: string, object_scope: count,
    object_domain: string, object_name: string, object_category: count,
    tase2_object_evidence: bool, first_variable_scope: count,
    first_variable_domain: string, first_variable_name: string,
    first_variable_category: count, first_result_type: count,
    first_result_raw: string, result_integer_count: count,
    result_first_integer: int, result_second_integer: int,
    result_component_count: count, result_first_choice: count,
    result_second_choice: count, result_third_choice: count,
    result_integer_value: int, result_floating_value: double,
    result_flags_raw: string, result_timestamp_value: int) &priority=-20
    {
    if ( pdu_type == 11 || pdu_type == 12 || pdu_type == 13 )
        print fmt("pdu=%d is_orig=%s phase=%s kind=%s", pdu_type,
                  is_orig, ICCP::association_phase(c),
                  ICCP::association_kind(c));
    }

# Observe the real downstream stores after every matched result.  In
# particular, accepted=F must leave them intact, while accepted=T must clear
# them.  Unmatched and wrong-direction Conclude PDUs emit no result event, so
# their effect is also visible in the next accepted=F snapshot.
event ICCP::mms_conclude_result_v1(
    c: connection, response_is_orig: bool, request_is_orig: bool,
    accepted: bool) &priority=-100
    {
    print fmt("result accepted=%s response_is_orig=%s request_is_orig=%s " +
              "confirmed=%d read=%s names=%d provenance=%s",
              accepted, response_is_orig, request_is_orig,
              pending_confirmed_count(c$uid), pending_read(c, 41)$name,
              pending_name_list_count(c$uid),
              mms_provenance(c, T));

    # Advance only after the low-priority snapshot. Nested result events are
    # queued behind their source PDU, so queuing every phase from zeek_init
    # would let the later successful Conclude clear association state before
    # the earlier rejected-result assertion runs.
    if ( ! accepted && ! response_is_orig && request_is_orig )
        {
        emit_mms(c, T, 11);
        emit_mms(c, F, 11);
        emit_mms(c, T, 13);
        }
    else if ( ! accepted && response_is_orig && ! request_is_orig )
        emit_mms(c, F, 12);
    }

event zeek_init()
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.71, $orig_p=49152/tcp,
             $resp_h=192.0.2.81, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs, $service=set("iccp"),
        $history="", $uid="Cconclude-direction"
    ];

    event ICCP::acse_message(
        c, T, T, 0, "1.0.9506.2.3", -1, -1, -1, F, 0, F, T, 24);
    emit_mms(c, T, 8);
    event ICCP::acse_message(
        c, F, T, 1, "1.0.9506.2.3", 0, -1, 0, F, 0, F, T, 24);
    emit_mms(c, F, 9);

    # Seed each downstream state family that a completed association must
    # clear.  The Read request populates both association and confirmed-request
    # correlation; the other two entries exercise evidence and provenance.
    emit_read_request(c, T, 41);
    ICCP::pending_name_lists[c$uid, T, 42] = [
        $object_class_choice=0, $object_class=2, $scope=0,
        $domain="", $continue_after=""
    ];
    ICCP::set_mms_provenance(c, T, 1);

    # An unmatched response cannot terminate an established association.
    emit_mms(c, F, 12);

    emit_mms(c, T, 11);
    # Same-direction response/error cannot answer the originator's request.
    emit_mms(c, T, 12);
    emit_mms(c, T, 13);
    # The peer's error rejects the outstanding conclude and restores state.
    emit_mms(c, F, 13);

    }
