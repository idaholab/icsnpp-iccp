# @TEST-DOC: The packet aggregate, authoritative v3 transfer event, and
# @TEST-DOC: stable unversioned compatibility event may arrive in any sibling
# @TEST-DOC: order. Exactly one policy transition is emitted in each order.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut uid action outcome invoke_id list_name known_list conformance conformance_reasons < iccp_transfers.log > output
# @TEST-EXEC: btest-diff output

module ICCP;

function test_connection(uid: string, orig_p: port): connection
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.230, $orig_p=orig_p,
             $resp_h=192.0.2.240, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid=uid
    ];
    local association = current_state(c);
    association$phase = "established";
    association$presentation_profile = T;
    association$acse_association = T;
    association$mms_negotiation = T;
    association$tase2_evidence = T;
    associations[c$uid] = association;
    return c;
    }

event simulate_transfer_aggregate(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    service_tag: count)
    {
    if ( consume_mms_parser_marker(c, is_orig) )
        mark_parser_transfer_delivery(
            c, is_orig, pdu_type, invoke_id, service_tag, 0);
    }

function emit_legacy(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    name: string)
    {
    event mms_transfer_set_message(
        c, is_orig, pdu_type, invoke_id, 11, 0, 0,
        pdu_type == 0 ? 1 : 0, pdu_type == 0 ? "D" : "",
        pdu_type == 0 ? name : "", pdu_type == 0 ? 1 : 0,
        pdu_type == 0 ? 0 : 0, "", pdu_type == 0 ? "P1" : "",
        F, 0, 0, 0, 0, 0, 0,
        pdu_type == 0 ? vector(0) : vector(),
        pdu_type == 0 ? vector("") : vector(),
        pdu_type == 0 ? vector("P1") : vector(),
        vector(), vector(), vector());
    }

function emit_v3(
    c: connection, is_orig: bool, pdu_type: count, invoke_id: int,
    name: string)
    {
    event mms_transfer_set_message_v3(
        c, is_orig, pdu_type, invoke_id, 11, 0, 0,
        pdu_type == 0 ? 1 : 0, pdu_type == 0 ? "D" : "",
        pdu_type == 0 ? name : "", pdu_type == 0 ? 1 : 0,
        0, "", pdu_type == 0 ? "P1" : "", F, 0, 0, 0, 0, 0, 0,
        pdu_type == 0 ? vector(0) : vector(),
        pdu_type == 0 ? vector("") : vector(),
        pdu_type == 0 ? vector("P1") : vector(),
        pdu_type == 0 ? vector(0) : vector(),
        vector(), vector(), vector(), 1);
    }

event queue_exchange(c: connection, invoke_id: int, name: string,
                     order: string)
    {
    event mms_provenance_marker_v1(c, T, 1);
    if ( order == "legacy_first" )
        {
        emit_legacy(c, T, 0, invoke_id, name);
        emit_v3(c, T, 0, invoke_id, name);
        event simulate_transfer_aggregate(c, T, 0, invoke_id, 11);
        }
    else if ( order == "aggregate_first" )
        {
        event simulate_transfer_aggregate(c, T, 0, invoke_id, 11);
        emit_legacy(c, T, 0, invoke_id, name);
        emit_v3(c, T, 0, invoke_id, name);
        }
    else
        {
        emit_v3(c, T, 0, invoke_id, name);
        emit_legacy(c, T, 0, invoke_id, name);
        event simulate_transfer_aggregate(c, T, 0, invoke_id, 11);
        }

    event mms_provenance_marker_v1(c, F, 1);
    if ( order == "legacy_first" )
        {
        emit_legacy(c, F, 1, invoke_id, "");
        emit_v3(c, F, 1, invoke_id, "");
        event simulate_transfer_aggregate(c, F, 1, invoke_id, 11);
        }
    else if ( order == "aggregate_first" )
        {
        event simulate_transfer_aggregate(c, F, 1, invoke_id, 11);
        emit_legacy(c, F, 1, invoke_id, "");
        emit_v3(c, F, 1, invoke_id, "");
        }
    else
        {
        emit_v3(c, F, 1, invoke_id, "");
        emit_legacy(c, F, 1, invoke_id, "");
        event simulate_transfer_aggregate(c, F, 1, invoke_id, 11);
        }
    }

event zeek_init()
    {
    event queue_exchange(
        test_connection("Ctransfer-legacy-first", 49170/tcp),
        1, "L_LEGACY", "legacy_first");
    event queue_exchange(
        test_connection("Ctransfer-aggregate-first", 49171/tcp),
        2, "L_AGGREGATE", "aggregate_first");
    event queue_exchange(
        test_connection("Ctransfer-v3-first", 49172/tcp),
        3, "L_V3", "v3_first");
    }
