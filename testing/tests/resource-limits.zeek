# @TEST-DOC: Check per-connection resource-limit events for every bounded
# @TEST-DOC: semantic-state collection, with all ICCP logs disabled. Adjacent
# @TEST-DOC: deferred control-limit alerts retain each PDU's captured provenance.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT > output
# @TEST-EXEC: btest-diff output

module ICCP;

redef ICCP::enable_iccp_log = F;
redef ICCP::enable_iccp_objects_log = F;
redef ICCP::enable_iccp_transfers_log = F;
redef ICCP::enable_iccp_controls_log = F;
redef ICCP::enable_iccp_errors_log = F;
redef ICCP::max_bilateral_domains = 1;
redef ICCP::max_pending_reads = 1;
redef ICCP::max_pending_confirmed = 1;
redef ICCP::max_pending_controls = 1;
redef ICCP::max_pending_transfer_sets = 1;
redef ICCP::max_known_transfer_sets = 1;

event ICCP::resource_limit_exceeded_v2(
    c: connection, is_orig: bool, resource: string, limit: count,
    current: count, invoke_id: int, provenance: string)
    {
    print fmt("resource=%s limit=%d current=%d invoke=%d provenance=%s",
              resource, limit, current, invoke_id, provenance);
    }

# Parser Read correlation normally retires at zero delay so sibling aggregate
# events can consume it. This fixture chains two exact bootstrap exchanges in
# one zeek_init turn, so explicitly retire the completed first exchange before
# starting the opposite endpoint's request.
event retire_fixture_read(
    c: connection, response_is_orig: bool, invoke_id: int) &priority=-20
    {
    retire_pending_read_for_response(c, response_is_orig, invoke_id);
    }

event zeek_init() &priority=-5
    {
    local no_counts: vector of count = vector();
    local no_ints: vector of int = vector();
    local no_strings: vector of string = vector();
    local c: connection = [
        $id=[$orig_h=192.0.2.130, $orig_p=49152/tcp,
             $resp_h=192.0.2.140, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs, $service=set("iccp"),
        $history="", $uid="Climits"
    ];

    event ICCP::presentation_message_v2(c, T, T, 2, 3,
                                     "2.2.1.0.1", "2.1.1", T, F, F, 32);
    event ICCP::acse_message(c, T, T, 0, "1.0.9506.2.3", -1, -1, -1,
                            F, 0, F, T, 24);
    event ICCP::mms_message(
        c, T, T, 8, T, 16, -1, 0, 0, F, 0, "\x00", "\x01",
        0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::acse_message(c, F, T, 1, "1.0.9506.2.3", 0, -1, 0,
                            F, 0, F, T, 24);
    # Learn one exact endpoint-owned Bilateral Table Domain. With the cap set
    # to one, the opposite serving endpoint's otherwise valid mapping is the
    # second retained endpoint/domain pair and must raise the limit event.
    event ICCP::mms_read_message_v3(
        c, T, 0, 70, 0, 1, 1, "DOMAIN_A", "Bilateral_Table_ID", 2,
        0, 0, 0, "", 0, 0, 0, 0, 0, 0, 1);
    event ICCP::mms_read_message_v3(
        c, F, 1, 70, 0, 0, 0, "", "", 0,
        1, 0, 10, "VERSION_A", 0, 0, 0, 0, 0, 0, 1);
    event retire_fixture_read(c, F, 70);
    event ICCP::mms_read_message_v3(
        c, F, 0, 71, 0, 1, 1, "DOMAIN_B", "Bilateral_Table_ID", 2,
        0, 0, 0, "", 0, 0, 0, 0, 0, 0, 1);
    event ICCP::mms_read_message_v3(
        c, T, 1, 71, 0, 0, 0, "", "", 0,
        1, 0, 10, "VERSION_B", 0, 0, 0, 0, 0, 0, 1);
    event retire_fixture_read(c, T, 71);

    # The second outstanding Read exceeds both generic and Read state.
    event ICCP::mms_message(
        c, T, T, 0, T, 12, 1, 4, 0, T, 2, "", "",
        0, "", "", 0, F, 0, "", "FIRST", 0, 0, "",
        0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_message(
        c, T, T, 0, T, 12, 2, 4, 0, T, 2, "", "",
        0, "", "", 0, F, 0, "", "SECOND", 0, 0, "",
        0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::mms_message(
        c, T, T, 0, T, 12, 1, 4, 0, T, 2, "", "",
        0, "", "", 0, F, 0, "", "REUSED", 0, 0, "",
        0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);

    # Retire the deliberately ambiguous generic fixture before testing the
    # independent specialized caps below.  Otherwise the association-wide
    # confirmed-request budget correctly blocks every later direct hook.
    event ICCP::mms_message(
        c, F, T, 1, T, 12, 1, 4, 0, T, 2, "", "",
        0, "", "", 0, F, 0, "", "", 0, 0, "",
        0, 0, 0, 0, 0, 0, 0, 0, 0.0, "", 0);

    event ICCP::mms_control_request_deferred(c, T, 10, 0, "", "WRITE1",
                                             1, 1, 1);
    event ICCP::mms_control_request_deferred(c, T, 11, 0, "", "WRITE2",
                                             1, 1, 1);
    event ICCP::mms_control_request_deferred(c, T, 10, 0, "", "WRITE_REUSED",
                                             1, 1, 2);

    # One confirmed definition fills known-list state; the next is refused.
    event ICCP::mms_transfer_set_message(
        c, T, 0, 20, 11, 0, 0, 1, "DOMAIN_A", "TS1", 1,
        0, "", "POINT1", F, 0, 0, 0, 0, 0, 0,
        vector(0), vector(""), vector("POINT1"),
        no_counts, no_ints, no_strings);
    event ICCP::mms_transfer_set_message(
        c, F, 1, 20, 11, 0, 0, 0, "", "", 0,
        0, "", "", F, 0, 0, 0, 0, 0, 0,
        no_counts, no_strings, no_strings, no_counts, no_ints, no_strings);
    event ICCP::mms_transfer_set_message(
        c, T, 0, 21, 11, 0, 0, 1, "DOMAIN_A", "TS2", 1,
        0, "", "POINT2", F, 0, 0, 0, 0, 0, 0,
        vector(0), vector(""), vector("POINT2"),
        no_counts, no_ints, no_strings);
    event ICCP::mms_transfer_set_message(
        c, F, 1, 21, 11, 0, 0, 0, "", "", 0,
        0, "", "", F, 0, 0, 0, 0, 0, 0,
        no_counts, no_strings, no_strings, no_counts, no_ints, no_strings);

    # A second outstanding transfer request exceeds pending state.
    event ICCP::mms_transfer_set_message(
        c, T, 0, 22, 12, 0, 0, 0, "", "TS1", 0,
        0, "", "", F, 0, 0, 0, 0, 0, 0,
        no_counts, no_strings, no_strings, no_counts, no_ints, no_strings);
    event ICCP::mms_transfer_set_message(
        c, T, 0, 23, 12, 0, 0, 0, "", "TS2", 0,
        0, "", "", F, 0, 0, 0, 0, 0, 0,
        no_counts, no_strings, no_strings, no_counts, no_ints, no_strings);
    event ICCP::mms_transfer_set_message(
        c, T, 0, 22, 12, 0, 0, 0, "", "TS1", 0,
        0, "", "", F, 0, 0, 0, 0, 0, 0,
        no_counts, no_strings, no_strings, no_counts, no_ints, no_strings);

    event ICCP::mms_transfer_support_value_message(
        c, T, 0, 30, 4, 1, "DOMAIN_A", "Transfer_Set_Name",
        0, 0, 0, "", 0, 0, 0, 0, 0, "", "");
    event ICCP::mms_transfer_support_value_message(
        c, T, 0, 31, 4, 1, "DOMAIN_A", "Transfer_Report_ACK",
        0, 0, 0, "", 0, 0, 0, 0, 0, "", "");

    # Fill one connection's control budget, then queue two same-kind alerts.
    # Both bridge markers must be consumed in FIFO pair order rather than the
    # second marker overwriting the first one's captured provenance.
    local adjacent: connection = [
        $id=[$orig_h=192.0.2.130, $orig_p=49153/tcp,
             $resp_h=192.0.2.140, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Climits-adjacent"
    ];
    local adjacent_generation = mms_policy_generation(adjacent);
    event ICCP::mms_control_request_deferred_v3(
        adjacent, T, 60, 0, "", "WRITE1", 1, 1, 1,
        1, adjacent_generation, "verified");
    event ICCP::mms_control_request_deferred_v3(
        adjacent, T, 61, 0, "", "WRITE2", 1, 1, 1,
        2, adjacent_generation, "verified");
    event ICCP::mms_control_request_deferred_v3(
        adjacent, T, 62, 0, "", "WRITE3", 1, 1, 1,
        3, adjacent_generation, "inferred");
    }
