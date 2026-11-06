# @TEST-DOC: Gate learned NamedVariableList state on the IEC 60870-6-503
# @TEST-DOC: Domain-specific Create and SPECIFIC full-vector Delete profile.
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut action outcome invoke_id list_scope list_domain list_name delete_scope number_matched number_deleted known_list conformance conformance_reasons < iccp_transfers.log | grep '^delete' > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: grep '^state ' .stdout > state
# @TEST-EXEC: btest-diff state

module ICCP;

function define_list(c: connection, invoke: int, name: string)
    {
    event ICCP::mms_transfer_set_message(
        c, T, 0, invoke, 11, 0, 0, 1, "D", name, 1,
        1, "D", "VALUE", F, 0, 0, 0, 0, 0, 0,
        vector(1), vector("D"), vector("VALUE"),
        vector(), vector(), vector());
    event ICCP::mms_transfer_set_message(
        c, F, 1, invoke, 11, 0, 0, 0, "", "", 0,
        0, "", "", F, 0, 0, 0, 0, 0, 0,
        vector(), vector(), vector(), vector(), vector(), vector());
    }

function known(c: connection, name: string): bool
    {
    return [c$uid, F, 1, "D", name] in ICCP::known_transfer_sets;
    }

event state_snapshot(c: connection, label: string)
    {
    print fmt("state %s L1=%s L2=%s L3=%s", label,
              known(c, "L1"), known(c, "L2"), known(c, "L3"));
    }

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.41, $orig_p=49152/tcp,
             $resp_h=192.0.2.42, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Cset-profile"
    ];
    local association = ICCP::current_state(c);
    association$phase = "established";
    association$presentation_profile = T;
    association$acse_association = T;
    association$mms_negotiation = T;
    association$tase2_evidence = T;
    association$originator_known = T;
    association$originator_is_orig = T;
    ICCP::associations[c$uid] = association;

    define_list(c, 1, "L1");
    define_list(c, 2, "L2");
    define_list(c, 3, "L3");
    event state_snapshot(c, "before");

    event ICCP::mms_transfer_set_message(
        c, T, 0, 10, 13, 0, 0, 1, "D", "L1", 0,
        0, "", "", F, 0, 2, 0, 0, 0, 0,
        vector(1, 1), vector("D", "D"), vector("L1", "L2"),
        vector(), vector(), vector());
    event ICCP::mms_transfer_set_message(
        c, F, 1, 10, 13, 0, 0, 0, "", "", 0,
        0, "", "", F, 0, 0, 2, 1, 0, 0,
        vector(), vector(), vector(), vector(), vector(), vector());
    event state_snapshot(c, "partial");

    # A generic selector is observable but cannot change verified state.
    event ICCP::mms_transfer_set_message(
        c, T, 0, 11, 13, 0, 0, 0, "", "", 0,
        0, "", "", F, 1, 0, 0, 0, 0, 0,
        vector(), vector(), vector(), vector(), vector(), vector());
    event ICCP::mms_transfer_set_message(
        c, F, 1, 11, 13, 0, 0, 0, "", "", 0,
        0, "", "", F, 0, 0, 1, 1, 0, 0,
        vector(), vector(), vector(), vector(), vector(), vector());
    event state_snapshot(c, "generic");

    # Validation covers the entire requested vector, not just its first name.
    event ICCP::mms_transfer_set_message(
        c, T, 0, 12, 13, 0, 0, 1, "D", "L3", 0,
        0, "", "", F, 0, 2, 0, 0, 0, 0,
        vector(1, 1), vector("D", "D"), vector("L3", "1bad"),
        vector(), vector(), vector());
    event state_snapshot(c, "invalid-vector");

    # A positive response with no deletion contradicts the TASE.2 profile and
    # must preserve the still-known Data Set.
    event ICCP::mms_transfer_set_message(
        c, T, 0, 13, 13, 0, 0, 1, "D", "L3", 0,
        0, "", "", F, 0, 1, 0, 0, 0, 0,
        vector(1), vector("D"), vector("L3"),
        vector(), vector(), vector());
    event ICCP::mms_transfer_set_message(
        c, F, 1, 13, 13, 0, 0, 0, "", "", 0,
        0, "", "", F, 0, 0, 1, 0, 0, 0,
        vector(), vector(), vector(), vector(), vector(), vector());
    event state_snapshot(c, "zero-deleted");

    # Once a positive response claims a deletion, the aggregate response does
    # not identify which entry succeeded.  Invalidate conservatively while
    # reporting both inconsistent count fields.
    event ICCP::mms_transfer_set_message(
        c, T, 0, 14, 13, 0, 0, 1, "D", "L3", 0,
        0, "", "", F, 0, 1, 0, 0, 0, 0,
        vector(1), vector("D"), vector("L3"),
        vector(), vector(), vector());
    event ICCP::mms_transfer_set_message(
        c, F, 1, 14, 13, 0, 0, 0, "", "", 0,
        0, "", "", F, 0, 0, 0, 1, 0, 0,
        vector(), vector(), vector(), vector(), vector(), vector());
    event state_snapshot(c, "inconsistent-positive");

    }
