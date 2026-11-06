# @TEST-DOC: Verify production TCP-gap recovery at a complete TPKT boundary,
# @TEST-DOC: candidate-versus-confirmed completeness, direction isolation,
# @TEST-DOC: complete tail commit after repeated gaps, while retaining a
# @TEST-DOC: durable non-exhaustive verdict for the gapped direction. Also
# @TEST-DOC: verify a terminal gap invalidates negotiated shared state before
# @TEST-DOC: peer traffic even when no later same-direction token exists, and
# @TEST-DOC: verify an incomplete no-FIN COTP lifecycle prefix does the same
# @TEST-DOC: before a complete peer-direction DT reaches an upper layer.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap gap.pcap direct-mms-gap-recovery
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap gap-copy.pcap direct-mms-gap-recovery
# @TEST-EXEC: cmp gap.pcap gap-copy.pcap
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap gap-tail.pcap direct-mms-gap-tail
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap gap-tail-copy.pcap direct-mms-gap-tail
# @TEST-EXEC: cmp gap-tail.pcap gap-tail-copy.pcap
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap gap-terminal.pcap direct-mms-gap-terminal-negotiated
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap gap-terminal-copy.pcap direct-mms-gap-terminal-negotiated
# @TEST-EXEC: cmp gap-terminal.pcap gap-terminal-copy.pcap
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap partial-boundary.pcap direct-mms-incomplete-cotp-boundary-peer
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap partial-boundary-copy.pcap direct-mms-incomplete-cotp-boundary-peer
# @TEST-EXEC: cmp partial-boundary.pcap partial-boundary-copy.pcap
# @TEST-EXEC: mkdir run
# @TEST-EXEC: cd run && zeek -Cr ../gap.pcap ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: mkdir tail-run
# @TEST-EXEC: cd tail-run && zeek -Cr ../gap-tail.pcap ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: mkdir terminal-run
# @TEST-EXEC: cd terminal-run && zeek -Cr ../gap-terminal.pcap ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: mkdir partial-boundary-run
# @TEST-EXEC: cd partial-boundary-run && zeek -Cr ../partial-boundary.pcap ${PACKAGE}/__load__.zeek %INPUT > ../partial-boundary-events
# @TEST-EXEC: zeek-cut layer < tail-run/iccp.log | awk '$1 == "mms" { n++ } END { exit n == 7 ? 0 : 1 }'
# @TEST-EXEC: zeek-cut layer message_type < tail-run/iccp.log | awk '$1 == "mms" && $2 == "3" { n++ } END { exit n == 3 ? 0 : 1 }'
# @TEST-EXEC: test "$(zeek-cut is_orig layer message_type association_kind association_phase operation provenance < terminal-run/iccp.log | grep -c '^F[[:space:]]mms[[:space:]]3[[:space:]]unknown[[:space:]]observation_gap[[:space:]]information_report[[:space:]]inferred$' || true)" -eq 1
# @TEST-EXEC: test "$(zeek-cut is_orig message_type status stream_completeness < terminal-run/iccp.log | grep -c '^T[[:space:]]direction_summary[[:space:]]non_exhaustive[[:space:]]direction_non_exhaustive_after_gap$' || true)" -eq 1
# @TEST-EXEC: test "$(zeek-cut is_orig stream_completeness < terminal-run/iccp.log | grep -Ec '^T[[:space:]](recovery_candidate_after_gap|verified_recovery_after_gap)$' || true)" -eq 0
# @TEST-EXEC: test "$(zeek-cut is_orig layer message_type association_kind association_phase < partial-boundary-run/iccp.log | grep -c '^F[[:space:]]acse[[:space:]]1[[:space:]]mms[[:space:]]established$' || true)" -eq 1
# @TEST-EXEC: test "$(zeek-cut is_orig message_type status stream_completeness < partial-boundary-run/iccp.log | grep -c '^T[[:space:]]direction_summary[[:space:]]non_exhaustive[[:space:]]direction_non_exhaustive_after_incomplete_record$' || true)" -eq 1
# @TEST-EXEC: test ! -s partial-boundary-events
# @TEST-EXEC: test ! -e run/iccp_errors.log
# @TEST-EXEC: test ! -e tail-run/iccp_errors.log
# @TEST-EXEC: test ! -e terminal-run/iccp_errors.log
# @TEST-EXEC: zeek-cut is_orig layer message_type status invoke_id provenance stream_completeness < run/iccp.log > output
# @TEST-EXEC: zeek-cut is_orig layer message_type status invoke_id provenance stream_completeness < tail-run/iccp.log >> output
# @TEST-EXEC: btest-diff output

module ICCP;

# These assertions intentionally produce no output on success. The new PCAP
# has four originator TPKTs begun but only three completed: CR, association CP,
# an Identify request, and then the incomplete replacement CR. This identifies
# the focused process without a test-only parser switch.
global recovery_test_record_starts: table[string, bool] of count;
global recovery_test_record_completions: table[string, bool] of count;
global recovery_test_cotp_markers: table[string] of count;
global recovery_test_association_established: set[string];
global recovery_test_partial_boundary_started: set[string];
global recovery_test_partial_boundary_marked: set[string];
global recovery_test_policy_reset: set[string];
global recovery_test_peer_recovery: set[string];
global recovery_test_peer_upper_layer: set[string];
global recovery_test_partial_checked: set[string];

function recovery_test_increment(
    values: table[string, bool] of count, uid: string, is_orig: bool): count
    {
    if ( [uid, is_orig] !in values )
        values[uid, is_orig] = 0;

    ++values[uid, is_orig];
    return values[uid, is_orig];
    }

event ICCP::stream_record_started(
    c: connection, is_orig: bool) &priority=-100
    {
    local record_count = recovery_test_increment(
        recovery_test_record_starts, c$uid, is_orig);
    if ( is_orig && record_count == 4 &&
         c$uid in recovery_test_association_established )
        add recovery_test_partial_boundary_started[c$uid];
    }

event ICCP::stream_record_completed(
    c: connection, is_orig: bool) &priority=-100
    {
    recovery_test_increment(
        recovery_test_record_completions, c$uid, is_orig);
    }

event ICCP::cotp_lifecycle_v1(
    c: connection, is_orig: bool, tpdu_type: count) &priority=-100
    {
    if ( c$uid !in recovery_test_cotp_markers )
        recovery_test_cotp_markers[c$uid] = 0;
    ++recovery_test_cotp_markers[c$uid];

    # The initial CR/CC are markers one and two. The partial replacement CR is
    # marker three and must have already run every production policy cleanup.
    if ( recovery_test_cotp_markers[c$uid] == 3 )
        {
        add recovery_test_partial_boundary_marked[c$uid];
        if ( is_orig && tpdu_type == 0xe0 )
            {
            if ( association_kind(c) == "unknown" &&
                 association_phase(c) == "transport_connecting" )
                add recovery_test_policy_reset[c$uid];
            else
                print "partial COTP boundary did not clear policy trust";
            }
        else
            print "unexpected third COTP lifecycle marker";
        }
    }

event ICCP::stream_recovery_started(
    c: connection, is_orig: bool, crossed_gap: bool) &priority=-100
    {
    if ( ! is_orig &&
         c$uid in recovery_test_partial_boundary_started )
        add recovery_test_peer_recovery[c$uid];
    }

event ICCP::presentation_message_v2(
    c: connection, is_orig: bool, recognized: bool, ppdu_type: count,
    context_id: count, abstract_syntax: string, transfer_syntax: string,
    dispatch_acse: bool, dispatch_mms: bool, inferred_mms: bool,
    payload_length: count) &priority=-100
    {
    if ( association_kind(c) == "mms" &&
         association_phase(c) == "established" )
        add recovery_test_association_established[c$uid];

    if ( ! is_orig &&
         c$uid in recovery_test_partial_boundary_started )
        add recovery_test_peer_upper_layer[c$uid];
    }

# Inspect the live association before production's default-priority lifecycle
# teardown; completeness emits its terminal direction summary later at -10.
event connection_state_remove(c: connection) &priority=5
    {
    if ( c$uid !in recovery_test_partial_boundary_started )
        return;

    add recovery_test_partial_checked[c$uid];

    if ( c$uid !in recovery_test_association_established )
        print "partial COTP boundary fixture never established association trust";
    if ( c$uid !in recovery_test_partial_boundary_marked ||
         c$uid !in recovery_test_cotp_markers ||
         recovery_test_cotp_markers[c$uid] != 3 )
        print "incomplete COTP CR prefix did not publish exactly one marker";
    if ( c$uid !in recovery_test_policy_reset )
        print "incomplete COTP CR prefix did not reset policy state";
    if ( association_kind(c) != "unknown" ||
         association_phase(c) != "transport_connecting" )
        print "partial COTP boundary policy state changed before teardown";
    if ( [c$uid, T] !in recovery_test_record_completions ||
         recovery_test_record_completions[c$uid, T] != 3 )
        print "partial COTP boundary unexpectedly completed its TPKT";
    if ( c$uid !in recovery_test_peer_recovery )
        print "peer DT did not enter recovery after incomplete COTP boundary";
    if ( c$uid in recovery_test_peer_upper_layer )
        print "peer DT reused upper-layer trust after incomplete COTP boundary";
    }

event zeek_done()
    {
    for ( uid in recovery_test_partial_boundary_started )
        if ( uid !in recovery_test_partial_checked )
            print "partial COTP boundary assertions did not run";
    }
