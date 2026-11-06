# Copyright 2026, Battelle Energy Alliance, LLC. All Rights Reserved.

################################################################################
##
## ICSNPP - ICCP
##
## This file tracks capture completeness, gaps, and recovery state for ICCP
## logging.
##
## Christopher B. Peterson and Christian J Weelborg
## Idaho National Lab, November 2026
##
################################################################################

module ICCP;

export {
    const completeness_state_timeout = 1hr &redef;
}

# Partial captures are a primary deployment and validation mode for this
# analyzer. Ask Zeek to report their ACK-confirmed TCP content gaps as well.
redef report_gaps_for_partial = T;

# Direction-scoped because either half of a TCP connection may have an
# independent capture gap. A missing entry means the record was produced by a
# synthetic/downstream event with no parser observation to support a claim.
global current_output_completeness: table[string, bool] of string
    &read_expire=completeness_state_timeout;
global malformed_recovery_reported: table[string, bool] of bool
    &read_expire=completeness_state_timeout;
# These terminal-history bits are bounded to two entries per active
# connection and explicitly removed at teardown. Do not expire them while a
# long-lived ICCP connection is idle, or its final verdict could lose history.
global direction_gap_observed: table[string, bool] of bool;
global direction_parse_recovery_observed: table[string, bool] of bool;
global direction_incomplete_record_observed: table[string, bool] of bool;
global direction_record_in_progress: table[string, bool] of bool;
global direction_complete_record_observed: table[string, bool] of bool;
# Internal teardown stage. It intentionally carries only the immutable UID:
# the connection record and its association state remain live until every
# stream_finished event queued ahead of this event has run.
global stream_connection_cleanup_v1: event(uid: string);

function output_completeness(c: connection, is_orig: bool): string
    {
    if ( [c$uid, is_orig] in current_output_completeness )
        return current_output_completeness[c$uid, is_orig];

    return "unknown";
    }

event ICCP::stream_started(c: connection, is_orig: bool) &priority=20
    {
    if ( [c$uid, is_orig] !in current_output_completeness )
        current_output_completeness[c$uid, is_orig] =
            "contiguous_observation";
    }

function mark_stream_gap(c: connection, is_orig: bool)
    {
    direction_gap_observed[c$uid, is_orig] = T;
    current_output_completeness[c$uid, is_orig] =
        "gap_observed_unrecovered";
    }

event ICCP::stream_gap(
    c: connection, is_orig: bool, length: count) &priority=20
    {
    mark_stream_gap(c, is_orig);
    }

# Track the TPKT lifecycle in Zeek instead of relying only on parser finalizers.
# For a no-FIN offline stream, Zeek can remove the analyzer while its Spicy
# child remains suspended; the child's %finally and the top-level %done hooks
# do not run. A clean boundary never starts a new child.
event ICCP::stream_record_started(
    c: connection, is_orig: bool) &priority=20
    {
    direction_record_in_progress[c$uid, is_orig] = T;
    }

event ICCP::stream_record_completed(
    c: connection, is_orig: bool) &priority=20
    {
    direction_complete_record_observed[c$uid, is_orig] = T;
    delete direction_record_in_progress[c$uid, is_orig];
    }

function mark_stream_incomplete(c: connection, is_orig: bool)
    {
    direction_incomplete_record_observed[c$uid, is_orig] = T;
    current_output_completeness[c$uid, is_orig] =
        "incomplete_record_observation";
    }

# A stream may finish after consuming the start of a plausible TPKT but before
# that record completes. No resynchronization hook fires in this case, so keep
# capture-boundary truncation distinct from malformed-byte recovery and make
# the terminal non-exhaustive verdict explicit without calling it a protocol
# error.
event ICCP::stream_incomplete(c: connection, is_orig: bool) &priority=20
    {
    mark_stream_incomplete(c, is_orig);
    }

function mark_parse_recovery_started(c: connection, is_orig: bool)
    {
    direction_parse_recovery_observed[c$uid, is_orig] = T;
    current_output_completeness[c$uid, is_orig] =
        "recovery_scan_after_parse_error";

    if ( [c$uid, is_orig] !in malformed_recovery_reported )
        {
        malformed_recovery_reported[c$uid, is_orig] = T;
        event ICCP::malformed_structure(
            c,
            "TPKT parser entered bounded recovery after malformed captured bytes");
        }
    }

event ICCP::stream_recovery_started(
    c: connection, is_orig: bool, crossed_gap: bool) &priority=20
    {
    if ( crossed_gap ||
         output_completeness(c, is_orig) == "gap_observed_unrecovered" ||
         output_completeness(c, is_orig) ==
            "recovery_candidate_after_gap" )
        return;

    mark_parse_recovery_started(c, is_orig);
    }

# Zeek's TCP reassembler is the authoritative source for ACK-confirmed missing
# sequence space. Spicy's top-level TCP parser receives a missing stream region
# but its %gap hook is reserved for sink reassembly, so translate the native
# event directly in every ICCP policy subsystem. Keep the analyzer guard: port
# 102 may be reassigned and unrelated analyzers also generate content_gap.
event content_gap(
    c: connection, is_orig: bool, seq: count, length: count) &priority=20
    {
    if ( lookup_connection_analyzer_id(
             c$id, Analyzer::ANALYZER_ICCP_TCP) == 0 )
        return;

    mark_stream_gap(c, is_orig);
    }

event ICCP::stream_recovery_candidate(
    c: connection, is_orig: bool, crossed_gap: bool) &priority=20
    {
    if ( crossed_gap ||
         output_completeness(c, is_orig) == "gap_observed_unrecovered" )
        current_output_completeness[c$uid, is_orig] =
            "recovery_candidate_after_gap";
    else
        {
        mark_parse_recovery_started(c, is_orig);
        current_output_completeness[c$uid, is_orig] =
            "recovery_candidate_after_parse_error";
        }
    }

event ICCP::stream_recovered(
    c: connection, is_orig: bool, crossed_gap: bool) &priority=20
    {
    if ( crossed_gap ||
         output_completeness(c, is_orig) == "gap_observed_unrecovered" ||
         output_completeness(c, is_orig) ==
            "recovery_candidate_after_gap" )
        current_output_completeness[c$uid, is_orig] =
            "verified_recovery_after_gap";
    else
        current_output_completeness[c$uid, is_orig] =
            "verified_recovery_after_parse_error";

    delete malformed_recovery_reported[c$uid, is_orig];
    }

function emit_terminal_incompleteness(c: connection, is_orig: bool)
    {
    if ( [c$uid, is_orig] in direction_gap_observed )
        event ICCP::stream_finished(
            c, is_orig, "non_exhaustive",
            "direction_non_exhaustive_after_gap");
    else if ( [c$uid, is_orig] in direction_parse_recovery_observed )
        event ICCP::stream_finished(
            c, is_orig, "non_exhaustive",
            "direction_non_exhaustive_after_parse_error");
    else if ( [c$uid, is_orig] in direction_incomplete_record_observed )
        event ICCP::stream_finished(
            c, is_orig, "non_exhaustive",
            "direction_non_exhaustive_after_incomplete_record");
    }

event connection_state_remove(c: connection) &priority=-10
    {
    # Packet::%init is delivered while bytes are parsed, even when a no-FIN
    # capture ends before the child can reach %done/%finally. Require an
    # earlier complete record so an isolated partial candidate remains an
    # ordinary unconfirmed reject rather than a misleading truncation verdict.
    if ( [c$uid, T] in direction_record_in_progress &&
         [c$uid, T] in direction_complete_record_observed )
        mark_stream_incomplete(c, T);
    if ( [c$uid, F] in direction_record_in_progress &&
         [c$uid, F] in direction_complete_record_observed )
        mark_stream_incomplete(c, F);

    # A successfully committed recovery verifies the records emitted after it;
    # it cannot prove that every message spanning or following missing bytes was
    # observable. Emit a durable terminal verdict for consumers that require
    # exhaustive direction-level output.
    emit_terminal_incompleteness(c, T);
    emit_terminal_incompleteness(c, F);

    }

# Queue teardown only after every connection_state_remove handler has had an
# opportunity to publish its own terminal events. Zeek drains nested events in
# FIFO order after the outer event finishes, so both stream summaries and any
# later teardown observations run before this UID-only cleanup.
event connection_state_remove(c: connection) &priority=-100
    {
    event ICCP::stream_connection_cleanup_v1(c$uid);
    }

event ICCP::stream_connection_cleanup_v1(uid: string)
    {
    delete current_output_completeness[uid, T];
    delete current_output_completeness[uid, F];
    delete malformed_recovery_reported[uid, T];
    delete malformed_recovery_reported[uid, F];
    delete direction_gap_observed[uid, T];
    delete direction_gap_observed[uid, F];
    delete direction_parse_recovery_observed[uid, T];
    delete direction_parse_recovery_observed[uid, F];
    delete direction_incomplete_record_observed[uid, T];
    delete direction_incomplete_record_observed[uid, F];
    delete direction_record_in_progress[uid, T];
    delete direction_record_in_progress[uid, F];
    delete direction_complete_record_observed[uid, T];
    delete direction_complete_record_observed[uid, F];
    }
