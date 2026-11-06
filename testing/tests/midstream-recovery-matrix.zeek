# @TEST-DOC: Exercise bounded midstream Presentation/MMS recovery with a valid
# @TEST-DOC: responder-side record, a malformed MMS lookalike followed by a
# @TEST-DOC: valid record, an ACSE-shaped non-MMS payload, a context identifier
# @TEST-DOC: contradicted by captured context state, and partial file boundaries,
# @TEST-DOC: including clean, viable-truncated, and already-invalid truncated
# @TEST-DOC: next-record boundaries.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap reverse.pcap direct-mms-midstream-reverse
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap malformed.pcap direct-mms-midstream-malformed
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap acse.pcap direct-mms-midstream-acse
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap unknown-context.pcap direct-mms-unknown-context
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap boundary.pcap direct-mms-capture-boundary
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap truncated.pcap direct-mms-truncated-tail
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap invalid-tail.pcap direct-mms-invalid-truncated-tail
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap clean.pcap direct-mms-midstream
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap reverse-copy.pcap direct-mms-midstream-reverse
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap malformed-copy.pcap direct-mms-midstream-malformed
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap acse-copy.pcap direct-mms-midstream-acse
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap unknown-context-copy.pcap direct-mms-unknown-context
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap boundary-copy.pcap direct-mms-capture-boundary
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap invalid-tail-copy.pcap direct-mms-invalid-truncated-tail
# @TEST-EXEC: cmp reverse.pcap reverse-copy.pcap
# @TEST-EXEC: cmp malformed.pcap malformed-copy.pcap
# @TEST-EXEC: cmp acse.pcap acse-copy.pcap
# @TEST-EXEC: cmp unknown-context.pcap unknown-context-copy.pcap
# @TEST-EXEC: cmp boundary.pcap boundary-copy.pcap
# @TEST-EXEC: cmp invalid-tail.pcap invalid-tail-copy.pcap
# @TEST-EXEC: mkdir reverse-run malformed-run acse-run unknown-context-run boundary-run truncated-run invalid-tail-run clean-run
# @TEST-EXEC: cd reverse-run && zeek -Cr ../reverse.pcap ${PACKAGE}/__load__.zeek %INPUT > ../reverse-events
# @TEST-EXEC: cd malformed-run && zeek -Cr ../malformed.pcap ${PACKAGE}/__load__.zeek %INPUT > ../malformed-events
# @TEST-EXEC: cd acse-run && zeek -Cr ../acse.pcap ${PACKAGE}/__load__.zeek %INPUT > ../acse-events
# @TEST-EXEC: cd unknown-context-run && zeek -Cr ../unknown-context.pcap ${PACKAGE}/__load__.zeek %INPUT > ../unknown-context-events
# @TEST-EXEC: cd boundary-run && zeek -Cr ../boundary.pcap ${PACKAGE}/__load__.zeek %INPUT > ../boundary-events
# @TEST-EXEC: cd truncated-run && zeek -Cr ../truncated.pcap ${PACKAGE}/__load__.zeek %INPUT > ../truncated-events
# @TEST-EXEC: cd invalid-tail-run && zeek -Cr ../invalid-tail.pcap ${PACKAGE}/__load__.zeek %INPUT > ../invalid-tail-events
# @TEST-EXEC: cd clean-run && zeek -Cr ../clean.pcap ${PACKAGE}/__load__.zeek %INPUT > ../clean-events
# @TEST-EXEC: test ! -e truncated-run/iccp_errors.log
# @TEST-EXEC: test ! -e clean-run/iccp_errors.log
# @TEST-EXEC: test "$(zeek-cut message_type status stream_completeness < truncated-run/iccp.log | grep -c '^direction_summary[[:space:]]non_exhaustive[[:space:]]direction_non_exhaustive_after_incomplete_record$' || true)" -eq 1
# @TEST-EXEC: test "$(zeek-cut message_type status stream_completeness < invalid-tail-run/iccp.log | grep -c '^direction_summary[[:space:]]non_exhaustive[[:space:]]direction_non_exhaustive_after_parse_error$' || true)" -eq 1
# @TEST-EXEC: test "$(zeek-cut message_type < clean-run/iccp.log | grep -c '^direction_summary$' || true)" -eq 0
# @TEST-EXEC: zeek-cut is_orig layer message_type status context_id abstract_syntax transfer_syntax invoke_id operation service_tag provenance stream_completeness < reverse-run/iccp.log | awk 'BEGIN { OFS="\t" } { print "reverse", $0 }' > output
# @TEST-EXEC: zeek-cut is_orig layer message_type status context_id abstract_syntax transfer_syntax invoke_id operation service_tag provenance stream_completeness < malformed-run/iccp.log | awk 'BEGIN { OFS="\t" } { print "malformed", $0 }' >> output
# @TEST-EXEC: zeek-cut is_orig layer message_type status context_id abstract_syntax transfer_syntax invoke_id operation service_tag provenance stream_completeness < acse-run/iccp.log | awk 'BEGIN { OFS="\t" } { print "acse", $0 }' >> output
# @TEST-EXEC: zeek-cut is_orig layer message_type status context_id abstract_syntax transfer_syntax invoke_id operation service_tag provenance stream_completeness < unknown-context-run/iccp.log | awk 'BEGIN { OFS="\t" } { print "unknown-context", $0 }' >> output
# @TEST-EXEC: zeek-cut is_orig layer message_type status context_id abstract_syntax transfer_syntax invoke_id operation service_tag provenance stream_completeness < boundary-run/iccp.log | awk 'BEGIN { OFS="\t" } { print "boundary", $0 }' >> output
# @TEST-EXEC: zeek-cut is_orig layer message_type status context_id abstract_syntax transfer_syntax invoke_id operation service_tag provenance stream_completeness < truncated-run/iccp.log | awk 'BEGIN { OFS="\t" } { print "truncated", $0 }' >> output
# @TEST-EXEC: zeek-cut is_orig layer message_type status context_id abstract_syntax transfer_syntax invoke_id operation service_tag provenance stream_completeness < invalid-tail-run/iccp.log | awk 'BEGIN { OFS="\t" } { print "invalid-tail", $0 }' >> output
# @TEST-EXEC: zeek-cut is_orig layer message_type status context_id abstract_syntax transfer_syntax invoke_id operation service_tag provenance stream_completeness < clean-run/iccp.log | awk 'BEGIN { OFS="\t" } { print "clean", $0 }' >> output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: awk 'BEGIN { OFS="\t" } { print "reverse", $0 }' reverse-events > events
# @TEST-EXEC: awk 'BEGIN { OFS="\t" } { print "malformed", $0 }' malformed-events >> events
# @TEST-EXEC: awk 'BEGIN { OFS="\t" } { print "acse", $0 }' acse-events >> events
# @TEST-EXEC: awk 'BEGIN { OFS="\t" } { print "unknown-context", $0 }' unknown-context-events >> events
# @TEST-EXEC: awk 'BEGIN { OFS="\t" } { print "boundary", $0 }' boundary-events >> events
# @TEST-EXEC: awk 'BEGIN { OFS="\t" } { print "truncated", $0 }' truncated-events >> events
# @TEST-EXEC: awk 'BEGIN { OFS="\t" } { print "invalid-tail", $0 }' invalid-tail-events >> events
# @TEST-EXEC: awk 'BEGIN { OFS="\t" } { print "clean", $0 }' clean-events >> events
# @TEST-EXEC: btest-diff events

module ICCP;

# Seed unmistakable state after ordinary connection-removal handlers but
# before completeness publishes its terminal verdict. The deferred UID-only
# cleanup must leave this state visible to stream_finished, then remove all of
# it before zeek_done. These checks stay silent on success so the protocol
# output remains the regression baseline.
event connection_state_remove(c: connection) &priority=-5
    {
    local state = current_state(c);
    state$phase = "terminal_cleanup_sentinel";
    associations[c$uid] = state;
    state_acse_lifecycle_spdu[c$uid, T] = 255;
    state_presentation_spdu[c$uid, F] = 255;
    }

event ICCP::stream_finished(
    c: connection, is_orig: bool, status: string,
    terminal_completeness: string) &priority=100
    {
    if ( c$uid !in associations ||
         associations[c$uid]$phase != "terminal_cleanup_sentinel" ||
         [c$uid, T] !in state_acse_lifecycle_spdu ||
         [c$uid, F] !in state_presentation_spdu )
        print "terminal summary observed state after premature cleanup";
    }

event zeek_done()
    {
    if ( |associations| != 0 ||
         |state_acse_lifecycle_spdu| != 0 ||
         |state_presentation_spdu| != 0 ||
         |current_output_completeness| != 0 ||
         |malformed_recovery_reported| != 0 ||
         |direction_gap_observed| != 0 ||
         |direction_parse_recovery_observed| != 0 ||
         |direction_incomplete_record_observed| != 0 ||
         |direction_record_in_progress| != 0 ||
         |direction_complete_record_observed| != 0 )
        print "terminal cleanup left connection lifecycle state behind";
    }

event ICCP::malformed_structure_v2(
    c: connection, reason: string, provenance: string)
    {
    print fmt("malformed bounded=%s reason_present=%s provenance=%s",
              |reason| <= 256, |reason| > 0, provenance);
    }
