# @TEST-DOC: Generate deterministic release and abort lifecycle traffic and
# @TEST-DOC: verify terminal ACSE APDUs traverse the real Zeek TCP analyzer
# @TEST-DOC: with their Session lifecycle context available before ACSE policy.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap release.pcap release
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap abort.pcap abort
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap release-copy.pcap release
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap abort-copy.pcap abort
# @TEST-EXEC: cmp release.pcap release-copy.pcap
# @TEST-EXEC: cmp abort.pcap abort-copy.pcap
# @TEST-EXEC: mkdir release-run abort-run
# @TEST-EXEC: cd release-run && zeek -Cr ../release.pcap ${PACKAGE}/__load__.zeek
# @TEST-EXEC: cd abort-run && zeek -Cr ../abort.pcap ${PACKAGE}/__load__.zeek
# @TEST-EXEC: zeek-cut layer message_type status association_phase reason diagnostic_code < release-run/iccp.log > output
# @TEST-EXEC: zeek-cut layer message_type status association_phase reason diagnostic_code < abort-run/iccp.log >> output
# @TEST-EXEC: btest-diff output

module ICCP;

# This assertion intentionally runs before the production ACSE handlers.  It
# catches a lifecycle marker emitted by a competing APDU %done hook: that
# ordering can change between incremental and clean Spicy generation.  A
# parser %init marker must always have been delivered before acse_message.
event ICCP::acse_message(
    c: connection, is_orig: bool, recognized: bool, apdu_type: count,
    application_context: string, association_result: int, reason: int,
    diagnostic_code: int, authentication_present: bool,
    authentication_length: count, is_opaque: bool, dispatch_mms: bool,
    payload_length: count) &priority=100
    {
    if ( recognized && [c$uid, is_orig] !in state_acse_lifecycle_spdu )
        print fmt("missing ACSE lifecycle context for APDU %d", apdu_type);
    }
