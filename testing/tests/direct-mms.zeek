# @TEST-DOC: Verify connection-scoped CP/CPA correlation across TCP directions,
# @TEST-DOC: accepted bidirectional direct MMS, rejected non-dispatch, unmatched
# @TEST-DOC: result recovery, and capture-started-midstream inference.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap negotiated.pcap direct-mms-negotiated
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap rejected.pcap direct-mms-rejected
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap unmatched.pcap direct-mms-unmatched
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap midstream.pcap direct-mms-midstream
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap negotiated-copy.pcap direct-mms-negotiated
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap rejected-copy.pcap direct-mms-rejected
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap unmatched-copy.pcap direct-mms-unmatched
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap midstream-copy.pcap direct-mms-midstream
# @TEST-EXEC: cmp negotiated.pcap negotiated-copy.pcap
# @TEST-EXEC: cmp rejected.pcap rejected-copy.pcap
# @TEST-EXEC: cmp unmatched.pcap unmatched-copy.pcap
# @TEST-EXEC: cmp midstream.pcap midstream-copy.pcap
# @TEST-EXEC: mkdir negotiated-run rejected-run unmatched-run midstream-run
# @TEST-EXEC: cd negotiated-run && zeek -Cr ../negotiated.pcap ${PACKAGE}/__load__.zeek %INPUT > ../legacy-negotiated
# @TEST-EXEC: cd rejected-run && zeek -Cr ../rejected.pcap ${PACKAGE}/__load__.zeek %INPUT > ../legacy-rejected
# @TEST-EXEC: cd unmatched-run && zeek -Cr ../unmatched.pcap ${PACKAGE}/__load__.zeek %INPUT > ../legacy-unmatched
# @TEST-EXEC: cd midstream-run && zeek -Cr ../midstream.pcap ${PACKAGE}/__load__.zeek %INPUT > ../legacy-midstream
# @TEST-EXEC: zeek-cut is_orig layer message_type status context_id abstract_syntax transfer_syntax association_kind association_phase operation service_tag provenance < negotiated-run/iccp.log > output
# @TEST-EXEC: zeek-cut is_orig layer message_type status context_id abstract_syntax transfer_syntax association_kind association_phase operation service_tag provenance < rejected-run/iccp.log >> output
# @TEST-EXEC: zeek-cut is_orig layer message_type status context_id abstract_syntax transfer_syntax association_kind association_phase operation service_tag provenance < unmatched-run/iccp.log >> output
# @TEST-EXEC: zeek-cut is_orig layer message_type status context_id abstract_syntax transfer_syntax association_kind association_phase operation service_tag provenance < midstream-run/iccp.log >> output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff legacy-negotiated
# @TEST-EXEC: btest-diff legacy-rejected
# @TEST-EXEC: btest-diff legacy-unmatched
# @TEST-EXEC: btest-diff legacy-midstream

global legacy_presentation_events: count = 0;

event ICCP::presentation_message(
    c: connection, is_orig: bool, recognized: bool, ppdu_type: count,
    context_id: count, abstract_syntax: string, transfer_syntax: string,
    dispatch_acse: bool, payload_length: count)
    {
    ++legacy_presentation_events;
    }

event zeek_done()
    {
    print legacy_presentation_events;
    }
