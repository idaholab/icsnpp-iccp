# @TEST-DOC: Exercise a verified TASE.2 association and supported Device
# @TEST-DOC: Success EventNotification through TCP, TPKT, COTP, Session,
# @TEST-DOC: Presentation, MMS, provenance, and control logging.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap input.pcap direct-mms-device-action
# @TEST-EXEC: zeek -Cr input.pcap ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut classification outcome object_scope object_name event_enrollment_scope event_enrollment_name severity current_state transition_time_kind transition_time_value notification_lost action_result_present provenance stream_completeness < iccp_controls.log > output
# @TEST-EXEC: btest-diff output
