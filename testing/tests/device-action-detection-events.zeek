# @TEST-DOC: Publish device_action_v2 only for supported device-action
# @TEST-DOC: notifications; candidates remain in the control log and do not
# @TEST-DOC: create high-confidence detection events.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT > output
# @TEST-EXEC: btest-diff output

module ICCP;

redef ICCP::enable_iccp_log = F;
redef ICCP::enable_iccp_objects_log = F;
redef ICCP::enable_iccp_transfers_log = F;
redef ICCP::enable_iccp_controls_log = F;
redef ICCP::enable_iccp_errors_log = F;

event ICCP::device_action_v2(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, classification: string, outcome: string,
    enrollment_scope: string, enrollment_domain: string,
    enrollment_name: string, condition_name: string, provenance: string)
    {
    print fmt("device_action kind=%s role=%s classification=%s outcome=%s enrollment=%s/%s/%s condition=%s provenance=%s",
        association_kind, endpoint_role, classification, outcome,
        enrollment_scope, enrollment_domain, enrollment_name,
        condition_name, provenance);
    }

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.201, $orig_p=49152/tcp,
             $resp_h=192.0.2.202, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Cdevice-alerts"
    ];
    event ICCP::presentation_message_v2(
        c, T, T, 2, 3, "2.2.1.0.1", "2.1.1", T, F, F, 32);
    event ICCP::acse_message(
        c, T, T, 0, "1.3.6.1.4.1", -1, -1, -1,
        F, 0, F, T, 24);
    event ICCP::acse_message(
        c, F, T, 1, "1.3.6.1.4.1", 0, -1, 0,
        F, 0, F, T, 24);
    event ICCP::mms_message(
        c, T, T, 8, T, 16, -1, 0, 0, F, 0, "\x00", "\x01",
        0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    # Establish affirmative TASE.2 evidence with a successful, correlated
    # Read of the mandatory Supported_Features object.  A standardized name
    # in a GetVariableAccessAttributes request is only an unverified peer
    # claim and must not promote the association.
    event ICCP::mms_read_message_v3(
        c, T, 0, 8, 0, 1, 0, "", "Supported_Features", 1,
        0, 0, 0, "", 0, 0, 0, 0, 0, 0, 1);
    event ICCP::mms_read_message_v3(
        c, F, 1, 8, 0, 0, 0, "", "", 0,
        1, 0, 4, "\x04\xa0", 0, 0, 0, 0, 0, 0, 1);
    event ICCP::mms_device_action_message_v1(
        c, F, 0, "", "ENROLL1", 0, "", "BREAKER_fail",
        0, T, 2, 2, "", -1, F, F, -1, F, 1);
    event ICCP::mms_device_action_message_v1(
        c, F, 0, "", "ENROLL1", 0, "", "BREAKER_fail",
        1, T, 2, 2, "", -1, F, F, -1, F, 1);
    }
