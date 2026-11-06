# @TEST-DOC: Classify the four supported Device action
# @TEST-DOC: EventNotifications only with exact TASE.2 association, object,
# @TEST-DOC: severity/state/loss, and action-result evidence. Preserve every
# @TEST-DOC: non-exact notification as an explicit candidate.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut classification outcome object_scope object_domain object_name event_enrollment_scope event_enrollment_domain event_enrollment_name severity current_state transition_time_kind transition_time_value notification_lost action_result_present provenance < iccp_controls.log > output
# @TEST-EXEC: btest-diff output

module ICCP;

function notify(c: connection, condition: string, condition_scope: count,
                severity: int, have_state: bool, state: int,
                lost: bool, action_result: bool)
    {
    event ICCP::mms_device_action_message_v1(
        c, F, 0, "", "ENROLL1", condition_scope, "", condition,
        severity, have_state, state, 1, "\x2a", 42, lost,
        F, -1, action_result, 1);
    }

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.190, $orig_p=49152/tcp,
             $resp_h=192.0.2.200, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Cdevice-actions"
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

    notify(c, "BREAKER_time", 0, 0, T, 2, F, F);
    notify(c, "BREAKER_reset", 0, 0, T, 2, F, F);
    notify(c, "BREAKER_success", 0, 0, T, 2, F, F);
    notify(c, "BREAKER_fail", 0, 0, T, 2, F, F);
    event ICCP::mms_device_action_message_v1(
        c, F, 1, "BILAT", "ENROLL2", 0, "", "PUMP_success",
        0, T, 2, 2, "", -1, F, F, -1, F, 1);

    notify(c, "BREAKER_success", 2, 0, T, 2, F, F);
    notify(c, "BREAKER_success", 0, 1, T, 2, F, F);
    notify(c, "BREAKER_success", 0, 0, F, -1, F, F);
    notify(c, "BREAKER_success", 0, 0, T, 1, F, F);
    notify(c, "BREAKER_success", 0, 0, T, 2, T, F);
    notify(c, "BREAKER_success", 0, 0, T, 2, F, T);
    notify(c, "BREAKER_other", 0, 0, T, 2, F, F);

    local mms_only: connection = [
        $id=[$orig_h=192.0.2.191, $orig_p=49153/tcp,
             $resp_h=192.0.2.200, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Cmms-device-action"
    ];
    notify(mms_only, "MOTOR_fail", 0, 0, T, 2, F, F);
    }
