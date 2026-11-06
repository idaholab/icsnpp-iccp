# @TEST-DOC: Cover the normative Data_StateQ named type and reserved
# @TEST-DOC: Event_Code_Detected transfer-support variable. TASE policy must
# @TEST-DOC: reject digit-leading identifiers without hiding generic MMS.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut object_name point_type state_value validity value_source normal_value timestamp_quality standardized_value < iccp_objects.log | grep -E '^(STATE_Q|BAD_STATE_Q)' > output
# @TEST-EXEC: zeek-cut action outcome invoke_id list_domain list_name named_type event_code_detected result_raw < iccp_transfers.log | grep -E '^(type_discovery|event_code_detected)' > inventory
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff inventory

module ICCP;

redef ICCP::legacy_gva_direct_event_compatibility = T;

function learn_type(c: connection, invoke_id: int, object_name: string,
                    named_type: string)
    {
    ICCP::configured_variable_types[
        c$id$resp_h, c$id$orig_h, 0, "", object_name] = named_type;
    event ICCP::mms_variable_type_message(
        c, T, 0, invoke_id, 6, 0, "", object_name, 0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, F, 1, invoke_id, 6, 0, "", "", 0, 0, "", named_type);
    }

function read_request(c: connection, invoke_id: int, object_name: string)
    {
    event ICCP::mms_message(
        c, T, T, 0, T, 24, invoke_id, 4, 0, T, 2, "", "",
        0, "", "", 0, F, 0, "", object_name, 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    }

function read_state_q(c: connection, invoke_id: int, object_name: string,
                      state_raw: string, marker: string)
    {
    local choices: vector of count = vector(4, 4);
    local raws: vector of string = vector(state_raw, "\x00\x36");
    local integers: vector of int = vector(-1, -1);
    integers[0] = 0;
    integers[1] = 0;
    local empty_choices: vector of count;
    local empty_raws: vector of string;
    local empty_integers: vector of int;
    event ICCP::mms_point_value_shape_v3(
        c, F, |marker|, choices, raws, integers, 0,
        empty_choices, empty_raws, empty_integers);
    event ICCP::mms_message(
        c, F, T, 1, T, 32, invoke_id, 4, 0, T, 2, "", "",
        0, "", "", 0, F, 0, "", "", 0, 2, marker, 0, 0, 0,
        2, 4, 4, 0, 0, 0.0, "\x00\x36", 0);
    }

function event_code(c: connection, invoke_id: int, domain: string,
                    raw: string, value: int)
    {
    event ICCP::mms_transfer_support_value_message(
        c, T, 0, invoke_id, 4, 1, domain, "Event_Code_Detected",
        0, 0, 0, "", 0, 0, 0, 0, 0, "", "");
    event ICCP::mms_transfer_support_value_message(
        c, F, 1, invoke_id, 4, 0, "", "", 1, 0, 5, raw,
        0, 0, 0, 0, value, "", "");
    }

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.10, $orig_p=49152/tcp,
             $resp_h=192.0.2.20, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Ctase-inventory"
    ];
    event ICCP::presentation_message_v2(
        c, T, T, 2, 3, "2.2.1.0.1", "2.1.1", T, F, F, 32);
    event ICCP::acse_message(
        c, T, T, 0, "1.0.9506.2.3", -1, -1, -1, F, 0, F, T, 24);
    event ICCP::mms_message(
        c, T, T, 8, T, 16, -1, 0, 0, F, 0, "\x00", "\x01",
        0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::acse_message(
        c, F, T, 1, "1.0.9506.2.3", 0, -1, 0, F, 0, F, T, 24);
    event ICCP::mms_read_message_v3(
        c, T, 0, 1, 0, 1, 0, "", "Supported_Features", 1,
        0, 0, 0, "", 0, 0, 0, 0, 0, 0, 1);
    event ICCP::mms_read_message_v3(
        c, F, 1, 1, 0, 0, 0, "", "", 0,
        1, 0, 4, "\x04\xa0", 0, 0, 0, 0, 0, 0, 1);

    learn_type(c, 10, "STATE_Q", "Data_StateQ");
    read_request(c, 20, "STATE_Q");
    read_state_q(c, 20, "STATE_Q", "\x00\xc0", "state-q");

    learn_type(c, 11, "BAD_STATE_Q", "Data_StateQ");
    read_request(c, 21, "BAD_STATE_Q");
    read_state_q(c, 21, "BAD_STATE_Q", "\x01\xc0", "bad-state-q");

    # The valid event code is decoded; a three-octet integer is rejected.
    event_code(c, 30, "CONTROL_CENTER_B", "\x07", 7);
    event_code(c, 31, "CONTROL_CENTER_B", "\x00\x00\x07", 7);

    # Both would remain visible to generic MMS policy, but neither may enter
    # TASE-specific correlation state because an Identifier starts with a digit.
    learn_type(c, 12, "1STATE", "Data_StateQ");
    event_code(c, 32, "1CONTROL_CENTER", "\x07", 7);
    }
