# @TEST-DOC: Verify complete GetNameList, ordered Write, and TypeDescription
# @TEST-DOC: parser evidence reaches bounded production logs with correlation.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut observation_kind invoke_id object_scope object_domain object_name object_class_choice object_class continue_after result_count logged_result_count omitted_result_count result_index more_follows result_pairing_status provenance < iccp_objects.log | grep '^name_list_' > objects
# @TEST-EXEC: zeek-cut classification outcome invoke_id object_scope object_domain object_name access_choice target_count_known target_count value_count logged_item_count omitted_item_count item_index pairing_status value_type value_raw value_raw_truncated integer_value boolean_value result_count success_count failure_count result_success result_error provenance < iccp_controls.log | grep '^write_' > controls
# @TEST-EXEC: zeek-cut action outcome invoke_id type_choice type_constructed type_raw type_raw_truncated type_packed type_number_of_elements type_component_count type_node_count type_maximum_depth provenance < iccp_transfers.log | grep '^type_description' > transfers
# @TEST-EXEC: btest-diff objects
# @TEST-EXEC: btest-diff controls
# @TEST-EXEC: btest-diff transfers

module ICCP;

redef ICCP::max_logged_information_report_results = 2;
redef ICCP::max_logged_result_raw_bytes = 2;

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.10, $orig_p=49152/tcp,
             $resp_h=192.0.2.20, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Cevidence"
    ];

    local empty_names: vector of string;
    event ICCP::mms_get_name_list_evidence_v1(
        c, T, 0, 10, 0, 0, 1, "CONTROL_CENTER_B", "CURSOR",
        0, empty_names, T, 1);
    event ICCP::mms_get_name_list_evidence_v1(
        c, F, 1, 10, 0, -1, 0, "", "",
        3, vector("POINT_A", "POINT_B", "POINT_C"), T, 1);

    local target_scopes: vector of count = vector(1, 1, 0);
    local target_domains: vector of string =
        vector("CONTROL_CENTER_B", "CONTROL_CENTER_B", "");
    local target_names: vector of string =
        vector("SETPOINT_A", "ENABLE_B", "LABEL_C");
    local choices: vector of count = vector(5, 3, 10);
    local raws: vector of string =
        vector("\x2a", "\xff", "long-value");
    local integers: vector of int = vector(-1, -1, -1);
    integers[0] = 42;
    integers[1] = 0;
    integers[2] = 0;
    local floats: vector of double = vector(0.0, 0.0, 0.0);
    local booleans: vector of bool = vector(F, T, F);
    local strings: vector of string = vector("", "", "long-value");
    local no_successes: vector of bool;
    local no_errors: vector of int;
    event ICCP::mms_write_evidence_v1(
        c, T, 0, 20, 0, 1, "CONTROL_CENTER_B", "SETPOINT_A",
        T, 3, 3, target_scopes, target_domains, target_names,
        choices, raws, integers, floats, booleans, strings,
        0, no_successes, no_errors, 1);

    local no_counts: vector of count;
    local no_strings: vector of string;
    local no_integers: vector of int;
    local no_floats: vector of double;
    local no_booleans: vector of bool;

    # Public event consumers must remain safe if another Zeek script emits
    # internally inconsistent vectors.  Summary success/failure totals are
    # intentionally omitted because the declared result count is unverifiable.
    event ICCP::mms_write_evidence_v1(
        c, F, 1, 21, 0, 0, "", "", F, 0, 0,
        no_counts, no_strings, no_strings, no_counts, no_strings,
        no_integers, no_floats, no_booleans, no_strings,
        3, vector(T), vector(-1), 1);
    local mismatched_errors: vector of int = vector(-1, -1, -1);
    mismatched_errors[0] = 7;
    mismatched_errors[1] = 8;
    mismatched_errors[2] = 9;
    event ICCP::mms_write_evidence_v1(
        c, F, 1, 22, 0, 0, "", "", F, 0, 0,
        no_counts, no_strings, no_strings, no_counts, no_strings,
        no_integers, no_floats, no_booleans, no_strings,
        1, vector(F, F, F), mismatched_errors, 1);

    event ICCP::mms_write_evidence_v1(
        c, F, 1, 20, 0, 0, "", "", F, 0, 0,
        no_counts, no_strings, no_strings, no_counts, no_strings,
        no_integers, no_floats, no_booleans, no_strings,
        3, vector(T, F, T), vector(-1, 7, -1), 1);

    event ICCP::mms_type_description_evidence_v1(
        c, F, 1, 30, 1, T, 0, F, 0, 0,
        "\x80\x01\xff\x81", T, 3, 0, 2, 2, 1);
    }
