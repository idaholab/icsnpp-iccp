# @TEST-DOC: IEC 60870-6-503 DSConditions specialization is restricted to the
# @TEST-DOC: exact Domain-specific DSConditions_Detected object. A configured
# @TEST-DOC: DSConditions alias at an arbitrary Domain name, VMD, or AA scope
# @TEST-DOC: remains generic MMS BitString evidence.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut object_scope object_domain object_name object_category point_type standardized_value < iccp.log | grep -E '(DSConditions_Detected|OTHER_CONDITIONS)' > output
# @TEST-EXEC: btest-diff output

module ICCP;

function condition_connection(): connection
    {
    return [
        $id=[$orig_h=192.0.2.121, $orig_p=49152/tcp,
             $resp_h=192.0.2.122, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Cconditions-scope"
    ];
    }

function seed_condition_tase2(c: connection)
    {
    local state = current_state(c);
    state$phase = "established";
    state$presentation_profile = T;
    state$acse_association = T;
    state$mms_negotiation = T;
    state$tase2_evidence = T;
    state$originator_known = T;
    state$originator_is_orig = T;
    associations[c$uid] = state;
    }

function condition_read(c: connection, invoke_id: int, scope: count,
                        domain: string, name: string, category: count)
    {
    event mms_message(
        c, T, T, 0, T, 20, invoke_id, 4, 0, T, 2, "", "",
        0, "", "", 0, F,
        scope, domain, name, category, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event mms_message(
        c, F, T, 1, T, 8, invoke_id, 4, 0, T, 2, "", "",
        0, "", "", 0, F,
        0, "", "", 0, 4, "\x03\xa8", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    }

event zeek_init()
    {
    local c = condition_connection();
    seed_condition_tase2(c);

    known_variable_types[
        c$uid, F, 1, "CONTROL_CENTER_B", "OTHER_CONDITIONS"] =
            "DSConditions";
    known_variable_types[
        c$uid, F, 0, "", "DSConditions_Detected"] = "DSConditions";
    known_variable_types[
        c$uid, F, 2, "", "DSConditions_Detected"] = "DSConditions";

    condition_read(c, 1, 1, "CONTROL_CENTER_B",
                   "DSConditions_Detected", 3);
    condition_read(c, 2, 1, "CONTROL_CENTER_B", "OTHER_CONDITIONS", 0);
    condition_read(c, 3, 0, "", "DSConditions_Detected", 0);
    condition_read(c, 4, 2, "", "DSConditions_Detected", 0);
    }
