# @TEST-DOC: Activate every supported configured TASE.2 type only when a
# @TEST-DOC: verified, direction-correlated GVA response carries the exact
# @TEST-DOC: recursive TypeDescription, mmsDeletable FALSE, and IEC-valid
# @TEST-DOC: ObjectName scope. Mismatches revoke stale exact state; unresolved
# @TEST-DOC: nested typeName and inferred parser evidence never learn.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT > state
# @TEST-EXEC: btest-diff state
# @TEST-EXEC: zeek-cut action outcome list_scope list_domain list_name named_type conformance_reasons < iccp_transfers.log > outcomes
# @TEST-EXEC: btest-diff outcomes

module ICCP;

function make_type_connection(): connection
    {
    return [
        $id=[$orig_h=192.0.2.111, $orig_p=49152/tcp,
             $resp_h=192.0.2.112, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Ctype-exact"
    ];
    }

function seed_type_tase2(c: connection)
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

event inspect_exact_type(c: connection, label: string, scope: count,
                         domain: string, name: string) &priority=-20
    {
    local learned = learned_variable_type_name(c, F, scope, domain, name);
    print fmt("%s scope=%d domain=%s object=%s learned=%s",
              label, scope, domain == "" ? "-" : domain, name,
              learned == "" ? "-" : learned);
    }

function emit_gva(
    c: connection, invoke_id: int, scope: count, domain: string,
    object_name: string, signature: TypeDescriptionSignature,
    deletable: bool, resolved: bool, unresolved: count,
    request_provenance: count, response_provenance: count,
    label: string)
    {
    local empty = empty_type_description_signature();
    event mms_gva_message_v3(
        c, T, 0, invoke_id, scope, domain, object_name,
        F, F, T, 0, empty$choices, empty$primary, empty$secondary,
        empty$child_counts, empty$packed, "", 0, 0,
        request_provenance);
    event mms_gva_message_v3(
        c, F, 1, invoke_id, 0, "", "", T, deletable, resolved,
        unresolved, signature$choices, signature$primary,
        signature$secondary, signature$child_counts, signature$packed,
        "", |signature$choices|, 4, response_provenance);
    event inspect_exact_type(c, label, scope, domain, object_name);
    }

event zeek_init()
    {
    local c = make_type_connection();
    seed_type_tase2(c);

    local names = vector(
        "DSTransferSet", "DSConditions", "Control_Command",
        "Control_Setpoint_Real", "Control_Setpoint_Discrete",
        "SBO_CheckBackName", "Tag_Value", "Data_Real", "Data_Discrete",
        "Data_State", "Data_StateSupplemental", "Data_RealQ",
        "Data_StateQ", "Data_StateSupplementalQ", "Data_DiscreteQ",
        "Data_RealQTimeTag", "Data_StateQTimeTag",
        "Data_StateSupplementalQTimeTag", "Data_DiscreteQTimeTag",
        "Data_RealExtended", "Data_StateExtended",
        "Data_StateSupplementalExtended", "Data_DiscreteExtended",
        "Data_RealQTimeTagExtended", "Data_StateQTimeTagExtended",
        "Data_StateSupplementalQTimeTagExtended",
        "Data_DiscreteQTimeTagExtended");
    local index: count = 0;
    local invoke_id: int = 1;
    while ( index < |names| )
        {
        local named_type = names[index];
        local scope: count = named_type == "DSTransferSet" ||
                             named_type == "DSConditions" ? 1 : 0;
        local domain = scope == 1 ? "CONTROL_CENTER_B" : "";
        local object_name = named_type == "DSConditions" ?
            "DSConditions_Detected" : fmt("TYPE_%d", index + 1);
        configured_variable_types[
            c$id$resp_h, c$id$orig_h, scope, domain, object_name] =
                named_type;
        emit_gva(c, invoke_id, scope, domain, object_name,
                 expected_tase2_type_signature(named_type), F, T, 0,
                 1, 1, fmt("exact-%s", named_type));
        ++index;
        ++invoke_id;
        }

    # Every standardized mapping rejects AA-specific scope. DSTransferSet is
    # additionally Domain-only, and DSConditions has a fixed Domain name.
    configured_variable_types[
        c$id$resp_h, c$id$orig_h, 2, "", "AA_REAL"] = "Data_Real";
    emit_gva(c, 100, 2, "", "AA_REAL",
             expected_tase2_type_signature("Data_Real"), F, T, 0,
             1, 1, "invalid-aa");
    configured_variable_types[
        c$id$resp_h, c$id$orig_h, 0, "", "VMD_DST"] = "DSTransferSet";
    emit_gva(c, 101, 0, "", "VMD_DST",
             expected_tase2_type_signature("DSTransferSet"), F, T, 0,
             1, 1, "invalid-dst-scope");
    configured_variable_types[
        c$id$resp_h, c$id$orig_h, 1, "CONTROL_CENTER_B", "OTHER"] =
            "DSConditions";
    emit_gva(c, 102, 1, "CONTROL_CENTER_B", "OTHER",
             expected_tase2_type_signature("DSConditions"), F, T, 0,
             1, 1, "invalid-conditions-name");

    # A contradictory later response removes a previously trusted exact type.
    configured_variable_types[
        c$id$resp_h, c$id$orig_h, 0, "", "STALE"] = "Data_Real";
    local real = expected_tase2_type_signature("Data_Real");
    emit_gva(c, 110, 0, "", "STALE", real, F, T, 0,
             1, 1, "stale-before");
    local wrong_real = expected_tase2_type_signature("Data_Real");
    wrong_real$primary[0] = 64;
    emit_gva(c, 111, 0, "", "STALE", wrong_real, F, T, 0,
             1, 1, "stale-after-mismatch");

    local unresolved_signature = empty_type_description_signature();
    unresolved_signature = append_type_description_node(
        unresolved_signature, 0, 0, 0, 0, F);
    unresolved_signature = append_type_description_node(
        unresolved_signature, 1, 1, 0, 1, F);
    configured_variable_types[
        c$id$resp_h, c$id$orig_h, 0, "", "UNRESOLVED"] = "Data_RealQ";
    emit_gva(c, 112, 0, "", "UNRESOLVED", unresolved_signature,
             F, F, 1, 1, 1, "nested-type-name");

    configured_variable_types[
        c$id$resp_h, c$id$orig_h, 0, "", "DELETABLE"] = "Data_Real";
    emit_gva(c, 113, 0, "", "DELETABLE", real, T, T, 0,
             1, 1, "deletable-true");

    local packed = expected_tase2_type_signature("Data_RealQ");
    packed$packed[|packed$packed| - 1] = T;
    configured_variable_types[
        c$id$resp_h, c$id$orig_h, 0, "", "PACKED"] = "Data_RealQ";
    emit_gva(c, 114, 0, "", "PACKED", packed, F, T, 0,
             1, 1, "packed-mismatch");

    # Inferred response evidence retires the verified pending request without
    # changing the already learned type. Reusing the invoke then succeeds.
    configured_variable_types[
        c$id$resp_h, c$id$orig_h, 0, "", "INFERRED"] = "Data_Real";
    emit_gva(c, 120, 0, "", "INFERRED", real, F, T, 0,
             1, 1, "inferred-initial");
    emit_gva(c, 121, 0, "", "INFERRED", wrong_real, F, T, 0,
             1, 2, "inferred-terminal");
    emit_gva(c, 121, 0, "", "INFERRED", real, F, T, 0,
             1, 1, "inferred-reuse");
    }
