module ICCP_CORPUS_VALIDATION;

# This policy emits aggregate counters only.  It must never print connection
# identifiers, packet contents, object names, values, or parser diagnostics.

global counts: table[string] of count &default=0;

function count_provenance(event_name: string, provenance: string)
    {
    ++counts[fmt("%s.%s", event_name, provenance)];
    }

event ICCP::unknown_object_access_v2(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, operation: string, invoke_id: int,
    object_scope: string, object_domain: string, object_name: string,
    name_model: string, provenance: string)
    {
    count_provenance("alert.unknown_object_access", provenance);
    }

event ICCP::write_attempt_v2(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, invoke_id: int, object_scope: string,
    object_domain: string, object_name: string, variable_count: count,
    data_count: count, data_node_count: count, provenance: string)
    {
    count_provenance("alert.write_attempt", provenance);
    }

event ICCP::write_failure_v2(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, invoke_id: int, outcome: string,
    object_scope: string, object_domain: string, object_name: string,
    failure_count: count, error_class: string, error_code: int,
    provenance: string)
    {
    count_provenance("alert.write_failure", provenance);
    }

event ICCP::unexpected_service_v2(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, association_phase: string, invoke_id: int,
    service_tag: count, operation: string, provenance: string)
    {
    count_provenance("alert.unexpected_service", provenance);
    }

event ICCP::authenticated_association_rejected_v2(
    c: connection, response_is_orig: bool, request_is_orig: bool,
    authentication_length: count, association_result: int,
    diagnostic_code: int, provenance: string)
    {
    count_provenance("alert.authenticated_association_rejected", provenance);
    }

event ICCP::resource_limit_exceeded_v2(
    c: connection, is_orig: bool, resource: string, limit: count,
    current: count, invoke_id: int, provenance: string)
    {
    count_provenance("alert.resource_limit_exceeded", provenance);
    }

event ICCP::malformed_structure_v2(
    c: connection, reason: string, provenance: string)
    {
    count_provenance("alert.malformed_structure", provenance);
    }

event zeek_done()
    {
    local event_names = vector(
        "alert.unknown_object_access",
        "alert.write_attempt",
        "alert.write_failure",
        "alert.unexpected_service",
        "alert.authenticated_association_rejected",
        "alert.resource_limit_exceeded",
        "alert.malformed_structure"
    );
    local provenance_names = vector("verified", "inferred", "unknown");

    for ( event_index in event_names )
        for ( provenance_index in provenance_names )
            {
            local key = fmt("%s.%s", event_names[event_index],
                            provenance_names[provenance_index]);
            print fmt("%s=%d", key, counts[key]);
            }
    }
