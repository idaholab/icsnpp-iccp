# @TEST-DOC: A verified configured type establishes the agreement-defined name
# @TEST-DOC: of that exact endpoint-owned object even at VMD scope or in a
# @TEST-DOC: Domain not learned by bootstrap. The opposite endpoint and an
# @TEST-DOC: otherwise unverified name remain private/unknown and alert.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT > alerts
# @TEST-EXEC: zeek-cut is_orig object_scope object_domain object_name name_model domain_kind bilateral_domain < iccp.log | grep '^.*ATTR_' > objects
# @TEST-EXEC: btest-diff alerts
# @TEST-EXEC: btest-diff objects

module ICCP;

redef ICCP::legacy_gva_direct_event_compatibility = T;
redef ICCP::enable_iccp_objects_log = F;
redef ICCP::enable_iccp_transfers_log = F;
redef ICCP::enable_iccp_controls_log = F;
redef ICCP::enable_iccp_errors_log = F;

global attribution_alerts: set[int] = set();

function make_connection(): connection
    {
    return [
        $id=[$orig_h=192.0.2.211, $orig_p=49152/tcp,
             $resp_h=192.0.2.212, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid="Cknown-attribution"
    ];
    }

function establish_tase2(c: connection)
    {
    event ICCP::presentation_message_v2(
        c, T, T, 2, 3, "2.2.1.0.1", "2.1.1", T, F, F, 32);
    event ICCP::acse_message(
        c, T, T, 0, "1.0.9506.2.3", -1, -1, -1,
        F, 0, F, T, 24);
    event ICCP::mms_message(
        c, T, T, 8, T, 16, -1, 0, 0, F, 0, "\x00", "\x01",
        0, "", "", 0, F, 0, "", "", 0, 0, "", 0, 0, 0,
        0, 0, 0, 0, 0, 0.0, "", 0);
    event ICCP::acse_message(
        c, F, T, 1, "1.0.9506.2.3", 0, -1, 0,
        F, 0, F, T, 24);
    event ICCP::mms_read_message_v3(
        c, T, 0, 8, 0, 1, 0, "", "Supported_Features", 1,
        0, 0, 0, "", 0, 0, 0, 0, 0, 0, 1);
    event ICCP::mms_read_message_v3(
        c, F, 1, 8, 0, 0, 0, "", "", 0,
        1, 0, 4, "\x04\xa0", 0, 0, 0, 0, 0, 0, 1);
    }

function learn_type(c: connection, invoke_id: int, scope: count,
                    domain: string, object_name: string,
                    named_type: string)
    {
    configured_variable_types[
        c$id$resp_h, c$id$orig_h, scope, domain, object_name] = named_type;
    event ICCP::mms_variable_type_message(
        c, T, 0, invoke_id, 6, scope, domain, object_name, 0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, F, 1, invoke_id, 6, 0, "", "", 0, 0, "", named_type);
    }

function probe(c: connection, request_is_orig: bool, invoke_id: int,
               scope: count, domain: string, object_name: string)
    {
    event ICCP::mms_message(
        c, request_is_orig, T, 0, T, 24, invoke_id, 6, 0,
        T, 4, "", "", scope, domain, object_name, 0, F,
        0, "", "", 0, 0, "", 0, 0, 0, 0, 0, 0, 0, 0,
        0.0, "", 0);
    }

event ICCP::unknown_object_access_v2(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, operation: string, invoke_id: int,
    object_scope: string, object_domain: string, object_name: string,
    name_model: string, provenance: string)
    {
    if ( /^ATTR_/ in object_name )
        add attribution_alerts[invoke_id];
    }

event zeek_done()
    {
    print fmt("alerts known_vmd=%s known_domain=%s wrong_endpoint=%s " +
              "unverified=%s total=%d",
              30 in attribution_alerts, 31 in attribution_alerts,
              32 in attribution_alerts, 33 in attribution_alerts,
              |attribution_alerts|);
    }

event zeek_init()
    {
    local c = make_connection();
    establish_tase2(c);

    learn_type(c, 10, 0, "", "ATTR_VMD", "Data_Discrete");
    learn_type(c, 11, 1, "CROSS_DOMAIN", "ATTR_DOMAIN", "Data_Real");

    probe(c, T, 30, 0, "", "ATTR_VMD");
    probe(c, T, 31, 1, "CROSS_DOMAIN", "ATTR_DOMAIN");
    probe(c, F, 32, 0, "", "ATTR_VMD");
    probe(c, T, 33, 1, "CROSS_DOMAIN", "ATTR_UNVERIFIED");
    }
