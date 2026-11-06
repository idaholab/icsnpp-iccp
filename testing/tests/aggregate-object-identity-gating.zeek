# @TEST-DOC: Aggregate MMS object identity is populated only by an actual
# @TEST-DOC: ObjectName-bearing variable access. GetNameList return identifiers
# @TEST-DOC: stay in dedicated name-list rows, and a named-list Write selector
# @TEST-DOC: stays in dedicated ordered Write evidence. Canonical positive
# @TEST-DOC: Info_Buff_N names are standardized at VMD/Domain scope; zero,
# @TEST-DOC: leading-zero, over-cap, and AA variants remain private/unknown.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap input.pcap direct-mms-aggregate-identity
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap input-copy.pcap direct-mms-aggregate-identity
# @TEST-EXEC: cmp input.pcap input-copy.pcap
# @TEST-EXEC: zeek -Cr input.pcap ${PACKAGE}/__load__.zeek %INPUT > alerts
# @TEST-EXEC: zeek-cut invoke_id object_scope object_domain object_name object_category name_model provenance < iccp.log | grep 'Info_Buff' > objects
# @TEST-EXEC: zeek-cut observation_kind invoke_id object_scope object_name result_index result_pairing_status provenance < iccp_objects.log | grep 'Vendor_Returned' > identifiers
# @TEST-EXEC: zeek-cut classification outcome invoke_id object_scope object_name access_choice target_count_known target_count value_count pairing_status provenance < iccp_controls.log | grep '^write_' > writes
# @TEST-EXEC: btest-diff alerts
# @TEST-EXEC: btest-diff objects
# @TEST-EXEC: btest-diff identifiers
# @TEST-EXEC: btest-diff writes

module ICCP;

event ICCP::unknown_object_access_v2(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, operation: string, invoke_id: int,
    object_scope: string, object_domain: string, object_name: string,
    name_model: string, provenance: string)
    {
    if ( /^Info_Buff/ in object_name || /^Vendor_/ in object_name )
        print fmt("unknown invoke=%d scope=%s domain=%s name=%s model=%s provenance=%s",
                  invoke_id, object_scope, object_domain, object_name,
                  name_model, provenance);
    }
