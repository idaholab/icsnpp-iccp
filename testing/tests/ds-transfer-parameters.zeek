# @TEST-DOC: Validate supported DSTransferSet Start/Stop parameters,
# @TEST-DOC: propagation onto replies, and fail-closed malformed candidates.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut action outcome invoke_id list_scope list_domain list_name named_type data_set_scope data_set_domain data_set_name start_time transfer_interval tle buffer_time integrity_check conditions condition_mask block_data critical report_by_exception all_changes_reported enabled event_code_requested conformance conformance_reasons provenance < iccp_transfers.log | grep -v '^type_discovery' > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: grep '^anomaly' .stdout > anomalies
# @TEST-EXEC: btest-diff anomalies

redef ICCP::legacy_gva_direct_event_compatibility = T;

event ICCP::dst_transfer_set_anomaly(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, invoke_id: int, object_scope: string,
    object_domain: string, object_name: string, classification: string,
    conformance: string, reasons: string)
    {
    print fmt("anomaly legacy invoke=%d object=%s/%s/%s classification=%s conformance=%s reasons=%s",
              invoke_id, object_scope, object_domain, object_name,
              classification, conformance, reasons);
    }

event ICCP::dst_transfer_set_anomaly_v2(
    c: connection, is_orig: bool, association_kind: string,
    endpoint_role: string, invoke_id: int, object_scope: string,
    object_domain: string, object_name: string, classification: string,
    conformance: string, reasons: string, provenance: string)
    {
    print fmt("anomaly v2 invoke=%d object=%s/%s/%s classification=%s conformance=%s reasons=%s provenance=%s",
              invoke_id, object_scope, object_domain, object_name,
              classification, conformance, reasons, provenance);
    }

function ds_integer_values(interval_value: int): vector of int
    {
    local values: vector of int = vector();
    values[0] = 0;
    values[1] = 1700000000;
    values[2] = interval_value;
    values[3] = 5;
    values[4] = 2;
    values[5] = 3600;
    values[6] = 0;
    values[7] = 0;
    values[8] = 0;
    values[9] = 0;
    values[10] = 0;
    values[11] = 0;
    values[12] = 7;
    return values;
    }

function ds_component_raws(conditions: string, enabled: string): vector of string
    {
    return vector("", "\x65\x53\xf1\x00", "\x3c", "\x05", "\x02",
                  "\x0e\x10", conditions, "\x00", "\xff", "\xff",
                  "\x00", enabled, "\x07");
    }

event zeek_init() &priority=-5
    {
    local c: connection = [
        $id=[$orig_h=192.0.2.10, $orig_p=49152/tcp,
             $resp_h=192.0.2.20, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs, $service=set("iccp"),
        $history="", $uid="Cdsparams"
    ];
    local choices = vector(2, 5, 5, 5, 5, 5, 4, 3, 3, 3, 3, 3, 5);
    local data_set_choices = vector(6, 10, 10);
    local data_set_values: vector of int = vector();
    data_set_values[0] = 0;
    data_set_values[1] = 0;
    data_set_values[2] = 0;

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
        c, T, 0, 20, 0, 1, 0, "", "Supported_Features", 1,
        0, 0, 0, "", 0, 0, 0, 0, 0, 0, 1);
    event ICCP::mms_read_message_v3(
        c, F, 1, 20, 0, 0, 0, "", "", 0,
        1, 0, 4, "\x04\xa0", 0, 0, 0, 0, 0, 0, 1);

    # Learn the exact named type for one normative ICC variable and one
    # deliberately nonconformant VCC variable.
    ICCP::configured_variable_types[
        c$id$resp_h, c$id$orig_h, 1, "CONTROL_CENTER_B", "TS_TYPED"] =
            "DSTransferSet";
    ICCP::configured_variable_types[
        c$id$resp_h, c$id$orig_h, 0, "", "TS_VCC"] =
            "DSTransferSet";
    event ICCP::mms_variable_type_message(
        c, T, 0, 1, 6, 1, "CONTROL_CENTER_B", "TS_TYPED", 0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, F, 1, 1, 6, 0, "", "", 0, 0, "", "DSTransferSet");
    event ICCP::mms_variable_type_message(
        c, T, 0, 2, 6, 0, "", "TS_VCC", 0, 0, "", "");
    event ICCP::mms_variable_type_message(
        c, F, 1, 2, 6, 0, "", "", 0, 0, "", "DSTransferSet");

    # Exact Start Transfer: external-event request makes EventCode meaningful.
    event ICCP::mms_ds_transfer_set_message_v1(
        c, T, 0, 10, 5, 0, 1, "CONTROL_CENTER_B", "TS_TYPED", 1, 1, 2,
        choices, ds_component_raws("\x03\xa8", "\xff"),
        ds_integer_values(60), data_set_choices,
        vector("\x00", "IGNORED", "DATA_SET"), data_set_values, 0);
    event ICCP::mms_transfer_control_message(
        c, F, 1, 10, 5, 0, 0, "", "", 0, 0, 0, F,
        0, 0, F, F, 1, 1, 0);

    # Exact Stop Transfer without OtherExternalEvent: the encoded event-code
    # slot exists in the named type but is intentionally not logged as active.
    event ICCP::mms_ds_transfer_set_message_v1(
        c, T, 0, 11, 5, 0, 1, "CONTROL_CENTER_B", "TS_TYPED", 1, 1, 2,
        choices, ds_component_raws("\x03\x20", "\x00"),
        ds_integer_values(60), data_set_choices,
        vector("\x00", "IGNORED", "DATA_SET"), data_set_values, 0);
    event ICCP::mms_error_message(c, F, 2, 11, -1, 7, 3, -1, "");

    # BER and 503 permit every nonzero one-octet TRUE value. The request stays
    # standards-conformant; the successful response is separately flagged as
    # a duplicate Start because the prior transfer remains active.
    event ICCP::mms_ds_transfer_set_message_v1(
        c, T, 0, 12, 5, 0, 1, "CONTROL_CENTER_B", "TS_TYPED", 1, 1, 2,
        choices,
        vector("", "\x65\x53\xf1\x00", "\x3c", "\x05", "\x02",
               "\x0e\x10", "\x03\xa8", "\x00", "\x01", "\x01",
               "\x00", "\x01", "\x07"),
        ds_integer_values(60), data_set_choices,
        vector("\x00", "IGNORED", "DATA_SET"), data_set_values, 0);
    event ICCP::mms_transfer_control_message(
        c, F, 1, 12, 5, 0, 0, "", "", 0, 0, 0, F,
        0, 0, F, F, 1, 1, 0);

    # Wrong unused-bit count, negative interval, malformed ObjectName, and a
    # VCC-scoped transfer variable all remain visible but are never promoted.
    event ICCP::mms_ds_transfer_set_message_v1(
        c, T, 0, 20, 5, 0, 1, "CONTROL_CENTER_B", "TS_TYPED", 1, 1, 2,
        choices, ds_component_raws("\x00\xa8", "\xff"),
        ds_integer_values(60), data_set_choices,
        vector("\x00", "IGNORED", "DATA_SET"), data_set_values, 0);
    event ICCP::mms_ds_transfer_set_message_v1(
        c, T, 0, 21, 5, 0, 1, "CONTROL_CENTER_B", "TS_TYPED", 1, 1, 2,
        choices, ds_component_raws("\x03\xa8", "\xff"),
        ds_integer_values(-1), data_set_choices,
        vector("\x00", "IGNORED", "DATA_SET"), data_set_values, 0);
    event ICCP::mms_ds_transfer_set_message_v1(
        c, T, 0, 22, 5, 0, 1, "CONTROL_CENTER_B", "TS_TYPED", 1, 1, 2,
        choices, ds_component_raws("\x03\xa8", "\xff"),
        ds_integer_values(60), data_set_choices,
        vector("\x00", "IGNORED", "bad-name"), data_set_values, 0);
    event ICCP::mms_ds_transfer_set_message_v1(
        c, T, 0, 23, 5, 0, 0, "", "TS_VCC", 1, 1, 2,
        choices, ds_component_raws("\x03\xa8", "\xff"),
        ds_integer_values(60), data_set_choices,
        vector("\x00", "IGNORED", "DATA_SET"), data_set_values, 0);
    event ICCP::mms_ds_transfer_set_message_v1(
        c, T, 0, 24, 5, 0, 1, "CONTROL_CENTER_B", "TS_TYPED", 1, 1, 2,
        choices, ds_component_raws("\x03", "\xff"),
        ds_integer_values(60), data_set_choices,
        vector("\x00", "IGNORED", "DATA_SET"), data_set_values, 0);
    }
