# Log Schema

The Malcolm-compatible schema begins with the Zeek `ICCP::Info` record written
to `iccp.log`. Standalone Zeek uses the same records and field meanings. The
authoritative type declarations are in `scripts/iccp_types.zeek`; this document
records the public field names, types, optionality, and compatibility rules.
The latest completed release-candidate schema gate matched all 277 documented
fields to their owning declarations across the five public ICCP log records.

The log path is `iccp`. One record is emitted for the completed analyzer stream
and for each completed Presentation, ACSE, or MMS value delivered through the
parser event interface. A direction that observes a TCP gap, parser recovery,
or a plausible capture-boundary-incomplete record after at least one valid
record also emits a terminal `direction_summary` record. For partial/no-FIN
captures, packet-start/completion state plus connection-removal fallback
provides this verdict even when suspended Spicy completion hooks do not run. A
dash in Zeek's ASCII output represents an unset optional field, not an empty
value observed on the wire.

## Connection and parser fields

| Field | Zeek type | Required | Meaning |
| --- | --- | --- | --- |
| `ts` | `time` | yes | Network time when the record is produced. |
| `uid` | `string` | yes | Zeek connection UID. |
| `id` | `conn_id` | yes | Originator/responder address and port tuple. Zeek writers may flatten this record into component columns. |
| `is_orig` | `bool` | yes | True when the parsed value travels from Zeek's connection originator. |
| `layer` | `string` | yes | Producing layer: `stream`, `presentation`, `acse`, or `mms`. |
| `message_type` | `string` | yes | `complete` for the completed stream record, `direction_summary` for a terminal non-exhaustive verdict, or the decimal parser-enum value for a layer PDU. Existing values are not renumbered. |
| `status` | `string` | yes | Decode/correlation outcome. Confirmed-service anomalies use `invoke_reused`, `ambiguous_response`, `direction_mismatch`, or `service_mismatch`; otherwise the layer-specific decoded/rejected status applies. |
| `payload_length` | `count` | yes | Length of the bounded payload or body represented by this record. |
| `detail` | `string` | no | Human-readable diagnostic, truncated to 256 bytes. It is not a stable machine-parsing field. |
| `provenance` | `string` | yes | Dispatch provenance for this record: `verified`, `inferred`, `unknown`, or `not_applicable`, as defined below. |
| `stream_completeness` | `string` | yes | Direction-scoped capture/recovery status for this record, as defined below. |

The stream `complete` record means the analyzer unit reached its normal parse
completion path. It is not an exhaustive-capture claim; that claim is governed
only by `stream_completeness` and any `direction_summary` record.

### Provenance values

`provenance` describes how the parser reached the MMS PDU that produced a
record. It does not assert that the association is TASE.2, that an object name
is standardized, or that all earlier packets in a correlated operation were
captured.

- `verified`: MMS was carried by a context-bound ACSE user-information EXTERNAL
  whose BER direct-reference and unique phase-eligible MMS-context
  indirect-reference validated, or by a direct Presentation context whose
  CP/CPA MMS/BER selection was accepted on this connection.
- `inferred`: bounded midstream recovery validated the complete Presentation
  envelope and complete MMS PDU, but the capture did not contain the earlier
  context negotiation.
- `unknown`: the source was a legacy/unversioned event or otherwise carried no
  parser provenance. Trust-sensitive consumers must not upgrade it.
- `not_applicable`: the record represents a non-MMS envelope or stream event.

Every `mms` row in `iccp.log` and every object, transfer, control, and error row
carries one of the first three values. A Presentation row that directly
dispatches MMS carries the same `verified` or `inferred` value; other
Presentation, ACSE, and stream rows use `not_applicable`.

### Stream-completeness values

`stream_completeness` is independent of MMS dispatch `provenance`. It describes
whether the parser has observed continuous bytes in this TCP direction and
whether a recovery trial has been structurally confirmed:

- `contiguous_observation`: no TCP gap or parser recovery has been observed
  since this direction's parser started. It does not assert that capture began
  at the TCP handshake or contains earlier association context.
- `gap_observed_unrecovered`: Zeek reported missing TCP sequence space and no
  later recovery candidate has yet been found.
- `recovery_scan_after_parse_error`: malformed captured bytes caused bounded
  synchronization scanning, but no later structural TPKT candidate has yet
  been found.
- `incomplete_record_observation`: at least one valid record was followed by
  the beginning of a plausible TPKT whose header or declared body did not
  finish before the capture boundary. This does not classify the wire bytes as
  malformed. The prior-complete-record requirement excludes an isolated
  partial candidate; a boundary immediately after the valid record starts no
  new child and remains `contiguous_observation`.
- `recovery_candidate_after_gap`: this record was emitted while trial-parsing
  the first structurally plausible TPKT after missing TCP bytes. The inner PDU
  may be complete, but the enclosing recovery trial has not yet committed.
- `recovery_candidate_after_parse_error`: the same trial state after malformed
  captured bytes rather than a reported TCP gap.
- `verified_recovery_after_gap`: a complete TPKT/COTP recovery trial after a
  gap committed successfully; later records in this direction carry this
  cumulative status.
- `verified_recovery_after_parse_error`: a complete recovery trial after
  malformed captured bytes committed successfully.
- `direction_non_exhaustive_after_gap`: terminal `direction_summary` verdict;
  one or more TCP gaps means the records emitted for this direction are not an
  exhaustive account, even if later records were structurally verified.
- `direction_non_exhaustive_after_parse_error`: terminal `direction_summary`
  verdict; parser recovery means the direction cannot make an exhaustive
  output claim even if later records were structurally verified.
- `direction_non_exhaustive_after_incomplete_record`: terminal
  `direction_summary` verdict; the capture ended inside a plausible TPKT after
  at least one complete record, without generating a malformed-protocol error.
  Connection removal can publish it for an OTH/no-FIN stream whose parser
  completion hooks did not run.
- `unknown`: the record came from a synthetic or legacy event path with no
  parser lifecycle evidence. Consumers must not treat it as contiguous.

The state is direction-scoped: an originator-side gap does not downgrade
responder-side records. A `verified_recovery_*` value verifies a recovered
record boundary; it does not promise that every PDU in the direction was
published. Trust-sensitive consumers must use the terminal
`direction_summary` verdict when they require exhaustive output. If a
direction has more than one terminal history, its summary uses the precedence
gap, then parse recovery, then incomplete record.

## Presentation and ACSE fields

| Field | Zeek type | Required | Meaning |
| --- | --- | --- | --- |
| `context_id` | `count` | no | Presentation context identifier when one is present. |
| `abstract_syntax` | `string` | no | Dotted abstract-syntax object identifier selected for the context. |
| `transfer_syntax` | `string` | no | Dotted transfer-syntax object identifier selected for the context. |
| `application_context` | `string` | no | Dotted ACSE application-context object identifier. |
| `association_result` | `int` | no | Wire-level AARE result value. |
| `reason` | `int` | no | Wire-level release or abort reason when decoded. |
| `diagnostic_code` | `int` | no | Wire-level association diagnostic value when decoded. |
| `authentication_present` | `bool` | yes | Whether ACSE authentication material was present; its value is never logged. |
| `authentication_length` | `count` | yes | Length of authentication material, without its content. |
| `is_opaque` | `bool` | yes | True when application user information is encrypted or otherwise opaque to the parser. |

## Association and operation fields

| Field | Zeek type | Required | Meaning |
| --- | --- | --- | --- |
| `association_kind` | `string` | yes | Current classification: `unknown`, `mms`, or `tase2`. |
| `association_phase` | `string` | yes | Bounded lifecycle phase from initial negotiation through release, abort, or MMS conclude. |
| `endpoint_role` | `string` | yes | Current endpoint role: `unknown`, `originator`, or `responder`. |
| `operation` | `string` | no | Stable lowercase MMS operation name. ICCP-relevant operations remain candidate mappings until profile evidence exists; `identify` is generic MMS diagnostic metadata. |
| `transfer_kind` | `string` | no | Value-delivery path: `read_response` or the established first-result label `information_report`; additional report rows live in `iccp_objects.log`. |
| `invoke_id` | `int` | no | MMS confirmed-service invocation identifier. |
| `service_tag` | `count` | no | Wire-level confirmed or unconfirmed MMS service tag. |
| `identify_outcome` | `string` | no | Identify correlation status: `requested`, `matched_response`, `unmatched_response`, `invoke_reused`, `ambiguous_response`, `direction_mismatch`, `service_mismatch`, or `state_limit`. |
| `vendor_name` | `string` | no | MMS Identify vendor name, capped at 256 bytes for logging. It is generic device identity, not TASE.2 evidence. |
| `model_name` | `string` | no | MMS Identify implementation model, capped at 256 bytes. |
| `revision` | `string` | no | MMS Identify implementation revision, capped at 256 bytes. |
| `abstract_syntax_count` | `count` | no | Number of OIDs in the optional bounded Identify abstract-syntax list. Zero is an observed empty/absent list on a decoded Identify record. |
| `first_abstract_syntax` | `string` | no | First decoded OID from that list when present; the full list is summarized by count. |

## Object and value fields

| Field | Zeek type | Required | Meaning |
| --- | --- | --- | --- |
| `object_scope` | `string` | no | MMS object-name scope: `vcc`, `icc`, or `aa`. |
| `object_domain` | `string` | no | Domain identifier for a domain-specific object. |
| `object_name` | `string` | no | MMS object identifier retained within parser bounds. |
| `object_category` | `string` | no | TASE.2 mapping or `unknown` when the name is not standardized evidence. |
| `name_model` | `string` | no | Naming interpretation: `standardized`; `agreement_defined` for an exact endpoint-owned object activated through configured type evidence, or for a valid name within that serving endpoint's confirmed Bilateral Table Domain; or `private_unknown`. |
| `domain_kind` | `string` | no | Object namespace: `vcc`, `icc`, `bilateral`, `aa`, or `unknown`; `bilateral` is evaluated in the observed object's serving-endpoint namespace. |
| `bilateral_domain` | `bool` | no | Whether current association state identifies this domain as the Bilateral Table Domain for the serving endpoint and peer. The two server directions are independent. |
| `result_count` | `count` | no | Declared number of ordered AccessResults in an InformationReport. |
| `failure_count` | `count` | no | Number of failure AccessResults in that report. |
| `logged_result_count` | `count` | no | Number of results whose object identity is complete and within the configured row limit. |
| `omitted_result_count` | `count` | no | Results not emitted as object-associated rows because identity is untrusted or the row limit was reached. |
| `result_pairing_status` | `string` | no | `explicit_complete`, `known_list_complete`, `count_mismatch`, `identity_incomplete`, or `untracked_list`; only the two complete states authorize result-to-object pairing. |
| `result_index` | `count` | no | Zero-based position of this InformationReport AccessResult. |
| `result_type` | `count` | no | Numeric MMS AccessResult/Data choice; zero denotes a failure result when `result_error` is present. |
| `result_error` | `int` | no | MMS DataAccessError code for a failed result. |
| `result_raw` | `string` | no | Hexadecimal result body after the configurable raw-byte cap; it is evidence, not a TASE.2 type assertion. |
| `result_raw_truncated` | `bool` | no | True when `result_raw` was shortened by the configured cap. |
| `value_type` | `count` | no | Numeric MMS Data choice for a correlated value. |
| `standardized_value` | `string` | no | Bounded normalized value or hexadecimal bytes for the recognized standardized object. |
| `conformance_blocks` | `string` | no | Bounded summary of supported-feature unused bits, raw bits, and recognized enabled blocks. |
| `conditions` | `string` | no | Comma-separated decoded `DSConditions` labels when the value passes validation. |
| `condition_mask` | `count` | no | Normalized `DSConditions` mask retained by the parser. |
| `point_type` | `string` | no | TASE.2 point form supported by an activated endpoint/object type mapping and exact wire shape, including basic, quality, timestamp, COV, and supplemental State forms. |
| `state_value` | `count` | no | Normalized state-family value. The precise bilateral type can remain ambiguous. |
| `tag_value` | `count` | no | Normalized Tag field from a validated supplemental State value. |
| `expected_state_value` | `count` | no | Normalized ExpectedState field from a validated supplemental State value. |
| `supplemental_reserved` | `count` | no | Reserved supplemental value retained without interpretation. |
| `integer_value` | `int` | no | Decoded integer primitive AccessResult or correlated point value. |
| `floating_value` | `double` | no | Decoded floating-point primitive AccessResult or correlated point value. |
| `boolean_value` | `bool` | no | Normalized primitive MMS Boolean AccessResult. |
| `string_value` | `string` | no | Bounded normalized VisibleString or MMSString AccessResult. |
| `object_identifier_value` | `string` | no | Normalized MMS object-identifier AccessResult. |
| `validity` | `string` | no | Quality validity: `valid`, `held`, `suspect`, or `invalid`. |
| `value_source` | `string` | no | Quality source: `telemetered`, `calculated`, `entered`, or `estimated`. |
| `normal_value` | `bool` | no | Decoded normal-value quality flag. |
| `timestamp_quality` | `bool` | no | Decoded timestamp-quality flag. |
| `timestamp_value` | `int` | no | Basic GMT-based point timestamp in epoch seconds. It is not a Zeek `time`. |
| `cov_value` | `count` | no | Exact unsigned16 COV counter from a correlated core Extended point form. |

## Bounds and sensitive data

All parser-originated strings are limited by the enclosing BER and layer
resource policies before log delivery. `detail` and each Identify
vendor/model/revision value have an additional 256-byte log limit. Container
contents are summarized rather than emitted as unbounded Zeek containers.
InformationReport object rows default to at most 128 results per report, and
each `result_raw` defaults to at most 256 source bytes before hexadecimal
encoding. Both limits are redefinable; normalized strings still use the
independent 256-byte detail bound.
Authentication values, complete application payloads, and ciphertext are
excluded; only presence, length, opacity metadata, and explicitly decoded
bounded value evidence are logged. `result_raw`, `value_raw`, and normalized values
can contain operational measurements or identifiers. Identify strings are
asset-identifying metadata even though they are not authentication secrets;
deployments should apply their normal log-access and retention controls.

## Specialized logs

### Object and value observations

`iccp_objects.log` uses `ICCP::ObjectInfo`. It separates object references and
value observations from protocol-envelope records while retaining the same
conservative interpretation in `iccp.log` for compatibility.

| Field | Zeek type | Required | Meaning |
| --- | --- | --- | --- |
| `ts` | `time` | yes | Network time when the record is produced. |
| `uid` | `string` | yes | Zeek connection UID. |
| `id` | `conn_id` | yes | Originator/responder address and port tuple. |
| `is_orig` | `bool` | yes | True when the object-bearing MMS message travels from the connection originator. |
| `association_kind` | `string` | yes | Current classification: `unknown`, `mms`, or `tase2`. |
| `association_phase` | `string` | yes | Association lifecycle phase at observation time. |
| `endpoint_role` | `string` | yes | Role of the sending endpoint: `unknown`, `originator`, or `responder`. |
| `observation_kind` | `string` | yes | `reference` for an object-bearing request, `read_response` for a correlated Read value, `information_report` for the compatibility first result, `information_report_result` for each additional trusted ordered result, or `name_list_request`, `name_list_response`, and `name_list_identifier` for bounded GetNameList evidence. |
| `operation` | `string` | no | Stable lowercase candidate ICCP operation name. |
| `invoke_id` | `int` | no | MMS confirmed-service invocation identifier. |
| `object_scope` | `string` | yes | MMS object-name scope: `vcc`, `icc`, `aa`, or `unknown` on an uncorrelated GetNameList response. |
| `object_domain` | `string` | no | Domain identifier for an ICC-scoped object. |
| `object_name` | `string` | yes | Bounded MMS object identifier; empty on GetNameList request/response summary rows, whose individual identifiers use separate rows. |
| `object_category` | `string` | no | Standardized TASE.2 category or `unknown`. |
| `name_model` | `string` | no | `standardized`; `agreement_defined` for an exact endpoint-owned object activated through configured type evidence, or for a valid name in that serving endpoint's confirmed Bilateral Table Domain; or `private_unknown`. |
| `domain_kind` | `string` | no | Object namespace: `vcc`, `icc`, `bilateral`, `aa`, or `unknown`; `bilateral` is serving-endpoint-specific. |
| `bilateral_domain` | `bool` | no | Whether association state identifies the object domain as the Bilateral Table Domain for the serving endpoint and peer. |
| `result_count` | `count` | no | Total ordered AccessResults in an InformationReport or identifiers in a GetNameList response. |
| `logged_result_count` | `count` | no | Number of GetNameList identifiers emitted within the configured vector-row limit. |
| `omitted_result_count` | `count` | no | GetNameList identifiers omitted because that row limit was reached. |
| `result_pairing_status` | `string` | no | InformationReport identity basis or GetNameList request/response correlation outcome. |
| `result_index` | `count` | no | Zero-based AccessResult/member or returned-identifier position. |
| `result_type` | `count` | no | Numeric MMS AccessResult/Data choice. |
| `result_error` | `int` | no | MMS DataAccessError code for a failed result. |
| `result_raw` | `string` | no | Bounded hexadecimal result body. |
| `result_raw_truncated` | `bool` | no | Whether the source body exceeded the raw-byte cap. |
| `object_class_choice` | `count` | no | GetNameList standard or companion-standard object-class alternative. |
| `object_class` | `int` | no | Numeric object class requested by GetNameList. |
| `continue_after` | `string` | no | Continuation identifier recovered from the direction-correlated request. |
| `more_follows` | `bool` | no | Response pagination flag. |
| `value_type` | `count` | no | Numeric MMS Data choice for an observed value. |
| `standardized_value` | `string` | no | Bounded normalized standardized value or hexadecimal fallback. |
| `conformance_blocks` | `string` | no | Bounded supported-feature bit summary. |
| `conditions` | `string` | no | Normalized `DSConditions` labels for a validated conditions value. |
| `condition_mask` | `count` | no | Normalized `DSConditions` mask. |
| `point_type` | `string` | no | Exact configured-type-backed TASE.2 point form. |
| `state_value` | `count` | no | Decoded state-family value. |
| `tag_value` | `count` | no | Decoded supplemental State Tag field. |
| `expected_state_value` | `count` | no | Decoded supplemental ExpectedState field. |
| `supplemental_reserved` | `count` | no | Uninterpreted supplemental reserved field. |
| `integer_value` | `int` | no | Decoded integer primitive or point value. |
| `floating_value` | `double` | no | Decoded floating-point primitive or point value. |
| `boolean_value` | `bool` | no | Normalized primitive MMS Boolean value. |
| `string_value` | `string` | no | Bounded normalized VisibleString or MMSString value. |
| `object_identifier_value` | `string` | no | Normalized MMS object identifier. |
| `validity` | `string` | no | Quality validity: `valid`, `held`, `suspect`, or `invalid`. |
| `value_source` | `string` | no | Quality source: `telemetered`, `calculated`, `entered`, or `estimated`. |
| `normal_value` | `bool` | no | Decoded normal-value quality flag. |
| `timestamp_quality` | `bool` | no | Decoded timestamp-quality flag. |
| `timestamp_value` | `int` | no | Basic GMT-based point timestamp in epoch seconds. |
| `cov_value` | `count` | no | Exact unsigned16 COV counter from a correlated core Extended point form. |
| `provenance` | `string` | yes | Provenance of the MMS PDU producing this object observation. |
| `stream_completeness` | `string` | yes | Direction-scoped capture/recovery status at this observation. |

### Transfer activity

`iccp_transfers.log` uses `ICCP::TransferInfo`. A request and its response are
separate records. Reports produce one summary record followed by at most one
`report_value` record per paired, bounded member/result entry.

| Field | Zeek type | Required | Meaning |
| --- | --- | --- | --- |
| `ts` | `time` | yes | Network time when the record is produced. |
| `uid` | `string` | yes | Zeek connection UID. |
| `id` | `conn_id` | yes | Originator/responder address and port tuple. |
| `is_orig` | `bool` | yes | True when the transfer message travels from the connection originator. |
| `action` | `string` | yes | Normalized lifecycle, report, `type_discovery`, `type_description`, Start/Stop, support-value, or Information Message activity. A report attributed to confirmed DSTransferSet state additionally uses `active_report`; the existing `report`/`report_value` rows remain unchanged. Exact Information Message reports use `information_message`. Confirmed Read observations use `next_transfer_set`, `transfer_set_name`, `event_code_detected`, `transfer_timestamp`, `read_report_ack_value`, and `read_report_nack_value`; the last two do not claim that an unconfirmed ACK/NACK InformationReport occurred. |
| `outcome` | `string` | yes | Lifecycle result. A positive response to an existing Data Set name uses `confirmed_existing_name` and does not replace known membership. Type discovery uses `configured`, `unmapped`, `invalid_configuration`, or `type_mismatch`; a decoded TypeDescription uses `observed`; support values use `decoded`, `invalid_value`, or `rejected`. |
| `invoke_id` | `int` | no | MMS invoke ID for confirmed define, inspect, delete, or GetVariableAccessAttributes traffic. Unconfirmed reports have none. |
| `list_scope` | `string` | no | Named-variable-list scope: `vcc`, `icc`, `aa`, or `unknown`. |
| `list_domain` | `string` | no | Domain identifier for an ICC-scoped named variable list. |
| `list_name` | `string` | no | Named variable list used as the transfer-set identity. |
| `named_type` | `string` | no | Exact standardized named type supplied by `configured_variable_types` and activated only after exact bootstrap Read evidence has classified the association as TASE.2 and a verified, direction-correlated GetVariableAccessAttributes response reports a non-deletable, fully resolved recursive TypeDescription equal to the supported signature for that configured alias and scope. A conformant wire response contains only an inline TypeDescription, so it is never treated as a source for this name. |
| `variable_count` | `count` | no | Number of variables supplied by a definition or returned by an inspection. |
| `first_variable_scope` | `string` | no | Scope of the first definition/inspection member, or of the member paired to a `report_value`. |
| `first_variable_domain` | `string` | no | Domain of that member when it is ICC-scoped. |
| `first_variable_name` | `string` | no | Name of that member. The `first_` prefix is retained for schema compatibility even on per-member `report_value` records. |
| `deletable` | `bool` | no | Inspect-response indication that the named list may be deleted. |
| `delete_scope` | `int` | no | Wire-level DeleteNamedVariableList scope selector from the request. |
| `number_matched` | `int` | no | Delete-response count of lists matching the request. |
| `number_deleted` | `int` | no | Delete-response count of lists actually deleted. |
| `result_count` | `count` | no | Number of access results in an information report. |
| `failure_count` | `count` | no | Number of failed access results in that report. |
| `logged_result_count` | `count` | no | Number of paired `report_value` rows emitted within the configured per-report limit. |
| `omitted_result_count` | `count` | no | Results not emitted as paired rows because identity was incomplete or the configured row limit was reached. |
| `known_list` | `bool` | no | Whether the named list is present in bounded state for this connection after the represented activity. |
| `result_index` | `count` | no | Zero-based result/member position on a `report_value` record. |
| `result_type` | `count` | no | Numeric MMS AccessResult choice for the paired result; zero denotes failure. |
| `result_error` | `int` | no | Wire-level data-access error code when the paired result failed. |
| `result_raw` | `string` | no | Lowercase hexadecimal encoding of the raw result, capped by `max_logged_result_raw_bytes`. |
| `result_raw_truncated` | `bool` | no | Whether `result_raw` omitted source bytes because the configured byte cap was reached. |
| `pairing_status` | `string` | no | Report/member correlation result: `complete`, `count_mismatch`, or `untracked_list`. |
| `timestamp_value` | `int` | no | `Transfer_Set_Time_Stamp` value as GMT-based epoch seconds. It is not a Zeek `time`. |
| `info_reference` | `int` | no | Information Message reference from a validated header. |
| `local_reference` | `int` | no | Information Message local reference from a validated header. |
| `message_id` | `int` | no | Information Message identifier from a validated header. |
| `message_size` | `count` | no | Nonnegative declared Information Message content size; absent when the header is invalid. |
| `buffer_capacity` | `count` | no | Capacity encoded by exact `Info_Buff_XX` membership. |
| `buffer_length` | `count` | no | Observed OCTET STRING length, used to audit the capacity check. The content itself is not logged. |
| `data_set_scope` | `string` | no | Scope encoded in an exact `DSTransferSet.DataSetName`: `vcc` or `icc`. |
| `data_set_domain` | `string` | no | Domain field carried in `DataSetName`; retained as wire evidence even when it does not affect lookup. |
| `data_set_name` | `string` | no | Validated MMS Identifier naming the data set referenced by the transfer configuration. |
| `start_time` | `int` | no | Nonnegative GMT-based StartTime in epoch seconds. |
| `transfer_interval` | `int` | no | Nonnegative Interval value from the exact transfer configuration. |
| `tle` | `int` | no | Nonnegative transfer-set TLE interval. |
| `buffer_time` | `int` | no | Nonnegative transfer-set BufferTime interval. |
| `integrity_check` | `int` | no | Nonnegative IntegrityCheck interval. |
| `conditions` | `string` | no | Decoded `DSConditions` labels from a validated value. |
| `condition_mask` | `count` | no | Normalized `DSConditions` mask. |
| `block_data` | `bool` | no | Exact `DSTransferSet.BlockData` value. |
| `critical` | `bool` | no | Exact `DSTransferSet.Critical` acknowledgment requirement. |
| `report_by_exception` | `bool` | no | Exact `DSTransferSet.RBE` value. |
| `all_changes_reported` | `bool` | no | Exact `DSTransferSet.AllChangesReported` value. |
| `enabled` | `bool` | no | Exact `DSTransferSet.Status`; true is Start and false is Stop. |
| `event_code_requested` | `int` | no | Optional event code retained from the transfer configuration. |
| `event_code_detected` | `int` | no | Signed 16-bit event code decoded from the reserved `Event_Code_Detected` transfer-support variable. |
| `conformance` | `string` | no | `parameters_conformant` for a `DSTransferSet` request that passes the implemented structural/value checks, or `standards_deviation` when an implemented Data Set/transfer check observes a deviation. Ordinary valid lifecycle rows may omit this field. |
| `conformance_reasons` | `string` | no | Stable comma-separated reason tokens identifying failed field, lifecycle, type-signature, deletability, resolution, standardized-scope, member-access, or duplicate-definition constraints. |
| `transfer_set_scope` | `string` | no | Scope of the agreement-defined DSTransferSet variable that established an `active_report`. |
| `transfer_set_domain` | `string` | no | Domain of that transfer-set variable when applicable. |
| `transfer_set_name` | `string` | no | Exact transfer-set variable name selected by unambiguous active-state correlation. |
| `transfer_state` | `string` | no | `active` or `stopped` lifecycle state at report observation time. |
| `report_access` | `string` | no | `named_list` or `explicit_variables`, taken directly from the InformationReport variable-access form. |
| `report_correlation` | `string` | no | Evidence basis or conservative outcome: `exact_data_set`, `rbe_subset`, `rbe_full_list_fallback`, `block_data_explicit`, `post_stop_observed`, `direction_mismatch`, `unexpected_explicit_non_rbe`, `unexpected_named_block_data`, or `ambiguous_active_transfer`. |
| `ack_required` | `bool` | no | Whether the correlated Start configuration had Critical set. This does not claim that an ACK was present or missing. |
| `type_choice` | `count` | no | Top-level MMS TypeDescription choice from a GetVariableAccessAttributes response. |
| `type_constructed` | `bool` | no | BER primitive/constructed form of that TypeDescription choice. |
| `type_signed_value` | `int` | no | Integer parameter carried by integer, unsigned, string-width, BCD, or MMSString TypeDescription alternatives. |
| `type_boolean_value` | `bool` | no | Boolean parameter of a binary-time TypeDescription. |
| `type_format_width` | `int` | no | Floating-point TypeDescription format width. |
| `type_exponent_width` | `int` | no | Floating-point TypeDescription exponent width. |
| `type_raw` | `string` | no | Bounded hexadecimal top-level TypeDescription value bytes. |
| `type_raw_truncated` | `bool` | no | Whether `type_raw` omitted bytes at the configured raw-byte cap. |
| `type_packed` | `bool` | no | Optional packed flag for an array or structure TypeDescription. |
| `type_number_of_elements` | `int` | no | Array element count. |
| `type_component_count` | `count` | no | Number of top-level structure components. |
| `type_node_count` | `count` | no | Total bounded recursive TypeDescription nodes. |
| `type_maximum_depth` | `count` | no | Maximum decoded TypeDescription nesting depth. |
| `provenance` | `string` | yes | Provenance of the MMS PDU producing this transfer record. |
| `stream_completeness` | `string` | yes | Direction-scoped capture/recovery status at this activity. |

Full membership and result arrays are not logged. State limits can therefore
affect correlation without causing an unbounded log record.
Information Message outcomes are `delivered`, `invalid_header`,
`invalid_buffer`, or `size_mismatch`; their buffer content is deliberately
suppressed from both transfer and object raw fields.
Agreement-defined Start/Stop outcomes carry their validated transmission
parameters through the request and direction-valid terminal record. A learned
`DSTransferSet` with malformed parameters is logged as `transfer_candidate` /
`invalid_parameters` and does not create correlation state. Individually valid
fields remain populated so an operator can understand the observed intent
without treating the complete operation as trusted. Every one-octet nonzero
Boolean TRUE encoding is standards-conformant.
Successful Start state is bounded and keyed by connection, client direction,
scope, domain, and transfer-set name. A successful duplicate Start is reported
as a standards deviation while the original active parameters remain intact.
A successful Stop changes only the matching full-identity state to `stopped`;
rejected and failed terminals leave the prior state intact.
Post-Stop reports remain attributable as `post_stop_observed`, but their count
is not treated as a protocol violation. Explicit reports require exact member
containment in a previously confirmed named-list definition. If more than one
active configuration could own a report, the row is `unresolved` and omits a
transfer-set identity instead of choosing one.

### Confirmed errors

`iccp_errors.log` uses `ICCP::ErrorInfo`. It records association context and
correlates an MMS ConfirmedError to bounded pending-request state.

| Field | Zeek type | Required | Meaning |
| --- | --- | --- | --- |
| `ts` | `time` | yes | Network time when the record is produced. |
| `uid` | `string` | yes | Zeek connection UID. |
| `id` | `conn_id` | yes | Originator/responder address and port tuple. |
| `is_orig` | `bool` | yes | True when the ConfirmedError travels from the connection originator. |
| `association_kind` | `string` | yes | Association classification at error time: `unknown`, `mms`, or `tase2`. |
| `outcome` | `string` | yes | Correlation result: `correlated`, `unexpected_error`, `ambiguous_response`, or `direction_mismatch`. A direction mismatch does not consume pending state. |
| `invoke_id` | `int` | no | Invoke ID carried by the ConfirmedError when valid and present. |
| `operation` | `string` | no | Candidate TASE.2 operation recovered from the correlated request. |
| `service_tag` | `count` | no | Confirmed-service tag recovered from the correlated request. |
| `modifier_position` | `int` | no | Wire-level position of the modifier that caused the service failure. |
| `error_class` | `string` | yes | Normalized MMS error class: `vmd_state`, `application_reference`, `definition`, `resource`, `service`, `service_preempt`, `time_resolution`, `access`, `initiate`, `conclude`, `cancel`, `file`, or `others`. |
| `error_class_code` | `count` | yes | Numeric MMS ServiceError class selector, retained even when unknown. |
| `error_code` | `int` | yes | Wire-level code within the selected MMS error class. |
| `additional_code` | `int` | no | Optional implementation-specific additional error code. |
| `description` | `string` | no | Optional additional description, truncated to 256 bytes. It is not a stable machine-parsing field. |
| `provenance` | `string` | yes | Provenance of the MMS ConfirmedError PDU producing this record. |
| `stream_completeness` | `string` | yes | Direction-scoped capture/recovery status at this error. |

### Control candidates and classified operations

`iccp_controls.log` uses `ICCP::ControlInfo`. A generic MMS Write remains
`write_candidate`. Exact single-object Writes become `operate_command`,
`operate_setpoint_discrete`, or `operate_setpoint_real` only when an explicit
endpoint/object mapping was activated after exact bootstrap Read classification
and the exact verified GetVariableAccessAttributes exchange described above,
and the value passed its validation.
Select and Tag classifications likewise
require correlated type, object, and value evidence. Incomplete evidence
remains an explicit candidate and never carries a decoded control claim.
Device EventNotifications use the same stream. Supported Device-action
classifications require complete association, event, state, loss, and result
evidence; all other well-formed notifications remain candidates.

| Field | Zeek type | Required | Meaning |
| --- | --- | --- | --- |
| `ts` | `time` | yes | Network time when the record is produced. |
| `uid` | `string` | yes | Zeek connection UID. |
| `id` | `conn_id` | yes | Originator/responder address and port tuple. |
| `is_orig` | `bool` | yes | True when the Read, Write, response, or error travels from the connection originator. |
| `association_kind` | `string` | yes | Association classification at observation time. |
| `association_phase` | `string` | yes | Association lifecycle phase at observation time. |
| `endpoint_role` | `string` | yes | Role of the sending endpoint. |
| `classification` | `string` | yes | Write/Select/Get Tag/Set Tag/Operate classifications described above, plus `device_timeout`, `device_local_reset`, `device_success`, `device_failure`, and their `_candidate` forms. Additive ordered evidence rows use `write_evidence`, `write_value`, and `write_result`. Exact operations require their documented association, type, object, value, or event-state evidence. |
| `named_type` | `string` | no | Configured standardized type used in the classification decision. It may be present on a candidate whose other evidence is incomplete. |
| `outcome` | `string` | yes | Common correlated-operation values include `requested`, `confirmed`, `rejected`, `invoke_reused`, `state_limit`, `direction_mismatch`, `partial_or_failed`, and conservative mismatch/ambiguity outcomes. Ordered value rows use `observed`; result rows use `succeeded` or `failed`. Event actions use `notified` or `candidate_notification`. Candidate outcomes do not assert the candidate operation occurred. |
| `invoke_id` | `int` | yes | MMS Read or Write invoke ID used for bounded request correlation; `-1` for unconfirmed EventNotification. |
| `object_scope` | `string` | no | First explicitly named variable scope: `vcc`, `icc`, `aa`, or `unknown`. |
| `object_domain` | `string` | no | Domain of the first explicitly named variable. |
| `object_name` | `string` | no | Name of the first explicitly named variable. |
| `variable_count` | `count` | no | Number of variables addressed by the Read or Write request. Exact Select, Tag, and Operate classifications require one. |
| `data_count` | `count` | no | Number of top-level MMS Data values in the request. |
| `data_node_count` | `count` | no | Bounded recursive MMS Data-node total in the request. |
| `access_choice` | `count` | no | Write variable-access form: explicit list or named-variable-list selector. |
| `target_count_known` | `bool` | no | True when explicit target identities are present on the wire; false for a named-list selector. |
| `target_count` | `count` | no | Number of explicit Write targets, when known. |
| `value_count` | `count` | no | Number of ordered Write Data values. |
| `logged_item_count` | `count` | no | Number of ordered Write value/result rows emitted within the configured vector-row limit. |
| `omitted_item_count` | `count` | no | Write value/result items omitted because that limit was reached. |
| `item_index` | `count` | no | Zero-based Write target/value/result position. |
| `pairing_status` | `string` | no | Correlation basis such as `explicit_complete`, `named_list_ordered`, `count_mismatch`, `direction_mismatch`, or an untrusted-evidence status. |
| `value_type` | `count` | no | Numeric MMS Data choice for this ordered Write value. |
| `value_raw` | `string` | no | Bounded hexadecimal Write value bytes. |
| `value_raw_truncated` | `bool` | no | Whether the original Write value exceeded the configured raw-byte cap. |
| `boolean_value` | `bool` | no | Decoded Boolean Write value. |
| `string_value` | `string` | no | Bounded decoded VisibleString or MMSString Write value. |
| `result_success` | `bool` | no | Per-item Write-response success status. |
| `result_error` | `int` | no | Per-item MMS DataAccessError value when the Write result failed. |
| `integer_value` | `int` | no | Signed command/discrete-setpoint value retained from an Operate request, or the one- or two-octet CheckBackID returned by a confirmed exact Select. |
| `floating_value` | `double` | no | Real setpoint retained from a classified request and propagated to its terminal result. |
| `tag_value` | `count` | no | Normalized Tag code present only on validated Get/Set Tag evidence. |
| `tag_state` | `string` | no | Normalized Tag state: `idle` or `armed`. |
| `tag_reason` | `string` | no | Printable Tag reason retained within the parser's configured bound. |
| `result_count` | `count` | no | Number of per-item Read AccessResults or Write results in the response. |
| `success_count` | `count` | no | Number of successful per-item results. |
| `failure_count` | `count` | no | Number of failed per-item results. |
| `error_class` | `string` | no | Normalized MMS error class for a rejected candidate. |
| `error_class_code` | `count` | no | Numeric MMS ServiceError class selector. |
| `error_code` | `int` | no | Wire-level code within that MMS error class. |
| `event_enrollment_scope` | `string` | no | Event Enrollment ObjectName scope: `vcc`, `icc`, or `aa`. |
| `event_enrollment_domain` | `string` | no | Domain component of an ICC-scoped Event Enrollment name. |
| `event_enrollment_name` | `string` | no | Event Enrollment object identifier. |
| `event_condition_scope` | `string` | no | Event Condition ObjectName scope. Exact Device actions require `vcc`. |
| `event_condition_domain` | `string` | no | Domain component when supplied by a non-exact condition candidate. |
| `severity` | `int` | no | MMS EventNotification severity used by Device-action validation. |
| `current_state` | `string` | no | Normalized MMS event-condition state: `disabled`, `idle`, or `active`. |
| `transition_time_kind` | `string` | no | `time_of_day`, `time_sequence_identifier`, or `undefined`. |
| `transition_time_value` | `int` | no | Unsigned sequence identifier when that EventTime choice is used. |
| `transition_time_raw` | `string` | no | Hex rendering of the bounded EventTime choice payload. |
| `notification_lost` | `bool` | no | MMS notificationLost, including its default false value. |
| `action_result_present` | `bool` | no | Whether the optional MMS actionResult field was present. |
| `provenance` | `string` | yes | Provenance of the MMS request, response, or error PDU producing this record. |
| `stream_completeness` | `string` | yes | Direction-scoped capture/recovery status at this candidate. |

## Configuration

The `max_logged_information_report_results` setting is also the common row
budget for GetNameList identifiers and ordered Write value/result evidence;
the existing InformationReport compatibility row keeps its documented minimum
of one, while these additive vector streams honor zero literally. Raw Write and
TypeDescription bytes use `max_logged_result_raw_bytes`.

Each currently implemented stream is independently configurable through the
`ICCP::enable_iccp_log`, `ICCP::enable_iccp_objects_log`,
`ICCP::enable_iccp_transfers_log`, `ICCP::enable_iccp_controls_log`, and
`ICCP::enable_iccp_errors_log` redefinable constants. All default to true;
disabling one suppresses its file without disabling parsing or state tracking.
`ICCP::max_logged_information_report_results` defaults to 128 associated
result rows per report, and `ICCP::max_logged_result_raw_bytes` defaults to 256
source bytes per result. A result-row limit of zero preserves the historical
first associated result on the aggregate record and therefore behaves as a
minimum limit of one; a raw-byte limit of zero emits an empty `result_raw` and
sets `result_raw_truncated` whenever source bytes were present.

## Compatibility

Existing field names, Zeek types, and meanings are stable. New optional fields
may be appended to an implemented log record. Removing or renaming a field,
changing its type, changing a required field to have a different default
meaning, or reinterpreting its values requires a documented major compatibility
change and updated Malcolm mappings and baseline tests.

Parser event compatibility follows the existing event names, argument order,
argument types, enum values, and documented meanings. New metadata should use
a versioned event or an appended optional record field.
