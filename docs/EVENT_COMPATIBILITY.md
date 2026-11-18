# Event Compatibility

## MMS Data Evidence

MMS primitive raw evidence is retained as a parser-bounded prefix of at most
256 bytes. The parser transports the original content length and an explicit
truncation flag separately, so Zeek policy does not need a complete raw value
to determine whether evidence was shortened.

The exported `ICCP::MMSDataEvidence` record groups the MMS choice, decoded
scalar values, raw prefix, original raw length, and truncation state used by
internal policy correlation. Policy output may apply a smaller configured log
limit; output truncation is true when either the parser or policy shortened the
value.

## Versioned Events

- `ICCP::mms_write_evidence_v2` is the authoritative parser-produced write
  event. It adds per-value original lengths and truncation flags. Every v2
  event also dispatches `ICCP::mms_write_evidence_v1` exactly once with the
  same bounded raw prefixes, preserving legacy packet subscribers. Direct v1
  callers remain supported and adapt into v2 with inferred length metadata;
  bridge guards prevent either direction from recursively redispatching.
- `ICCP::mms_information_report_results_v3` is the parser-produced report
  event. It adds per-result original lengths and truncation flags. It dispatches
  the existing v2 event after storing exact metadata, preserving existing v2
  handlers. Direct v2 callers remain supported with inferred metadata.
- `ICCP::mms_first_result_evidence_v1` is additive evidence for confirmed Read
  responses. It supplies exact first-result length and truncation metadata to
  control and transfer-support consumers without changing their legacy event
  signatures.

No public event was removed in Phase 3. Legacy aggregate events continue to be
emitted where existing consumers depend on them, but any raw MMS data strings
they carry are bounded prefixes rather than complete unbounded values.
