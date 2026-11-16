# Analyzer Coverage

This document summarizes behavior implemented and tested by ICSNPP-ICCP. It
describes the package, not every optional feature or implementation-specific
extension that may appear in a deployment.

The clause-level comparison with the locally available IEC/ISO editions and
the boundary of any release claim are recorded in
[`STANDARDS_TRACEABILITY.md`](STANDARDS_TRACEABILITY.md).

## Status terms

- `partial`: useful semantic behavior is implemented, but some valid variants,
  state transitions, or semantic correlations remain unimplemented or
  unverified.
- `structural`: the protocol structure and metadata are decoded without a more
  specific ICCP interpretation.
- `raw`: identifying and bounded evidence available for that path is retained
  without assigning an unsupported semantic label; this does not imply that
  arbitrary service bodies are exported.

## Protocol and operation coverage

| Area | Status | Analyzer behavior |
| --- | --- | --- |
| Transport and OSI framing | partial | Parses bounded TPKT, COTP, Session, Presentation, and association envelopes for the supported ICCP profile, including Session CONNECT/ACCEPT carrying CP(AARQ)/CPA(AARE), normal-mode Presentation, BER transfer syntax, and supported segmentation; unsupported variants are rejected or retained as bounded generic evidence according to the path |
| Association lifecycle | partial | Tracks observed COTP epochs, context, endpoint role, acceptance/rejection, FINISH/RLRQ, positive DISCONNECT/RLRE, negative NOT-FINISHED/RLRE that retains the association, ABORT/ARU/ABRT, provenance, and capture completeness; malformed transport/Session boundaries and TCP gaps invalidate exact trust before later decoding |
| MMS messages and transactions | partial | Decodes the supported message alternatives, transaction identifiers, common requests and responses, errors, and bounded unknown services; unsupported service bodies remain generic rather than semantically decoded |
| Object discovery | structural | Records requested scope, continuation state, returned names, and pagination metadata |
| Type discovery | partial | Parses bounded recursive `TypeDescription` values and activates a configured type only after exact bootstrap Read evidence has classified the association as TASE.2 and a verified, connection-scoped, direction-correct response reports `mmsDeletable=false`, matches that supported type's complete resolved signature, and uses a supported basic scope/name; ambiguous, inferred, absent, unresolved, mismatched, or unmapped evidence teaches no type. Activated Domain objects are not required to equal the learned Bilateral Table Domain, and `SBO_CheckBackName` activation does not itself enforce `_SBO`; those are documented semantic limits |
| Read activity | partial | Correlates requests and responses and records object identity, result metadata, and supported values |
| Write activity | partial | Records bounded ordered targets, values, per-item results, failures, and detection events; named-list member identities require previously established list state |
| Controls | partial | Classifies supported Operate, Select, and Tag activity when the required object, type, direction, and transaction evidence is present |
| Named lists | partial | Tracks definition, membership, inspection, deletion, and result pairing within bounded connection state. A recognized TASE.2 Create requires a Domain-specific list name, complete named-member vectors, VMD- or Domain-specific non-special ObjectNames, Domain-specific scope for the four special transfer objects, and no member `AlternateAccess`; it does not independently prove that non-special members are Data Values or that member/list Domains equal the learned Bilateral Domain. A positive Define of a previously verified name is flagged and cannot replace known membership. Only a nonempty SPECIFIC vector of Domain-specific Delete names changes learned state; inconsistent positive matched/deleted counts are flagged, zero deletions preserve prior state, and any claimed deletion conservatively invalidates every requested identity. Active-transfer deletion prohibition, scope-dependent inspect `mmsDeletable`, and learning predefined membership from inspection are not implemented |
| Reported values | partial | Records ordered results and associates them with objects only when identity and cardinality are complete |
| Point values | partial | Exposes supported scalar, state, quality, time, counter, and supplemental fields after type verification; configured point-family shape decoding currently applies only to the first InformationReport result, while later ordered rows remain generic evidence |
| Transfer activity | partial | Specializes the IEC 60870-6-503:2014 Data Set Transfer Set (`DSTransferSet`) parameter and bounded Start/Stop/report paths. The standard-specified AA-specific Information Message compatibility path has bounded Boolean Start/Stop handling; its normative status is internally inconsistent in this edition. BlockData headers are checked but opaque blocked values are not decoded; learned-Bilateral-Domain equality, allocation-before-Start, completeness of required report forms for special members included in the Data Set, named-list membership/result cardinality for active reports, and actual InformationReport ACK/NACK correlation are not complete. Informative/historical Time Series and Transfer Account variants remain generic/bounded |
| Device identity and notifications | partial | Records privacy-bounded identity fields, supported action classifications, and generic candidates |
| Information Messages | partial | Recognizes an exact ordered `Info_Mess_Header` / `Info_Buff_XX` pair in a verified named list or explicit-variable report, validates supported header/capacity constraints, and deliberately omits arbitrary message bodies. A conflicting single-`f` spelling elsewhere in the reviewed edition remains generic |
| Errors and diagnostics | partial | Correlates supported service errors and reports bounded parser, resource, and capability diagnostics |
| Unknown or private content | raw | Preserves safe service, object, and bounded length/structure metadata without assigning a guessed ICCP meaning; arbitrary bodies are not exported |

## Classification and trust behavior

A well-formed MMS operation can be logged without being classified as ICCP.
The association values are:

| Value | Meaning |
| --- | --- |
| `unknown` | The required connection context was not observed or is incomplete |
| `mms` | Observed connection evidence establishes MMS |
| `tase2` | MMS context plus ICCP-specific traffic establishes ICCP/TASE.2 |

Port numbers, familiar object spelling, isolated service tags, and plausible
value shapes do not independently establish a more specific classification.
Depending on the operation, semantic classification can require confirmed
association context, object namespace, configured bilateral type evidence,
transaction identity, direction, value compatibility, or previously confirmed
list/transfer state. MMS GetVariableAccessAttributes responses carry an inline
`TypeDescription`; they do not carry a standardized named type. The analyzer
therefore treats site configuration as the expected alias and learns it only
after exact bootstrap Read evidence has classified the association as TASE.2,
verified parser evidence contains the exact resolved signature, and the object
passes the implemented alias-specific basic scope/name checks. Learned-Domain
equality and configured SBO suffix enforcement remain the limits listed above.
A nested MMS TypeSpecification
may legally use `typeName`; such a tree is parsed but remains unresolved and
cannot activate the configured alias. Some standardized aliases
share the same wire shape, so wire shape alone cannot choose between them. The
matcher compares recursive type choices, widths, packing, and child counts; it
does not use optional structure-component names as type identity.

Correlation state is connection-scoped, bounded, and cleared at lifecycle
boundaries and reported TCP gaps. Contradictory or ambiguous evidence remains
generic or candidate activity. Later complete traffic can establish fresh
state normally, but cannot revive pre-gap association trust.

Bilateral Table Domain evidence is additionally serving-endpoint-scoped because
both peers can act as server over one association. The compatibility helper
`is_bilateral_domain(c, domain)` reports a union across the association;
internal name/domain classification instead uses the endpoint-specific helper.
A conflicting second successful Domain bootstrap invalidates only that server
direction until the association is reset.

Every MMS-derived record carries dispatch provenance and direction-scoped
stream-completeness fields. These distinguish negotiated parsing from bounded
midstream recovery and identify directions that cannot make an exhaustive
output claim. They describe observation quality; they do not manufacture
association facts missing from the capture.

After loss or malformed input, synchronization uses the structural
TPKT/class-0 COTP-DT prefix for recoverable ICCP application traffic or a
strict class-0 CR prefix that can establish a fresh transport epoch. CC, DR,
and ER remain bounded transport records when encountered at an established
record boundary; recovery does not search for those less-selective
transport-only candidates. The TPKT reserved octet is ignored as required by
RFC 2126, including when it is nonzero, but recovery does not trust an
arbitrary `0x03`, reserved byte, and plausible length until the DT or strict CR
prefix also validates. DC-family prefixes still invalidate stale trust,
but the TPDU is rejected in every state because ICCP's strict RFC 1006 class-0
profile does not use DC. Treating an ER family prefix as a trust-reset
boundary is a conservative analyzer policy against stale state, not a claim
that every ER normatively terminates a COTP connection. The strict profile
rejects both ISO normal-format ED and the RFC 1006/RFC 2126 negotiated class-0
expedited-data extension in every state, including midstream captures. A gap
therefore continues to invalidate exact association trust unless a complete
fresh opposite-direction CR/CC exchange is subsequently observed. A
same-direction CC cannot consume the CR token or establish DATA. This reset is
performed at the gap itself: it also applies when the affected direction ends
at the missing region, before later peer-direction traffic is processed.
Recovery cannot operate on payload that Zeek's TCP reassembler never delivers.
In particular, an advancing ACK becomes durable after that sending endpoint
has appeared; a corresponding old segment captured later can be discarded as
already acknowledged. The analyzer reports the resulting gap/non-exhaustive
direction and can synchronize at a later deliverable TPKT, but it never
reconstructs the withheld bytes.

If, after at least one valid TPKT, capture teardown interrupts the header or
declared body of a plausible next TPKT, the direction is marked
`incomplete_record_observation` and receives a terminal
`direction_non_exhaustive_after_incomplete_record` summary. This reports an
incomplete observation, not malformed ICCP/TASE.2. The packet-start marker is
recorded while bytes arrive and connection removal supplies the verdict when a
partial/no-FIN stream never runs the suspended Spicy child's completion hooks.
The marker is actionable only after an earlier complete TPKT; an isolated
partial candidate stays unconfirmed. A capture ending directly after a
complete record never starts another packet child and remains clean. If
multiple terminal conditions exist, the published precedence is gap, then
parse recovery, then incomplete record.

The offline causal oracle independently encodes the supported production
framing and default Zeek 8 TCP reassembly rules used for comparison. It is not
universal Zeek equivalence: classic PCAP only, no IP-fragment reassembly, no
site-specific TCP `redef` discovery, no timestamp-exact post-close tuple reuse,
and no guarantee for every pathological or partially captured handshake.
Gapped-corpus equality is per-file cardinality unless explicitly stated as an
identity comparison.

## Recorded release-candidate evidence

The latest completed local validation used 61 authorized, non-distributed
captures in four bounded batches. The causal column models bytes available to
the production analyzer; the ideal column additionally performs capture-local
sequence-sorted reconstruction.

| Capture group | Files | Ideal MMS | Causal MMS | Plugin MMS |
| --- | ---: | ---: | ---: | ---: |
| Gap-free | 20 | 1,850 | 1,850 | 1,850 |
| Gapped | 41 | 29,318 | 29,176 | 29,176 |
| Per-file total | 61 | 31,168 | 31,026 | 31,026 |

The plugin's top-level tag counts were 876 tag-0, 796 tag-1, and 29,354 tag-3
records, totaling 31,026. All four independent semantic comparison gates
matched production output. The same release-candidate snapshot also recorded
112 passing transport runtime tests, 260 bounded deterministic fuzz mutations,
277 schema fields, 147 offline local-corpus-tool tests, 70 btests, and a
passing isolated package/install/registration/installed-log gate. This is
regression evidence for the tested profile and inputs, not certified
conformance or proof of behavior for every implementation.

## Data handling

Supported values are normalized only after exact bootstrap Read evidence has
classified the association as TASE.2 and an explicit site mapping has been
activated by direction-correct object-attribute evidence on the same connection.
Malformed, ambiguous, unsupported, unmapped, or shape-mismatched
values remain bounded evidence. Reserved or unexpected values are retained
when safe instead of being converted into a normal value.

Result-to-object pairing requires complete identity and cardinality. Count
mismatches, unknown lists, incomplete identities, and logging limits remain
visible in summary fields without assigning results to guessed objects.
Configured point-family shape decoding and exact point classification currently
apply only to the first result of an explicit InformationReport. Subsequent
ordered results retain their identity, scalar value, error, and bounded raw
evidence, but remain generic rather than receiving an exact point-family label.

Recursive MMS `Data` forests use one 4,096-node budget across every success or
failure root and descendant in an enclosing AccessResult or Write-value list.
Explicit variable lists likewise share one 4,096-node budget across entries and
every nested `AlternateAccess` selection; starting another list member does not
reset it.

Information Message bodies and authentication values are not logged. Operators
requiring those bytes must retain and protect the source capture separately.

## Stable operation names

The package currently emits these generic names when the corresponding MMS
operation is decoded:

- `delete_named_variable_list`
- `define_named_variable_list`
- `device_action`
- `get_name_list`
- `get_named_variable_list_attributes`
- `get_variable_access_attributes`
- `identify`
- `information_report`
- `read`
- `service_error`
- `write`

More specific labels are emitted only when the required evidence is present.
Exact field definitions and provenance values are documented in
[`LOG_SCHEMA.md`](LOG_SCHEMA.md).

## Validation boundary

Positive and negative synthetic tests cover representative paths for the
semantic classifications listed above. Committed synthetic comparison
captures and independent decoders provide additional structural validation;
authorized deployment captures can extend that evidence but are not
distributed with the package. This regression evidence is not a formal
conformance suite, and the project does not claim that every deployed product,
optional exchange, encoding, or error path has been observed. Unknown and
private content is therefore kept visible and bounded rather than forced into
a known category.

Known profile limits include definite-length BER only, the base VisibleString
MMS Identifier form (negotiated UTF-8 Identifiers are not yet connection-state
aware), plus a byte-exact compatibility exception for the mandatory
VMD-specific `TASE.2_Version` name in ObjectName and relevant GetNameList
Identifier/ContinueAfter positions. That exception does not admit other
punctuation or arbitrary UTF-8 identifiers. Other limits include IEEE
single/double MMS floating values and rejection of the valid MMS
`Data` GeneralizedTime alternative until its lexical forms are validated. The
profile rejects the RFC 1006 testing-only CR/CC initial-data extension, ISO
normal-format ED, and the RFC 1006/RFC 2126 negotiated class-0 expedited-data
extension. It dispatches one Presentation PDV or ACSE EXTERNAL
per containing value. Valid unsupported multiplicity or encoding profiles are
rejected or retained as opaque rather than partially dispatched.
Association-information dispatch additionally requires an explicit BER
direct-reference and an indirect-reference matching the unique proposed or
accepted MMS context for that negotiation phase. These are interoperability
limits, not evidence that the peer sent malformed ICCP.

This is a passive analyzer, not a TASE.2/MMS endpoint implementation. It does
not implement or claim the IEC 60870-6-702 conformance procedure, a complete
ISO 9506 Initiate CBB negotiation validator, or every service/state machine
required of a conforming client or server. A syntactically valid unsupported
form can therefore remain generic or be rejected by the documented parser
profile without establishing that the peer itself is nonconforming.

Specialized TASE.2 interpretation is also intentionally narrower than the full
object-model catalog. It covers the reviewed indication-point, control,
`DSTransferSet`, Data Set report, and Information Message evidence paths.
The exact IEC 60870-6-802 subset comprises the configured 20 `Data_*` layouts,
three direct control primitives, `SBO_CheckBackName`, and `Tag_Value`.

The 20 supported `Data_*` aliases are:

- `Data_Real`, `Data_Discrete`, `Data_State`, and
  `Data_StateSupplemental`;
- `Data_RealQ`, `Data_StateQ`, `Data_StateSupplementalQ`, and
  `Data_DiscreteQ`;
- `Data_RealQTimeTag`, `Data_StateQTimeTag`,
  `Data_StateSupplementalQTimeTag`, and `Data_DiscreteQTimeTag`;
- `Data_RealExtended`, `Data_StateExtended`,
  `Data_StateSupplementalExtended`, and `Data_DiscreteExtended`; and
- `Data_RealQTimeTagExtended`, `Data_StateQTimeTagExtended`,
  `Data_StateSupplementalQTimeTagExtended`, and
  `Data_DiscreteQTimeTagExtended`.

`IndicationPointConfig`, `ControlConfig`, standalone `COV_Counter`, the optional
SBO state structure, single/packed protection events, and device-outage
scheduling/report objects remain unnormalized MMS evidence. Transfer-account,
scheduling, and other unlisted families likewise remain generic. The older
Time Series and Transfer Account transfer-set models retained by IEC
60870-6-503:2014 for informational/historical use are not specialized. The
edition gives inconsistent status to its Information Message transfer-set
model: it retains explicit type, object, and report mappings while elsewhere
calling that model historical/informational or out of scope. The analyzer
recognizes only the documented AA-specific Boolean Start/Stop compatibility
path.

IEC 60870-6-802 contains an editorial spelling variation for the supplemental
state extended-time type. The analyzer uses
`Data_StateSupplementalQTimeTagExtended`, matching the mapping-table spelling;
this normalization does not add another supported proprietary type.
