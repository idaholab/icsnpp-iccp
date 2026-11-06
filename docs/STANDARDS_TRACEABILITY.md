# Standards Traceability and Release Boundary

## Purpose

This record maps the parser's implemented profile to the standards available
during the 2026-09-09 review. It is an engineering traceability assessment, not
a product certification or a substitute for the standards themselves.

The comparison used these local reference editions:

- IEC 60870-6-503:2014, TASE.2 services and protocol;
- IEC 60870-6-802:2014, TASE.2 object models;
- ISO 9506-1:2003, MMS service definition; and
- ISO 9506-2:2003, MMS protocol specification.

The licensed reference files are intentionally ignored by Git and are not part
of the package, test corpus, or generated documentation.

## Status terms

- **Aligned** means only that the named, implemented behavior was compared
  with the cited definition and has focused regression evidence. It does not
  mean that the analyzer or a peer satisfies a standards conformance block.
- **Corrected** means the comparison found a discrepancy and this worktree now
  contains a corresponding code and regression change.
- **Partial** means useful standards-based behavior is present, but some
  conformant variants or semantic correlation remain deliberately unsupported.
- **Generic** means the parser safely exposes MMS evidence without assigning a
  stronger TASE.2 meaning.

## Traceability summary

| Standards area | Reference area | Result in this worktree |
| --- | --- | --- |
| TASE.2 association and bootstrap | IEC 60870-6-503, 5.3.3 and 7.2.2 | Partial. Association lifecycle and individual fixed bootstrap values, including the expected TASE.2 version value, are shape/value checked. One verified value can establish analyzer classification, so the complete three-object exchange is neither required nor treated as conformance proof. Because both peers may act as client and server on one association, a verified Bilateral Table Domain is owned by the serving endpoint. A conflicting second Domain for the same serving endpoint invalidates that endpoint's mapping until association reset without contaminating the peer's independent server VCC. |
| TASE.2-to-MMS service mapping | IEC 60870-6-503, Clause 7 and Annex A | Aligned at the operation-tag level for the implemented GetNameList, Identify, Read, Write, GetVariableAccessAttributes, named-list, InformationReport, and EventNotification subset. This is not full service-procedure coverage. |
| MMS service semantics | ISO 9506-1, Clauses 7-8, 10, 14, and 18 | Partial. The analyzer observes the implemented protocol exchanges and correlations; it does not implement MMS-user/provider behavior, local object models, access-control decisions, or the service conformance requirements of an endpoint. |
| Data Value and type discovery | IEC 60870-6-503, 7.2.3; ISO 9506-2, 14.9 | Corrected/partial. A configured name is an expectation, not wire evidence. Learning first requires exact bootstrap Read evidence to classify the association as TASE.2, then verified parser provenance, a direction-correct response, `mmsDeletable=false`, the implemented alias-specific basic scope/name checks, and equality between the complete resolved recursive `TypeDescription` and one supported structural signature. Nested TypeSpecification `typeName` is legal but unresolved and therefore cannot activate a mapping. Optional component names are not used as type identity, and shape-equivalent standardized aliases still require site configuration. Domain-specific configured objects are not required to match the serving endpoint's learned Bilateral Table Domain; this is a site-policy relaxation rather than proof of the IEC client-Domain mapping. Type activation for `SBO_CheckBackName` also does not independently enforce the `_SBO` suffix, although exact Select classification does. |
| Data Set lifecycle | IEC 60870-6-503, 7.2.4; ISO 9506-2, 14.12-14.14 | Corrected/partial. Learned state is endpoint-owned. Creation mutates it only for a Domain-specific list name with complete named members. Non-special members must use VMD- or Domain-specific ObjectNames, the four special transfer objects must be Domain-specific, and packet-derived members containing `AlternateAccess` remain observable but unverified. The analyzer does not independently prove that each non-special member is a Data Value, or enforce Bilateral/list-Domain equality. A positive Define of a previously verified name is a standards deviation and cannot replace existing membership. Deletion mutates state only for a nonempty SPECIFIC vector of Domain-specific names. A positive response whose matched or deleted count differs from the requested name count is flagged as a standards deviation; zero deletions preserve prior state, while any positive aggregate deletion invalidates every requested identity because the response does not identify individual successes. Active Transfer Set references are not checked before accepting observed deletion. GetNamedVariableListAttributes responses do not teach predefined membership or validate the scope-dependent `mmsDeletable` rule. Other MMS selectors remain observable but unverified. |
| Data Set Transfer Set parameters | IEC 60870-6-503, 7.2.5 and 8.2.7 | Corrected/partial. The Domain-specific outer variable, 13 ordered fields, parameter bounds, embedded identity scope, and full active-state key are checked. `parameters_conformant` describes the supported structural/value checks on that request only; correspondence between the outer/embedded Domains and the learned Bilateral Table Domain, allocation, and the complete Start/Stop/report sequence are not thereby proven. |
| Transfer reports | IEC 60870-6-503, 7.2.5.5 | Partial. Ordinary report identity and available result rows are bounded and state-correlated. BlockData access, available top-level special-value shapes, payload cardinality/type, and rule byte are checked, but blocked member contents remain unverified without their IEC 60870-6-802 storage types. Named-list active correlation does not independently require membership/result cardinality equality, and RBE/BlockData handling does not prove that every special member included in the Data Set appeared in its required report form. Actual client InformationReport ACK/NACK correlation is not implemented. |
| Information Message transfer and reports | IEC 60870-6-503, 5.2.7-5.2.8, 6.8, 7.2.5.5.4, 8.2.7, 8.3.6-8.3.9, and 8.5; IEC 60870-6-802, 6.4 | Partial. The AA-specific `IM_Transfer_Set` Boolean Start/Stop compatibility path is recognized. IEC 60870-6-503:2014 is internally inconsistent about this path: some clauses specify it or call its type normative, while others call the transfer-set model historical/informational or out of scope. The exact ordered `Info_Mess_Header` / `Info_Buff_XX` pair is recognized in known-list and explicit-variable reports, and header/capacity constraints are checked. The edition also contains a conflicting single-`f` buffer spelling elsewhere; that form remains generic. Arbitrary message bodies are deliberately omitted and other representations remain generic. |
| Point value types | IEC 60870-6-802, 6.2.1 | Aligned only for the configured 20 `Data_*` layouts listed in the coverage document. Classification requires a matching resolved type signature, a matching value shape, and VMD- or Domain-specific scope; later InformationReport results are not all normalized to point-family fields. |
| Control and tag types | IEC 60870-6-802, 6.2.2; IEC 60870-6-503, 7.2.6 | Partial/aligned subset for three direct control primitives, `SBO_CheckBackName`, and `Tag_Value` under the documented evidence model. The optional SBO state structure and broader control object model are not normalized. AA-specific objects do not receive these labels. Exact Select requires `_SBO`, but GVA type activation alone currently accepts a configured `SBO_CheckBackName` on another valid VMD/Domain identifier. |
| Optional object-model families | IEC 60870-6-802, Clauses 5-7 | Generic. Configuration/SBO-state, protection-event, DeviceOutage, transfer-account, scheduling, and other unlisted semantic families are not specialized. |
| MMS object names, access, values, and types | ISO 9506-2, Clauses 7 and 14; IEC 60870-6-503, 8.3.4 | Corrected/partial. Implemented ObjectName, VariableSpecification, AlternateAccess, Data, AccessResult, and TypeDescription forms are recursively bounded. The analyzer intentionally supports only definite-length BER and a subset of encoding/profile variants; negotiated Identifier character-set variants are not connection-state aware. A byte-exact exception admits the mandatory VMD-specific `TASE.2_Version` name in ObjectName and relevant GetNameList Identifier/ContinueAfter positions without widening the ordinary base Identifier repertoire. |
| MMS errors and rejects | ISO 9506-2, Clauses 7-8 | Corrected/partial. Implemented enum holes, ordering, and supported service-specific forms are validated. Public logging does not yet distinguish an absent additional code from every possible signed value. |
| MMS Initiate and Conclude | ISO 9506-2, Clause 8 | Partial. Fields and directions are parsed and lifecycle state is bounded. Full Initiate proposal/response subset negotiation validation is not a claimed feature. |

## Material corrections found by the direct comparison

The standards pass identified issues that broader parser and safety tests did
not reveal. The current remediation set includes:

- correcting the outer `DSTransferSet` object from VMD-specific to
  Domain-specific scope;
- separating learned variable and named-list state by the endpoint that owns
  the object;
- separating Bilateral Table Domain evidence by serving endpoint, including
  sticky per-endpoint ambiguity after a conflicting bootstrap observation;
- restricting exact point, control, and tag attribution to their implemented
  alias-specific VMD/Domain scope checks;
- restricting `DSTransferSet` to Domain scope and `DSConditions` to the exact
  `DSConditions_Detected` item name in Domain scope;
- retaining all names in a specific named-list deletion request;
- keying active Transfer Sets by connection, client role, scope, domain, and
  name and preserving prior state after a peer incorrectly accepts a duplicate
  Start;
- treating every nonzero one-octet BER Boolean as a valid TRUE encoding;
- decoding the mandatory fixed `TASE.2_Version` name despite the period that
  requires the MMS `char` form or narrow profile compatibility handling;
- distinguishing a Read of an ACK/NACK support object from an actual
  InformationReport acknowledgement;
- validating the BlockData access/result header and rule while leaving opaque
  blocked member contents explicitly unverified;
- accepting the exact explicit-variable Information Message header/buffer
  pair as well as a previously verified named-list pair;
- tightening recursive TypeDescription and AlternateAccess grammar, required
  nonempty collections, VariableSpecification direction, ServiceError/Reject
  alternatives, GeneralizedTime handling, and Conclude direction state; and
- requiring verified provenance, a non-deletable fully resolved recursive GVA
  type match, and implemented alias-specific basic scope/name checks before
  activating configured type state.

The corrections have focused regression evidence under `testing/`. Those tests
are evidence for the implemented paths, not a formal protocol-conformance
suite or a claim about untested variants.

## What this assessment can and cannot confirm

The available references support the limited statement that the listed parser
paths were designed and tested against a bounded subset of the 2014 TASE.2
service/object model over the 2003 MMS edition. They do not support a claim of
complete TASE.2 or MMS conformance.

In particular, IEC 60870-6-503 delegates formal TASE.2 conformance to IEC
60870-6-702, which was not in the reviewed reference set. The review also did
not include every applicable OSI/RFC base standard, later amendment or
corrigendum, a formal protocol-conformance suite, or representative captures
from every vendor/profile combination.

The accurate release description is therefore:

> A passive, bounded ICCP/TASE.2 analyzer implementing the documented IEC
> 60870-6-503/-802 and ISO 9506 subset, with unimplemented or unverified forms
> retained as generic evidence or rejected by the documented parser limits.

Do not describe the package as fully IEC-certified, fully MMS-conformant, or a
complete implementation of every TASE.2 conformance block.
