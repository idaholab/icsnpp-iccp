# Parser Resource and Acceptance Limits

The analyzer applies explicit limits at each protocol layer before promoting
bytes to trusted ICCP semantics. These are compile-time parser constants unless
an individual public parser type accepts an optional stricter argument.

## MMS Data

| Limit | Default | Scope |
| --- | ---: | --- |
| Data nesting depth | 16 | Maximum nested MMS `array`/`structure` depth. This matches the maximum nesting level accepted by the supported MMS negotiation profile. `DataValue`, `DataChildren`, `AccessResult`, `AccessResultList`, and `DataList` accept an optional stricter depth argument. |
| Data value length | 1 MiB | Maximum encoded content length for one semantic MMS Data value. |
| Data forest value bytes | 4 MiB | Cumulative encoded content reserved across all roots and descendants in one Read result list or Write value list. Constructed parent and child lengths both count. |
| Data forest elements | 4,096 | Aggregate MMS Data/AccessResult nodes in one forest, shared with the BER element ceiling. |
| Primitive raw prefix | 256 bytes | Maximum raw primitive evidence retained by the parser. Original length and truncation state are transported separately. Constructed values retain decoded shape rather than complete parent bodies. |

The depth ceiling is a parser safety maximum, not a claim that a peer
negotiated that value. Initiate request/response nesting values remain visible
to policy. The parser currently uses the supported ceiling of 16 for packet
decoding and permits focused parser users to select a lower value.

## BER

| Limit | Default |
| --- | ---: |
| High-tag-number octets | 5 |
| Definite-length octets | 4 |
| One BER value | 16 MiB |
| BER nesting depth | 32 |
| BER elements per shared parse state | 4,096 |
| INTEGER content | 8 octets |
| OID arc encoding | 9 octets |
| OID encoded value | 1,024 bytes |
| OID arc count | 128 |
| Rendered OID text | 2,048 bytes |

Only definite BER lengths are accepted. Upper-layer MMS limits can reject a
value before the broader BER byte ceiling is reached.

## Transport and Session

| Layer | Limit | Default |
| --- | --- | ---: |
| TPKT | Packet length | 65,535 bytes |
| TPKT | Recovery scan | 1 MiB, in 64 KiB blocks |
| COTP | Parameters | 64 |
| COTP | Reassembled TSDU | 16 MiB |
| COTP | TSDU fragments | 256 |
| Session | Parameter nesting depth | 4 |
| Session | Parameters | 256 |
| Session | Presentation payload | 16 MiB |
| Session | SSDU fragments | 256 |

## Presentation and ACSE

| Layer | Limit | Default |
| --- | --- | ---: |
| Presentation | Contexts | 64 |
| Presentation | Transfer syntaxes per context | 16 |
| Presentation | PDV lists | 64 |
| Presentation | Normal-mode fields | 64 |
| ACSE | APDU fields | 64 |
| ACSE | EXTERNAL values | 16 |

Changing a limit requires rebuilding the Spicy analyzer and rerunning the
boundary, malformed-input, fuzz, and package-loading test suites. Limits should
only be raised with representative traffic and corresponding resource
measurements.
