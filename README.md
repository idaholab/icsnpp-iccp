# Build Status

[![build-and-test](https://github.com/idaholab/icsnpp-iccp/actions/workflows/build.yml/badge.svg)](https://github.com/idaholab/icsnpp-iccp/actions/workflows/build.yml)

# ICSNPP-ICCP

Industrial Control Systems Network Protocol Parsers (ICSNPP) - Inter-Control
Center Communications Protocol (ICCP), also known as TASE.2.

## Overview

ICSNPP-ICCP is a Zeek plugin, written in
[Spicy](https://docs.zeek.org/projects/spicy/en/latest/), for parsing and
logging ICCP/TASE.2 traffic carried over MMS.

The parser produces five log files:

- `iccp.log`
- `iccp_objects.log`
- `iccp_transfers.log`
- `iccp_controls.log`
- `iccp_errors.log`

See the [Logging Capabilities](#logging-capabilities) section for a summary of
each log. Complete field definitions are available in
[`docs/LOG_SCHEMA.md`](docs/LOG_SCHEMA.md).

## Architecture

The package installs one Zeek protocol analyzer. MMS and the supporting OSI
layers are internal parts of its decoding path:

```text
TCP/102
  -> TPKT and COTP
  -> OSI Session and Presentation
  -> ACSE and MMS
  -> ICCP classification and connection state
  -> Zeek events and logs
```

The analyzer tracks negotiated protocol context, association state, MMS
transactions, and direction-scoped capture completeness. It can recover
bounded records after TCP gaps or malformed input, while marking output that
may not represent a complete conversation.

## Installation

### Package Manager

This package requires Zeek 8.x and a compatible Zeek Spicy installation.

```bash
zkg refresh
zkg install https://github.com/idaholab/icsnpp-iccp
```

Confirm that Zeek can find the analyzer:

```bash
zeek -NN | grep ICCP
```

If `zkg` is configured to load installed packages, the analyzer and its Zeek
scripts will load automatically.

## Installation (via git clone)

The manual build requires Zeek 8.x, a compatible Spicy toolchain, CMake 3.15
or newer, and a supported C/C++ compiler.

```bash
git clone https://github.com/idaholab/icsnpp-iccp.git
cd icsnpp-iccp
cmake -S . -B build
cmake --build build --parallel 2
zkg install .
```

Spicy-generated C++ files can require significant memory while compiling. Use
`--parallel 1` on memory-constrained systems.

## Protocol Detection and Custom Ports

The ICCP analyzer uses port-based registration. The default server port is
`102/tcp`.

To retain the default and add another ICCP server port, extend
`ICCP::iccp_ports` in a Zeek site policy loaded after this package:

```zeek
redef ICCP::iccp_ports += { 12002/tcp };
```

The configured ports are registered with the analyzer and added to Zeek's
`likely_server_ports` direction heuristic. Adding a port only to
`likely_server_ports` does not enable parsing.

Port configuration is read when Zeek starts. Restart or redeploy the affected
Zeek processes after changing the set. This package does not provide a payload
signature for discovering ICCP on otherwise unregistered ports.

## Logging Capabilities

All five logs are enabled by default and can be disabled independently without
disabling protocol parsing or state tracking.

| Log | Configuration | Description |
| --- | --- | --- |
| `iccp.log` | `ICCP::enable_iccp_log` | Connection, protocol-layer, association, operation, provenance, and capture-completeness records. |
| `iccp_objects.log` | `ICCP::enable_iccp_objects_log` | Object references, names, values, and related MMS evidence. |
| `iccp_transfers.log` | `ICCP::enable_iccp_transfers_log` | Data set transfer configuration, lifecycle, reports, and bounded transfer evidence. |
| `iccp_controls.log` | `ICCP::enable_iccp_controls_log` | Control candidates and supported classified Write, Select, Tag, Operate, and device-action activity. |
| `iccp_errors.log` | `ICCP::enable_iccp_errors_log` | Correlated MMS confirmed-service errors and diagnostics. |

The parser keeps uncertain or incomplete evidence explicit. A well-formed MMS
operation may be logged without being classified as ICCP when the required
association, object, type, direction, or transaction evidence is unavailable.

See [`docs/LOG_SCHEMA.md`](docs/LOG_SCHEMA.md) for all fields, types,
optionality, limits, and compatibility rules.

## Configuring TASE.2 Object Types

Exact point and control classification requires an explicit site mapping.
Mappings identify the server, peer, MMS scope, domain, object name, and
expected standardized type.

```zeek
redef ICCP::configured_variable_types += {
    [192.0.2.20, 192.0.2.10, 0, "", "BREAKER_1"] = "Control_Command",
    [192.0.2.20, 192.0.2.10, 1, "CONTROL_CENTER_B", "MW_FLOW"] =
        "Data_RealQ"
};
```

Scopes are `0` for VCC, `1` for domain/ICC, and `2` for
association-specific objects. A configured type is activated only after the
analyzer observes the required association and verified MMS type evidence.
Shape-equivalent standardized types still require an explicit site mapping.

See [`docs/COVERAGE.md`](docs/COVERAGE.md) for the complete classification and
trust requirements.

## Coverage

The parser implements a documented subset of ICCP/TASE.2, MMS, ACSE,
Presentation, Session, COTP, and TPKT. It is a passive network analyzer, not a
TASE.2 endpoint or protocol-conformance test suite.

- [`docs/COVERAGE.md`](docs/COVERAGE.md) describes implemented behavior and
  known limits.
- [`docs/STANDARDS_TRACEABILITY.md`](docs/STANDARDS_TRACEABILITY.md) maps the
  implementation to the reviewed IEC and ISO standards.
- [`docs/LOG_SCHEMA.md`](docs/LOG_SCHEMA.md) documents the public log schema.

## Developer Testing

Run the complete local verification workflow with:

```bash
bash testing/scripts/verify
```

The workflow builds the analyzer and runs parser, policy, malformed-input,
schema, package-installation, and supported-version tests. Some validation
steps require Wireshark command-line tools and standard Unix utilities; see the
verification script for the complete dependency checks.

## ICSNPP Packages

Additional ICSNPP protocol parsers are available from the
[ICSNPP project](https://github.com/cisagov/icsnpp).

### License

See [`LICENSE`](LICENSE), [`NOTICE - ICCP.txt`](NOTICE%20-%20ICCP.txt), and
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
