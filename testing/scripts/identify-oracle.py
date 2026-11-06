#!/usr/bin/env python3

"""Independent, bounded MMS Identify semantic oracle.

The input is classic PCAP with one raw MMS PDU per DLT_USER0 packet. This
module imports neither the production Spicy grammar nor the TCP/MMS extractor.
Captured identity strings are represented only by lengths and three independent
fingerprints in its private normalized output.
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import pathlib
import stat
import struct
import sys
import tempfile
from collections.abc import Iterator
from typing import BinaryIO, TextIO


MAX_HIGH_TAG_OCTETS = 5
MAX_LENGTH_OCTETS = 4
MAX_VALUE_LENGTH = 16 * 1024 * 1024
MAX_CAPTURE_PACKETS = 1_000_000
MAX_CAPTURE_BYTES = 512 * 1024 * 1024
MAX_ELEMENT_COUNT = 4096
MAX_INTEGER_OCTETS = 8
MAX_OID_ARC_OCTETS = 9
MAX_TOTAL_ABSTRACT_SYNTAXES = 1_000_000
MAX_OUTPUT_RECORDS = 1_000_000
MAX_OUTPUT_BYTES = 1024 * 1024 * 1024
HASH_PARAMETERS = (
    (257, 4294967291),
    (263, 4294967279),
    (269, 4294967231),
)


class OracleError(ValueError):
    """A bounded structural or semantic validation failure."""


@dataclasses.dataclass
class OutputBudget:
    records: int = 0
    bytes_written: int = 0

    def add_record(self) -> None:
        self.records += 1
        if self.records > MAX_OUTPUT_RECORDS:
            raise OracleError("Identify records exceed aggregate output-row bound")

    def _reserve(self, byte_count: int) -> None:
        if self.bytes_written + byte_count > MAX_OUTPUT_BYTES:
            raise OracleError("derived artifacts exceed aggregate output-byte bound")
        self.bytes_written += byte_count

    def write_text(self, output: TextIO, value: str) -> None:
        self._reserve(len(value.encode(output.encoding or "ascii")))
        output.write(value)

    def write_binary(self, output: BinaryIO, value: bytes) -> None:
        self._reserve(len(value))
        output.write(value)


@dataclasses.dataclass(frozen=True)
class TLV:
    tag_class: int
    constructed: bool
    tag: int
    value: bytes
    end: int


@dataclasses.dataclass(frozen=True)
class Identify:
    pdu_type: int
    invoke_id: int
    vendor: bytes = b""
    model: bytes = b""
    revision: bytes = b""
    abstract_syntaxes: tuple[str, ...] = ()


@dataclasses.dataclass
class Counters:
    packets: int = 0
    non_identify: int = 0
    requests: int = 0
    responses: int = 0
    abstract_syntaxes: int = 0


@dataclasses.dataclass(frozen=True)
class StagedArtifact:
    temporary: pathlib.Path
    final: pathlib.Path
    inode: tuple[int, int]


class ArtifactTransaction:
    """Stage private files beside their targets and publish without replacement."""

    def __init__(self) -> None:
        self.artifacts: list[StagedArtifact] = []

    def __enter__(self) -> "ArtifactTransaction":
        return self

    def _descriptor(self, path: pathlib.Path) -> int:
        try:
            parent = path.parent.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise OracleError(f"unable to resolve output parent: {path}") from error
        final = parent / path.name
        if any(artifact.final == final for artifact in self.artifacts):
            raise OracleError(f"duplicate transactional output: {path}")
        descriptor, temporary = tempfile.mkstemp(
            prefix=".iccp-stage-", suffix=".tmp", dir=parent
        )
        try:
            os.fchmod(descriptor, 0o600)
        except BaseException:
            os.close(descriptor)
            pathlib.Path(temporary).unlink(missing_ok=True)
            raise
        metadata = os.fstat(descriptor)
        self.artifacts.append(
            StagedArtifact(
                pathlib.Path(temporary), final,
                (metadata.st_dev, metadata.st_ino),
            )
        )
        return descriptor

    def open_binary(self, path: pathlib.Path) -> BinaryIO:
        descriptor = self._descriptor(path)
        try:
            return os.fdopen(descriptor, "wb")
        except BaseException:
            os.close(descriptor)
            raise

    def open_text(self, path: pathlib.Path, encoding: str = "ascii") -> TextIO:
        descriptor = self._descriptor(path)
        try:
            return os.fdopen(
                descriptor, "w", encoding=encoding, newline=""
            )
        except BaseException:
            os.close(descriptor)
            raise

    def _cleanup_staging(self, suppress_errors: bool = True) -> None:
        first_error: OSError | None = None
        for artifact in self.artifacts:
            try:
                artifact.temporary.unlink(missing_ok=True)
            except OSError as error:
                if first_error is None:
                    first_error = error
        if first_error is not None and not suppress_errors:
            raise first_error

    def _publish(self) -> None:
        try:
            for artifact in self.artifacts:
                metadata = artifact.temporary.stat(follow_symlinks=False)
                if (
                    (metadata.st_dev, metadata.st_ino) != artifact.inode
                    or not stat.S_ISREG(metadata.st_mode)
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                ):
                    raise OracleError("staged artifact identity or mode changed")
                os.link(
                    artifact.temporary,
                    artifact.final,
                    follow_symlinks=False,
                )
                final_metadata = artifact.final.stat(follow_symlinks=False)
                if (
                    (final_metadata.st_dev, final_metadata.st_ino)
                    != artifact.inode
                    or not stat.S_ISREG(final_metadata.st_mode)
                ):
                    raise OracleError("published artifact identity changed")
            self._cleanup_staging(suppress_errors=False)
        except BaseException:
            # Never unlink a final pathname here.  A check-then-unlink rollback
            # would race with another process replacing that name after the
            # check.  Each successfully linked artifact is complete and stays
            # published; the exception reports that the set did not finish.
            self._cleanup_staging()
            raise

    def __exit__(self, exception_type, exception, traceback) -> bool:
        if exception_type is not None:
            self._cleanup_staging()
            return False
        self._publish()
        return False


def validate_artifact_paths(
    input_paths: list[tuple[str, pathlib.Path]],
    output_paths: list[tuple[str, pathlib.Path]],
) -> None:
    """Reject path, symlink-target, and hard-link aliases before creation."""

    for description, path in output_paths:
        if path.is_symlink():
            raise OracleError(f"{description} must not be a symbolic link: {path}")

    seen_paths: dict[pathlib.Path, str] = {}
    seen_inodes: dict[tuple[int, int], str] = {}
    for description, path in input_paths + output_paths:
        try:
            resolved = path.resolve(strict=False)
        except (OSError, RuntimeError) as error:
            raise OracleError(f"unable to resolve {description}: {path}") from error
        if resolved in seen_paths:
            raise OracleError(
                f"path collision between {seen_paths[resolved]} and {description}: "
                f"{path}"
            )
        seen_paths[resolved] = description
        try:
            metadata = path.stat()
        except FileNotFoundError:
            continue
        inode = (metadata.st_dev, metadata.st_ino)
        if inode in seen_inodes:
            raise OracleError(
                f"inode collision between {seen_inodes[inode]} and {description}: "
                f"{path}"
            )
        seen_inodes[inode] = description

    for description, path in output_paths:
        if path.exists():
            raise FileExistsError(f"{description} already exists: {path}")


def value_hash(value: bytes, multiplier: int, modulus: int) -> int:
    result = 0
    for octet in value:
        result = (result * multiplier + octet) % modulus
    return result


def value_hashes(value: bytes) -> tuple[int, int, int]:
    return tuple(
        value_hash(value, multiplier, modulus)
        for multiplier, modulus in HASH_PARAMETERS
    )


def _identifier(data: bytes, offset: int, limit: int) -> tuple[int, bool, int, int]:
    if offset >= limit:
        raise OracleError("truncated BER identifier")
    first = data[offset]
    offset += 1
    tag_class = first >> 6
    constructed = bool(first & 0x20)
    tag = first & 0x1F
    if tag != 0x1F:
        return tag_class, constructed, tag, offset

    tag = 0
    for index in range(MAX_HIGH_TAG_OCTETS):
        if offset >= limit:
            raise OracleError("truncated BER high-tag-number")
        octet = data[offset]
        offset += 1
        if index == 0 and octet & 0x7F == 0:
            raise OracleError("non-minimal BER high-tag-number")
        tag = (tag << 7) | (octet & 0x7F)
        if not octet & 0x80:
            if tag < 31:
                raise OracleError("non-minimal BER high-tag-number")
            return tag_class, constructed, tag, offset
    raise OracleError("BER high-tag-number exceeds bound")


def _length(data: bytes, offset: int, limit: int) -> tuple[int, int]:
    if offset >= limit:
        raise OracleError("truncated BER length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0:
        raise OracleError("indefinite BER length is unsupported")
    if count > MAX_LENGTH_OCTETS or offset + count > limit:
        raise OracleError("BER length-of-length exceeds bound or is truncated")
    if data[offset] == 0:
        raise OracleError("non-minimal BER long-form length")
    result = int.from_bytes(data[offset : offset + count], "big")
    if result < 0x80:
        raise OracleError("non-minimal BER long-form length")
    return result, offset + count


def read_tlv(data: bytes, offset: int = 0) -> TLV:
    tag_class, constructed, tag, offset = _identifier(data, offset, len(data))
    length, value_offset = _length(data, offset, len(data))
    if length > MAX_VALUE_LENGTH or value_offset + length > len(data):
        raise OracleError("BER value exceeds bound or is truncated")
    end = value_offset + length
    return TLV(tag_class, constructed, tag, data[value_offset:end], end)


def read_children(data: bytes) -> tuple[TLV, ...]:
    children: list[TLV] = []
    offset = 0
    while offset < len(data):
        if len(children) >= MAX_ELEMENT_COUNT:
            raise OracleError("BER element count exceeds bound")
        child = read_tlv(data, offset)
        children.append(child)
        offset = child.end
    return tuple(children)


def decode_integer(value: bytes) -> int:
    if not value or len(value) > MAX_INTEGER_OCTETS:
        raise OracleError("MMS INTEGER width is invalid")
    if len(value) > 1 and (
        (value[0] == 0 and value[1] & 0x80 == 0)
        or (value[0] == 0xFF and value[1] & 0x80)
    ):
        raise OracleError("MMS INTEGER is not minimally encoded")
    result = int.from_bytes(value, "big", signed=bool(value[0] & 0x80))
    if result < 0:
        raise OracleError("MMS invoke ID is negative")
    return result


def decode_oid(value: bytes) -> str:
    if not value:
        raise OracleError("BER OBJECT IDENTIFIER has an empty value")
    components: list[int] = []
    component = 0
    component_octets = 0
    for octet in value:
        if component_octets == 0 and octet == 0x80:
            raise OracleError("BER OBJECT IDENTIFIER is not minimally encoded")
        component_octets += 1
        if component_octets > MAX_OID_ARC_OCTETS:
            raise OracleError("BER OBJECT IDENTIFIER component exceeds bound")
        component = (component << 7) | (octet & 0x7F)
        if not octet & 0x80:
            components.append(component)
            component = 0
            component_octets = 0
    if component_octets or not components:
        raise OracleError("BER OBJECT IDENTIFIER component is truncated")
    first = components.pop(0)
    if first < 40:
        arcs = [0, first]
    elif first < 80:
        arcs = [1, first - 40]
    else:
        arcs = [2, first - 80]
    return ".".join(str(arc) for arc in (*arcs, *components))


def _validate_mms_string(value: bytes) -> None:
    try:
        value.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise OracleError("MMS Identify string is not valid UTF-8") from error


def parse_identify(pdu: bytes) -> Identify | None:
    outer = read_tlv(pdu)
    if outer.end != len(pdu):
        raise OracleError("MMS PDU has trailing bytes")
    if outer.tag_class != 2 or outer.tag not in (0, 1):
        return None
    if not outer.constructed:
        raise OracleError("MMS confirmed PDU is primitive")
    fields = read_children(outer.value)
    if len(fields) < 2:
        raise OracleError("MMS confirmed PDU has too few fields")
    invoke = fields[0]
    if invoke.tag_class != 0 or invoke.constructed or invoke.tag != 2:
        raise OracleError("MMS confirmed PDU has invalid invoke ID")
    invoke_id = decode_integer(invoke.value)

    service_index = 1
    if outer.tag == 0 and fields[1].tag_class == 0 and fields[1].tag == 16:
        if not fields[1].constructed or not read_children(fields[1].value):
            raise OracleError("MMS modifier list is invalid or empty")
        service_index += 1
    if service_index >= len(fields):
        raise OracleError("MMS confirmed PDU is missing a service")
    service = fields[service_index]
    if service.tag_class != 2:
        raise OracleError("MMS confirmed service is not context-specific")
    if service_index + 1 < len(fields):
        detail = fields[service_index + 1]
        if (
            service_index + 2 != len(fields)
            or detail.tag_class != 2
            or not detail.constructed
            or detail.tag != 79
        ):
            raise OracleError("MMS confirmed PDU has invalid trailing fields")
    if service.tag != 2:
        return None

    if outer.tag == 0:
        if service.constructed or service.value:
            raise OracleError("MMS Identify request is not primitive NULL")
        return Identify(0, invoke_id)

    if not service.constructed:
        raise OracleError("MMS Identify response is primitive")
    response = read_children(service.value)
    if len(response) not in (3, 4):
        raise OracleError("MMS Identify response has invalid field count")
    strings: list[bytes] = []
    for tag, field in enumerate(response[:3]):
        if field.tag_class != 2 or field.constructed or field.tag != tag:
            raise OracleError("MMS Identify response fields are invalid or out of order")
        _validate_mms_string(field.value)
        strings.append(field.value)
    syntaxes: tuple[str, ...] = ()
    if len(response) == 4:
        syntax_list = response[3]
        if syntax_list.tag_class != 2 or not syntax_list.constructed or syntax_list.tag != 3:
            raise OracleError("MMS Identify abstract-syntax list is invalid")
        oid_fields = read_children(syntax_list.value)
        for field in oid_fields:
            if field.tag_class != 0 or field.constructed or field.tag != 6:
                raise OracleError("MMS Identify abstract syntax is not an OID")
        syntaxes = tuple(decode_oid(field.value) for field in oid_fields)
    return Identify(1, invoke_id, *strings, syntaxes)


def record_line(index: int, value: Identify) -> str:
    first_syntax = value.abstract_syntaxes[0] if value.abstract_syntaxes else ""
    fields: list[object] = ["I", index, value.pdu_type, value.invoke_id]
    for identity in (value.vendor, value.model, value.revision):
        fields.extend((len(identity), *value_hashes(identity)))
    fields.extend((len(value.abstract_syntaxes), first_syntax))
    return "\t".join(str(field) for field in fields)


def pcap_packets(path: pathlib.Path) -> Iterator[bytes]:
    with path.open("rb") as handle:
        header = handle.read(24)
        if len(header) != 24:
            raise OracleError("truncated PCAP header")
        if header[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            byte_order = "<"
        elif header[:4] in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            byte_order = ">"
        else:
            raise OracleError("input is not classic PCAP")
        version_major, version_minor, _, _, snaplen, network = struct.unpack(
            byte_order + "HHIIII", header[4:]
        )
        if (version_major, version_minor) != (2, 4):
            raise OracleError("unsupported classic PCAP format version")
        if snaplen == 0 or snaplen > MAX_VALUE_LENGTH:
            raise OracleError("invalid PCAP snaplen")
        if network != 147:
            raise OracleError("oracle input must use DLT_USER0")
        packet_count = 0
        captured_bytes = 0
        while True:
            packet_header = handle.read(16)
            if not packet_header:
                return
            if len(packet_header) != 16:
                raise OracleError("truncated PCAP packet header")
            _, _, captured, original = struct.unpack(byte_order + "IIII", packet_header)
            if captured > MAX_VALUE_LENGTH or captured > snaplen or captured > original:
                raise OracleError("invalid PCAP packet length")
            if captured != original:
                raise OracleError("snap-truncated PCAP packet")
            packet_count += 1
            if packet_count > MAX_CAPTURE_PACKETS:
                raise OracleError("PCAP packet count exceeds bound")
            captured_bytes += captured
            if captured_bytes > MAX_CAPTURE_BYTES:
                raise OracleError("PCAP captured bytes exceed bound")
            packet = handle.read(captured)
            if len(packet) != captured:
                raise OracleError("truncated PCAP packet")
            yield packet


def _analyze(path: pathlib.Path, records_path: pathlib.Path,
             summary_path: pathlib.Path, pdus_path: pathlib.Path | None,
             transaction: ArtifactTransaction) -> Counters:
    counters = Counters()
    output_budget = OutputBudget()
    outputs = [("records output", records_path), ("summary output", summary_path)]
    if pdus_path is not None:
        outputs.append(("PDU output", pdus_path))
    validate_artifact_paths([("input PCAP", path)], outputs)
    records_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    if pdus_path is not None:
        pdus_path.parent.mkdir(parents=True, exist_ok=True)
    with transaction.open_text(records_path) as records:
        pdu_output = (
            transaction.open_binary(pdus_path) if pdus_path is not None else None
        )
        try:
            index = 0
            for packet in pcap_packets(path):
                counters.packets += 1
                identify = parse_identify(packet)
                if identify is None:
                    counters.non_identify += 1
                    continue
                index += 1
                output_budget.add_record()
                if identify.pdu_type == 0:
                    counters.requests += 1
                else:
                    counters.responses += 1
                counters.abstract_syntaxes += len(identify.abstract_syntaxes)
                if counters.abstract_syntaxes > MAX_TOTAL_ABSTRACT_SYNTAXES:
                    raise OracleError("Identify abstract syntaxes exceed aggregate bound")
                output_budget.write_text(records, record_line(index, identify) + "\n")
                if pdu_output is not None:
                    output_budget.write_binary(pdu_output, packet)
        finally:
            if pdu_output is not None:
                pdu_output.close()
    with transaction.open_text(summary_path) as summary:
        for field in dataclasses.fields(Counters):
            output_budget.write_text(
                summary,
                f"identify.{field.name}\t{getattr(counters, field.name)}\n",
            )
    return counters


def analyze(path: pathlib.Path, records_path: pathlib.Path,
            summary_path: pathlib.Path, pdus_path: pathlib.Path | None) -> Counters:
    with ArtifactTransaction() as transaction:
        return _analyze(
            path, records_path, summary_path, pdus_path, transaction
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input_pcap", type=pathlib.Path)
    parser.add_argument("records", type=pathlib.Path)
    parser.add_argument("summary", type=pathlib.Path)
    parser.add_argument("--pdus", type=pathlib.Path)
    args = parser.parse_args()
    try:
        counters = analyze(args.input_pcap, args.records, args.summary, args.pdus)
    except (OSError, OracleError) as error:
        print(f"identify oracle: {error}", file=sys.stderr)
        return 1
    print(f"identify_requests={counters.requests}")
    print(f"identify_responses={counters.responses}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
