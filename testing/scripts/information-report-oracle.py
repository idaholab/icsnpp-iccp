#!/usr/bin/env python3

"""Independent, bounded MMS Read/InformationReport and TASE.2 oracle.

The input is a classic-PCAP file whose DLT_USER0 packets each contain one raw
MMS PDU (the format emitted by extract-local-mms.py).  This module deliberately
does not import the production Spicy grammar or the local TCP/MMS extractor.
It validates MMS structure and Data encodings, then independently counts
supported TASE.2 indication-type wire-shape candidates. Shape
candidates are not point-type claims: a trusted classification additionally
requires an explicit site type mapping activated by a correlated, valid
GetVariableAccessAttributes exchange for the same object and connection.
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
MAX_NESTING_DEPTH = 32
MAX_ELEMENT_COUNT = 4096
MAX_INTEGER_OCTETS = 8
MAX_METADATA_ROWS = 1_000_000
MAX_TYPE_MAPPINGS = 65_536
MAX_SIDECAR_BYTES = 64 * 1024 * 1024
MAX_PENDING_CORRELATIONS = 65_536
MAX_TOTAL_RESULTS = 1_000_000
MAX_TOTAL_DATA_NODES = 4_000_000
MAX_CLASSIFICATIONS = 1_000_000
MAX_OUTPUT_ROWS = 3_000_000
MAX_OUTPUT_BYTES = 1024 * 1024 * 1024
HASH_PARAMETERS = (
    (257, 4294967291),
    (263, 4294967279),
    (269, 4294967231),
)
TASE2_INDICATION_TYPES = (
    "Data_Real",
    "Data_State",
    "Data_StateSupplemental",
    "Data_Discrete",
    "Data_RealQ",
    "Data_StateQ",
    "Data_StateSupplementalQ",
    "Data_DiscreteQ",
    "Data_RealQTimeTag",
    "Data_StateQTimeTag",
    "Data_DiscreteQTimeTag",
    "Data_StateSupplementalQTimeTag",
    "Data_RealExtended",
    "Data_StateExtended",
    "Data_DiscreteExtended",
    "Data_StateSupplementalExtended",
    "Data_RealQTimeTagExtended",
    "Data_StateQTimeTagExtended",
    "Data_DiscreteQTimeTagExtended",
    "Data_StateSupplementalQTimeTagExtended",
)
SUPPORTED_TASE2_POINT_TYPES = (
    "Data_Real",
    "Data_Discrete",
    "Data_State",
    "Data_StateSupplemental",
    "Data_RealQ",
    "Data_StateQ",
    "Data_StateSupplementalQ",
    "Data_DiscreteQ",
    "Data_RealQTimeTag",
    "Data_StateQTimeTag",
    "Data_StateSupplementalQTimeTag",
    "Data_DiscreteQTimeTag",
    "Data_RealExtended",
    "Data_StateExtended",
    "Data_StateSupplementalExtended",
    "Data_DiscreteExtended",
    "Data_RealQTimeTagExtended",
    "Data_StateQTimeTagExtended",
    "Data_StateSupplementalQTimeTagExtended",
    "Data_DiscreteQTimeTagExtended",
)


class OracleError(ValueError):
    """A bounded structural or semantic validation failure."""


@dataclasses.dataclass
class OutputBudget:
    rows: int = 0
    bytes_written: int = 0

    def _reserve(self, byte_count: int, row_count: int = 0) -> None:
        if self.rows + row_count > MAX_OUTPUT_ROWS:
            raise OracleError("derived artifacts exceed aggregate output-row bound")
        if self.bytes_written + byte_count > MAX_OUTPUT_BYTES:
            raise OracleError("derived artifacts exceed aggregate output-byte bound")
        self.rows += row_count
        self.bytes_written += byte_count

    def write_text(
        self, output: TextIO, value: str, rows: int | None = None
    ) -> None:
        if rows is None:
            rows = value.count("\n")
        self._reserve(len(value.encode(output.encoding or "utf-8")), rows)
        output.write(value)

    def write_binary(self, output: BinaryIO, value: bytes) -> None:
        self._reserve(len(value))
        output.write(value)


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


@dataclasses.dataclass(frozen=True)
class TLV:
    tag_class: int
    constructed: bool
    tag: int
    value: bytes
    start: int
    value_start: int
    end: int


@dataclasses.dataclass(frozen=True)
class ObjectName:
    scope: int = 0
    domain: str = ""
    item: str = ""


@dataclasses.dataclass(frozen=True)
class DataNode:
    choice: int
    raw: bytes
    children: tuple["DataNode", ...] = ()
    integer: int = 0


# Canonical post-order TypeDescription node:
# (choice, primary parameter, secondary parameter, child count, packed).
TypeDescriptionNode = tuple[int, int, int, int, bool]


@dataclasses.dataclass(frozen=True)
class GvaAttributes:
    deletable: bool
    signature: tuple[TypeDescriptionNode, ...]
    unresolved_type_names: int

    @property
    def choice(self) -> int:
        return self.signature[-1][0]


@dataclasses.dataclass(frozen=True)
class AccessResult:
    choice: int
    error: int
    raw: bytes
    node: DataNode | None


@dataclasses.dataclass(frozen=True)
class InformationReport:
    access_choice: int
    variable_count: int
    first_variable: ObjectName
    named_list: ObjectName
    results: tuple[AccessResult, ...]
    variables: tuple[ObjectName, ...] = ()


@dataclasses.dataclass(frozen=True)
class ReadRequest:
    specification_with_result: bool
    access_choice: int
    variables: tuple[ObjectName, ...]
    named_list: ObjectName


@dataclasses.dataclass(frozen=True)
class ReadResponse:
    returned_access_choice: int
    returned_variables: tuple[ObjectName, ...]
    returned_named_list: ObjectName
    results: tuple[AccessResult, ...]


@dataclasses.dataclass(frozen=True)
class WriteRequest:
    access_choice: int
    variables: tuple[ObjectName, ...]
    named_list: ObjectName
    data: tuple[DataNode, ...]


@dataclasses.dataclass(frozen=True)
class WriteResult:
    success: bool
    error: int = -1


@dataclasses.dataclass(frozen=True)
class WriteResponse:
    results: tuple[WriteResult, ...]


@dataclasses.dataclass(frozen=True)
class SelectClassification:
    classification: str
    outcome: str
    checkback_id: int | None = None
    access_error: int | None = None


@dataclasses.dataclass(frozen=True)
class TagClassification:
    classification: str
    outcome: str
    tag_value: int | None = None
    tag_state: str = ""
    reason: str = ""
    access_error: int | None = None


@dataclasses.dataclass(frozen=True)
class Classification:
    flow_id: int
    direction: int
    transfer_kind: str
    invoke_id: int
    object_name: ObjectName
    named_type: str
    point_type: str


@dataclasses.dataclass(frozen=True)
class ConfirmedPdu:
    kind: int
    invoke_id: int
    service: TLV


@dataclasses.dataclass(frozen=True)
class PacketMetadata:
    packet_index: int
    flow_id: int
    direction: int
    capture_packet: int


@dataclasses.dataclass
class Counters:
    packets: int = 0
    non_reports: int = 0
    reports: int = 0
    explicit_reports: int = 0
    named_list_reports: int = 0
    variables: int = 0
    results: int = 0
    failures: int = 0
    data_nodes: int = 0
    get_variable_access_attributes_requests: int = 0
    get_variable_access_attributes_responses: int = 0
    get_variable_access_attributes_matched: int = 0
    get_variable_access_attributes_unmatched_responses: int = 0
    get_variable_access_attributes_direction_mismatches: int = 0
    get_variable_access_attributes_duplicate_requests: int = 0
    get_variable_access_attributes_ambiguous_responses: int = 0
    get_variable_access_attributes_address_requests: int = 0
    get_variable_access_attributes_errors_cleared: int = 0
    tase2_supported_type_discoveries: int = 0
    tase2_unsupported_type_discoveries: int = 0
    read_requests: int = 0
    read_responses: int = 0
    read_matched: int = 0
    read_unmatched_responses: int = 0
    read_direction_mismatches: int = 0
    read_duplicate_requests: int = 0
    read_ambiguous_responses: int = 0
    read_errors_cleared: int = 0
    read_cardinality_mismatches: int = 0
    read_returned_access_mismatches: int = 0
    read_results: int = 0
    read_failures: int = 0
    tase2_read_shape_candidate_results: int = 0
    tase2_read_verified_results: int = 0
    tase2_read_missing_named_type_results: int = 0
    tase2_read_named_type_shape_mismatches: int = 0
    tase2_read_unpaired_candidate_results: int = 0
    tase2_shape_candidate_results: int = 0
    tase2_shape_ambiguous_results: int = 0
    tase2_shape_unmatched_results: int = 0
    tase2_verified_results: int = 0
    tase2_missing_named_type_results: int = 0
    tase2_named_type_shape_mismatches: int = 0
    tase2_candidate_types: dict[str, int] = dataclasses.field(
        default_factory=lambda: {name: 0 for name in TASE2_INDICATION_TYPES}
    )


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
    if count > MAX_LENGTH_OCTETS:
        raise OracleError("BER length-of-length exceeds bound")
    if offset + count > limit:
        raise OracleError("truncated BER long-form length")
    if data[offset] == 0:
        raise OracleError("non-minimal BER long-form length")
    length = int.from_bytes(data[offset : offset + count], "big")
    if length < 0x80:
        raise OracleError("non-minimal BER long-form length")
    return length, offset + count


def read_tlv(data: bytes, offset: int = 0, limit: int | None = None) -> TLV:
    if limit is None:
        limit = len(data)
    if offset < 0 or limit > len(data) or offset >= limit:
        raise OracleError("TLV offset is outside input")
    start = offset
    tag_class, constructed, tag, offset = _identifier(data, offset, limit)
    length, value_start = _length(data, offset, limit)
    if length > MAX_VALUE_LENGTH:
        raise OracleError("BER value exceeds bound")
    end = value_start + length
    if end > limit:
        raise OracleError("truncated BER value")
    return TLV(tag_class, constructed, tag, data[value_start:end], start,
               value_start, end)


def read_children(data: bytes, depth: int = 1) -> tuple[TLV, ...]:
    if depth > MAX_NESTING_DEPTH:
        raise OracleError("BER nesting exceeds bound")
    children: list[TLV] = []
    offset = 0
    while offset < len(data):
        if len(children) >= MAX_ELEMENT_COUNT:
            raise OracleError("BER element count exceeds bound")
        child = read_tlv(data, offset)
        children.append(child)
        offset = child.end
    return tuple(children)


def decode_integer(value: bytes, *, unsigned: bool = False) -> int:
    if not value or len(value) > MAX_INTEGER_OCTETS:
        raise OracleError("MMS INTEGER width is invalid")
    if len(value) > 1:
        if value[0] == 0 and value[1] & 0x80 == 0:
            raise OracleError("MMS INTEGER is not minimally encoded")
        if value[0] == 0xFF and value[1] & 0x80:
            raise OracleError("MMS INTEGER is not minimally encoded")
    result = int.from_bytes(value, "big", signed=bool(value[0] & 0x80))
    if unsigned and result < 0:
        raise OracleError("MMS unsigned value is negative")
    return result


def decode_identifier(value: bytes) -> str:
    if not 1 <= len(value) <= 32:
        raise OracleError("MMS Identifier length is invalid")
    if any(
        not (
            ord("A") <= octet <= ord("Z")
            or ord("a") <= octet <= ord("z")
            or ord("0") <= octet <= ord("9")
            or octet in (ord("$"), ord("_"))
        )
        for octet in value
    ):
        raise OracleError("MMS Identifier repertoire is invalid")
    return value.decode("ascii")


def decode_object_name(data: bytes) -> ObjectName:
    field = read_tlv(data)
    if field.end != len(data) or field.tag_class != 2 or field.tag > 2:
        raise OracleError("invalid MMS ObjectName")
    if field.tag in (0, 2):
        if field.constructed:
            raise OracleError("simple MMS ObjectName is constructed")
        return ObjectName(field.tag, "", decode_identifier(field.value))
    if not field.constructed:
        raise OracleError("domain-specific MMS ObjectName is primitive")
    names = read_children(field.value)
    if len(names) != 2:
        raise OracleError("domain-specific MMS ObjectName needs two identifiers")
    for name in names:
        if name.tag_class != 0 or name.constructed or name.tag != 26:
            raise OracleError("invalid domain-specific MMS identifier")
    return ObjectName(
        1, decode_identifier(names[0].value), decode_identifier(names[1].value)
    )


def _variable_specification(data: bytes) -> ObjectName:
    field = read_tlv(data)
    if field.tag_class != 2 or field.tag > 4 or field.end > len(data):
        raise OracleError("invalid MMS VariableSpecification")
    if field.tag <= 3 and not field.constructed:
        raise OracleError("constructed MMS VariableSpecification is primitive")
    if field.tag == 4 and field.constructed:
        raise OracleError("invalidated MMS VariableSpecification is constructed")
    if field.tag == 0:
        return decode_object_name(field.value)
    return ObjectName()


def decode_variable_access(
    field: TLV,
) -> tuple[int, int, ObjectName, ObjectName, tuple[ObjectName, ...]]:
    if field.tag_class != 2 or not field.constructed or field.tag > 1:
        raise OracleError("invalid MMS VariableAccessSpecification")
    if field.tag == 1:
        return 1, 0, ObjectName(), decode_object_name(field.value), ()

    entries = read_children(field.value)
    if not entries:
        raise OracleError("MMS variable list is empty")
    names: list[ObjectName] = []
    for entry in entries:
        if entry.tag_class != 0 or not entry.constructed or entry.tag != 16:
            raise OracleError("invalid MMS variable-list entry")
        name = _variable_specification(entry.value)
        names.append(name)
    return 0, len(entries), names[0], ObjectName(), tuple(names)


def _consume_data_node(budget: list[int]) -> None:
    budget[0] += 1
    if budget[0] > MAX_ELEMENT_COUNT:
        raise OracleError("MMS Data elements exceed bound")


def decode_data(
    field: TLV, depth: int = 0, budget: list[int] | None = None
) -> DataNode:
    if budget is None:
        budget = [0]
    _consume_data_node(budget)
    if depth > MAX_NESTING_DEPTH:
        raise OracleError("MMS Data nesting exceeds bound")
    if field.tag_class != 2 or field.tag == 0 or field.tag > 17:
        raise OracleError("invalid MMS Data choice")
    if field.tag in (1, 2):
        if not field.constructed:
            raise OracleError("constructed MMS Data choice is primitive")
        children = tuple(
            decode_data(child, depth + 1, budget)
            for child in read_children(field.value, depth + 1)
        )
        return DataNode(field.tag, field.value, children)
    if field.constructed:
        raise OracleError("primitive MMS Data choice is constructed")

    integer = 0
    if field.tag == 3:
        if len(field.value) != 1:
            raise OracleError("MMS Boolean Data has invalid width")
    elif field.tag in (4, 14):
        if not field.value or field.value[0] > 7:
            raise OracleError("MMS BitString Data is invalid")
        if len(field.value) == 1 and field.value[0] != 0:
            raise OracleError("empty MMS BitString has unused bits")
        if len(field.value) > 1 and field.value[0] and (
            field.value[-1] & ((1 << field.value[0]) - 1)
        ):
            raise OracleError("MMS BitString has nonzero unused bits")
    elif field.tag in (5, 13):
        integer = decode_integer(field.value)
    elif field.tag == 6:
        integer = decode_integer(field.value, unsigned=True)
    elif field.tag == 7:
        if len(field.value) not in (5, 9):
            raise OracleError("MMS FloatingPoint Data has invalid width")
        expected = 8 if len(field.value) == 5 else 11
        if field.value[0] != expected:
            raise OracleError("MMS FloatingPoint format is invalid")
    elif field.tag == 10:
        decode_identifier(field.value)
    elif field.tag == 12 and len(field.value) not in (4, 6):
        raise OracleError("MMS BinaryTime Data has invalid width")
    elif field.tag == 17:
        if len(field.value) != 8:
            raise OracleError("MMS UtcTime Data has invalid width")
        seconds = int.from_bytes(field.value[0:4], "big")
        fraction = int.from_bytes(field.value[4:7], "big")
        integer = seconds * 1000 + fraction * 1000 // 16777216
    return DataNode(field.tag, field.value, (), integer)


def decode_access_result(
    field: TLV, budget: list[int] | None = None
) -> AccessResult:
    if field.tag_class != 2 or field.tag > 17:
        raise OracleError("invalid MMS AccessResult")
    if field.tag == 0:
        if budget is None:
            budget = [0]
        _consume_data_node(budget)
        if field.constructed:
            raise OracleError("MMS DataAccessError is constructed")
        error = decode_integer(field.value, unsigned=True)
        if error > 11:
            raise OracleError("MMS DataAccessError is out of range")
        return AccessResult(0, error, b"", None)
    node = decode_data(field, budget=budget)
    return AccessResult(field.tag, -1, field.value, node)


def _wrapped_variable_access(
    wrapper: TLV,
) -> tuple[int, tuple[ObjectName, ...], ObjectName]:
    if wrapper.tag_class != 2 or not wrapper.constructed:
        raise OracleError("invalid wrapped MMS VariableAccessSpecification")
    access = read_tlv(wrapper.value)
    if access.end != len(wrapper.value):
        raise OracleError("MMS VariableAccessSpecification has trailing data")
    choice, _, _, named_list, variables = decode_variable_access(access)
    return choice, variables, named_list


def decode_read_request(service: TLV) -> ReadRequest:
    if service.tag_class != 2 or not service.constructed or service.tag != 4:
        raise OracleError("invalid MMS Read request service")
    fields = read_children(service.value)
    index = 0
    specification_with_result = False
    if (
        index < len(fields) and fields[index].tag_class == 2
        and not fields[index].constructed and fields[index].tag == 0
    ):
        if len(fields[index].value) != 1 or fields[index].value not in (
            b"\x00", b"\xff"
        ):
            raise OracleError("MMS Read specificationWithResult is invalid")
        specification_with_result = fields[index].value == b"\xff"
        index += 1
    if (
        index >= len(fields) or fields[index].tag_class != 2
        or not fields[index].constructed or fields[index].tag != 1
    ):
        raise OracleError("MMS Read request is missing variable access")
    access_choice, variables, named_list = _wrapped_variable_access(fields[index])
    index += 1
    if index != len(fields):
        raise OracleError("MMS Read request fields are out of order")
    return ReadRequest(
        specification_with_result, access_choice, variables, named_list
    )


def decode_read_response(service: TLV) -> ReadResponse:
    if service.tag_class != 2 or not service.constructed or service.tag != 4:
        raise OracleError("invalid MMS Read response service")
    fields = read_children(service.value)
    index = 0
    returned_access_choice = -1
    returned_variables: tuple[ObjectName, ...] = ()
    returned_named_list = ObjectName()
    if (
        index < len(fields) and fields[index].tag_class == 2
        and fields[index].constructed and fields[index].tag == 0
    ):
        (
            returned_access_choice,
            returned_variables,
            returned_named_list,
        ) = _wrapped_variable_access(fields[index])
        index += 1
    if (
        index >= len(fields) or fields[index].tag_class != 2
        or not fields[index].constructed or fields[index].tag != 1
    ):
        raise OracleError("MMS Read response is missing access results")
    result_fields = read_children(fields[index].value)
    if not result_fields:
        raise OracleError("MMS Read response result list is empty")
    data_budget = [0]
    results = tuple(
        decode_access_result(field, data_budget) for field in result_fields
    )
    index += 1
    if index != len(fields):
        raise OracleError("MMS Read response fields are out of order")
    return ReadResponse(
        returned_access_choice,
        returned_variables,
        returned_named_list,
        results,
    )


def decode_write_request(service: TLV) -> WriteRequest:
    if service.tag_class != 2 or not service.constructed or service.tag != 5:
        raise OracleError("invalid MMS Write request service")
    fields = read_children(service.value)
    if len(fields) != 2:
        raise OracleError("MMS Write request needs access and data lists")
    access_choice, _, _, named_list, variables = decode_variable_access(fields[0])
    data_list = fields[1]
    if (
        data_list.tag_class != 2 or not data_list.constructed
        or data_list.tag != 0
    ):
        raise OracleError("MMS Write request has invalid data list")
    data_fields = read_children(data_list.value)
    if not data_fields:
        raise OracleError("MMS Write request data list is empty")
    data_budget = [0]
    data = tuple(decode_data(field, budget=data_budget) for field in data_fields)
    return WriteRequest(access_choice, variables, named_list, data)


def decode_write_response(service: TLV) -> WriteResponse:
    if service.tag_class != 2 or not service.constructed or service.tag != 5:
        raise OracleError("invalid MMS Write response service")
    fields = read_children(service.value)
    if not fields:
        raise OracleError("MMS Write response result list is empty")
    results: list[WriteResult] = []
    for field in fields:
        if field.tag_class != 2 or field.constructed or field.tag not in (0, 1):
            raise OracleError("invalid MMS Write result")
        if field.tag == 1:
            if field.value:
                raise OracleError("MMS Write success result is not NULL")
            results.append(WriteResult(True))
        else:
            error = decode_integer(field.value, unsigned=True)
            if error > 11:
                raise OracleError("MMS DataAccessError is out of range")
            results.append(WriteResult(False, error))
    return WriteResponse(tuple(results))


def _exact_tase2_object(
    request_choice: int, variables: tuple[ObjectName, ...], suffix: str,
    named_type: ObjectName | None, type_name: str,
) -> bool:
    if request_choice != 0 or len(variables) != 1:
        return False
    selected = variables[0]
    valid_scope = (
        (selected.scope == 0 and not selected.domain)
        or (selected.scope == 1 and bool(selected.domain))
    )
    return (
        valid_scope and selected.item.endswith(suffix)
        and len(selected.item) > len(suffix)
        and named_type is not None and named_type.item == type_name
    )


def _decode_tag_value(node: DataNode) -> tuple[int, str, str]:
    if node.choice != 2 or len(node.children) != 2:
        raise OracleError("Tag_Value is not a two-component structure")
    flags, reason = node.children
    if flags.choice != 4 or len(flags.raw) != 2 or flags.raw[0] != 5:
        raise OracleError("Tag_Value Flags is not a three-bit BIT STRING")
    if flags.raw[1] & 0x1F:
        raise OracleError("Tag_Value Flags has nonzero reserved bits")
    tag_value = ((flags.raw[1] & 0x80) != 0) * 2 + (
        (flags.raw[1] & 0x40) != 0
    )
    if tag_value > 2:
        raise OracleError("Tag_Value tag is reserved")
    if reason.choice != 10 or len(reason.raw) > 255:
        raise OracleError("Tag_Value Reason is invalid")
    return (
        tag_value,
        "armed" if flags.raw[1] & 0x20 else "idle",
        decode_identifier(reason.raw),
    )


def classify_tase2_get_tag(
    request: ReadRequest, named_type: ObjectName | None,
    response: ReadResponse,
) -> TagClassification:
    exact = _exact_tase2_object(
        request.access_choice, request.variables, "_TAG", named_type,
        "Tag_Value",
    )
    classification = "get_tag" if exact else "get_tag_candidate"
    if len(response.results) != 1:
        return TagClassification(classification, "invalid_response")
    result = response.results[0]
    if result.choice == 0:
        return TagClassification(
            classification,
            "failed" if exact else "candidate_failure",
            access_error=result.error,
        )
    if result.node is None:
        return TagClassification(classification, "invalid_response")
    try:
        tag_value, tag_state, reason = _decode_tag_value(result.node)
    except OracleError:
        return TagClassification(classification, "invalid_response")
    return TagClassification(
        classification,
        "confirmed" if exact else "candidate_response",
        tag_value if exact else None,
        tag_state if exact else "",
        reason if exact else "",
    )


def classify_tase2_set_tag(
    request: WriteRequest, named_type: ObjectName | None,
    response: WriteResponse,
) -> TagClassification:
    exact_identity = _exact_tase2_object(
        request.access_choice, request.variables, "_TAG", named_type,
        "Tag_Value",
    )
    tag_value: int | None = None
    tag_state = ""
    reason = ""
    exact_shape = False
    if len(request.data) == 1:
        try:
            tag_value, tag_state, reason = _decode_tag_value(request.data[0])
            exact_shape = True
        except OracleError:
            pass
    exact = exact_identity and exact_shape
    classification = "set_tag" if exact else "set_tag_candidate"
    if len(response.results) != 1:
        return TagClassification(classification, "invalid_response")
    result = response.results[0]
    if not result.success:
        return TagClassification(
            classification,
            "partial_or_failed",
            tag_value if exact else None,
            tag_state if exact else "",
            reason if exact else "",
            result.error,
        )
    return TagClassification(
        classification, "confirmed",
        tag_value if exact else None,
        tag_state if exact else "",
        reason if exact else "",
    )


def classify_tase2_select(
    request: ReadRequest, named_type: ObjectName | None,
    response: ReadResponse,
) -> SelectClassification:
    """Independently apply the supported TASE.2 Select mapping."""
    exact = False
    if request.access_choice == 0 and len(request.variables) == 1:
        selected = request.variables[0]
        valid_scope = (
            (selected.scope == 0 and not selected.domain)
            or (selected.scope == 1 and bool(selected.domain))
        )
        exact = (
            valid_scope
            and selected.item.endswith("_SBO")
            and len(selected.item) > 4
            and named_type is not None
            and named_type.item == "SBO_CheckBackName"
        )
    classification = "select" if exact else "select_candidate"

    if len(response.results) != 1:
        return SelectClassification(classification, "invalid_response")
    result = response.results[0]
    if result.choice == 0:
        return SelectClassification(
            classification,
            "failed" if exact else "candidate_failure",
            access_error=result.error,
        )
    if (
        result.choice == 5 and result.node is not None
        and 1 <= len(result.raw) <= 2
    ):
        return SelectClassification(
            classification,
            "confirmed" if exact else "candidate_response",
            checkback_id=result.node.integer if exact else None,
        )
    return SelectClassification(classification, "invalid_response")


def decode_confirmed_pdu(pdu: bytes) -> ConfirmedPdu | None:
    outer = read_tlv(pdu)
    if outer.end != len(pdu):
        raise OracleError("MMS PDU has trailing bytes")
    if outer.tag_class != 2 or outer.tag not in (0, 1):
        return None
    if not outer.constructed:
        raise OracleError("MMS confirmed PDU is primitive")
    fields = read_children(outer.value)
    if len(fields) < 2:
        raise OracleError("MMS confirmed PDU is missing invoke ID or service")
    invoke = fields[0]
    if invoke.tag_class != 0 or invoke.constructed or invoke.tag != 2:
        raise OracleError("MMS confirmed PDU has invalid invoke ID")
    invoke_id = decode_integer(invoke.value, unsigned=True)
    service_index = 1
    if (
        outer.tag == 0
        and len(fields) > 2
        and fields[1].tag_class == 0
        and fields[1].constructed
        and fields[1].tag == 16
    ):
        service_index += 1
    if service_index >= len(fields):
        raise OracleError("MMS confirmed PDU has invalid service cardinality")
    service = fields[service_index]
    if service.tag_class != 2:
        raise OracleError("MMS confirmed service is not context-specific")
    remaining = len(fields) - service_index - 1
    if remaining == 1:
        detail = fields[service_index + 1]
        if detail.tag_class != 2 or not detail.constructed or detail.tag != 79:
            raise OracleError("MMS confirmed PDU has invalid companion detail")
    elif remaining != 0:
        raise OracleError("MMS confirmed PDU has invalid service cardinality")
    return ConfirmedPdu(outer.tag, invoke_id, service)


def decode_confirmed_error_invoke(pdu: bytes) -> int | None:
    outer = read_tlv(pdu)
    if outer.end != len(pdu):
        raise OracleError("MMS PDU has trailing bytes")
    if outer.tag_class != 2 or outer.tag != 2:
        return None
    if not outer.constructed:
        raise OracleError("MMS ConfirmedError is primitive")
    fields = read_children(outer.value)
    if len(fields) < 2:
        raise OracleError("MMS ConfirmedError is incomplete")
    invoke = fields[0]
    if invoke.tag_class != 2 or invoke.constructed or invoke.tag != 0:
        raise OracleError("MMS ConfirmedError invoke ID is invalid")
    invoke_id = decode_integer(invoke.value, unsigned=True)
    index = 1
    if (
        index < len(fields) and fields[index].tag_class == 2
        and not fields[index].constructed and fields[index].tag == 1
    ):
        decode_integer(fields[index].value, unsigned=True)
        index += 1
    if (
        index >= len(fields) or fields[index].tag_class != 2
        or not fields[index].constructed or fields[index].tag != 2
    ):
        raise OracleError("MMS ConfirmedError service error is invalid")
    service_fields = read_children(fields[index].value)
    if not service_fields or service_fields[0].tag_class != 2:
        raise OracleError("MMS ServiceError is missing error class")
    error_class = service_fields[0]
    if not error_class.constructed or error_class.tag != 0:
        raise OracleError("MMS ServiceError error class is invalid")
    encoded_class = read_tlv(error_class.value)
    if (
        encoded_class.end != len(error_class.value)
        or encoded_class.tag_class != 2 or encoded_class.constructed
        or encoded_class.tag > 12
    ):
        raise OracleError("MMS ServiceError error class is invalid")
    decode_integer(encoded_class.value)
    last_tag = 0
    for field in service_fields[1:]:
        if field.tag_class != 2 or field.tag <= last_tag or field.tag > 3:
            raise OracleError("MMS ServiceError fields are out of order")
        last_tag = field.tag
    index += 1
    if index != len(fields):
        raise OracleError("MMS ConfirmedError fields are out of order")
    return invoke_id


def confirmed_service(pdu: bytes) -> tuple[int, int] | None:
    """Return (confirmed-PDU tag, service tag) without decoding service data."""
    confirmed = decode_confirmed_pdu(pdu)
    if confirmed is None:
        return None
    return confirmed.kind, confirmed.service.tag


def validate_address(data: bytes) -> None:
    address = read_tlv(data)
    if (
        address.end != len(data) or address.tag_class != 2
        or address.constructed or address.tag > 2
    ):
        raise OracleError("invalid MMS Address")
    if address.tag == 0:
        decode_integer(address.value, unsigned=True)
    elif address.tag == 1:
        decode_identifier(address.value)


def decode_gva_request(service: TLV) -> ObjectName | None:
    if service.tag_class != 2 or not service.constructed or service.tag != 6:
        raise OracleError("invalid GetVariableAccessAttributes request service")
    choice = read_tlv(service.value)
    if choice.end != len(service.value) or choice.tag_class != 2:
        raise OracleError("invalid GetVariableAccessAttributes request choice")
    if choice.tag == 1 and choice.constructed:
        validate_address(choice.value)
        return None
    if choice.tag != 0 or not choice.constructed:
        raise OracleError("invalid GetVariableAccessAttributes request choice")
    return decode_object_name(choice.value)


def _validate_type_specification(
    field: TLV, depth: int, budget: list[int], allow_type_name: bool = True,
    signature: list[TypeDescriptionNode] | None = None,
    unresolved: list[int] | None = None,
) -> None:
    if field.tag_class != 2:
        raise OracleError("MMS TypeSpecification is not context-specific")
    if field.tag == 0:
        if not allow_type_name:
            raise OracleError("MMS TypeSpecification typeName is not permitted here")
        if not field.constructed:
            raise OracleError("MMS TypeSpecification typeName is primitive")
        decode_object_name(field.value)
        if unresolved is not None:
            unresolved[0] += 1
        if signature is not None:
            signature.append((0, 0, 0, 0, False))
        return
    _validate_type_description(
        field, depth, budget, allow_type_name, signature, unresolved
    )


def _validate_explicit_type_specification(
    field: TLV, expected_tag: int, depth: int, budget: list[int],
    allow_type_name: bool = True,
    signature: list[TypeDescriptionNode] | None = None,
    unresolved: list[int] | None = None,
) -> None:
    if (
        field.tag_class != 2
        or not field.constructed
        or field.tag != expected_tag
    ):
        raise OracleError("MMS TypeSpecification wrapper is invalid")
    inner = read_tlv(field.value)
    if inner.end != len(field.value):
        raise OracleError("MMS TypeSpecification has trailing data")
    _validate_type_specification(
        inner, depth, budget, allow_type_name, signature, unresolved
    )


def _validate_type_description(
    field: TLV, depth: int = 1, budget: list[int] | None = None,
    allow_type_name: bool = True,
    signature: list[TypeDescriptionNode] | None = None,
    unresolved: list[int] | None = None,
) -> int:
    if budget is None:
        budget = [0]
    if depth > MAX_NESTING_DEPTH:
        raise OracleError("MMS TypeDescription nesting exceeds bound")
    budget[0] += 1
    if budget[0] > MAX_ELEMENT_COUNT:
        raise OracleError("MMS TypeDescription element count exceeds bound")

    # The MMS module uses the ASN.1 default (explicit) tagging. Most choices
    # spell out IMPLICIT, but mMSString deliberately does not: context [16]
    # therefore wraps a complete universal INTEGER TLV.
    constructed_tags = {1, 2, 7, 16}
    supported_tags = constructed_tags | {3, 4, 5, 6, 9, 10, 11, 12, 13, 15, 16}
    if field.tag_class != 2 or field.tag not in supported_tags:
        raise OracleError("MMS TypeDescription choice is invalid")
    if field.constructed != (field.tag in constructed_tags):
        raise OracleError("MMS TypeDescription form is invalid")

    primary = 0
    secondary = 0
    child_count = 0
    packed = False

    if field.tag in (3, 11, 15):
        if field.value:
            raise OracleError("MMS TypeDescription NULL is not empty")
    elif field.tag in (4, 9, 10):
        value = decode_integer(field.value)
        if not -(1 << 31) <= value <= (1 << 31) - 1:
            raise OracleError("MMS TypeDescription Integer32 is out of range")
        primary = value
    elif field.tag == 16:
        value_field = read_tlv(field.value)
        if (
            value_field.end != len(field.value)
            or value_field.tag_class != 0
            or value_field.constructed
            or value_field.tag != 2
        ):
            raise OracleError("MMS mMSString TypeDescription is invalid")
        value = decode_integer(value_field.value)
        if not -(1 << 31) <= value <= (1 << 31) - 1:
            raise OracleError("MMS TypeDescription Integer32 is out of range")
        primary = value
    elif field.tag in (5, 6, 13):
        value = decode_integer(field.value, unsigned=True)
        if value > 127:
            raise OracleError("MMS TypeDescription Unsigned8 is out of range")
        primary = value
    elif field.tag == 12:
        if len(field.value) != 1:
            raise OracleError("MMS TypeDescription BOOLEAN is invalid")
        primary = int(field.value != b"\x00")
    elif field.tag == 7:
        fields = read_children(field.value, depth + 1)
        if len(fields) != 2:
            raise OracleError("MMS floating-point TypeDescription is incomplete")
        for component_index, component in enumerate(fields):
            if (
                component.tag_class != 0
                or component.constructed
                or component.tag != 2
            ):
                raise OracleError("MMS floating-point TypeDescription is invalid")
            value = decode_integer(component.value, unsigned=True)
            if value > 127:
                raise OracleError("MMS TypeDescription Unsigned8 is out of range")
            if component_index == 0:
                primary = value
            else:
                secondary = value
    elif field.tag == 1:
        fields = read_children(field.value, depth + 1)
        index = 0
        if (
            fields
            and fields[0].tag_class == 2
            and not fields[0].constructed
            and fields[0].tag == 0
        ):
            if len(fields[0].value) != 1:
                raise OracleError("MMS array packed flag is invalid")
            packed = fields[0].value != b"\x00"
            index += 1
        if index >= len(fields):
            raise OracleError("MMS array TypeDescription lacks its element count")
        element_count = fields[index]
        if (
            element_count.tag_class != 2
            or element_count.constructed
            or element_count.tag != 1
        ):
            raise OracleError("MMS array element count is invalid")
        count = decode_integer(element_count.value, unsigned=True)
        if count > (1 << 31) - 1:
            raise OracleError("MMS Unsigned32 is out of range")
        primary = count
        child_count = 1
        index += 1
        if index + 1 != len(fields):
            raise OracleError("MMS array TypeDescription lacks one element type")
        # elementType is a TypeSpecification. Its typeName alternative is
        # legal even though the enclosing GVA value starts at TypeDescription.
        _validate_explicit_type_specification(
            fields[index], 2, depth + 1, budget, True,
            signature, unresolved,
        )
    elif field.tag == 2:
        fields = read_children(field.value, depth + 1)
        index = 0
        if (
            fields
            and fields[0].tag_class == 2
            and not fields[0].constructed
            and fields[0].tag == 0
        ):
            if len(fields[0].value) != 1:
                raise OracleError("MMS structure packed flag is invalid")
            packed = fields[0].value != b"\x00"
            index += 1
        if (
            index + 1 != len(fields)
            or fields[index].tag_class != 2
            or not fields[index].constructed
            or fields[index].tag != 1
        ):
            raise OracleError("MMS structure TypeDescription lacks components")
        components = read_children(fields[index].value, depth + 1)
        if not components:
            raise OracleError("MMS structure TypeDescription has no components")
        child_count = len(components)
        for component in components:
            budget[0] += 1
            if budget[0] > MAX_ELEMENT_COUNT:
                raise OracleError("MMS TypeDescription element count exceeds bound")
            if (
                component.tag_class != 0
                or not component.constructed
                or component.tag != 16
            ):
                raise OracleError("MMS structure component is not a SEQUENCE")
            fields = read_children(component.value, depth + 1)
            index = 0
            if (
                fields
                and fields[0].tag_class == 2
                and not fields[0].constructed
                and fields[0].tag == 0
            ):
                decode_identifier(fields[0].value)
                index += 1
            if index + 1 != len(fields):
                raise OracleError("MMS structure component lacks one type")
            # componentType is also a TypeSpecification and may name a type.
            _validate_explicit_type_specification(
                fields[index], 1, depth + 1, budget, True,
                signature, unresolved,
            )
    if signature is not None:
        signature.append(
            (field.tag, primary, secondary, child_count, packed)
        )
    return field.tag


def expected_tase2_type_signature(
    name: str,
) -> tuple[TypeDescriptionNode, ...]:
    """Return the IEC 60870-6-503/802 type's canonical post-order shape."""

    def primitive(choice: int, primary: int = 0, secondary: int = 0):
        return ((choice, primary, secondary, 0, False),)

    def structure(*components: tuple[TypeDescriptionNode, ...]):
        nodes: tuple[TypeDescriptionNode, ...] = ()
        for component in components:
            nodes += component
        return nodes + ((2, 0, 0, len(components), False),)

    integer16 = primitive(5, 16)
    integer32 = primitive(5, 32)
    unsigned16 = primitive(6, 16)
    bits8 = primitive(4, 8)
    real = primitive(7, 32, 8)
    timestamp_extended = structure(integer32, integer16)

    if name == "Data_Real":
        return real
    if name == "Data_Discrete":
        return integer32
    if name in ("Data_State", "Data_StateSupplemental"):
        return bits8
    if name == "Data_RealQ":
        return structure(real, bits8)
    if name == "Data_DiscreteQ":
        return structure(integer32, bits8)
    if name in ("Data_StateQ", "Data_StateSupplementalQ"):
        return structure(bits8, bits8)
    if name == "Data_RealQTimeTag":
        return structure(real, integer32, bits8)
    if name == "Data_DiscreteQTimeTag":
        return structure(integer32, integer32, bits8)
    if name == "Data_StateQTimeTag":
        return structure(integer32, bits8)
    if name == "Data_StateSupplementalQTimeTag":
        return structure(bits8, integer32, bits8)
    if name == "Data_RealExtended":
        return structure(real, integer32, bits8, unsigned16)
    if name == "Data_DiscreteExtended":
        return structure(integer32, integer32, bits8, unsigned16)
    if name == "Data_StateExtended":
        return structure(integer32, bits8, unsigned16)
    if name == "Data_StateSupplementalExtended":
        return structure(bits8, integer32, bits8, unsigned16)
    if name == "Data_RealQTimeTagExtended":
        return structure(real, timestamp_extended, bits8)
    if name == "Data_DiscreteQTimeTagExtended":
        return structure(integer32, timestamp_extended, bits8)
    if name == "Data_StateQTimeTagExtended":
        return structure(timestamp_extended, bits8)
    if name == "Data_StateSupplementalQTimeTagExtended":
        return structure(bits8, timestamp_extended, bits8)
    raise OracleError(f"unsupported TASE.2 TypeDescription mapping: {name}")


def decode_gva_attributes(service: TLV) -> GvaAttributes:
    if service.tag_class != 2 or not service.constructed or service.tag != 6:
        raise OracleError("invalid GetVariableAccessAttributes response service")
    fields = read_children(service.value)
    if len(fields) < 2:
        raise OracleError("GetVariableAccessAttributes response is incomplete")
    deletable = fields[0]
    if (
        deletable.tag_class != 2 or deletable.constructed or deletable.tag != 0
        or len(deletable.value) != 1
    ):
        raise OracleError("GetVariableAccessAttributes deletable field is invalid")
    index = 1
    if (
        index < len(fields) and fields[index].tag_class == 2
        and fields[index].constructed and fields[index].tag == 1
    ):
        validate_address(fields[index].value)
        index += 1
    if (
        index >= len(fields) or fields[index].tag_class != 2
        or not fields[index].constructed or fields[index].tag != 2
    ):
        raise OracleError("GetVariableAccessAttributes type field is invalid")
    type_field = fields[index]
    index += 1
    if index < len(fields) and fields[index].tag_class == 2 and fields[index].tag == 3:
        if fields[index].constructed:
            raise OracleError("GetVariableAccessAttributes access control is invalid")
        decode_identifier(fields[index].value)
        index += 1
    if index < len(fields) and fields[index].tag_class == 2 and fields[index].tag == 4:
        if fields[index].constructed:
            raise OracleError("GetVariableAccessAttributes meaning is invalid")
        decode_identifier(fields[index].value)
        index += 1
    if index != len(fields):
        raise OracleError("GetVariableAccessAttributes fields are out of order")
    description = read_tlv(type_field.value)
    if description.end != len(type_field.value):
        raise OracleError("GetVariableAccessAttributes type has trailing data")
    signature: list[TypeDescriptionNode] = []
    unresolved = [0]
    _validate_type_description(
        description, allow_type_name=False, signature=signature,
        unresolved=unresolved,
    )
    return GvaAttributes(
        deletable=deletable.value != b"\x00",
        signature=tuple(signature),
        unresolved_type_names=unresolved[0],
    )


def decode_gva_response(service: TLV) -> int:
    """Validate a GVA response and retain the historical choice-only API."""
    return decode_gva_attributes(service).choice


def _integer(node: DataNode, width: int, *, nonnegative: bool = False) -> bool:
    return (
        node.choice == 5
        and 0 < len(node.raw) <= width
        and (not nonnegative or node.integer >= 0)
    )


def _float32(node: DataNode) -> bool:
    return node.choice == 7 and len(node.raw) == 5 and node.raw[0] == 8


def _bit_string_8(node: DataNode) -> bool:
    return node.choice == 4 and len(node.raw) == 2 and node.raw[0] == 0


def _cov_counter(node: DataNode) -> bool:
    return (
        node.choice == 6
        and 0 < len(node.raw) <= 3
        and 0 <= node.integer <= 65535
    )


def _timestamp_extended(node: DataNode) -> bool:
    if node.choice != 2 or len(node.children) != 2:
        return False
    seconds, milliseconds = node.children
    return (
        _integer(seconds, 4, nonnegative=True)
        and _integer(milliseconds, 2, nonnegative=True)
        and milliseconds.integer <= 999
    )


def tase2_indication_candidates(node: DataNode | None) -> tuple[str, ...]:
    """Return every supported indication type with this exact shape."""
    if node is None:
        return ()
    candidates: list[str] = []
    if _float32(node):
        candidates.append("Data_Real")
    if _bit_string_8(node):
        candidates.extend(("Data_State", "Data_StateSupplemental"))
    if _integer(node, 4):
        candidates.append("Data_Discrete")
    if node.choice != 2:
        return tuple(candidates)

    children = node.children
    if len(children) == 2:
        first, second = children
        if _float32(first) and _bit_string_8(second):
            candidates.append("Data_RealQ")
        if _bit_string_8(first) and _bit_string_8(second):
            candidates.extend(("Data_StateQ", "Data_StateSupplementalQ"))
        if _integer(first, 4) and _bit_string_8(second):
            candidates.append("Data_DiscreteQ")
        if _integer(first, 4, nonnegative=True) and _bit_string_8(second):
            candidates.append("Data_StateQTimeTag")
        if _timestamp_extended(first) and _bit_string_8(second):
            candidates.append("Data_StateQTimeTagExtended")
    elif len(children) == 3:
        first, second, third = children
        if _float32(first) and _integer(second, 4, nonnegative=True) and _bit_string_8(third):
            candidates.append("Data_RealQTimeTag")
        if _integer(first, 4) and _integer(second, 4, nonnegative=True) and _bit_string_8(third):
            candidates.append("Data_DiscreteQTimeTag")
        if _bit_string_8(first) and _integer(second, 4, nonnegative=True) and _bit_string_8(third):
            candidates.append("Data_StateSupplementalQTimeTag")
        if _integer(first, 4, nonnegative=True) and _bit_string_8(second) and _cov_counter(third):
            candidates.append("Data_StateExtended")
        if _float32(first) and _timestamp_extended(second) and _bit_string_8(third):
            candidates.append("Data_RealQTimeTagExtended")
        if _integer(first, 4) and _timestamp_extended(second) and _bit_string_8(third):
            candidates.append("Data_DiscreteQTimeTagExtended")
        if _bit_string_8(first) and _timestamp_extended(second) and _bit_string_8(third):
            candidates.append("Data_StateSupplementalQTimeTagExtended")
    elif len(children) == 4:
        first, second, third, fourth = children
        if _float32(first) and _integer(second, 4, nonnegative=True) and _bit_string_8(third) and _cov_counter(fourth):
            candidates.append("Data_RealExtended")
        if _integer(first, 4) and _integer(second, 4, nonnegative=True) and _bit_string_8(third) and _cov_counter(fourth):
            candidates.append("Data_DiscreteExtended")
        if _bit_string_8(first) and _integer(second, 4, nonnegative=True) and _bit_string_8(third) and _cov_counter(fourth):
            candidates.append("Data_StateSupplementalExtended")
    return tuple(candidates)


def tase2_point_label(named_type: str) -> str:
    labels = {
        "Data_Real": "real",
        "Data_Discrete": "discrete",
        "Data_State": "state",
        "Data_StateSupplemental": "state_supplemental",
        "Data_RealQ": "real_q",
        "Data_StateQ": "state_q",
        "Data_StateSupplementalQ": "state_supplemental_q",
        "Data_DiscreteQ": "discrete_q",
        "Data_RealQTimeTag": "real_q_time",
        "Data_StateQTimeTag": "state_q_time",
        "Data_StateSupplementalQTimeTag": "state_supplemental_q_time",
        "Data_DiscreteQTimeTag": "discrete_q_time",
        "Data_RealExtended": "real_extended",
        "Data_StateExtended": "state_extended",
        "Data_StateSupplementalExtended": "state_supplemental_extended",
        "Data_DiscreteExtended": "discrete_extended",
        "Data_RealQTimeTagExtended": "real_q_time_extended",
        "Data_StateQTimeTagExtended": "state_q_time_extended",
        "Data_StateSupplementalQTimeTagExtended":
            "state_supplemental_q_time_extended",
        "Data_DiscreteQTimeTagExtended": "discrete_q_time_extended",
    }
    try:
        return labels[named_type]
    except KeyError as error:
        raise OracleError("unsupported TASE.2 point type") from error


def classification_line(classification: Classification) -> str:
    name = classification.object_name
    return "\t".join(
        str(value)
        for value in (
            classification.flow_id,
            classification.direction,
            classification.transfer_kind,
            classification.invoke_id,
            name.scope,
            name.domain,
            name.item,
            classification.named_type,
            classification.point_type,
        )
    )


def parse_information_report(pdu: bytes) -> InformationReport | None:
    outer = read_tlv(pdu)
    if outer.end != len(pdu):
        raise OracleError("MMS PDU has trailing bytes")
    if outer.tag_class != 2 or outer.tag != 3:
        return None
    if not outer.constructed:
        raise OracleError("MMS UnconfirmedPDU is primitive")

    unconfirmed_fields = read_children(outer.value)
    if not unconfirmed_fields:
        raise OracleError("MMS UnconfirmedPDU has no service")
    service = unconfirmed_fields[0]
    if service.tag_class != 2:
        raise OracleError("MMS unconfirmed service is not context-specific")
    if service.tag != 0:
        return None
    if not service.constructed:
        raise OracleError("MMS InformationReport service is primitive")
    if len(unconfirmed_fields) > 2:
        raise OracleError("MMS UnconfirmedPDU has extra fields")
    if len(unconfirmed_fields) == 2:
        detail = unconfirmed_fields[1]
        if detail.tag_class != 2 or not detail.constructed or detail.tag != 79:
            raise OracleError("invalid MMS unconfirmed companion detail")

    fields = read_children(service.value)
    if len(fields) != 2:
        raise OracleError("MMS InformationReport needs access and result fields")
    access_choice, variable_count, first_variable, named_list, variables = (
        decode_variable_access(fields[0])
    )
    result_list = fields[1]
    if result_list.tag_class != 2 or not result_list.constructed or result_list.tag != 0:
        raise OracleError("invalid MMS InformationReport result list")
    result_fields = read_children(result_list.value)
    data_budget = [0]
    results = tuple(
        decode_access_result(field, data_budget) for field in result_fields
    )
    return InformationReport(
        access_choice, variable_count, first_variable, named_list, results, variables
    )


def _component_metadata(result: AccessResult) -> tuple[int, int, int, int, int, int,
                                                               int, int, bytes, int]:
    if result.node is None or result.choice not in (1, 2):
        integer = result.node.integer if result.node is not None else 0
        return 0, 0, 0, 0, 0, 0, integer, 0, b"", 0
    children = result.node.children
    integers = [child.integer for child in children if child.choice in (5, 6, 13, 17)]
    first_integer = integers[0] if integers else 0
    second_integer = integers[1] if len(integers) > 1 else 0
    first_choice = children[0].choice if children else 0
    second_choice = children[1].choice if len(children) > 1 else 0
    third_choice = children[2].choice if len(children) > 2 else 0
    first_value = children[0].integer if children else 0
    flags = children[1].raw if len(children) > 1 else b""
    timestamp = children[2].integer if len(children) > 2 else 0
    return (len(integers), first_integer, second_integer, len(children),
            first_choice, second_choice, first_value, third_choice, flags,
            timestamp)


def report_lines(index: int, report: InformationReport) -> Iterator[str]:
    first = report.results[0] if report.results else AccessResult(0, -1, b"", None)
    (integer_count, first_integer, second_integer, component_count,
     first_component, second_component, first_value, third_component,
     flags, timestamp) = _component_metadata(first)
    failures = sum(result.error >= 0 for result in report.results)
    yield "\t".join(
        str(value)
        for value in (
            "R", index, report.access_choice, report.variable_count,
            report.first_variable.scope, report.first_variable.domain,
            report.first_variable.item, report.named_list.scope,
            report.named_list.domain, report.named_list.item,
            len(report.results), failures, first.choice, len(first.raw),
            *value_hashes(first.raw), integer_count, first_integer, second_integer,
            component_count, first_component, second_component,
            third_component, first_value, len(flags), *value_hashes(flags), timestamp,
        )
    )
    for result_index, result in enumerate(report.results):
        yield "\t".join(
            str(value)
            for value in (
                "V", index, result_index, result.choice, result.error,
                len(result.raw), *value_hashes(result.raw),
            )
        )


def pcap_packets(path: pathlib.Path) -> Iterator[bytes]:
    with path.open("rb") as handle:
        header = handle.read(24)
        if len(header) != 24:
            raise OracleError("truncated PCAP header")
        magic = header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            byte_order = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
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


def packet_metadata(path: pathlib.Path) -> tuple[PacketMetadata, ...]:
    if path.stat().st_size > MAX_SIDECAR_BYTES:
        raise OracleError("MMS metadata exceeds sidecar-byte bound")
    rows: list[PacketMetadata] = []
    try:
        with path.open("r", encoding="ascii", newline="") as handle:
            header = handle.readline().rstrip("\n")
            if header != "packet_index\tflow_id\tdirection\tcapture_packet":
                raise OracleError("invalid MMS metadata header")
            previous_capture_packet = 0
            for line_number, line in enumerate(handle, 2):
                if len(rows) >= MAX_METADATA_ROWS:
                    raise OracleError("MMS metadata exceeds row bound")
                fields = line.rstrip("\n").split("\t")
                if len(fields) != 4:
                    raise OracleError(f"invalid MMS metadata row {line_number}")
                try:
                    row = PacketMetadata(*(int(field) for field in fields))
                except ValueError as error:
                    raise OracleError(
                        f"invalid MMS metadata row {line_number}"
                    ) from error
                if row.packet_index != len(rows) + 1 or row.flow_id < 1:
                    raise OracleError("MMS metadata indices are not sequential")
                if row.direction not in (0, 1):
                    raise OracleError("MMS metadata direction is invalid")
                if row.capture_packet < 1:
                    raise OracleError("MMS metadata capture index is invalid")
                if row.capture_packet < previous_capture_packet:
                    raise OracleError("MMS metadata is not in capture order")
                previous_capture_packet = row.capture_packet
                rows.append(row)
    except UnicodeError as error:
        raise OracleError("MMS metadata is not ASCII") from error
    return tuple(rows)


def configured_type_mappings(
    path: pathlib.Path | None,
) -> dict[tuple[int, int, ObjectName], str]:
    if path is None:
        return {}
    if path.stat().st_size > MAX_SIDECAR_BYTES:
        raise OracleError("configured-type mapping exceeds sidecar-byte bound")
    mappings: dict[tuple[int, int, ObjectName], str] = {}
    try:
        with path.open("r", encoding="ascii", newline="") as handle:
            header = handle.readline().rstrip("\n")
            expected_header = (
                "flow_id\tserver_direction\tscope\tdomain\t"
                "object_name\tnamed_type"
            )
            if header != expected_header:
                raise OracleError("invalid configured-type mapping header")
            for row_count, line in enumerate(handle, 1):
                line_number = row_count + 1
                if row_count > MAX_TYPE_MAPPINGS:
                    raise OracleError("configured-type mapping exceeds row bound")
                fields = line.rstrip("\n").split("\t")
                if len(fields) != 6:
                    raise OracleError(
                        f"invalid configured-type mapping row {line_number}"
                    )
                try:
                    flow_id = int(fields[0])
                    server_direction = int(fields[1])
                    scope = int(fields[2])
                except ValueError as error:
                    raise OracleError(
                        f"invalid configured-type mapping row {line_number}"
                    ) from error
                domain, object_name, named_type = fields[3:]
                if (
                    flow_id < 1
                    or server_direction not in (0, 1)
                    or scope not in (0, 1, 2)
                ):
                    raise OracleError(
                        f"invalid configured-type mapping row {line_number}"
                    )
                if scope == 1:
                    decode_identifier(domain.encode("ascii"))
                elif domain:
                    raise OracleError(
                        f"invalid configured-type mapping row {line_number}"
                    )
                decode_identifier(object_name.encode("ascii"))
                if named_type not in SUPPORTED_TASE2_POINT_TYPES:
                    raise OracleError(
                        f"unsupported configured type at row {line_number}"
                    )
                key = (
                    flow_id,
                    server_direction,
                    ObjectName(scope, domain, object_name),
                )
                if key in mappings:
                    raise OracleError(
                        f"duplicate configured-type mapping at row {line_number}"
                    )
                mappings[key] = named_type
    except UnicodeError as error:
        raise OracleError("configured-type mapping is not ASCII") from error
    return mappings


def reserve_pending_correlation(
    pending: dict[object, object], invalid: set[object], key: object
) -> None:
    if key in pending or key in invalid:
        return
    if len(pending) + len(invalid) >= MAX_PENDING_CORRELATIONS:
        raise OracleError("pending transaction correlation exceeds entry bound")


def append_classification(
    classifications: list[Classification], classification: Classification,
    total_classifications: int, retain: bool,
) -> None:
    if total_classifications > MAX_CLASSIFICATIONS:
        raise OracleError("verified classifications exceed entry bound")
    if retain:
        classifications.append(classification)


def _analyze(path: pathlib.Path, records_path: pathlib.Path,
             summary_path: pathlib.Path, reports_path: pathlib.Path | None,
             metadata_path: pathlib.Path | None,
             classifications_path: pathlib.Path | None,
             type_mappings_path: pathlib.Path | None,
             transaction: ArtifactTransaction) -> Counters:
    counters = Counters()
    inputs = [("input PCAP", path)]
    if metadata_path is not None:
        inputs.append(("metadata input", metadata_path))
    if type_mappings_path is not None:
        inputs.append(("type-mapping input", type_mappings_path))
    outputs = [("records output", records_path), ("summary output", summary_path)]
    if reports_path is not None:
        outputs.append(("report-PDU output", reports_path))
    if classifications_path is not None:
        outputs.append(("classifications output", classifications_path))
    validate_artifact_paths(inputs, outputs)
    metadata_available = metadata_path is not None
    metadata = packet_metadata(metadata_path) if metadata_available else ()
    type_mappings = configured_type_mappings(type_mappings_path)
    pending: dict[tuple[int, int, int], ObjectName] = {}
    invalid_gva_invokes: set[tuple[int, int, int]] = set()
    pending_reads: dict[tuple[int, int, int], ReadRequest] = {}
    invalid_read_invokes: set[tuple[int, int, int]] = set()
    learned_types: dict[tuple[int, int, ObjectName], str] = {}
    classifications: list[Classification] = []
    total_results = 0
    total_data_nodes = 0
    output_budget = OutputBudget()
    records_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    if reports_path is not None:
        reports_path.parent.mkdir(parents=True, exist_ok=True)
    if classifications_path is not None:
        classifications_path.parent.mkdir(parents=True, exist_ok=True)
    with transaction.open_text(records_path, encoding="utf-8") as records:
        reports_output = (
            transaction.open_binary(reports_path)
            if reports_path is not None else None
        )
        try:
            for packet in pcap_packets(path):
                counters.packets += 1
                if metadata_available and counters.packets > len(metadata):
                    raise OracleError("MMS metadata has fewer rows than packets")
                packet_context = (
                    metadata[counters.packets - 1] if metadata_available else None
                )
                confirmed = decode_confirmed_pdu(packet)
                confirmed_error_invoke = decode_confirmed_error_invoke(packet)
                if confirmed_error_invoke is not None and packet_context is not None:
                    error_key = (
                        packet_context.flow_id,
                        1 - packet_context.direction,
                        confirmed_error_invoke,
                    )
                    if error_key in pending:
                        del pending[error_key]
                        counters.get_variable_access_attributes_errors_cleared += 1
                    elif error_key in invalid_gva_invokes:
                        invalid_gva_invokes.remove(error_key)
                        counters.get_variable_access_attributes_errors_cleared += 1
                    if error_key in pending_reads:
                        del pending_reads[error_key]
                        counters.read_errors_cleared += 1
                    elif error_key in invalid_read_invokes:
                        invalid_read_invokes.remove(error_key)
                        counters.read_errors_cleared += 1
                service = (
                    None
                    if confirmed is None
                    else (confirmed.kind, confirmed.service.tag)
                )
                if service == (0, 6):
                    counters.get_variable_access_attributes_requests += 1
                    object_name = decode_gva_request(confirmed.service)
                    if packet_context is not None:
                        key = (
                            packet_context.flow_id,
                            packet_context.direction,
                            confirmed.invoke_id,
                        )
                        if object_name is None:
                            counters.get_variable_access_attributes_address_requests += 1
                        elif key in invalid_gva_invokes:
                            counters.get_variable_access_attributes_duplicate_requests += 1
                        elif key in pending:
                            counters.get_variable_access_attributes_duplicate_requests += 1
                            invalid_gva_invokes.add(key)
                            del pending[key]
                        else:
                            reserve_pending_correlation(pending, invalid_gva_invokes, key)
                            pending[key] = object_name
                elif service == (1, 6):
                    counters.get_variable_access_attributes_responses += 1
                    attributes = decode_gva_attributes(confirmed.service)
                    if packet_context is not None:
                        request_key = (
                            packet_context.flow_id,
                            1 - packet_context.direction,
                            confirmed.invoke_id,
                        )
                        same_direction_key = (
                            packet_context.flow_id,
                            packet_context.direction,
                            confirmed.invoke_id,
                        )
                        if request_key in invalid_gva_invokes:
                            counters.get_variable_access_attributes_ambiguous_responses += 1
                            invalid_gva_invokes.remove(request_key)
                        elif request_key in pending:
                            prior = pending.pop(request_key)
                            counters.get_variable_access_attributes_matched += 1
                            named_type = type_mappings.get(
                                (
                                    packet_context.flow_id,
                                    packet_context.direction,
                                    prior,
                                ),
                                "",
                            )
                            exact_type = bool(named_type) and (
                                not attributes.deletable
                                and attributes.unresolved_type_names == 0
                                and attributes.signature
                                == expected_tase2_type_signature(named_type)
                            )
                            if exact_type:
                                learned_types[
                                    (
                                        packet_context.flow_id,
                                        packet_context.direction,
                                        prior,
                                    )
                                ] = named_type
                                counters.tase2_supported_type_discoveries += 1
                            else:
                                counters.tase2_unsupported_type_discoveries += 1
                        elif (
                            same_direction_key in pending
                            or same_direction_key in invalid_gva_invokes
                        ):
                            counters.get_variable_access_attributes_direction_mismatches += 1
                        else:
                            counters.get_variable_access_attributes_unmatched_responses += 1
                if service == (0, 4):
                    counters.read_requests += 1
                    request = decode_read_request(confirmed.service)
                    if packet_context is not None:
                        key = (
                            packet_context.flow_id,
                            packet_context.direction,
                            confirmed.invoke_id,
                        )
                        if key in invalid_read_invokes:
                            counters.read_duplicate_requests += 1
                        elif key in pending_reads:
                            counters.read_duplicate_requests += 1
                            invalid_read_invokes.add(key)
                            del pending_reads[key]
                        else:
                            reserve_pending_correlation(
                                pending_reads, invalid_read_invokes, key
                            )
                            pending_reads[key] = request
                elif service == (1, 4):
                    counters.read_responses += 1
                    response = decode_read_response(confirmed.service)
                    total_results += len(response.results)
                    if total_results > MAX_TOTAL_RESULTS:
                        raise OracleError("MMS results exceed aggregate entry bound")
                    total_data_nodes += sum(
                        _node_count(result.node) for result in response.results
                    )
                    if total_data_nodes > MAX_TOTAL_DATA_NODES:
                        raise OracleError("MMS Data nodes exceed aggregate entry bound")
                    counters.read_results += len(response.results)
                    counters.read_failures += sum(
                        result.error >= 0 for result in response.results
                    )
                    if packet_context is not None:
                        request_key = (
                            packet_context.flow_id,
                            1 - packet_context.direction,
                            confirmed.invoke_id,
                        )
                        same_direction_key = (
                            packet_context.flow_id,
                            packet_context.direction,
                            confirmed.invoke_id,
                        )
                        if request_key in invalid_read_invokes:
                            counters.read_ambiguous_responses += 1
                            invalid_read_invokes.remove(request_key)
                        elif request_key in pending_reads:
                            request = pending_reads.pop(request_key)
                            counters.read_matched += 1
                            returned_access_present = (
                                response.returned_access_choice >= 0
                            )
                            access_matches = (
                                request.specification_with_result
                                == returned_access_present
                                and (
                                    not returned_access_present
                                    or (
                                        response.returned_access_choice
                                        == request.access_choice
                                        and response.returned_variables
                                        == request.variables
                                        and response.returned_named_list
                                        == request.named_list
                                    )
                                )
                            )
                            if not access_matches:
                                counters.read_returned_access_mismatches += 1
                            cardinality_matches = (
                                request.access_choice == 0
                                and len(request.variables) == len(response.results)
                            )
                            if request.access_choice == 0 and not cardinality_matches:
                                counters.read_cardinality_mismatches += 1
                            first = response.results[0]
                            candidates = tase2_indication_candidates(first.node)
                            if candidates:
                                counters.tase2_read_shape_candidate_results += 1
                                object_name = (
                                    request.variables[0]
                                    if request.variables else ObjectName()
                                )
                                if (
                                    not access_matches or not cardinality_matches
                                    or not object_name.item
                                ):
                                    counters.tase2_read_unpaired_candidate_results += 1
                                else:
                                    named_type = learned_types.get(
                                        (
                                            packet_context.flow_id,
                                            packet_context.direction,
                                            object_name,
                                        ),
                                        "",
                                    )
                                    if not named_type:
                                        counters.tase2_read_missing_named_type_results += 1
                                    elif named_type in candidates:
                                        point_type = tase2_point_label(named_type)
                                        counters.tase2_read_verified_results += 1
                                        counters.tase2_verified_results += 1
                                        append_classification(
                                            classifications,
                                            Classification(
                                                packet_context.flow_id,
                                                packet_context.direction,
                                                "read_response",
                                                confirmed.invoke_id,
                                                object_name,
                                                named_type,
                                                point_type,
                                            ),
                                            counters.tase2_verified_results,
                                            classifications_path is not None,
                                        )
                                    else:
                                        counters.tase2_read_named_type_shape_mismatches += 1
                        elif (
                            same_direction_key in pending_reads
                            or same_direction_key in invalid_read_invokes
                        ):
                            counters.read_direction_mismatches += 1
                        else:
                            counters.read_unmatched_responses += 1
                report = parse_information_report(packet)
                if report is None:
                    counters.non_reports += 1
                    continue
                counters.reports += 1
                if report.access_choice == 0:
                    counters.explicit_reports += 1
                    counters.variables += report.variable_count
                else:
                    counters.named_list_reports += 1
                counters.results += len(report.results)
                total_results += len(report.results)
                if total_results > MAX_TOTAL_RESULTS:
                    raise OracleError("MMS results exceed aggregate entry bound")
                counters.failures += sum(result.error >= 0 for result in report.results)
                report_data_nodes = sum(
                    _node_count(result.node) for result in report.results
                )
                total_data_nodes += report_data_nodes
                if total_data_nodes > MAX_TOTAL_DATA_NODES:
                    raise OracleError("MMS Data nodes exceed aggregate entry bound")
                counters.data_nodes += report_data_nodes
                for result_index, result in enumerate(report.results):
                    candidates = tase2_indication_candidates(result.node)
                    if candidates:
                        counters.tase2_shape_candidate_results += 1
                        if len(candidates) > 1:
                            counters.tase2_shape_ambiguous_results += 1
                        for candidate in candidates:
                            counters.tase2_candidate_types[candidate] += 1
                        named_type = ""
                        if (
                            packet_context is not None
                            and report.access_choice == 0
                            and result_index == 0
                            and len(report.variables) == len(report.results)
                            and result_index < len(report.variables)
                            and report.variables[result_index].item
                        ):
                            named_type = learned_types.get(
                                (
                                    packet_context.flow_id,
                                    packet_context.direction,
                                    report.variables[result_index],
                                ),
                                "",
                            )
                        if not named_type:
                            counters.tase2_missing_named_type_results += 1
                        elif named_type in candidates:
                            counters.tase2_verified_results += 1
                            append_classification(
                                classifications,
                                Classification(
                                    packet_context.flow_id,
                                    packet_context.direction,
                                    "information_report",
                                    -1,
                                    report.variables[result_index],
                                    named_type,
                                    tase2_point_label(named_type),
                                ),
                                counters.tase2_verified_results,
                                classifications_path is not None,
                            )
                        else:
                            counters.tase2_named_type_shape_mismatches += 1
                    else:
                        counters.tase2_shape_unmatched_results += 1
                for line in report_lines(counters.reports, report):
                    output_budget.write_text(records, line + "\n", 1)
                if reports_output is not None:
                    output_budget.write_binary(reports_output, packet)
        finally:
            if reports_output is not None:
                reports_output.close()
    if metadata_available and len(metadata) != counters.packets:
        raise OracleError("MMS metadata has more rows than packets")
    if classifications_path is not None:
        with transaction.open_text(
            classifications_path, encoding="utf-8"
        ) as output:
            output_budget.write_text(
                output,
                "flow_id\tdirection\ttransfer_kind\tinvoke_id\tobject_scope\t"
                "object_domain\tobject_name\tnamed_type\tpoint_type\n",
                1,
            )
            for classification in classifications:
                output_budget.write_text(
                    output, classification_line(classification) + "\n", 1
                )

    with transaction.open_text(summary_path) as summary:
        for field in dataclasses.fields(Counters):
            if field.name == "tase2_candidate_types":
                continue
            output_budget.write_text(
                summary,
                f"information_report.{field.name}\t"
                f"{getattr(counters, field.name)}\n",
            )
        type_discovery_total = (
            counters.get_variable_access_attributes_requests
            + counters.get_variable_access_attributes_responses
        )
        output_budget.write_text(
            summary,
            f"tase2_profile.type_discovery_records\t{type_discovery_total}\n",
        )
        output_budget.write_text(
            summary,
            "tase2_profile.correlation_not_implemented\t"
            f"{int(type_discovery_total > 0 and not metadata_available)}\n"
        )
        output_budget.write_text(
            summary,
            f"tase2_profile.correlation_available\t{int(metadata_available)}\n"
        )
        output_budget.write_text(
            summary,
            "tase2_profile.verified_classifications\t"
            f"{counters.tase2_verified_results}\n"
        )
        output_budget.write_text(
            summary,
            "tase2_profile.shape_candidate_results\t"
            f"{counters.tase2_shape_candidate_results}\n"
        )
        output_budget.write_text(
            summary,
            "tase2_profile.shape_ambiguous_results\t"
            f"{counters.tase2_shape_ambiguous_results}\n"
        )
        output_budget.write_text(
            summary,
            "tase2_profile.shape_unmatched_results\t"
            f"{counters.tase2_shape_unmatched_results}\n"
        )
        output_budget.write_text(
            summary,
            "tase2_profile.missing_named_type_results\t"
            f"{counters.tase2_missing_named_type_results}\n"
        )
        output_budget.write_text(
            summary, f"tase2_profile.read_requests\t{counters.read_requests}\n"
        )
        output_budget.write_text(
            summary, f"tase2_profile.read_responses\t{counters.read_responses}\n"
        )
        output_budget.write_text(
            summary, f"tase2_profile.read_matches\t{counters.read_matched}\n"
        )
        output_budget.write_text(
            summary,
            "tase2_profile.read_verified_classifications\t"
            f"{counters.tase2_read_verified_results}\n"
        )
        output_budget.write_text(
            summary,
            "tase2_profile.read_shape_candidate_results\t"
            f"{counters.tase2_read_shape_candidate_results}\n"
        )
        for name in TASE2_INDICATION_TYPES:
            output_budget.write_text(
                summary,
                f"tase2_profile.shape.{name}\t"
                f"{counters.tase2_candidate_types[name]}\n"
            )
    return counters


def analyze(path: pathlib.Path, records_path: pathlib.Path,
            summary_path: pathlib.Path, reports_path: pathlib.Path | None,
            metadata_path: pathlib.Path | None = None,
            classifications_path: pathlib.Path | None = None,
            type_mappings_path: pathlib.Path | None = None) -> Counters:
    with ArtifactTransaction() as transaction:
        return _analyze(
            path, records_path, summary_path, reports_path, metadata_path,
            classifications_path, type_mappings_path, transaction,
        )


def _node_count(node: DataNode | None) -> int:
    if node is None:
        return 0
    return 1 + sum(_node_count(child) for child in node.children)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input_pcap", type=pathlib.Path)
    parser.add_argument("records", type=pathlib.Path)
    parser.add_argument("summary", type=pathlib.Path)
    parser.add_argument("--reports", type=pathlib.Path,
                        help="write concatenated raw InformationReport PDUs")
    parser.add_argument("--metadata", type=pathlib.Path,
                        help="privacy-local flow/direction sidecar from extractor")
    parser.add_argument(
        "--classifications", type=pathlib.Path,
        help="write privacy-local independently verified point records",
    )
    parser.add_argument(
        "--type-mappings", type=pathlib.Path,
        help="read explicit flow/server/object-to-TASE.2-type mappings",
    )
    args = parser.parse_args()
    try:
        counters = analyze(
            args.input_pcap, args.records, args.summary, args.reports,
            args.metadata, args.classifications, args.type_mappings,
        )
    except (OSError, OracleError) as error:
        print(f"information-report oracle: {error}", file=sys.stderr)
        return 1
    print(f"information_reports={counters.reports}")
    print(f"information_report_results={counters.results}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
