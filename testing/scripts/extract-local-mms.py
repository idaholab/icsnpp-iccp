#!/usr/bin/env python3

"""Extract bounded direct MMS PDUs for private independent validation.

This utility is intentionally separate from the production Spicy parser.  It
uses a small read-only PCAP/Ethernet/TCP reader and standards-shaped framing
walk for TPKT, COTP DT, Session Data Transfer, and Presentation PDVs.
It emits no addresses, ports, names, values, timestamps, or packet bytes to
stdout.  The output PCAP still contains capture-derived MMS bytes and must
remain in the private validation directory.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import os
import pathlib
import stat
import struct
import sys
import tempfile
from dataclasses import dataclass, field
from typing import BinaryIO, Iterator

MAX_TPKT_LENGTH = 65535
MAX_CAPTURED_PACKET_LENGTH = 16 * 1024 * 1024
MAX_CAPTURE_PACKETS = 1_000_000
MAX_CAPTURE_BYTES = 512 * 1024 * 1024
MAX_VLAN_HEADERS = 8
MAX_IPV6_EXTENSION_HEADERS = 16
MAX_TCP_CONNECTIONS = 65_536
MAX_TCP_EVENTS = 1_000_000
MAX_DIRECTION_STREAMS = 131_072
MAX_SEGMENTS_PER_DIRECTION = 65_536
MAX_CAUSAL_PENDING_SEGMENTS = 1024
MAX_CAUSAL_PENDING_BYTES = 64 * 1024 * 1024
MAX_EXTRACTED_PDUS = 1_000_000
MAX_EXTRACTED_BYTES = 512 * 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024 * 1024
ZEEK_TOO_LARGE_SEQUENCE_DELTA = 1024 * 1024
ZEEK_TCP_MAX_INITIAL_WINDOW = 16_384
ZEEK_TCP_MAX_ABOVE_HOLE_WITHOUT_ACKS = 16_384
ZEEK_TCP_EXCESSIVE_DATA_WITHOUT_ACKS = 10 * 1024 * 1024
MMS_CONSTRUCTED_TOP_LEVEL_TAGS = frozenset(
    (0, 1, 2, 3, 4, 7, 8, 9, 10, 13)
)
MMS_PRIMITIVE_TOP_LEVEL_TAGS = frozenset((5, 6, 11, 12))


@dataclass
class DirectionStream:
    segments: list["CapturedSegment"] = field(default_factory=list)


@dataclass(frozen=True)
class CapturedSegment:
    packet_index: int
    sequence: int
    payload: bytes


@dataclass(frozen=True)
class ReassembledChunk:
    data: bytes
    # Byte ranges are half-open offsets into data. Only the capture-local
    # packet number is retained; endpoint and timestamp data never leave the
    # extractor.
    origins: tuple[tuple[int, int, int], ...]


@dataclass(frozen=True)
class OrderedRecord:
    packet_index: int
    data: bytes


@dataclass(frozen=True)
class ExtractedMms:
    capture_packet_index: int
    serial: int
    flow_id: int
    direction: int
    payload: bytes


@dataclass(frozen=True)
class TcpEvent:
    packet_index: int
    connection_key: tuple[tuple[bytes, int], tuple[bytes, int]]
    generation: int
    source: tuple[bytes, int]
    destination: tuple[bytes, int]
    sequence: int
    acknowledgement: int
    flags: int
    payload: bytes

    def direction_key(self) -> tuple[object, ...]:
        return (
            self.connection_key,
            self.generation,
            self.source,
            self.destination,
        )

    def reverse_direction_key(self) -> tuple[object, ...]:
        return (
            self.connection_key,
            self.generation,
            self.destination,
            self.source,
        )


@dataclass
class BufferedSegment:
    sequence: int
    payload: bytes

    @property
    def end(self) -> int:
        return self.sequence + len(self.payload)


@dataclass(frozen=True)
class RetainedRange:
    """One disjoint reassembler block retained until an ACK trims it."""

    sequence: int
    end: int

    @property
    def size(self) -> int:
        return self.end - self.sequence


@dataclass
class CausalDirection:
    # Next byte the stream analyzer needs in order to deliver contiguously.
    cursor: int | None = None
    # Absolute sequence immediately before the first data-space octet Zeek
    # expects after observing a packet from this endpoint.  Unlike a peer ACK,
    # that own-direction observation makes the partial-connection baseline
    # durable.
    start_sequence: int | None = None
    # Zeek keeps its endpoint ACK, reassembler trim, and delivery positions
    # separately.  They normally converge, but not at the beginning of a
    # partial connection (see advance_causal_ack()).
    acknowledgement_floor: int | None = None
    trim_floor: int | None = None
    initial_data_sequence: int | None = None
    partial_connection: bool = False
    pending: list[BufferedSegment] = field(default_factory=list)
    # Zeek retains delivered blocks until an ACK (or its initial-window
    # heuristic) trims them. Keep range-only mirrors so memory accounting can
    # match Zeek without duplicating capture bytes.
    retained: list[RetainedRange] = field(default_factory=list)
    epochs: list[bytes] = field(default_factory=list)
    current_epoch: bytearray = field(default_factory=bytearray)
    pending_bytes: int = 0
    retained_bytes: int = 0
    payload_observed: bool = False
    highest_data_end: int | None = None
    # Absolute sequence immediately after the FIN packet's payload and before
    # its control octet. TCP ACKs covering FIN are clamped here for reassembly.
    fin_data_end: int | None = None
    skip_deliveries: bool = False


@dataclass
class ConnectionState:
    generation: int = 0
    active: bool = False
    initial_syn_sequence: int | None = None
    fin_senders: set[tuple[bytes, int]] = field(default_factory=set)


class Counters(collections.Counter[str]):
    def write(self, output: BinaryIO, budget: "OutputBudget | None" = None) -> None:
        for key in sorted(self):
            value = f"{key}\t{self[key]}\n".encode()
            if budget is None:
                output.write(value)
            else:
                budget.write(output, value)


@dataclass
class OutputBudget:
    bytes_written: int = 0
    pdu_records: int = 0

    def add_pdu(self) -> None:
        self.pdu_records += 1
        if self.pdu_records > MAX_EXTRACTED_PDUS:
            raise ValueError("derived output exceeds extracted-PDU bound")

    def write(self, output: BinaryIO, value: bytes) -> None:
        if self.bytes_written + len(value) > MAX_OUTPUT_BYTES:
            raise ValueError("derived artifacts exceed aggregate output-byte bound")
        output.write(value)
        self.bytes_written += len(value)


@dataclass(frozen=True)
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
            raise ValueError(f"unable to resolve output parent: {path}") from error
        final = parent / path.name
        if any(artifact.final == final for artifact in self.artifacts):
            raise ValueError(f"duplicate transactional output: {path}")
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
                    raise ValueError("staged artifact identity or mode changed")
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
                    raise ValueError("published artifact identity changed")
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


def validate_distinct_paths(
    capture_path: pathlib.Path, output_paths: list[pathlib.Path]
) -> None:
    """Reject aliases before any output artifact can be created."""

    for path in output_paths:
        if path.is_symlink():
            raise ValueError(
                f"path collision: output must not be a symbolic link: {path}"
            )

    seen_paths: dict[pathlib.Path, str] = {}
    seen_inodes: dict[tuple[int, int], str] = {}
    named_paths = [("input capture", capture_path)] + [
        ("output", path) for path in output_paths
    ]

    for description, path in named_paths:
        try:
            resolved = path.resolve(strict=False)
        except (OSError, RuntimeError) as error:
            raise ValueError(f"unable to resolve {description}: {path}") from error
        if resolved in seen_paths:
            raise ValueError(
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
            raise ValueError(
                f"inode collision between {seen_inodes[inode]} and {description}: "
                f"{path}"
            )
        seen_inodes[inode] = description

    for path in output_paths:
        if path.exists():
            raise FileExistsError(f"output already exists: {path}")


def endpoint(address: bytes, port: int) -> tuple[bytes, int]:
    return address, port


def canonical_connection(
    source: tuple[bytes, int], destination: tuple[bytes, int]
) -> tuple[tuple[bytes, int], tuple[bytes, int]]:
    return tuple(sorted((source, destination)))  # type: ignore[return-value]


def ethernet_ip_payload(packet: bytes) -> tuple[int, bytes] | None:
    if len(packet) < 14:
        return None
    ether_type = int.from_bytes(packet[12:14], "big")
    offset = 14
    vlan_headers = 0
    while ether_type in (0x8100, 0x88A8, 0x9100):
        vlan_headers += 1
        if vlan_headers > MAX_VLAN_HEADERS:
            return None
        if offset + 4 > len(packet):
            return None
        ether_type = int.from_bytes(packet[offset + 2 : offset + 4], "big")
        offset += 4
    return ether_type, packet[offset:]


def ipv6_tcp_offset(payload: bytes) -> tuple[int, int] | None:
    if len(payload) < 40:
        return None
    payload_end = int.from_bytes(payload[4:6], "big") + 40
    if payload_end > len(payload):
        return None
    next_header = payload[6]
    offset = 40
    extension_headers = 0
    while next_header in (0, 43, 44, 51, 60):
        extension_headers += 1
        if extension_headers > MAX_IPV6_EXTENSION_HEADERS:
            return None
        if next_header == 44:
            # This independent reader does not reassemble IP fragments. Even
            # an atomic fragment header is rejected so a later capture change
            # cannot silently alter that trust boundary.
            return None
        if offset + 2 > payload_end:
            return None
        following = payload[offset]
        if next_header == 51:
            extension_length = (payload[offset + 1] + 2) * 4
        else:
            extension_length = (payload[offset + 1] + 1) * 8
        if offset + extension_length > payload_end:
            return None
        next_header = following
        offset += extension_length
    if next_header != 6:
        return None
    return offset, payload_end


def tcp_packet(
    packet: bytes,
) -> tuple[bytes, bytes, int, int, int, int, int, bytes] | None:
    ethernet = ethernet_ip_payload(packet)
    if ethernet is None:
        return None
    ether_type, payload = ethernet

    if ether_type == 0x0800:
        if len(payload) < 20 or payload[0] >> 4 != 4 or payload[9] != 6:
            return None
        ip_header_length = (payload[0] & 0x0F) * 4
        total_length = int.from_bytes(payload[2:4], "big")
        if ip_header_length < 20 or total_length < ip_header_length:
            return None
        if total_length > len(payload):
            return None
        fragment = int.from_bytes(payload[6:8], "big")
        if fragment & 0x3FFF:
            return None
        ip_end = total_length
        source_address = payload[12:16]
        destination_address = payload[16:20]
        tcp_offset = ip_header_length
    elif ether_type == 0x86DD:
        if len(payload) < 40 or payload[0] >> 4 != 6:
            return None
        parsed_offset = ipv6_tcp_offset(payload)
        if parsed_offset is None:
            return None
        tcp_offset, ip_end = parsed_offset
        source_address = payload[8:24]
        destination_address = payload[24:40]
    else:
        return None

    if tcp_offset + 20 > ip_end:
        return None
    tcp = payload[tcp_offset:ip_end]
    tcp_header_length = (tcp[12] >> 4) * 4
    if tcp_header_length < 20 or tcp_header_length > len(tcp):
        return None
    return (
        source_address,
        destination_address,
        int.from_bytes(tcp[0:2], "big"),
        int.from_bytes(tcp[2:4], "big"),
        int.from_bytes(tcp[4:8], "big"),
        int.from_bytes(tcp[8:12], "big"),
        tcp[13],
        tcp[tcp_header_length:],
    )


def pcap_packets(capture_path: pathlib.Path) -> Iterator[bytes]:
    with capture_path.open("rb") as capture:
        global_header = capture.read(24)
        if len(global_header) != 24:
            raise ValueError("capture has a truncated PCAP header")
        magic = global_header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            byte_order = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            byte_order = ">"
        else:
            raise ValueError("input is not a supported classic PCAP")
        version_major, version_minor, snaplen, link_type = struct.unpack(
            f"{byte_order}HH8xII", global_header[4:24]
        )
        if (version_major, version_minor) != (2, 4):
            raise ValueError("input PCAP has an unsupported format version")
        if snaplen == 0:
            raise ValueError("input PCAP has a zero snaplen")
        if snaplen > MAX_CAPTURED_PACKET_LENGTH:
            raise ValueError("input PCAP snaplen exceeds supported bound")
        if link_type != 1:
            raise ValueError("input PCAP is not Ethernet")

        packet_count = 0
        captured_bytes = 0
        while True:
            packet_header = capture.read(16)
            if not packet_header:
                return
            if len(packet_header) != 16:
                raise ValueError("capture has a truncated packet header")
            included_length, original_length = struct.unpack(
                f"{byte_order}II", packet_header[8:16]
            )
            if included_length > original_length:
                raise ValueError(
                    "PCAP packet included length exceeds original length"
                )
            if included_length > snaplen:
                raise ValueError("PCAP packet included length exceeds snaplen")
            if included_length > MAX_CAPTURED_PACKET_LENGTH:
                raise ValueError("PCAP packet included length exceeds supported bound")
            packet_count += 1
            if packet_count > MAX_CAPTURE_PACKETS:
                raise ValueError("input PCAP exceeds supported packet-count bound")
            captured_bytes += included_length
            if captured_bytes > MAX_CAPTURE_BYTES:
                raise ValueError("input PCAP exceeds supported captured-byte bound")
            packet = capture.read(included_length)
            if len(packet) != included_length:
                raise ValueError("capture has a truncated packet")
            yield packet


def collect_streams(
    capture_path: pathlib.Path, counters: Counters
) -> tuple[dict[tuple[object, ...], DirectionStream], list[TcpEvent]]:
    connections: dict[
        tuple[tuple[bytes, int], tuple[bytes, int]], ConnectionState
    ] = {}
    streams: dict[tuple[object, ...], DirectionStream] = {}
    events: list[TcpEvent] = []

    for packet_index, packet in enumerate(pcap_packets(capture_path), 1):
        counters["input.packets"] += 1
        parsed_tcp = tcp_packet(packet)
        if parsed_tcp is None:
            continue
        (
            source_address,
            destination_address,
            source_port,
            destination_port,
            sequence_number,
            acknowledgement_number,
            flags,
            payload,
        ) = parsed_tcp

        source = endpoint(source_address, source_port)
        destination = endpoint(destination_address, destination_port)
        connection_key = canonical_connection(source, destination)
        if (
            connection_key not in connections
            and len(connections) >= MAX_TCP_CONNECTIONS
        ):
            raise ValueError("input PCAP exceeds supported TCP connection bound")
        state = connections.setdefault(connection_key, ConnectionState())

        syn = bool(flags & 0x02)
        ack = bool(flags & 0x10)
        if syn and not ack:
            # A retransmitted opening SYN belongs to the same tuple
            # generation. A different SYN sequence starts a fresh connection
            # even when the prior FIN/RST was absent from the capture.
            if (
                not state.active
                or state.initial_syn_sequence != sequence_number
            ):
                state.generation += 1
                state.initial_syn_sequence = sequence_number
                state.fin_senders.clear()
            state.active = True
        elif not state.active:
            state.generation += 1
            state.active = True
            state.initial_syn_sequence = None
            state.fin_senders.clear()

        event = TcpEvent(
            packet_index=packet_index,
            connection_key=connection_key,
            generation=state.generation,
            source=source,
            destination=destination,
            sequence=sequence_number + (1 if syn else 0),
            acknowledgement=acknowledgement_number,
            flags=flags,
            payload=payload,
        )
        if len(events) >= MAX_TCP_EVENTS:
            raise ValueError("input PCAP exceeds supported TCP event bound")
        events.append(event)

        if payload:
            direction_key = event.direction_key()
            if (
                direction_key not in streams
                and len(streams) >= MAX_DIRECTION_STREAMS
            ):
                raise ValueError("input PCAP exceeds supported direction-stream bound")
            direction = streams.setdefault(direction_key, DirectionStream())
            if len(direction.segments) >= MAX_SEGMENTS_PER_DIRECTION:
                raise ValueError(
                    "input PCAP exceeds supported per-direction segment bound"
                )
            direction.segments.append(
                CapturedSegment(packet_index, event.sequence, payload)
            )
            counters["tcp.payload_segments"] += 1
            counters["tcp.payload_bytes"] += len(payload)

        if flags & 0x04:
            state.active = False
        elif flags & 0x01:
            # A one-sided FIN is only a TCP half-close; the peer may legally
            # continue sending application data in this same connection.
            # Without timestamps this independent reader cannot exactly model
            # Zeek's delayed removal after a full close, so it conservatively
            # begins a new implicit generation only after both endpoints FIN.
            state.fin_senders.add(source)
            if len(state.fin_senders) == 2:
                state.active = False

    counters["tcp.direction_streams"] = len(streams)
    return streams, events


def contiguous_chunks(
    stream: DirectionStream, counters: Counters
) -> Iterator[ReassembledChunk]:
    if not stream.segments:
        return

    first_captured = min(stream.segments, key=lambda segment: segment.packet_index)
    ordered = sorted(
        (
            (unwrap_sequence(segment.sequence, first_captured.sequence), segment)
            for segment in stream.segments
        ),
        key=lambda sequenced: sequenced[0],
    )
    current = bytearray()
    origins: list[tuple[int, int, int]] = []
    cursor: int | None = None

    for sequence, segment in ordered:
        payload = segment.payload
        if cursor is None:
            start = len(current)
            current.extend(payload)
            origins.append((start, len(current), segment.packet_index))
            cursor = sequence + len(payload)
            continue

        if sequence > cursor:
            counters["tcp.gaps"] += 1
            if current:
                yield ReassembledChunk(bytes(current), tuple(origins))
            current = bytearray(payload)
            origins = [(0, len(current), segment.packet_index)]
            cursor = sequence + len(payload)
            continue

        overlap = cursor - sequence
        if overlap >= len(payload):
            counters["tcp.duplicate_segments"] += 1
            continue

        if overlap > 0:
            counters["tcp.overlap_bytes"] += overlap
        start = len(current)
        current.extend(payload[overlap:])
        origins.append((start, len(current), segment.packet_index))
        cursor += len(payload) - overlap

    if current:
        yield ReassembledChunk(bytes(current), tuple(origins))


def unwrap_sequence(value: int, reference: int) -> int:
    """Map a TCP number around reference with Zeek's signed serial arithmetic.

    The exactly-half-space case maps backward.  Zeek compares sequence
    numbers through a signed 32-bit delta, where 0x80000000 is negative; a
    nearest-candidate implementation otherwise chooses the forward candidate
    on that tie and can invent a 2-GiB ACK advance.
    """

    modulus = 1 << 32
    half_space = 1 << 31
    delta = ((value & 0xFFFFFFFF) - (reference & 0xFFFFFFFF)) & 0xFFFFFFFF
    if delta >= half_space:
        delta -= modulus
    return reference + delta


def close_causal_epoch(state: CausalDirection) -> None:
    if state.current_epoch:
        state.epochs.append(bytes(state.current_epoch))
        state.current_epoch.clear()


def no_data_acked(state: CausalDirection) -> bool:
    """Mirror TCP_Endpoint::NoDataAcked(), including the SYN allowance."""

    return (
        state.start_sequence is not None
        and state.acknowledgement_floor
        in (state.start_sequence, state.start_sequence + 1)
    )


def trim_retained_ranges(state: CausalDirection, sequence: int) -> int:
    """Drop complete Zeek-style blocks whose upper edge is at the trim point."""

    retained: list[RetainedRange] = []
    removed = 0
    for item in state.retained:
        if item.end <= sequence:
            removed += item.size
        else:
            retained.append(item)
    state.retained = retained
    state.retained_bytes -= removed
    return removed


def clear_causal_blocks(state: CausalDirection) -> None:
    state.pending.clear()
    state.pending_bytes = 0
    state.retained.clear()
    state.retained_bytes = 0


def apply_initial_window_trim(
    state: CausalDirection, delivered: int, counters: Counters
) -> None:
    """Release delivered blocks when Zeek assumes peer ACKs are invisible."""

    if (
        delivered <= 0
        or not ZEEK_TCP_MAX_INITIAL_WINDOW
        or not no_data_acked(state)
        or state.highest_data_end is None
        or state.initial_data_sequence is None
        or state.highest_data_end - state.initial_data_sequence
        <= ZEEK_TCP_MAX_INITIAL_WINDOW
    ):
        return

    assert state.cursor is not None
    removed = trim_retained_ranges(state, state.cursor)
    state.trim_floor = max(
        state.trim_floor if state.trim_floor is not None else state.cursor,
        state.cursor,
    )
    counters["tcp.initial_window_trim_events"] += 1
    counters["tcp.initial_window_trim_bytes"] += removed


def apply_reassembly_ceilings(
    state: CausalDirection, counters: Counters
) -> None:
    """Apply the default Zeek 8 TCP reassembler abandonment thresholds."""

    if state.skip_deliveries:
        return

    assert state.cursor is not None
    if (
        ZEEK_TCP_MAX_ABOVE_HOLE_WITHOUT_ACKS
        and no_data_acked(state)
        and state.retained
    ):
        highest_end = max(item.end for item in state.retained)
        above_hole = max(0, highest_end - state.cursor)
        if above_hole > ZEEK_TCP_MAX_ABOVE_HOLE_WITHOUT_ACKS:
            counters["tcp.above_hole_abandonments"] += 1
            counters["tcp.above_hole_abandoned_span"] += above_hole
            counters["tcp.abandoned_retained_bytes"] += state.retained_bytes
            clear_causal_blocks(state)
            state.skip_deliveries = True
            return

    if (
        ZEEK_TCP_EXCESSIVE_DATA_WITHOUT_ACKS
        and state.retained_bytes > ZEEK_TCP_EXCESSIVE_DATA_WITHOUT_ACKS
    ):
        counters["tcp.excessive_data_abandonments"] += 1
        counters["tcp.abandoned_retained_bytes"] += state.retained_bytes
        clear_causal_blocks(state)
        state.skip_deliveries = True


def insert_causal_segment(
    state: CausalDirection,
    sequence: int,
    payload: bytes,
    counters: Counters,
) -> None:
    if state.cursor is None:
        state.cursor = sequence
    else:
        sequence = unwrap_sequence(sequence, state.cursor)

    assert state.cursor is not None
    lower_bound = max(
        state.cursor,
        state.acknowledgement_floor
        if state.acknowledgement_floor is not None
        else state.cursor,
        state.trim_floor if state.trim_floor is not None else state.cursor,
    )
    end = sequence + len(payload)
    if end <= lower_bound:
        counters["tcp.late_segments"] += 1
        counters["tcp.late_bytes"] += len(payload)
        return
    if sequence < lower_bound:
        trim = lower_bound - sequence
        counters["tcp.late_prefix_bytes"] += trim
        payload = payload[trim:]
        sequence = lower_bound

    fragments = [(sequence, payload)]
    overlap_bytes = 0
    conflicting_overlap_bytes = 0
    for existing in state.pending:
        next_fragments: list[tuple[int, bytes]] = []
        for fragment_sequence, fragment_payload in fragments:
            fragment_end = fragment_sequence + len(fragment_payload)
            overlap_start = max(fragment_sequence, existing.sequence)
            overlap_end = min(fragment_end, existing.end)
            if overlap_start >= overlap_end:
                next_fragments.append((fragment_sequence, fragment_payload))
                continue

            overlap_bytes += overlap_end - overlap_start
            fragment_slice = fragment_payload[
                overlap_start - fragment_sequence : overlap_end - fragment_sequence
            ]
            existing_slice = existing.payload[
                overlap_start - existing.sequence : overlap_end - existing.sequence
            ]
            conflicting_overlap_bytes += sum(
                left != right for left, right in zip(fragment_slice, existing_slice)
            )

            if fragment_sequence < overlap_start:
                next_fragments.append(
                    (
                        fragment_sequence,
                        fragment_payload[: overlap_start - fragment_sequence],
                    )
                )
            if overlap_end < fragment_end:
                next_fragments.append(
                    (
                        overlap_end,
                        fragment_payload[overlap_end - fragment_sequence :],
                    )
                )
        fragments = next_fragments
        if not fragments:
            break

    if overlap_bytes:
        counters["tcp.overlap_bytes"] += overlap_bytes
    if conflicting_overlap_bytes:
        counters["tcp.conflicting_overlap_bytes"] += conflicting_overlap_bytes
    if not fragments:
        counters["tcp.duplicate_segments"] += 1
        return

    added = [
        BufferedSegment(fragment_sequence, fragment_payload)
        for fragment_sequence, fragment_payload in fragments
    ]
    added_bytes = sum(len(segment.payload) for segment in added)
    if len(state.pending) + len(added) > MAX_CAUSAL_PENDING_SEGMENTS:
        raise ValueError("causal TCP state exceeds pending-segment bound")
    if state.pending_bytes + added_bytes > MAX_CAUSAL_PENDING_BYTES:
        raise ValueError("causal TCP state exceeds pending-byte bound")
    state.pending.extend(added)
    state.pending_bytes += added_bytes
    state.pending.sort(key=lambda segment: segment.sequence)
    state.retained.extend(
        RetainedRange(segment.sequence, segment.end) for segment in added
    )
    state.retained_bytes += added_bytes
    state.retained.sort(key=lambda item: item.sequence)


def drain_causal_segments(state: CausalDirection, counters: Counters) -> int:
    assert state.cursor is not None
    delivered_bytes = 0
    while state.pending:
        segment = state.pending[0]
        if segment.end <= state.cursor:
            state.pending.pop(0)
            state.pending_bytes -= len(segment.payload)
            continue
        if segment.sequence > state.cursor:
            return delivered_bytes

        offset = state.cursor - segment.sequence
        delivered = segment.payload[offset:]
        state.current_epoch.extend(delivered)
        state.cursor += len(delivered)
        state.pending.pop(0)
        state.pending_bytes -= len(segment.payload)
        counters["tcp.delivered_bytes"] += len(delivered)
        delivered_bytes += len(delivered)

    return delivered_bytes


def advance_causal_ack(
    state: CausalDirection, acknowledgement: int, counters: Counters
) -> bool:
    if state.cursor is None:
        counters["tcp.acks_without_direction_baseline"] += 1
        return False

    if state.acknowledgement_floor is None:
        state.acknowledgement_floor = (
            state.start_sequence
            if state.start_sequence is not None
            else state.cursor
        )
    if state.trim_floor is None:
        state.trim_floor = state.cursor

    endpoint_acknowledgement = unwrap_sequence(
        acknowledgement, state.acknowledgement_floor
    )
    if (
        state.start_sequence is not None
        and endpoint_acknowledgement < state.start_sequence
    ):
        counters["tcp.ack_underflow_events"] += 1
        return False

    acknowledgement_delta = (
        endpoint_acknowledgement - state.acknowledgement_floor
    )
    acknowledgement_raw = endpoint_acknowledgement & 0xFFFFFFFF
    if acknowledgement_delta > 0:
        # Zeek treats a zero ACK with an implausibly large positive delta as a
        # broken ACK for endpoint state.  AckReceived still receives its
        # relative target, so the reassembler trim below remains independent.
        if not (
            acknowledgement_raw == 0
            and acknowledgement_delta > ZEEK_TOO_LARGE_SEQUENCE_DELTA
        ):
            state.acknowledgement_floor = endpoint_acknowledgement
    else:
        counters["tcp.nonadvancing_acks"] += 1

    reassembly_acknowledgement = endpoint_acknowledgement
    if (
        state.fin_data_end is not None
        and reassembly_acknowledgement > state.fin_data_end
    ):
        counters["tcp.fin_ack_clamps"] += 1
        counters["tcp.fin_ack_clamped_bytes"] += (
            reassembly_acknowledgement - state.fin_data_end
        )
        reassembly_acknowledgement = state.fin_data_end

    assert state.trim_floor is not None
    if reassembly_acknowledgement <= state.trim_floor:
        return False

    previous_trim_floor = state.trim_floor

    if state.skip_deliveries:
        if state.cursor < reassembly_acknowledgement:
            state.cursor = reassembly_acknowledgement
        state.trim_floor = reassembly_acknowledgement
        trim_retained_ranges(state, reassembly_acknowledgement)
        return state.trim_floor > previous_trim_floor

    # TCP_Reassembler::Undelivered deliberately ignores relative targets 1
    # and 2 for a partial connection.  Relative 1 cannot advance the initial
    # trim position; relative 2 advances trim by one byte but (per Zeek's own
    # TODO) leaves last_reassem_seq behind.  Keeping the two positions
    # separate prevents a later acknowledged prefix from being emitted at EOF.
    if (
        state.partial_connection
        and state.initial_data_sequence is not None
        and state.cursor == state.initial_data_sequence
        and reassembly_acknowledgement == state.initial_data_sequence + 1
    ):
        state.trim_floor = reassembly_acknowledgement
        trim_retained_ranges(state, reassembly_acknowledgement)
        counters["tcp.partial_initial_gap_suppressions"] += 1
        return True

    while state.cursor < reassembly_acknowledgement:
        delivered = drain_causal_segments(state, counters)
        apply_initial_window_trim(state, delivered, counters)
        if state.cursor >= reassembly_acknowledgement:
            break

        next_sequence = reassembly_acknowledgement
        for segment in state.pending:
            if segment.end <= state.cursor:
                continue
            if segment.sequence < reassembly_acknowledgement:
                next_sequence = max(state.cursor, segment.sequence)
            break

        if next_sequence <= state.cursor:
            # A segment covering cursor would have been consumed by drain.
            raise AssertionError("causal TCP buffer failed to advance")

        close_causal_epoch(state)
        counters["tcp.ack_gap_events"] += 1
        counters["tcp.ack_gap_bytes"] += next_sequence - state.cursor
        state.cursor = next_sequence

    delivered = drain_causal_segments(state, counters)
    apply_initial_window_trim(state, delivered, counters)
    trim_retained_ranges(state, reassembly_acknowledgement)
    state.trim_floor = max(state.trim_floor, reassembly_acknowledgement)
    return state.trim_floor > previous_trim_floor


def causal_chunks(
    events: list[TcpEvent], counters: Counters
) -> dict[tuple[object, ...], list[bytes]]:
    states: dict[tuple[object, ...], CausalDirection] = {}
    partial_connections: dict[tuple[object, ...], bool] = {}
    first_directions: dict[tuple[object, ...], tuple[object, ...]] = {}
    began_with_syn_ack: set[tuple[object, ...]] = set()
    connection_directions: dict[
        tuple[object, ...], list[CausalDirection]
    ] = {}

    for event in events:
        connection_generation = (event.connection_key, event.generation)
        if connection_generation not in partial_connections:
            partial_connections[connection_generation] = not bool(
                event.flags & 0x02
            ) or bool(event.flags & 0x10)
            first_directions[connection_generation] = event.direction_key()
            if (
                event.flags & 0x02
                and event.flags & 0x10
                and not event.flags & 0x05
            ):
                began_with_syn_ack.add(connection_generation)

        direction_key = event.direction_key()
        state = states.get(direction_key)

        # If capture starts at a responder SYN/ACK, Zeek initially marks the
        # connection partial.  The missing originator's first ordinary ACK
        # completes the inferred handshake and clears that status before
        # reassembly.  This matters for the special one-byte initial-gap rule.
        if (
            partial_connections[connection_generation]
            and connection_generation in began_with_syn_ack
            and direction_key != first_directions[connection_generation]
            and state is None
            and event.flags & 0x10
            and not event.flags & 0x07
        ):
            partial_connections[connection_generation] = False
            for existing in connection_directions.get(
                connection_generation, []
            ):
                existing.partial_connection = False
            counters["tcp.inferred_handshake_completions"] += 1

        if state is None:
            if len(states) >= MAX_DIRECTION_STREAMS:
                raise ValueError(
                    "input PCAP exceeds supported causal-direction bound"
                )

            # Zeek initializes a partial endpoint from the first packet sent by
            # that endpoint, even when it carries no payload.  A peer ACK seen
            # before this packet only initializes an INACTIVE endpoint
            # provisionally and is replaced here, so it cannot by itself make
            # this endpoint's first payload late.
            state = CausalDirection(
                cursor=event.sequence,
                start_sequence=event.sequence - 1,
                acknowledgement_floor=event.sequence - 1,
                trim_floor=event.sequence,
                initial_data_sequence=event.sequence,
                partial_connection=partial_connections[connection_generation],
            )
            states[direction_key] = state
            connection_directions.setdefault(connection_generation, []).append(
                state
            )
            counters["tcp.own_direction_baselines"] += 1

        if event.payload:
            state.payload_observed = True
            assert state.cursor is not None
            sequence = unwrap_sequence(event.sequence, state.cursor)
            if (
                state.start_sequence is not None
                and sequence < state.start_sequence
            ):
                # TCPSessionAdapter rejects a segment whose base sequence is
                # below the durable endpoint start before calling DataSent().
                # It is not eligible for prefix trimming in the reassembler.
                counters["tcp.sequence_underflow_segments"] += 1
                counters["tcp.sequence_underflow_bytes"] += len(event.payload)
            elif event.flags & 0x04:
                # Zeek does not pass payload carried on RST packets to stream
                # analyzers.
                counters["tcp.rst_payload_segments"] += 1
                counters["tcp.rst_payload_bytes"] += len(event.payload)
            elif state.skip_deliveries:
                counters["tcp.skipped_delivery_segments"] += 1
                counters["tcp.skipped_delivery_bytes"] += len(event.payload)
            else:
                data_end = sequence + len(event.payload)
                state.highest_data_end = max(
                    state.highest_data_end
                    if state.highest_data_end is not None
                    else data_end,
                    data_end,
                )
                insert_causal_segment(state, sequence, event.payload, counters)
                delivered = drain_causal_segments(state, counters)
                apply_initial_window_trim(state, delivered, counters)
                apply_reassembly_ceilings(state, counters)

        if event.flags & 0x01:
            assert state.cursor is not None
            fin_sequence = unwrap_sequence(event.sequence, state.cursor)
            # Event.sequence already accounts for SYN. FIN follows any data
            # carried by this packet and consumes the next sequence octet.
            state.fin_data_end = fin_sequence + len(event.payload)

        if event.flags & 0x10:
            reverse_key = event.reverse_direction_key()
            reverse_state = states.get(reverse_key)
            if reverse_state is None:
                # Zeek may provisionally initialize an INACTIVE peer from this
                # ACK, but the peer's first own packet replaces that numeric
                # baseline. AckReceived() also cannot advance beyond the
                # reassembler's initial position in this state, so do not turn
                # it into a durable delivery floor.
                counters["tcp.provisional_peer_acks"] += 1
            else:
                advanced_without_payload = advance_causal_ack(
                    reverse_state, event.acknowledgement, counters
                )
                if (
                    not reverse_state.payload_observed
                    and advanced_without_payload
                ):
                    counters["tcp.ack_without_payload_baseline"] += 1

    chunks: dict[tuple[object, ...], list[bytes]] = {}
    for direction_key, state in states.items():
        close_causal_epoch(state)
        if state.pending:
            counters["tcp.capture_boundary_segments"] += len(state.pending)
            counters["tcp.capture_boundary_bytes"] += sum(
                len(segment.payload) for segment in state.pending
            )
        if state.epochs:
            chunks[direction_key] = state.epochs

    counters["tcp.direction_streams"] = sum(
        state.payload_observed for state in states.values()
    )
    counters["tcp.delivery_epochs"] = sum(len(value) for value in chunks.values())
    return chunks


def cotp_cr_parameters_valid(data: bytes, start: int, end: int) -> bool:
    """Validate the bounded COTP CR parameter list used by production."""

    parameter_count = 0
    offset = start
    while offset < end:
        if offset + 2 > end:
            return False
        code = data[offset]
        parameter_length = data[offset + 1]
        offset += 2
        if offset + parameter_length > end:
            return False
        if code in (0xC0, 0xC4, 0xC6) and parameter_length != 1:
            return False
        if code == 0xC3 and parameter_length != 2:
            return False
        offset += parameter_length
        parameter_count += 1
        if parameter_count > 64:
            return False
    return True


def tpkt_recovery_candidate(data: bytes, offset: int, length: int) -> bool:
    """Return whether *offset* has the supported structural recovery prefix.

    The reserved TPKT octet is deliberately not inspected.  RFC 2126 says a
    receiver ignores it, but accepting every ``0x03`` as a framing boundary is
    unsafe while scanning an arbitrary midstream byte sequence: an MMS value
    can otherwise advertise a plausible length and make the oracle skip real
    TPKTs before the invalid COTP header is noticed.  The production parser's
    synchronizer likewise confirms either a class-0 DT prefix or its strict
    class-0 CR recovery prefix before committing a recovery candidate.  CR
    records must remain visible to the COTP walk because they invalidate any
    partially accumulated DT TSDU.
    """

    data_transfer = (
        offset + 7 <= len(data)
        and data[offset] == 3
        and data[offset + 4] == 2
        and data[offset + 5] == 0xF0
        and data[offset + 6] & 0x7F == 0
    )
    if data_transfer:
        return True

    if not (
        11 <= length <= 132
        and offset + 11 <= len(data)
        and data[offset] == 3
        and 6 <= data[offset + 4] < 0xFF
        and data[offset + 4] < length - 4
        and data[offset + 5] == 0xE0
        and data[offset + 6 : offset + 8] == b"\x00\x00"
        and data[offset + 8 : offset + 10] != b"\x00\x00"
        and data[offset + 10] == 0
    ):
        return False

    # The strict class-0 profile rejects CR user data, so the TPKT body must
    # end exactly with the LI-bounded connection header.  If capture ends
    # before that advertised boundary, the conclusive prefix is still a
    # plausible truncated CR and must stop scanning rather than expose a
    # nested byte pattern as a new packet.
    length_indicator = data[offset + 4]
    if length != length_indicator + 5:
        return False
    end = offset + length
    if end > len(data):
        return True
    return cotp_cr_parameters_valid(data, offset + 11, end)


def tpkt_records(chunk: bytes, counters: Counters) -> Iterator[bytes]:
    offset = 0
    while offset + 4 <= len(chunk):
        # RFC 2126 requires receivers to ignore the reserved octet.
        if chunk[offset] != 3:
            offset += 1
            counters["tpkt.scan_bytes"] += 1
            continue

        length = int.from_bytes(chunk[offset + 2 : offset + 4], "big")
        if length < 7 or length > MAX_TPKT_LENGTH:
            offset += 1
            counters["tpkt.invalid_lengths"] += 1
            continue

        if not tpkt_recovery_candidate(chunk, offset, length):
            offset += 1
            counters["tpkt.invalid_cotp_prefixes"] += 1
            counters["tpkt.scan_bytes"] += 1
            continue

        end = offset + length
        if end > len(chunk):
            counters["tpkt.truncated_records"] += 1
            break

        counters["tpkt.records"] += 1
        yield chunk[offset + 4 : end]
        offset = end


def ordered_tpkt_records(
    chunk: ReassembledChunk, counters: Counters
) -> Iterator[OrderedRecord]:
    offset = 0
    while offset + 4 <= len(chunk.data):
        if chunk.data[offset] != 3:
            offset += 1
            counters["tpkt.scan_bytes"] += 1
            continue
        length = int.from_bytes(chunk.data[offset + 2 : offset + 4], "big")
        if length < 7 or length > MAX_TPKT_LENGTH:
            offset += 1
            counters["tpkt.invalid_lengths"] += 1
            continue
        if not tpkt_recovery_candidate(chunk.data, offset, length):
            offset += 1
            counters["tpkt.invalid_cotp_prefixes"] += 1
            counters["tpkt.scan_bytes"] += 1
            continue
        end = offset + length
        if end > len(chunk.data):
            counters["tpkt.truncated_records"] += 1
            break
        source_packets = (
            packet_index
            for start, origin_end, packet_index in chunk.origins
            if start < end and origin_end > offset
        )
        try:
            packet_index = max(source_packets)
        except ValueError as error:
            raise AssertionError("reassembled TPKT has no capture origin") from error
        counters["tpkt.records"] += 1
        yield OrderedRecord(packet_index, chunk.data[offset + 4 : end])
        offset = end


def cotp_dt_fragment(
    record: bytes, counters: Counters
) -> tuple[bytes, bool] | None:
    """Validate the production parser's strict class-0 normal DT header."""

    if len(record) < 3:
        counters["cotp.truncated"] += 1
        return None
    if record[0] != 2:
        counters["cotp.invalid_headers"] += 1
        return None
    if record[1] != 0xF0:
        counters["cotp.non_dt"] += 1
        return None
    if record[2] & 0x7F:
        counters["cotp.invalid_tpdu_numbers"] += 1
        return None
    return record[3:], bool(record[2] & 0x80)


def cotp_tsdus(records: Iterator[bytes], counters: Counters) -> Iterator[bytes]:
    current = bytearray()
    for record in records:
        fragment = cotp_dt_fragment(record, counters)
        if fragment is None:
            current.clear()
            continue

        payload, end_of_tsdu = fragment
        current.extend(payload)
        if end_of_tsdu:
            counters["cotp.tsdus"] += 1
            yield bytes(current)
            current.clear()

    if current:
        counters["cotp.incomplete_tsdus"] += 1


def ordered_cotp_tsdus(
    records: Iterator[OrderedRecord], counters: Counters
) -> Iterator[OrderedRecord]:
    current = bytearray()
    packet_index = 0
    for ordered in records:
        record = ordered.data
        fragment = cotp_dt_fragment(record, counters)
        if fragment is None:
            current.clear()
            packet_index = 0
            continue
        payload, end_of_tsdu = fragment
        current.extend(payload)
        packet_index = max(packet_index, ordered.packet_index)
        if end_of_tsdu:
            counters["cotp.tsdus"] += 1
            yield OrderedRecord(packet_index, bytes(current))
            current.clear()
            packet_index = 0
    if current:
        counters["cotp.incomplete_tsdus"] += 1


def definite_length(data: bytes, offset: int) -> tuple[int, int] | None:
    if offset >= len(data):
        return None
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    octets = first & 0x7F
    if octets == 0 or octets > 8 or offset + 1 + octets > len(data):
        return None
    if data[offset + 1] == 0:
        return None
    value = int.from_bytes(data[offset + 1 : offset + 1 + octets], "big")
    if value < 0x80:
        return None
    return value, offset + 1 + octets


def tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int] | None:
    if offset >= len(data):
        return None
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        return None
    parsed_length = definite_length(data, offset + 1)
    if parsed_length is None:
        return None
    length, value_offset = parsed_length
    end = value_offset + length
    if end > len(data):
        return None
    return tag, data[value_offset:end], end


def session_length(data: bytes, offset: int) -> tuple[int, int] | None:
    """Decode an X.225 length indicator, not a BER length determinant."""

    if offset >= len(data):
        return None
    first = data[offset]
    if first != 0xFF:
        return first, offset + 1
    if offset + 3 > len(data):
        return None
    value = int.from_bytes(data[offset + 1 : offset + 3], "big")
    if value < 0xFF:
        return None
    return value, offset + 3


def session_payload(tsdu: bytes, counters: Counters) -> bytes | None:
    if len(tsdu) < 2 or tsdu[0] != 1:
        counters["session.non_data_transfer"] += 1
        return None

    parsed_length = session_length(tsdu, 1)
    if parsed_length is None:
        counters["session.invalid_lengths"] += 1
        return None
    parameter_length, parameter_offset = parsed_length
    payload_offset = parameter_offset + parameter_length
    if payload_offset > len(tsdu):
        counters["session.truncated"] += 1
        return None

    remainder = tsdu[payload_offset:]
    if len(remainder) >= 2 and remainder[0] == 1:
        concatenated_length = session_length(remainder, 1)
        if concatenated_length is None:
            counters["session.invalid_concatenated_lengths"] += 1
            return None
        parameter_length, parameter_offset = concatenated_length
        payload_offset = parameter_offset + parameter_length
        if payload_offset > len(remainder):
            counters["session.truncated_concatenated"] += 1
            return None
        counters["session.concatenated_data_transfer"] += 1
        remainder = remainder[payload_offset:]

    counters["session.data_transfer"] += 1
    return remainder


def presentation_pdvs(
    presentation: bytes, counters: Counters
) -> Iterator[tuple[int, bytes]]:
    outer = tlv(presentation)
    if outer is None or outer[0] != 0x61 or outer[2] != len(presentation):
        counters["presentation.invalid_outer"] += 1
        return

    offset = 0
    outer_value = outer[1]
    while offset < len(outer_value):
        pdv_list = tlv(outer_value, offset)
        if pdv_list is None or pdv_list[0] != 0x30:
            counters["presentation.invalid_pdv_list"] += 1
            return
        offset = pdv_list[2]

        child_offset = 0
        context_tlv = tlv(pdv_list[1], child_offset)
        if context_tlv is None or context_tlv[0] != 0x02:
            counters["presentation.missing_context"] += 1
            continue
        child_offset = context_tlv[2]
        if not context_tlv[1] or context_tlv[1][0] & 0x80:
            counters["presentation.invalid_context"] += 1
            continue
        context_id = int.from_bytes(context_tlv[1], "big")

        syntax_or_value = tlv(pdv_list[1], child_offset)
        if syntax_or_value is None:
            counters["presentation.missing_value"] += 1
            continue
        if syntax_or_value[0] == 0x06:
            child_offset = syntax_or_value[2]
            syntax_or_value = tlv(pdv_list[1], child_offset)
            if syntax_or_value is None:
                counters["presentation.missing_value"] += 1
                continue

        if syntax_or_value[0] != 0xA0:
            counters["presentation.unsupported_encoding"] += 1
            continue
        if syntax_or_value[2] != len(pdv_list[1]):
            counters["presentation.trailing_pdv_data"] += 1
            continue

        counters["presentation.pdvs"] += 1
        counters[f"presentation.context_{context_id}"] += 1
        yield context_id, syntax_or_value[1]


def mms_candidate(payload: bytes, counters: Counters) -> bytes | None:
    parsed = tlv(payload)
    if parsed is None or parsed[2] != len(payload):
        counters["mms.invalid_outer"] += 1
        return None
    identifier = parsed[0]
    if identifier & 0xC0 != 0x80 or identifier & 0x1F > 13:
        counters["mms.unsupported_top_tag"] += 1
        return None
    tag_number = identifier & 0x1F
    constructed = bool(identifier & 0x20)
    if (
        tag_number in MMS_CONSTRUCTED_TOP_LEVEL_TAGS and not constructed
    ) or (
        tag_number in MMS_PRIMITIVE_TOP_LEVEL_TAGS and constructed
    ):
        counters["mms.invalid_top_tag_form"] += 1
        return None
    counters[f"mms.tag_{tag_number}"] += 1
    return payload


def write_pcap_header(
    output: BinaryIO, budget: OutputBudget | None = None
) -> None:
    value = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 147)
    if budget is None:
        output.write(value)
    else:
        budget.write(output, value)


def write_pcap_packet(
    output: BinaryIO, packet_index: int, payload: bytes,
    budget: OutputBudget | None = None,
) -> None:
    header = struct.pack("<IIII", packet_index, 0, len(payload), len(payload))
    if budget is None:
        output.write(header)
        output.write(payload)
    else:
        budget.write(output, header)
        budget.write(output, payload)


def collect_ordered_mms(
    streams: dict[tuple[object, ...], DirectionStream], counters: Counters
) -> list[ExtractedMms]:
    flow_first_packet: dict[tuple[object, ...], int] = {}
    for direction_key, stream in streams.items():
        flow_key = direction_key[:2]
        first = min(segment.packet_index for segment in stream.segments)
        flow_first_packet[flow_key] = min(flow_first_packet.get(flow_key, first), first)
    flow_ids = {
        flow_key: index
        for index, flow_key in enumerate(
            sorted(flow_first_packet, key=lambda key: flow_first_packet[key]), 1
        )
    }

    extracted: list[ExtractedMms] = []
    extracted_bytes = 0
    serial = 0
    for direction_key, stream in streams.items():
        connection_key, generation, source, _ = direction_key
        flow_id = flow_ids[(connection_key, generation)]
        direction = 0 if source == connection_key[0] else 1
        for chunk in contiguous_chunks(stream, counters):
            for tsdu in ordered_cotp_tsdus(ordered_tpkt_records(chunk, counters), counters):
                presentation = session_payload(tsdu.data, counters)
                if presentation is None:
                    continue
                for _, payload in presentation_pdvs(presentation, counters):
                    candidate = mms_candidate(payload, counters)
                    if candidate is None:
                        continue
                    serial += 1
                    if serial > MAX_EXTRACTED_PDUS:
                        raise ValueError("ordered extraction exceeds PDU-count bound")
                    extracted_bytes += len(candidate)
                    if extracted_bytes > MAX_EXTRACTED_BYTES:
                        raise ValueError("ordered extraction exceeds PDU-byte bound")
                    extracted.append(
                        ExtractedMms(
                            tsdu.packet_index, serial, flow_id, direction, candidate
                        )
                    )
    extracted.sort(key=lambda record: (record.capture_packet_index, record.serial))
    return extracted


def write_ordered_mms(
    extracted: list[ExtractedMms], counters: Counters, output: BinaryIO,
    confirmed_output: BinaryIO | None, metadata_output: BinaryIO | None,
    budget: OutputBudget | None = None,
) -> None:
    confirmed_packet_index = 0
    extracted_bytes = 0
    for packet_index, record in enumerate(extracted, 1):
        if budget is not None:
            budget.add_pdu()
        extracted_bytes += len(record.payload)
        write_pcap_packet(output, packet_index, record.payload, budget)
        if metadata_output is not None:
            metadata_row = (
                f"{packet_index}\t{record.flow_id}\t{record.direction}\t"
                f"{record.capture_packet_index}\n"
            ).encode("ascii")
            if budget is None:
                metadata_output.write(metadata_row)
            else:
                budget.write(metadata_output, metadata_row)
        if record.payload[0] in (0xA0, 0xA1):
            confirmed_packet_index += 1
            if confirmed_output is not None:
                write_pcap_packet(
                    confirmed_output, confirmed_packet_index, record.payload,
                    budget,
                )
    counters["mms.extracted_pdus"] = len(extracted)
    counters["mms.extracted_bytes"] = extracted_bytes
    counters["mms.confirmed_extracted_pdus"] = confirmed_packet_index


def extract_mms_chunks(
    chunks: Iterator[bytes],
    counters: Counters,
    output: BinaryIO | None = None,
    confirmed_output: BinaryIO | None = None,
    budget: OutputBudget | None = None,
) -> None:
    packet_index = 0
    confirmed_packet_index = 0
    for chunk in chunks:
        records = tpkt_records(chunk, counters)
        for tsdu in cotp_tsdus(records, counters):
            presentation = session_payload(tsdu, counters)
            if presentation is None:
                continue
            for _, payload in presentation_pdvs(presentation, counters):
                candidate = mms_candidate(payload, counters)
                if candidate is None:
                    continue
                packet_index += 1
                if packet_index > MAX_EXTRACTED_PDUS:
                    raise ValueError("causal extraction exceeds PDU-count bound")
                counters["mms.extracted_bytes"] += len(candidate)
                if counters["mms.extracted_bytes"] > MAX_EXTRACTED_BYTES:
                    raise ValueError("causal extraction exceeds PDU-byte bound")
                if budget is not None:
                    budget.add_pdu()
                if output is not None:
                    write_pcap_packet(output, packet_index, candidate, budget)
                if candidate[0] in (0xA0, 0xA1):
                    confirmed_packet_index += 1
                    if confirmed_output is not None:
                        write_pcap_packet(
                            confirmed_output, confirmed_packet_index, candidate,
                            budget,
                        )

    counters["mms.extracted_pdus"] = packet_index
    counters["mms.confirmed_extracted_pdus"] = confirmed_packet_index


def extract(
    capture_path: pathlib.Path,
    output_path: pathlib.Path,
    summary_path: pathlib.Path,
    confirmed_output_path: pathlib.Path | None = None,
    causal_output_path: pathlib.Path | None = None,
    metadata_output_path: pathlib.Path | None = None,
) -> Counters:
    output_paths = [output_path, summary_path]
    if confirmed_output_path is not None:
        output_paths.append(confirmed_output_path)
    if causal_output_path is not None:
        output_paths.append(causal_output_path)
    if metadata_output_path is not None:
        output_paths.append(metadata_output_path)
    validate_distinct_paths(capture_path, output_paths)

    counters = Counters()
    output_budget = OutputBudget()
    streams, events = collect_streams(capture_path, counters)

    with ArtifactTransaction() as transaction:
        with contextlib.ExitStack() as outputs:
            output = outputs.enter_context(transaction.open_binary(output_path))
            write_pcap_header(output, output_budget)
            confirmed_output = None
            if confirmed_output_path is not None:
                confirmed_output = outputs.enter_context(
                    transaction.open_binary(confirmed_output_path)
                )
                write_pcap_header(confirmed_output, output_budget)
            metadata_output = None
            if metadata_output_path is not None:
                metadata_output = outputs.enter_context(
                    transaction.open_binary(metadata_output_path)
                )
                output_budget.write(
                    metadata_output,
                    b"packet_index\tflow_id\tdirection\tcapture_packet\n",
                )
            write_ordered_mms(
                collect_ordered_mms(streams, counters), counters, output,
                confirmed_output, metadata_output, output_budget,
            )

            causal_output = None
            if causal_output_path is not None:
                causal_output = outputs.enter_context(
                    transaction.open_binary(causal_output_path)
                )
                write_pcap_header(causal_output, output_budget)

            causal_counters = Counters()
            delivery_chunks = causal_chunks(events, causal_counters)
            extract_mms_chunks(
                (
                    chunk
                    for direction_chunks in delivery_chunks.values()
                    for chunk in direction_chunks
                ),
                causal_counters,
                causal_output,
                budget=output_budget,
            )
            for key, value in causal_counters.items():
                counters[f"causal.{key}"] = value

            summary = outputs.enter_context(transaction.open_binary(summary_path))
            counters.write(summary, output_budget)
    return counters


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input_pcap", type=pathlib.Path)
    parser.add_argument("output_pcap", type=pathlib.Path)
    parser.add_argument("summary", type=pathlib.Path)
    parser.add_argument("--confirmed-output", type=pathlib.Path)
    parser.add_argument("--causal-output", type=pathlib.Path)
    parser.add_argument("--metadata-output", type=pathlib.Path)
    args = parser.parse_args()

    output_paths = [args.output_pcap, args.summary]
    if args.confirmed_output is not None:
        output_paths.append(args.confirmed_output)
    if args.causal_output is not None:
        output_paths.append(args.causal_output)
    if args.metadata_output is not None:
        output_paths.append(args.metadata_output)
    try:
        for output_path in output_paths:
            output_path.parent.mkdir(parents=True, exist_ok=True)
        counters = extract(
            args.input_pcap,
            args.output_pcap,
            args.summary,
            args.confirmed_output,
            args.causal_output,
            args.metadata_output,
        )
    except (OSError, RuntimeError, ValueError) as error:
        print(f"local MMS extractor: {error}", file=sys.stderr)
        return 1
    print(f"extracted_mms_pdus={counters['mms.extracted_pdus']}")
    print(f"causal_mms_pdus={counters['causal.mms.extracted_pdus']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
