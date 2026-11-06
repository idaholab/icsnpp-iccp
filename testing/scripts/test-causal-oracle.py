#!/usr/bin/env python3

"""Focused unit tests for the capture-order/ACK-aware TCP oracle."""

from __future__ import annotations

import importlib.util
import io
import os
import pathlib
import stat
import struct
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).with_name("extract-local-mms.py")
SPEC = importlib.util.spec_from_file_location("extract_local_mms", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
EXTRACTOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = EXTRACTOR
SPEC.loader.exec_module(EXTRACTOR)

CLIENT = (b"\x0a\x00\x00\x01", 49152)
SERVER = (b"\x0a\x00\x00\x02", 102)
CONNECTION = EXTRACTOR.canonical_connection(CLIENT, SERVER)


def event(
    packet_index: int,
    source: tuple[bytes, int],
    destination: tuple[bytes, int],
    sequence: int,
    acknowledgement: int,
    flags: int,
    payload: bytes = b"",
):
    return EXTRACTOR.TcpEvent(
        packet_index=packet_index,
        connection_key=CONNECTION,
        generation=1,
        source=source,
        destination=destination,
        sequence=sequence,
        acknowledgement=acknowledgement,
        flags=flags,
        payload=payload,
    )


def client_data(packet_index: int, sequence: int, payload: bytes):
    return event(packet_index, CLIENT, SERVER, sequence, 1, 0x18, payload)


def server_ack(packet_index: int, acknowledgement: int):
    return event(packet_index, SERVER, CLIENT, 1, acknowledgement, 0x10)


def client_ack(packet_index: int, sequence: int, acknowledgement: int = 1):
    return event(
        packet_index, CLIENT, SERVER, sequence, acknowledgement, 0x10
    )


def run(events):
    counters = EXTRACTOR.Counters()
    chunks = EXTRACTOR.causal_chunks(events, counters)
    client_key = (CONNECTION, 1, CLIENT, SERVER)
    return chunks.get(client_key, []), counters


def write_pcap(
    path: pathlib.Path,
    *,
    snaplen: int = 65535,
    version: tuple[int, int] = (2, 4),
    included_length: int | None = None,
    original_length: int | None = None,
    payload: bytes = b"",
) -> None:
    with path.open("wb") as output:
        output.write(b"\xd4\xc3\xb2\xa1")
        output.write(
            struct.pack("<HHIIII", version[0], version[1], 0, 0, snaplen, 1)
        )
        if included_length is not None:
            if original_length is None:
                original_length = included_length
            output.write(
                struct.pack("<IIII", 0, 0, included_length, original_length)
            )
            output.write(payload)


def tcp_header() -> bytes:
    return struct.pack(
        "!HHIIBBHHH", CLIENT[1], SERVER[1], 1, 1, 0x50, 0x18, 0, 0, 0
    )


def ethernet_frame(ether_type: int, payload: bytes) -> bytes:
    return b"\0" * 12 + ether_type.to_bytes(2, "big") + payload


def ipv4_tcp_frame(fragment: int = 0) -> bytes:
    header = bytearray(20)
    header[0] = 0x45
    header[2:4] = (40).to_bytes(2, "big")
    header[6:8] = fragment.to_bytes(2, "big")
    header[8] = 64
    header[9] = 6
    header[12:16] = CLIENT[0]
    header[16:20] = SERVER[0]
    return ethernet_frame(0x0800, bytes(header) + tcp_header())


def ipv6_fragmented_tcp_frame(fragment: int = 0) -> bytes:
    header = bytearray(40)
    header[0] = 0x60
    header[4:6] = (28).to_bytes(2, "big")
    header[6] = 44
    header[7] = 64
    header[8:24] = b"\x20\x01\x0d\xb8" + b"\0" * 12
    header[24:40] = b"\x20\x01\x0d\xb8" + b"\0" * 11 + b"\x01"
    fragment_header = bytes((6, 0)) + fragment.to_bytes(2, "big") + b"\0" * 4
    return ethernet_frame(0x86DD, bytes(header) + fragment_header + tcp_header())


def ipv6_extended_tcp_frame(extension_count: int) -> bytes:
    header = bytearray(40)
    header[0] = 0x60
    header[4:6] = (extension_count * 8 + 20).to_bytes(2, "big")
    header[6] = 0 if extension_count else 6
    header[7] = 64
    header[8:24] = b"\x20\x01\x0d\xb8" + b"\0" * 12
    header[24:40] = b"\x20\x01\x0d\xb8" + b"\0" * 11 + b"\x01"
    extensions = b"".join(
        bytes((0 if index + 1 < extension_count else 6, 0)) + b"\0" * 6
        for index in range(extension_count)
    )
    return ethernet_frame(0x86DD, bytes(header) + extensions + tcp_header())


def vlan_wrapped_ipv4_tcp_frame(vlan_count: int) -> bytes:
    if vlan_count == 0:
        return ipv4_tcp_frame()
    tags = b"".join(
        b"\0\0"
        + (0x8100 if index + 1 < vlan_count else 0x0800).to_bytes(2, "big")
        for index in range(vlan_count)
    )
    return (
        b"\0" * 12
        + (0x8100).to_bytes(2, "big")
        + tags
        + ipv4_tcp_frame()[14:]
    )


def parsed_tcp(
    source=CLIENT,
    destination=SERVER,
    *,
    sequence: int = 1,
    flags: int = 0x18,
    payload: bytes = b"",
):
    return (
        source[0],
        destination[0],
        source[1],
        destination[1],
        sequence,
        1,
        flags,
        payload,
    )


def collect_parsed_packets(packets):
    counters = EXTRACTOR.Counters()
    with mock.patch.object(
        EXTRACTOR, "pcap_packets", return_value=iter([b""] * len(packets))
    ):
        with mock.patch.object(EXTRACTOR, "tcp_packet", side_effect=packets):
            return EXTRACTOR.collect_streams(pathlib.Path("unused.pcap"), counters)


class CausalOracleTest(unittest.TestCase):
    def test_ack_before_payload_rejects_already_acknowledged_segment(self):
        chunks, counters = run(
            [
                client_ack(1, 100),
                server_ack(2, 104),
                client_data(3, 100, b"LATE"),
                client_data(4, 104, b"NEXT"),
            ]
        )
        self.assertEqual(chunks, [b"NEXT"])
        self.assertEqual(counters["tcp.ack_without_payload_baseline"], 1)
        self.assertEqual(counters["tcp.late_segments"], 1)
        self.assertEqual(counters["tcp.late_bytes"], 4)
        self.assertEqual(counters["tcp.direction_streams"], 1)

    def test_ack_before_payload_trims_acknowledged_prefix(self):
        chunks, counters = run(
            [
                client_ack(1, 100),
                server_ack(2, 102),
                client_data(3, 100, b"ABCD"),
            ]
        )
        self.assertEqual(chunks, [b"CD"])
        self.assertEqual(counters["tcp.late_prefix_bytes"], 2)

    def test_peer_ack_is_provisional_until_direction_is_observed(self):
        chunks, counters = run(
            [
                server_ack(1, 104),
                client_data(2, 100, b"LATE"),
                client_data(3, 104, b"NEXT"),
            ]
        )
        self.assertEqual(chunks, [b"LATENEXT"])
        self.assertEqual(counters["tcp.provisional_peer_acks"], 1)
        self.assertEqual(counters["tcp.ack_without_payload_baseline"], 0)
        self.assertEqual(counters["tcp.late_segments"], 0)

    def test_ack_before_payload_handles_sequence_wrap(self):
        chunks, counters = run(
            [
                client_ack(1, 0xFFFFFFFC),
                server_ack(2, 0),
                client_data(3, 0xFFFFFFFC, b"LATE"),
                client_data(4, 0, b"NEXT"),
            ]
        )
        self.assertEqual(chunks, [b"NEXT"])
        self.assertEqual(counters["tcp.late_segments"], 1)

    def test_sequence_underflow_is_rejected_before_reassembler_trimming(self):
        chunks, counters = run(
            [
                client_ack(1, 1000),
                server_ack(2, 900),
                client_data(3, 998, b"UNDERFLOW"),
                client_data(4, 1000, b"DATA"),
            ]
        )
        self.assertEqual(chunks, [b"DATA"])
        self.assertEqual(counters["tcp.sequence_underflow_segments"], 1)
        self.assertEqual(counters["tcp.sequence_underflow_bytes"], 9)

    def test_half_sequence_space_tie_maps_backward_like_zeek(self):
        self.assertEqual(EXTRACTOR.unwrap_sequence(0x80000000, 0), -(1 << 31))
        self.assertEqual(EXTRACTOR.unwrap_sequence(0, 1 << 31), 0)

    def test_partial_one_byte_initial_ack_buffers_trimmed_suffix_at_end(self):
        chunks, counters = run(
            [
                client_ack(1, 100),
                server_ack(2, 101),
                client_data(3, 100, b"XRECORD"),
            ]
        )
        self.assertEqual(chunks, [])
        self.assertEqual(counters["tcp.partial_initial_gap_suppressions"], 1)
        self.assertEqual(counters["tcp.late_prefix_bytes"], 1)
        self.assertEqual(counters["tcp.capture_boundary_bytes"], 6)

    def test_partial_one_byte_initial_ack_needs_later_ack_to_release_suffix(self):
        chunks, counters = run(
            [
                client_ack(1, 100),
                server_ack(2, 101),
                client_data(3, 100, b"XREC"),
                client_data(4, 104, b"ORD"),
                server_ack(5, 107),
            ]
        )
        self.assertEqual(chunks, [b"RECORD"])
        self.assertEqual(counters["tcp.ack_gap_events"], 1)
        self.assertEqual(counters["tcp.ack_gap_bytes"], 1)
        self.assertEqual(counters["tcp.capture_boundary_bytes"], 0)

    def test_established_connection_does_not_suppress_one_byte_gap(self):
        chunks, counters = run(
            [
                event(1, CLIENT, SERVER, 101, 0, 0x02),
                event(2, SERVER, CLIENT, 501, 101, 0x12),
                client_data(3, 101, b""),
                server_ack(4, 102),
                client_data(5, 101, b"XRECORD"),
            ]
        )
        self.assertEqual(chunks, [b"RECORD"])
        self.assertEqual(counters["tcp.partial_initial_gap_suppressions"], 0)
        self.assertEqual(counters["tcp.ack_gap_events"], 1)
        self.assertEqual(counters["tcp.ack_gap_bytes"], 1)

    def test_inferred_missing_syn_handshake_clears_partial_suppression(self):
        chunks, counters = run(
            [
                event(1, SERVER, CLIENT, 501, 101, 0x12),
                client_ack(2, 101, 501),
                server_ack(3, 102),
                client_data(4, 101, b"XRECORD"),
            ]
        )
        self.assertEqual(chunks, [b"RECORD"])
        self.assertEqual(counters["tcp.inferred_handshake_completions"], 1)
        self.assertEqual(counters["tcp.partial_initial_gap_suppressions"], 0)
        self.assertEqual(counters["tcp.ack_gap_events"], 1)

    def test_prebaseline_ack_state_respects_direction_bound(self):
        with mock.patch.object(EXTRACTOR, "MAX_DIRECTION_STREAMS", 1):
            with self.assertRaisesRegex(ValueError, "causal-direction bound"):
                EXTRACTOR.causal_chunks(
                    [
                        server_ack(1, 100),
                        client_data(2, 100, b"DATA"),
                    ],
                    EXTRACTOR.Counters(),
                )

    def test_out_of_order_bytes_are_causal_when_filled_before_ack(self):
        chunks, counters = run(
            [
                client_data(1, 100, b"AAAA"),
                client_data(2, 108, b"CCCC"),
                client_data(3, 104, b"BBBB"),
                server_ack(4, 112),
            ]
        )
        self.assertEqual(chunks, [b"AAAABBBBCCCC"])
        self.assertEqual(counters["tcp.ack_gap_events"], 0)

    def test_ack_exposes_gap_but_preserves_already_captured_tail(self):
        chunks, counters = run(
            [
                client_data(1, 100, b"AAAA"),
                client_data(2, 108, b"CCCC"),
                server_ack(3, 112),
            ]
        )
        self.assertEqual(chunks, [b"AAAA", b"CCCC"])
        self.assertEqual(counters["tcp.ack_gap_events"], 1)
        self.assertEqual(counters["tcp.ack_gap_bytes"], 4)

    def test_retransmission_after_ack_gap_is_too_late_to_rewind(self):
        chunks, counters = run(
            [
                client_data(1, 100, b"AAAA"),
                client_data(2, 108, b"CCCC"),
                server_ack(3, 112),
                client_data(4, 104, b"BBBB"),
            ]
        )
        self.assertEqual(chunks, [b"AAAA", b"CCCC"])
        self.assertEqual(counters["tcp.late_segments"], 1)
        self.assertEqual(counters["tcp.late_bytes"], 4)

    def test_unacknowledged_tail_is_labeled_capture_boundary(self):
        chunks, counters = run(
            [
                client_data(1, 100, b"AAAA"),
                client_data(2, 108, b"CCCC"),
            ]
        )
        self.assertEqual(chunks, [b"AAAA"])
        self.assertEqual(counters["tcp.capture_boundary_segments"], 1)
        self.assertEqual(counters["tcp.capture_boundary_bytes"], 4)

    def test_first_observed_overlap_wins_and_conflict_is_counted(self):
        chunks, counters = run(
            [
                client_data(1, 100, b"AAAA"),
                client_data(2, 108, b"CCCC"),
                client_data(3, 106, b"XXYY"),
                server_ack(4, 112),
            ]
        )
        self.assertEqual(chunks, [b"AAAA", b"XXCCCC"])
        self.assertEqual(counters["tcp.overlap_bytes"], 2)
        self.assertEqual(counters["tcp.conflicting_overlap_bytes"], 2)

    def test_sequence_numbers_unwrap_across_32_bit_boundary(self):
        chunks, counters = run(
            [
                client_data(1, 0xFFFFFFFC, b"AAAA"),
                client_data(2, 0, b"BBBB"),
                server_ack(3, 4),
            ]
        )
        self.assertEqual(chunks, [b"AAAABBBB"])
        self.assertEqual(counters["tcp.ack_gap_events"], 0)

    def test_ideal_reassembly_unwraps_sequence_numbers(self):
        segment_orders = (
            (
                EXTRACTOR.CapturedSegment(1, 0xFFFFFFFC, b"AAAA"),
                EXTRACTOR.CapturedSegment(2, 0, b"BBBB"),
            ),
            (
                EXTRACTOR.CapturedSegment(2, 0xFFFFFFFC, b"AAAA"),
                EXTRACTOR.CapturedSegment(1, 0, b"BBBB"),
            ),
        )
        for segments in segment_orders:
            with self.subTest(segments=segments):
                counters = EXTRACTOR.Counters()
                stream = EXTRACTOR.DirectionStream(segments=list(segments))

                chunks = list(EXTRACTOR.contiguous_chunks(stream, counters))

                self.assertEqual([chunk.data for chunk in chunks], [b"AAAABBBB"])
                self.assertEqual(counters["tcp.gaps"], 0)

    def test_duplicate_at_pending_segment_limit_does_not_add_state(self):
        state = EXTRACTOR.CausalDirection()
        counters = EXTRACTOR.Counters()
        with mock.patch.object(EXTRACTOR, "MAX_CAUSAL_PENDING_SEGMENTS", 1):
            EXTRACTOR.insert_causal_segment(state, 10, b"a", counters)
            EXTRACTOR.insert_causal_segment(state, 10, b"a", counters)

        self.assertEqual(len(state.pending), 1)
        self.assertEqual(state.pending_bytes, 1)
        self.assertEqual(counters["tcp.duplicate_segments"], 1)

    def test_fin_ack_is_clamped_to_payload_end(self):
        chunks, counters = run(
            [
                event(
                    1, CLIENT, SERVER, 100, 1, 0x19, payload=b"DATA"
                ),
                server_ack(2, 105),
            ]
        )

        self.assertEqual(chunks, [b"DATA"])
        self.assertEqual(counters["tcp.fin_ack_clamps"], 1)
        self.assertEqual(counters["tcp.fin_ack_clamped_bytes"], 1)
        self.assertEqual(counters["tcp.ack_gap_events"], 0)
        self.assertEqual(counters["tcp.ack_gap_bytes"], 0)

    def test_initial_window_trim_matches_strict_zeek_threshold(self):
        with (
            mock.patch.object(EXTRACTOR, "ZEEK_TCP_MAX_INITIAL_WINDOW", 3),
            mock.patch.object(
                EXTRACTOR, "ZEEK_TCP_MAX_ABOVE_HOLE_WITHOUT_ACKS", 0
            ),
            mock.patch.object(
                EXTRACTOR, "ZEEK_TCP_EXCESSIVE_DATA_WITHOUT_ACKS", 0
            ),
        ):
            chunks, counters = run(
                [
                    client_data(1, 100, b"ABCD"),
                    client_data(2, 102, b"CDEF"),
                ]
            )

        self.assertEqual(chunks, [b"ABCDEF"])
        self.assertEqual(counters["tcp.initial_window_trim_events"], 2)
        self.assertEqual(counters["tcp.initial_window_trim_bytes"], 6)
        self.assertEqual(counters["tcp.late_prefix_bytes"], 2)

        with (
            mock.patch.object(EXTRACTOR, "ZEEK_TCP_MAX_INITIAL_WINDOW", 4),
            mock.patch.object(
                EXTRACTOR, "ZEEK_TCP_MAX_ABOVE_HOLE_WITHOUT_ACKS", 0
            ),
            mock.patch.object(
                EXTRACTOR, "ZEEK_TCP_EXCESSIVE_DATA_WITHOUT_ACKS", 0
            ),
        ):
            _, boundary_counters = run([client_data(1, 100, b"ABCD")])

        self.assertEqual(boundary_counters["tcp.initial_window_trim_events"], 0)

    def test_above_hole_limit_abandons_delivery_permanently(self):
        with (
            mock.patch.object(EXTRACTOR, "ZEEK_TCP_MAX_INITIAL_WINDOW", 0),
            mock.patch.object(
                EXTRACTOR, "ZEEK_TCP_MAX_ABOVE_HOLE_WITHOUT_ACKS", 4
            ),
            mock.patch.object(
                EXTRACTOR, "ZEEK_TCP_EXCESSIVE_DATA_WITHOUT_ACKS", 0
            ),
        ):
            chunks, counters = run(
                [
                    client_data(1, 100, b"A"),
                    client_data(2, 105, b"Z"),
                    client_data(3, 101, b"FILL"),
                ]
            )

        self.assertEqual(chunks, [b"A"])
        self.assertEqual(counters["tcp.above_hole_abandonments"], 1)
        self.assertEqual(counters["tcp.above_hole_abandoned_span"], 5)
        self.assertEqual(counters["tcp.skipped_delivery_segments"], 1)
        self.assertEqual(counters["tcp.skipped_delivery_bytes"], 4)
        self.assertEqual(counters["tcp.capture_boundary_bytes"], 0)

        with (
            mock.patch.object(EXTRACTOR, "ZEEK_TCP_MAX_INITIAL_WINDOW", 0),
            mock.patch.object(
                EXTRACTOR, "ZEEK_TCP_MAX_ABOVE_HOLE_WITHOUT_ACKS", 4
            ),
            mock.patch.object(
                EXTRACTOR, "ZEEK_TCP_EXCESSIVE_DATA_WITHOUT_ACKS", 0
            ),
        ):
            boundary_chunks, boundary_counters = run(
                [
                    client_data(1, 100, b"A"),
                    client_data(2, 104, b"Z"),
                    client_data(3, 101, b"BBB"),
                ]
            )

        self.assertEqual(boundary_chunks, [b"ABBBZ"])
        self.assertEqual(boundary_counters["tcp.above_hole_abandonments"], 0)

    def test_excessive_retained_data_abandons_future_delivery(self):
        with (
            mock.patch.object(EXTRACTOR, "ZEEK_TCP_MAX_INITIAL_WINDOW", 0),
            mock.patch.object(
                EXTRACTOR, "ZEEK_TCP_MAX_ABOVE_HOLE_WITHOUT_ACKS", 0
            ),
            mock.patch.object(
                EXTRACTOR, "ZEEK_TCP_EXCESSIVE_DATA_WITHOUT_ACKS", 3
            ),
        ):
            chunks, counters = run(
                [
                    client_data(1, 100, b"A"),
                    server_ack(2, 101),
                    client_data(3, 101, b"BCDE"),
                    client_data(4, 105, b"FUTURE"),
                ]
            )

        self.assertEqual(chunks, [b"ABCDE"])
        self.assertEqual(counters["tcp.excessive_data_abandonments"], 1)
        self.assertEqual(counters["tcp.abandoned_retained_bytes"], 4)
        self.assertEqual(counters["tcp.skipped_delivery_segments"], 1)
        self.assertEqual(counters["tcp.skipped_delivery_bytes"], 6)


class FramingParityTest(unittest.TestCase):
    def test_tpkt_reserved_octet_is_ignored_in_both_walks(self):
        encoded = b"\x03\x7f\x00\x07\x02\xf0\x80"

        counters = EXTRACTOR.Counters()
        self.assertEqual(list(EXTRACTOR.tpkt_records(encoded, counters)), [
            b"\x02\xf0\x80"
        ])
        self.assertEqual(counters["tpkt.records"], 1)
        self.assertEqual(counters["tpkt.scan_bytes"], 0)

        ordered_counters = EXTRACTOR.Counters()
        ordered = list(
            EXTRACTOR.ordered_tpkt_records(
                EXTRACTOR.ReassembledChunk(encoded, ((0, len(encoded), 17),)),
                ordered_counters,
            )
        )
        self.assertEqual(ordered, [
            EXTRACTOR.OrderedRecord(17, b"\x02\xf0\x80")
        ])

    def test_tpkt_scan_rejects_false_complete_candidate(self):
        false_candidate = b"\x03\x7f\x00\x0bBAD"
        valid = b"\x03\x91\x00\x07\x02\xf0\x80"
        encoded = false_candidate + valid

        counters = EXTRACTOR.Counters()
        self.assertEqual(
            list(EXTRACTOR.tpkt_records(encoded, counters)),
            [b"\x02\xf0\x80"],
        )
        self.assertEqual(counters["tpkt.invalid_cotp_prefixes"], 1)

        ordered_counters = EXTRACTOR.Counters()
        ordered = list(
            EXTRACTOR.ordered_tpkt_records(
                EXTRACTOR.ReassembledChunk(encoded, ((0, len(encoded), 23),)),
                ordered_counters,
            )
        )
        self.assertEqual(ordered, [
            EXTRACTOR.OrderedRecord(23, b"\x02\xf0\x80")
        ])
        self.assertEqual(
            ordered_counters["tpkt.invalid_cotp_prefixes"], 1
        )

    def test_tpkt_scan_rejects_false_truncated_candidate(self):
        false_candidate = b"\x03\x44\xff\xffBAD"
        valid = b"\x03\xa5\x00\x07\x02\xf0\x80"
        encoded = false_candidate + valid

        counters = EXTRACTOR.Counters()
        self.assertEqual(
            list(EXTRACTOR.tpkt_records(encoded, counters)),
            [b"\x02\xf0\x80"],
        )
        self.assertEqual(counters["tpkt.truncated_records"], 0)
        self.assertEqual(counters["tpkt.invalid_cotp_prefixes"], 1)

        ordered_counters = EXTRACTOR.Counters()
        ordered = list(
            EXTRACTOR.ordered_tpkt_records(
                EXTRACTOR.ReassembledChunk(encoded, ((0, len(encoded), 29),)),
                ordered_counters,
            )
        )
        self.assertEqual(ordered, [
            EXTRACTOR.OrderedRecord(29, b"\x02\xf0\x80")
        ])
        self.assertEqual(
            ordered_counters["tpkt.truncated_records"], 0
        )

    def test_tpkt_scan_stops_at_structural_truncated_dt(self):
        nested = b"\x03\xb6\x00\x07\x02\xf0\x80"
        encoded = b"\x03\x73\x00\x40\x02\xf0\x80payload" + nested

        counters = EXTRACTOR.Counters()
        self.assertEqual(list(EXTRACTOR.tpkt_records(encoded, counters)), [])
        self.assertEqual(counters["tpkt.truncated_records"], 1)

        ordered_counters = EXTRACTOR.Counters()
        ordered = list(
            EXTRACTOR.ordered_tpkt_records(
                EXTRACTOR.ReassembledChunk(encoded, ((0, len(encoded), 31),)),
                ordered_counters,
            )
        )
        self.assertEqual(ordered, [])
        self.assertEqual(
            ordered_counters["tpkt.truncated_records"], 1
        )

    def test_tpkt_scan_recovers_strict_class_zero_cr(self):
        connection_request = (
            b"\x03\x81\x00\x0b\x06\xe0\x00\x00\x00\x01\x00"
        )
        data_transfer = b"\x03\x92\x00\x08\x02\xf0\x80X"
        encoded = b"garbage" + connection_request + data_transfer

        counters = EXTRACTOR.Counters()
        self.assertEqual(
            list(EXTRACTOR.tpkt_records(encoded, counters)),
            [connection_request[4:], data_transfer[4:]],
        )

        ordered_counters = EXTRACTOR.Counters()
        ordered = list(
            EXTRACTOR.ordered_tpkt_records(
                EXTRACTOR.ReassembledChunk(encoded, ((0, len(encoded), 37),)),
                ordered_counters,
            )
        )
        self.assertEqual(ordered, [
            EXTRACTOR.OrderedRecord(37, connection_request[4:]),
            EXTRACTOR.OrderedRecord(37, data_transfer[4:]),
        ])

    def test_tpkt_scan_rejects_false_cr_before_nested_dt(self):
        nested = b"\x03\xc7\x00\x08\x02\xf0\x80X"
        cases = (
            # A CR TPKT above production's 128-byte contained COTP bound.
            b"\x03\x01\x00\x85\x80\xe0\x00\x00\x00\x01\x00" + nested,
            # A no-user-data CR whose fixed-width TPDU-size parameter is
            # malformed (C0 requires a one-octet value).
            b"\x03\x02\x00\x0d\x08\xe0\x00\x00\x00\x01\x00\xc0\x02"
            + nested,
        )
        for encoded in cases:
            with self.subTest(encoded=encoded[:13]):
                counters = EXTRACTOR.Counters()
                self.assertEqual(
                    list(EXTRACTOR.tpkt_records(encoded, counters)),
                    [nested[4:]],
                )
                self.assertEqual(counters["tpkt.truncated_records"], 0)

                ordered_counters = EXTRACTOR.Counters()
                ordered = list(
                    EXTRACTOR.ordered_tpkt_records(
                        EXTRACTOR.ReassembledChunk(
                            encoded, ((0, len(encoded), 39),)
                        ),
                        ordered_counters,
                    )
                )
                self.assertEqual(ordered, [
                    EXTRACTOR.OrderedRecord(39, nested[4:])
                ])

    def test_cotp_cr_clears_pending_fragment_before_later_dt(self):
        first = b"\x03\x11\x00\x0c\x02\xf0\x00first"
        connection_request = (
            b"\x03\x22\x00\x0b\x06\xe0\x00\x00\x00\x01\x00"
        )
        second = b"\x03\x33\x00\x0d\x02\xf0\x80second"
        encoded = first + connection_request + second

        counters = EXTRACTOR.Counters()
        records = EXTRACTOR.tpkt_records(encoded, counters)
        self.assertEqual(
            list(EXTRACTOR.cotp_tsdus(records, counters)),
            [b"second"],
        )
        self.assertEqual(counters["cotp.invalid_headers"], 1)

        ordered_counters = EXTRACTOR.Counters()
        ordered_records = EXTRACTOR.ordered_tpkt_records(
            EXTRACTOR.ReassembledChunk(encoded, ((0, len(encoded), 41),)),
            ordered_counters,
        )
        self.assertEqual(
            list(EXTRACTOR.ordered_cotp_tsdus(
                ordered_records, ordered_counters
            )),
            [EXTRACTOR.OrderedRecord(41, b"second")],
        )
        self.assertEqual(ordered_counters["cotp.invalid_headers"], 1)

    def test_cotp_requires_exact_class_zero_dt_header(self):
        cases = (
            (b"\x03\xf0\x80Xpayload", "cotp.invalid_headers"),
            (b"\x02\xf1\x80payload", "cotp.non_dt"),
            (b"\x02\xf0\x81payload", "cotp.invalid_tpdu_numbers"),
        )
        for record, counter in cases:
            with self.subTest(record=record):
                counters = EXTRACTOR.Counters()
                self.assertEqual(
                    list(EXTRACTOR.cotp_tsdus(iter((record,)), counters)), []
                )
                self.assertEqual(counters[counter], 1)

        counters = EXTRACTOR.Counters()
        fragments = iter((b"\x02\xf0\x00first", b"\x02\xf0\x80second"))
        self.assertEqual(
            list(EXTRACTOR.cotp_tsdus(fragments, counters)),
            [b"firstsecond"],
        )

        ordered_counters = EXTRACTOR.Counters()
        ordered = iter(
            (
                EXTRACTOR.OrderedRecord(4, b"\x02\xf0\x00first"),
                EXTRACTOR.OrderedRecord(9, b"\x02\xf0\x80second"),
            )
        )
        self.assertEqual(
            list(EXTRACTOR.ordered_cotp_tsdus(ordered, ordered_counters)),
            [EXTRACTOR.OrderedRecord(9, b"firstsecond")],
        )

    def test_session_uses_x225_short_and_extended_lengths(self):
        short_payload = b"presentation-short"
        counters = EXTRACTOR.Counters()
        self.assertEqual(
            EXTRACTOR.session_payload(
                b"\x01\x81" + b"\x00" * 129 + short_payload,
                counters,
            ),
            short_payload,
        )

        extended_payload = b"presentation-extended"
        counters = EXTRACTOR.Counters()
        self.assertEqual(
            EXTRACTOR.session_payload(
                b"\x01\xff\x00\xff" + b"\x00" * 255 + extended_payload,
                counters,
            ),
            extended_payload,
        )

        for invalid in (b"\x01\xff", b"\x01\xff\x00\xfe"):
            with self.subTest(invalid=invalid):
                counters = EXTRACTOR.Counters()
                self.assertIsNone(EXTRACTOR.session_payload(invalid, counters))
                self.assertEqual(counters["session.invalid_lengths"], 1)

    def test_concatenated_session_spdu_uses_x225_length(self):
        counters = EXTRACTOR.Counters()
        tsdu = b"\x01\x00\x01\xff\x00\xff" + b"\x00" * 255 + b"P"
        self.assertEqual(EXTRACTOR.session_payload(tsdu, counters), b"P")
        self.assertEqual(counters["session.concatenated_data_transfer"], 1)

    def test_mms_accepts_all_standard_top_level_tag_forms(self):
        accepted = []
        for tag in range(14):
            identifier = (
                0xA0 | tag
                if tag in EXTRACTOR.MMS_CONSTRUCTED_TOP_LEVEL_TAGS
                else 0x80 | tag
            )
            payload = bytes((identifier, 0))
            counters = EXTRACTOR.Counters()
            with self.subTest(tag=tag, identifier=identifier):
                self.assertEqual(
                    EXTRACTOR.mms_candidate(payload, counters), payload
                )
                self.assertEqual(counters[f"mms.tag_{tag}"], 1)
            accepted.append(payload)

        self.assertEqual(accepted[0], b"\xa0\x00")
        self.assertEqual(accepted[1], b"\xa1\x00")

    def test_mms_rejects_wrong_forms_and_nonstandard_tags(self):
        for tag in range(14):
            identifier = (
                0x80 | tag
                if tag in EXTRACTOR.MMS_CONSTRUCTED_TOP_LEVEL_TAGS
                else 0xA0 | tag
            )
            counters = EXTRACTOR.Counters()
            with self.subTest(tag=tag, identifier=identifier):
                self.assertIsNone(
                    EXTRACTOR.mms_candidate(bytes((identifier, 0)), counters)
                )
                self.assertEqual(counters["mms.invalid_top_tag_form"], 1)

        for identifier in (0x60, 0x8E, 0xAE):
            counters = EXTRACTOR.Counters()
            with self.subTest(identifier=identifier):
                self.assertIsNone(
                    EXTRACTOR.mms_candidate(bytes((identifier, 0)), counters)
                )
                self.assertEqual(counters["mms.unsupported_top_tag"], 1)


class PacketParsingSafetyTest(unittest.TestCase):
    def test_bounds_vlan_header_traversal(self):
        with mock.patch.object(EXTRACTOR, "MAX_VLAN_HEADERS", 1):
            self.assertIsNotNone(
                EXTRACTOR.tcp_packet(vlan_wrapped_ipv4_tcp_frame(1))
            )
            self.assertIsNone(
                EXTRACTOR.tcp_packet(vlan_wrapped_ipv4_tcp_frame(2))
            )

    def test_bounds_ipv6_extension_header_traversal(self):
        with mock.patch.object(EXTRACTOR, "MAX_IPV6_EXTENSION_HEADERS", 1):
            self.assertIsNotNone(EXTRACTOR.tcp_packet(ipv6_extended_tcp_frame(1)))
            self.assertIsNone(EXTRACTOR.tcp_packet(ipv6_extended_tcp_frame(2)))

    def test_rejects_ipv4_fragments_but_accepts_do_not_fragment(self):
        for fragment in (0x2000, 0x0001):
            with self.subTest(fragment=fragment):
                self.assertIsNone(EXTRACTOR.tcp_packet(ipv4_tcp_frame(fragment)))

        self.assertIsNotNone(EXTRACTOR.tcp_packet(ipv4_tcp_frame(0x4000)))

    def test_rejects_ipv6_fragment_header(self):
        for fragment in (0, 0x0001, 0x0008):
            with self.subTest(fragment=fragment):
                self.assertIsNone(
                    EXTRACTOR.tcp_packet(ipv6_fragmented_tcp_frame(fragment))
                )

    def test_rejects_snap_truncated_ipv4_datagram(self):
        frame = ipv4_tcp_frame()
        self.assertIsNone(EXTRACTOR.tcp_packet(frame[:-1]))

    def test_rejects_snap_truncated_ipv6_datagram(self):
        frame = ipv6_extended_tcp_frame(0)
        self.assertIsNone(EXTRACTOR.tcp_packet(frame[:-1]))


class PcapSafetyTest(unittest.TestCase):
    def test_rejects_unsupported_classic_pcap_version(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = pathlib.Path(directory) / "invalid.pcap"
            write_pcap(capture, version=(2, 3))

            with self.assertRaisesRegex(ValueError, "format version"):
                list(EXTRACTOR.pcap_packets(capture))

    def test_rejects_included_length_larger_than_original_length(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = pathlib.Path(directory) / "invalid.pcap"
            write_pcap(capture, included_length=2, original_length=1)

            with self.assertRaisesRegex(ValueError, "exceeds original length"):
                list(EXTRACTOR.pcap_packets(capture))

    def test_rejects_included_length_larger_than_snaplen(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = pathlib.Path(directory) / "invalid.pcap"
            write_pcap(capture, snaplen=1, included_length=2)

            with self.assertRaisesRegex(ValueError, "exceeds snaplen"):
                list(EXTRACTOR.pcap_packets(capture))

    def test_rejects_capture_snaplen_larger_than_safety_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = pathlib.Path(directory) / "invalid.pcap"
            write_pcap(
                capture, snaplen=EXTRACTOR.MAX_CAPTURED_PACKET_LENGTH + 1
            )

            with self.assertRaisesRegex(ValueError, "snaplen exceeds"):
                list(EXTRACTOR.pcap_packets(capture))

    def test_accepts_packet_lengths_within_header_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = pathlib.Path(directory) / "valid.pcap"
            write_pcap(
                capture,
                snaplen=4,
                included_length=4,
                original_length=8,
                payload=b"test",
            )

            self.assertEqual(list(EXTRACTOR.pcap_packets(capture)), [b"test"])

    def test_rejects_input_output_path_collision_without_truncating(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = pathlib.Path(directory) / "input.pcap"
            summary = pathlib.Path(directory) / "summary.tsv"
            write_pcap(capture)
            original = capture.read_bytes()

            with self.assertRaisesRegex(ValueError, "path collision"):
                EXTRACTOR.extract(capture, capture, summary)

            self.assertEqual(capture.read_bytes(), original)
            self.assertFalse(summary.exists())

    def test_rejects_colliding_outputs_without_truncating(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            capture = root / "input.pcap"
            artifact = root / "artifact"
            write_pcap(capture)
            artifact.write_bytes(b"retain me")

            with self.assertRaisesRegex(ValueError, "path collision"):
                EXTRACTOR.extract(capture, artifact, artifact)

            self.assertEqual(artifact.read_bytes(), b"retain me")

    def test_rejects_hard_link_to_input_without_truncating(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            capture = root / "input.pcap"
            alias = root / "alias.pcap"
            summary = root / "summary.tsv"
            write_pcap(capture)
            original = capture.read_bytes()
            os.link(capture, alias)

            with self.assertRaisesRegex(ValueError, "inode collision"):
                EXTRACTOR.extract(capture, alias, summary)

            self.assertEqual(capture.read_bytes(), original)
            self.assertEqual(alias.read_bytes(), original)
            self.assertFalse(summary.exists())

    def test_rejects_symlink_to_input_without_truncating(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            capture = root / "input.pcap"
            alias = root / "alias.pcap"
            summary = root / "summary.tsv"
            write_pcap(capture)
            original = capture.read_bytes()
            alias.symlink_to(capture)

            with self.assertRaisesRegex(ValueError, "path collision"):
                EXTRACTOR.extract(capture, alias, summary)

            self.assertEqual(capture.read_bytes(), original)
            self.assertFalse(summary.exists())

    def test_rejects_capture_over_packet_count_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = pathlib.Path(directory) / "invalid.pcap"
            write_pcap(
                capture, snaplen=1, included_length=1,
                original_length=1, payload=b"a",
            )
            with capture.open("ab") as output:
                output.write(struct.pack("<IIII", 0, 0, 1, 1))
                output.write(b"b")

            with mock.patch.object(EXTRACTOR, "MAX_CAPTURE_PACKETS", 1):
                with self.assertRaisesRegex(ValueError, "packet-count bound"):
                    list(EXTRACTOR.pcap_packets(capture))

    def test_rejects_capture_over_total_byte_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = pathlib.Path(directory) / "invalid.pcap"
            write_pcap(
                capture, snaplen=2, included_length=2,
                original_length=2, payload=b"ab",
            )

            with mock.patch.object(EXTRACTOR, "MAX_CAPTURE_BYTES", 1):
                with self.assertRaisesRegex(ValueError, "captured-byte bound"):
                    list(EXTRACTOR.pcap_packets(capture))

    def test_bounds_causal_pending_state(self):
        state = EXTRACTOR.CausalDirection()
        counters = EXTRACTOR.Counters()
        with mock.patch.object(EXTRACTOR, "MAX_CAUSAL_PENDING_SEGMENTS", 1):
            EXTRACTOR.insert_causal_segment(state, 10, b"a", counters)
            with self.assertRaisesRegex(ValueError, "pending-segment bound"):
                EXTRACTOR.insert_causal_segment(state, 20, b"b", counters)

        state = EXTRACTOR.CausalDirection()
        with mock.patch.object(EXTRACTOR, "MAX_CAUSAL_PENDING_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "pending-byte bound"):
                EXTRACTOR.insert_causal_segment(state, 10, b"ab", counters)

    def test_bounds_fragments_created_by_one_causal_segment(self):
        state = EXTRACTOR.CausalDirection(
            cursor=0,
            pending=[EXTRACTOR.BufferedSegment(12, b"cc")],
            pending_bytes=2,
        )
        counters = EXTRACTOR.Counters()
        with mock.patch.object(EXTRACTOR, "MAX_CAUSAL_PENDING_SEGMENTS", 2):
            with self.assertRaisesRegex(ValueError, "pending-segment bound"):
                EXTRACTOR.insert_causal_segment(state, 10, b"abcdef", counters)

    def test_capture_derived_outputs_are_private(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            capture = root / "empty.pcap"
            write_pcap(capture)
            paths = {
                name: root / name
                for name in (
                    "all.pcap",
                    "confirmed.pcap",
                    "causal.pcap",
                    "metadata.tsv",
                    "summary.tsv",
                )
            }

            EXTRACTOR.extract(
                capture,
                paths["all.pcap"],
                paths["summary.tsv"],
                paths["confirmed.pcap"],
                paths["causal.pcap"],
                paths["metadata.tsv"],
            )

            for path in paths.values():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_capture_derived_outputs_do_not_clobber_existing_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            capture = root / "empty.pcap"
            output = root / "existing.pcap"
            summary = root / "summary.tsv"
            write_pcap(capture)
            output.write_bytes(b"retain me")

            with self.assertRaises(FileExistsError):
                EXTRACTOR.extract(capture, output, summary)

            self.assertEqual(output.read_bytes(), b"retain me")
            self.assertFalse(summary.exists())

    def test_existing_later_output_prevents_all_output_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            capture = root / "empty.pcap"
            output = root / "new-output.pcap"
            summary = root / "existing-summary.tsv"
            write_pcap(capture)
            summary.write_bytes(b"retain me")

            with self.assertRaises(FileExistsError):
                EXTRACTOR.extract(capture, output, summary)

            self.assertFalse(output.exists())
            self.assertEqual(summary.read_bytes(), b"retain me")

    def test_late_failure_publishes_no_partial_final_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            capture = root / "empty.pcap"
            output = root / "derived.pcap"
            summary = root / "summary.tsv"
            write_pcap(capture)

            # The PCAP header fits, but the later summary does not. Nothing
            # final-named may expose that otherwise-valid partial PCAP.
            with mock.patch.object(EXTRACTOR, "MAX_OUTPUT_BYTES", 24):
                with self.assertRaisesRegex(ValueError, "output-byte"):
                    EXTRACTOR.extract(capture, output, summary)

            self.assertFalse(output.exists())
            self.assertFalse(summary.exists())
            self.assertEqual(list(root.glob(".*.tmp")), [])

    def test_publication_collision_retains_complete_earlier_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first = root / "first.tsv"
            second = root / "second.tsv"

            with self.assertRaises(FileExistsError):
                with EXTRACTOR.ArtifactTransaction() as transaction:
                    with transaction.open_binary(first) as output:
                        output.write(b"first")
                    with transaction.open_binary(second) as output:
                        output.write(b"second")
                    # Model a target appearing after preflight but before the
                    # atomic no-replace publication phase.
                    second.write_bytes(b"retain me")

            self.assertEqual(first.read_bytes(), b"first")
            self.assertEqual(second.read_bytes(), b"retain me")
            self.assertEqual(list(root.glob(".*.tmp")), [])

    def test_published_name_replacement_is_never_unlinked_by_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first = root / "first.tsv"
            second = root / "second.tsv"
            real_link = os.link

            def replace_after_link(source, destination, **kwargs):
                real_link(source, destination, **kwargs)
                if pathlib.Path(destination) == first:
                    first.unlink()
                    first.write_bytes(b"replacement")

            with (
                mock.patch.object(
                    EXTRACTOR.os, "link", side_effect=replace_after_link
                ),
                self.assertRaisesRegex(ValueError, "published artifact identity"),
            ):
                with EXTRACTOR.ArtifactTransaction() as transaction:
                    with transaction.open_binary(first) as output:
                        output.write(b"first")
                    with transaction.open_binary(second) as output:
                        output.write(b"second")

            self.assertEqual(first.read_bytes(), b"replacement")
            self.assertFalse(second.exists())
            self.assertEqual(list(root.glob(".*.tmp")), [])

    def test_derived_pdu_and_output_byte_budgets_are_enforced(self):
        def exercise() -> None:
            with (
                mock.patch.object(
                    EXTRACTOR, "tpkt_records", return_value=iter((b"record",))
                ),
                mock.patch.object(
                    EXTRACTOR, "cotp_tsdus", return_value=iter((b"tsdu",))
                ),
                mock.patch.object(EXTRACTOR, "session_payload", return_value=b"ppdu"),
                mock.patch.object(
                    EXTRACTOR,
                    "presentation_pdvs",
                    return_value=iter(((1, b"\xa0"),)),
                ),
                mock.patch.object(EXTRACTOR, "mms_candidate", return_value=b"\xa0"),
            ):
                EXTRACTOR.extract_mms_chunks(
                    iter((b"chunk",)), EXTRACTOR.Counters()
                )

        with mock.patch.object(EXTRACTOR, "MAX_EXTRACTED_PDUS", 0):
            with self.assertRaisesRegex(ValueError, "PDU-count"):
                exercise()
        with mock.patch.object(EXTRACTOR, "MAX_EXTRACTED_BYTES", 0):
            with self.assertRaisesRegex(ValueError, "PDU-byte"):
                exercise()

        output = io.BytesIO()
        budget = EXTRACTOR.OutputBudget()
        with mock.patch.object(EXTRACTOR, "MAX_EXTRACTED_PDUS", 1):
            budget.add_pdu()
            with self.assertRaisesRegex(ValueError, "extracted-PDU"):
                budget.add_pdu()
        with mock.patch.object(EXTRACTOR, "MAX_OUTPUT_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "output-byte"):
                budget.write(output, b"ab")
        self.assertEqual(output.getvalue(), b"")


class CaptureStateBoundsTest(unittest.TestCase):
    def test_retransmitted_syn_does_not_split_connection_generation(self):
        _, events = collect_parsed_packets(
            [
                parsed_tcp(sequence=100, flags=0x02),
                parsed_tcp(sequence=100, flags=0x02),
                parsed_tcp(sequence=101, payload=b"a"),
            ]
        )
        self.assertEqual([item.generation for item in events], [1, 1, 1])

    def test_new_syn_sequence_starts_fresh_connection_generation(self):
        _, events = collect_parsed_packets(
            [
                parsed_tcp(sequence=100, flags=0x02),
                parsed_tcp(sequence=200, flags=0x02),
            ]
        )
        self.assertEqual([item.generation for item in events], [1, 2])

    def test_one_sided_fin_keeps_peer_payload_in_same_generation(self):
        _, events = collect_parsed_packets(
            [
                parsed_tcp(sequence=100, payload=b"first"),
                parsed_tcp(sequence=105, flags=0x11),
                parsed_tcp(SERVER, CLIENT, sequence=500, payload=b"peer"),
            ]
        )
        self.assertEqual([item.generation for item in events], [1, 1, 1])

    def test_both_fins_close_implicit_generation(self):
        _, events = collect_parsed_packets(
            [
                parsed_tcp(sequence=100, flags=0x11),
                parsed_tcp(SERVER, CLIENT, sequence=500, flags=0x11),
                parsed_tcp(sequence=101, payload=b"new"),
            ]
        )
        self.assertEqual([item.generation for item in events], [1, 1, 2])

    def test_rst_closes_implicit_generation(self):
        _, events = collect_parsed_packets(
            [
                parsed_tcp(sequence=100, flags=0x14),
                parsed_tcp(sequence=101, payload=b"new"),
            ]
        )
        self.assertEqual([item.generation for item in events], [1, 2])

    def test_bounds_tcp_connections(self):
        other_client = (b"\x0a\x00\x00\x03", 49153)
        packets = [parsed_tcp(), parsed_tcp(other_client, SERVER)]

        with mock.patch.object(EXTRACTOR, "MAX_TCP_CONNECTIONS", 1):
            with self.assertRaisesRegex(ValueError, "TCP connection bound"):
                collect_parsed_packets(packets)

    def test_bounds_tcp_events(self):
        packets = [parsed_tcp(), parsed_tcp(sequence=2)]

        with mock.patch.object(EXTRACTOR, "MAX_TCP_EVENTS", 1):
            with self.assertRaisesRegex(ValueError, "TCP event bound"):
                collect_parsed_packets(packets)

    def test_bounds_direction_streams(self):
        packets = [
            parsed_tcp(payload=b"a"),
            parsed_tcp(SERVER, CLIENT, payload=b"b"),
        ]

        with mock.patch.object(EXTRACTOR, "MAX_DIRECTION_STREAMS", 1):
            with self.assertRaisesRegex(ValueError, "direction-stream bound"):
                collect_parsed_packets(packets)

    def test_bounds_segments_per_direction(self):
        packets = [
            parsed_tcp(sequence=1, payload=b"a"),
            parsed_tcp(sequence=2, payload=b"b"),
        ]

        with mock.patch.object(EXTRACTOR, "MAX_SEGMENTS_PER_DIRECTION", 1):
            with self.assertRaisesRegex(ValueError, "per-direction segment bound"):
                collect_parsed_packets(packets)


if __name__ == "__main__":
    unittest.main()
