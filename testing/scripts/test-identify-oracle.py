#!/usr/bin/env python3

"""Focused tests for the independent MMS Identify oracle."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import stat
import struct
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).with_name("identify-oracle.py")
SPEC = importlib.util.spec_from_file_location("identify_oracle", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
ORACLE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ORACLE
SPEC.loader.exec_module(ORACLE)


REQUEST = bytes.fromhex("a0050201018200")
RESPONSE = bytes.fromhex("a114020101a20f800441636d6581024d318203312e30")
RESPONSE_WITH_OID = bytes.fromhex(
    "a11d020101a218800441636d6581024d318203312e30a307060528ca220201"
)


def write_pcap(
    path: pathlib.Path,
    packets: tuple[bytes, ...] = (),
    *,
    version: tuple[int, int] = (2, 4),
    snaplen: int = 65535,
    original_extra: int = 0,
) -> None:
    with path.open("wb") as output:
        output.write(
            struct.pack(
                "<IHHIIII", 0xA1B2C3D4, version[0], version[1],
                0, 0, snaplen, 147,
            )
        )
        for index, packet in enumerate(packets, 1):
            output.write(
                struct.pack(
                    "<IIII", index, 0, len(packet), len(packet) + original_extra
                )
            )
            output.write(packet)


class IdentifyOracleTest(unittest.TestCase):
    def test_request_is_primitive_null(self):
        value = ORACLE.parse_identify(REQUEST)
        self.assertEqual(value, ORACLE.Identify(0, 1))

    def test_response_strings(self):
        value = ORACLE.parse_identify(RESPONSE)
        self.assertIsNotNone(value)
        assert value is not None
        self.assertEqual((value.vendor, value.model, value.revision),
                         (b"Acme", b"M1", b"1.0"))

    def test_optional_abstract_syntax_oid(self):
        value = ORACLE.parse_identify(RESPONSE_WITH_OID)
        self.assertIsNotNone(value)
        assert value is not None
        self.assertEqual(value.abstract_syntaxes, ("1.0.9506.2.1",))

    def test_non_identify_is_ignored(self):
        self.assertIsNone(ORACLE.parse_identify(bytes.fromhex("a1050201018300")))
        self.assertIsNone(ORACLE.parse_identify(bytes.fromhex("a303810100")))

    def test_invalid_request_forms_are_rejected(self):
        for value in ("a006020101820100", "a005020101a200"):
            with self.subTest(value=value), self.assertRaises(ORACLE.OracleError):
                ORACLE.parse_identify(bytes.fromhex(value))

    def test_missing_and_reordered_response_fields_are_rejected(self):
        for value in (
            "a10f020101a20a800441636d6581024d31",
            "a114020101a20f810441636d6580024d318203312e30",
        ):
            with self.subTest(value=value), self.assertRaises(ORACLE.OracleError):
                ORACLE.parse_identify(bytes.fromhex(value))

    def test_invalid_utf8_is_rejected(self):
        with self.assertRaisesRegex(ORACLE.OracleError, "UTF-8"):
            ORACLE.parse_identify(bytes.fromhex(
                "a112020101a20d8002c32881024d318203312e30"
            ))

    def test_invalid_oid_is_rejected(self):
        with self.assertRaisesRegex(ORACLE.OracleError, "empty value"):
            ORACLE.parse_identify(bytes.fromhex(
                "a118020101a213800441636d6581024d318203312e30a3020600"
            ))

    def test_classic_pcap_analysis_writes_private_normalized_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            capture = root / "identify.pcap"
            write_pcap(capture, (REQUEST, RESPONSE_WITH_OID))
            artifacts = [root / name for name in ("records.tsv", "summary.tsv", "pdus.bin")]
            counters = ORACLE.analyze(
                capture, artifacts[0], artifacts[1], artifacts[2]
            )
            self.assertEqual((counters.requests, counters.responses), (1, 1))
            self.assertEqual(counters.abstract_syntaxes, 1)
            self.assertEqual((root / "pdus.bin").read_bytes(),
                             REQUEST + RESPONSE_WITH_OID)
            records = (root / "records.tsv").read_text()
            self.assertNotIn("Acme", records)
            self.assertEqual(len(records.splitlines()), 2)
            for artifact in artifacts:
                self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)

    def test_analysis_does_not_clobber_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            capture = root / "identify.pcap"
            output = root / "records.tsv"
            write_pcap(capture, (REQUEST,))
            output.write_bytes(b"retain me")

            with self.assertRaises(FileExistsError):
                ORACLE.analyze(capture, output, root / "summary.tsv", None)

            self.assertEqual(output.read_bytes(), b"retain me")
            self.assertFalse((root / "summary.tsv").exists())

    def test_existing_later_output_prevents_all_output_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            capture = root / "identify.pcap"
            records = root / "records.tsv"
            summary = root / "summary.tsv"
            write_pcap(capture, (REQUEST,))
            summary.write_bytes(b"retain me")

            with self.assertRaises(FileExistsError):
                ORACLE.analyze(capture, records, summary, None)

            self.assertFalse(records.exists())
            self.assertEqual(summary.read_bytes(), b"retain me")

    def test_late_failure_publishes_no_partial_final_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            capture = root / "identify.pcap"
            records = root / "records.tsv"
            summary = root / "summary.tsv"
            pdus = root / "pdus.bin"
            write_pcap(capture, (REQUEST,))
            identify = ORACLE.parse_identify(REQUEST)
            assert identify is not None
            pre_summary_bytes = len(
                (ORACLE.record_line(1, identify) + "\n").encode("ascii")
            ) + len(REQUEST)

            with mock.patch.object(
                ORACLE, "MAX_OUTPUT_BYTES", pre_summary_bytes
            ):
                with self.assertRaisesRegex(ORACLE.OracleError, "output-byte"):
                    ORACLE.analyze(capture, records, summary, pdus)

            for artifact in (records, summary, pdus):
                self.assertFalse(artifact.exists())
            self.assertEqual(list(root.glob(".*.tmp")), [])

    def test_publication_collision_retains_complete_oracle_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first = root / "first.tsv"
            second = root / "second.tsv"
            with self.assertRaises(FileExistsError):
                with ORACLE.ArtifactTransaction() as transaction:
                    with transaction.open_text(first) as output:
                        output.write("first\n")
                    with transaction.open_text(second) as output:
                        output.write("second\n")
                    second.write_text("retain me\n", encoding="ascii")
            self.assertEqual(first.read_text(encoding="ascii"), "first\n")
            self.assertEqual(second.read_text(encoding="ascii"), "retain me\n")
            self.assertEqual(list(root.glob(".*.tmp")), [])

    def test_analysis_rejects_input_and_output_aliases_before_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            capture = root / "identify.pcap"
            write_pcap(capture, (REQUEST,))
            original = capture.read_bytes()

            with self.assertRaisesRegex(ORACLE.OracleError, "path collision"):
                ORACLE.analyze(capture, capture, root / "summary.tsv", None)
            self.assertEqual(capture.read_bytes(), original)

            alias = root / "hard-link.pcap"
            os.link(capture, alias)
            with self.assertRaisesRegex(ORACLE.OracleError, "inode collision"):
                ORACLE.analyze(capture, alias, root / "summary.tsv", None)
            self.assertEqual(capture.read_bytes(), original)

            symbolic = root / "symbolic-output.tsv"
            symbolic.symlink_to(root / "unrelated.tsv")
            with self.assertRaisesRegex(ORACLE.OracleError, "symbolic link"):
                ORACLE.analyze(capture, symbolic, root / "summary.tsv", None)

    def test_analysis_rejects_colliding_outputs_before_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            capture = root / "identify.pcap"
            artifact = root / "artifact.tsv"
            write_pcap(capture, (REQUEST,))
            artifact.write_bytes(b"retain me")

            with self.assertRaisesRegex(ORACLE.OracleError, "path collision"):
                ORACLE.analyze(capture, artifact, artifact, None)
            self.assertEqual(artifact.read_bytes(), b"retain me")

    def test_pcap_header_and_snap_truncation_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            bad_version = root / "version.pcap"
            write_pcap(bad_version, version=(2, 3))
            with self.assertRaisesRegex(ORACLE.OracleError, "format version"):
                list(ORACLE.pcap_packets(bad_version))

            truncated = root / "truncated.pcap"
            write_pcap(truncated, (REQUEST,), original_extra=1)
            with self.assertRaisesRegex(ORACLE.OracleError, "snap-truncated"):
                list(ORACLE.pcap_packets(truncated))

            bad_snaplen = root / "snaplen.pcap"
            write_pcap(bad_snaplen, (REQUEST,), snaplen=len(REQUEST) - 1)
            with self.assertRaisesRegex(ORACLE.OracleError, "packet length"):
                list(ORACLE.pcap_packets(bad_snaplen))

    def test_pcap_aggregate_budgets_are_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = pathlib.Path(directory) / "identify.pcap"
            write_pcap(capture, (REQUEST, REQUEST))
            with mock.patch.object(ORACLE, "MAX_CAPTURE_PACKETS", 1):
                with self.assertRaisesRegex(ORACLE.OracleError, "packet count"):
                    list(ORACLE.pcap_packets(capture))
            with mock.patch.object(ORACLE, "MAX_CAPTURE_BYTES", len(REQUEST)):
                with self.assertRaisesRegex(ORACLE.OracleError, "captured bytes"):
                    list(ORACLE.pcap_packets(capture))

    def test_corpus_wide_syntax_and_output_budgets_are_enforced(self):
        cases = (
            ("MAX_TOTAL_ABSTRACT_SYNTAXES", 0, RESPONSE_WITH_OID,
             "abstract syntaxes"),
            ("MAX_OUTPUT_RECORDS", 0, REQUEST, "output-row"),
            ("MAX_OUTPUT_BYTES", 0, REQUEST, "output-byte"),
        )
        for limit_name, limit, packet, message in cases:
            with self.subTest(limit=limit_name), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                capture = root / "identify.pcap"
                write_pcap(capture, (packet,))
                with mock.patch.object(ORACLE, limit_name, limit):
                    with self.assertRaisesRegex(ORACLE.OracleError, message):
                        ORACLE.analyze(
                            capture,
                            root / "records.tsv",
                            root / "summary.tsv",
                            root / "pdus.bin",
                        )


if __name__ == "__main__":
    unittest.main()
