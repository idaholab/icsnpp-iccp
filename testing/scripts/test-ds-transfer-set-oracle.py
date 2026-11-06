#!/usr/bin/env python3
"""Focused tests for the independent DSTransferSet Write oracle."""

import importlib.util
from pathlib import Path
import unittest


PATH = Path(__file__).with_name("ds-transfer-set-oracle.py")
SPEC = importlib.util.spec_from_file_location("ds_transfer_set_oracle", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


PDU = bytes.fromhex(
    "a06e020102a569a0223020a01ea11c"
    "1a10434f4e54524f4c5f43454e5445525f42"
    "1a0854535f5459504544"
    "a043a241a2168601008a0749474e4f5245448a08444154415f534554"
    "85046553f10085013c85010585010285020e10840203a8"
    "8301008301ff8301ff8301008301ff850107"
)


class DSTransferSetOracleTest(unittest.TestCase):
    def test_exact_start_transfer(self):
        decoded = MODULE.parse_dst_transfer_write(PDU)
        self.assertEqual(decoded["target"], "TS_TYPED")
        self.assertEqual(decoded["target_domain"], "CONTROL_CENTER_B")
        self.assertEqual(decoded["data_set_name"], "DATA_SET")
        self.assertEqual(decoded["start_time"], 1700000000)
        self.assertEqual(decoded["interval"], 60)
        self.assertEqual(decoded["condition_mask"], 21)
        self.assertTrue(decoded["critical"])
        self.assertTrue(decoded["report_by_exception"])
        self.assertTrue(decoded["enabled"])
        self.assertEqual(decoded["event_code_requested"], 7)

    def test_vmd_scoped_transfer_target_fails_closed(self):
        vmd_pdu = bytes.fromhex(
            "a05a020102a555a00e300ca00a800854535f5459504544"
            "a043a241a2168601008a0749474e4f5245448a08444154415f534554"
            "85046553f10085013c85010585010285020e10840203a8"
            "8301008301ff8301ff8301008301ff850107"
        )
        with self.assertRaises(MODULE.DecodeError):
            MODULE.parse_dst_transfer_write(vmd_pdu)

    def test_reserved_condition_bits_fail_closed(self):
        malformed = PDU.replace(b"\x84\x02\x03\xa8", b"\x84\x02\x03\xa9")
        with self.assertRaises(MODULE.DecodeError):
            MODULE.parse_dst_transfer_write(malformed)

    def test_negative_interval_fails_closed(self):
        malformed = PDU.replace(b"\x85\x01\x3c", b"\x85\x01\xff", 1)
        with self.assertRaises(MODULE.DecodeError):
            MODULE.parse_dst_transfer_write(malformed)

    def test_every_one_octet_nonzero_true_is_conformant(self):
        for true_octet in (0x01, 0x02, 0x7F, 0x80, 0xFE, 0xFF):
            with self.subTest(true_octet=true_octet):
                alternate = PDU.replace(
                    b"\x83\x01\xff",
                    b"\x83\x01" + bytes((true_octet,)),
                )
                decoded = MODULE.parse_dst_transfer_write(alternate)
                self.assertEqual(
                    decoded["conformance"], "parameters_conformant"
                )
                self.assertEqual(decoded["conformance_reasons"], "")


if __name__ == "__main__":
    unittest.main()
