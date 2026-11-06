#!/usr/bin/env python3

import importlib.util
from pathlib import Path
import unittest


PATH = Path(__file__).with_name("event-notification-oracle.py")
SPEC = importlib.util.spec_from_file_location("event_notification_oracle", PATH)
ORACLE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(ORACLE)


class EventNotificationOracleTest(unittest.TestCase):
    exact = bytes.fromhex(
        "a32ba229a0098007454e524f4c4c31"
        "a111800f425245414b45525f73756363657373"
        "820100830102a40381012a"
    )

    def test_exact_success(self):
        event = ORACLE.decode(self.exact)
        self.assertEqual(event.enrollment.name, "ENROLL1")
        self.assertEqual(event.condition.name, "BREAKER_success")
        self.assertEqual(event.transition_value, 42)
        self.assertEqual(ORACLE.classify(event), "device_success")

    def test_missing_association_is_candidate(self):
        event = ORACLE.decode(self.exact)
        self.assertEqual(ORACLE.classify(event, False),
                         "device_success_candidate")

    def test_wrong_severity_is_candidate(self):
        event = ORACLE.decode(self.exact.replace(b"\x82\x01\x00",
                                                 b"\x82\x01\x01"))
        self.assertEqual(ORACLE.classify(event), "device_success_candidate")

    def test_missing_state_is_well_formed_candidate(self):
        data = bytes.fromhex(
            "a328a226a0098007454e524f4c4c31"
            "a111800f425245414b45525f73756363657373"
            "820100a40381012a"
        )
        self.assertEqual(ORACLE.classify(ORACLE.decode(data)),
                         "device_success_candidate")

    def test_missing_mandatory_field_rejected(self):
        malformed = bytes.fromhex(
            "a328a226a0098007454e524f4c4c31"
            "a111800f425245414b45525f73756363657373"
            "820100a40381012a"
        ).replace(b"\x82\x01\x00", b"")
        malformed = bytes([0xA3, len(malformed) - 2, 0xA2,
                           len(malformed) - 4]) + malformed[4:]
        with self.assertRaises(ORACLE.DecodeError):
            ORACLE.decode(malformed)


if __name__ == "__main__":
    unittest.main()
