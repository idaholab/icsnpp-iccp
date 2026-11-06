#!/usr/bin/env python3

"""Focused tests for the independent MMS InformationReport oracle."""

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


MODULE_PATH = pathlib.Path(__file__).with_name("information-report-oracle.py")
SPEC = importlib.util.spec_from_file_location("information_report_oracle", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
ORACLE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ORACLE
SPEC.loader.exec_module(ORACLE)


def length(value: int) -> bytes:
    if value < 0x80:
        return bytes((value,))
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(encoded),)) + encoded


def tlv(tag: bytes | int, value: bytes) -> bytes:
    identifier = bytes((tag,)) if isinstance(tag, int) else tag
    return identifier + length(len(value)) + value


def type_component(description: bytes) -> bytes:
    return tlv(0x30, tlv(0xA1, description))


def structure_type(*components: bytes) -> bytes:
    return tlv(0xA2, tlv(0xA1, b"".join(
        type_component(component) for component in components
    )))


def point_type_description(name: str) -> bytes:
    integer16 = bytes.fromhex("850110")
    integer32 = bytes.fromhex("850120")
    unsigned16 = bytes.fromhex("860110")
    bits8 = bytes.fromhex("840108")
    real = bytes.fromhex("a706020120020108")
    timestamp_extended = structure_type(integer32, integer16)

    descriptions = {
        "Data_Real": real,
        "Data_Discrete": integer32,
        "Data_State": bits8,
        "Data_StateSupplemental": bits8,
        "Data_RealQ": structure_type(real, bits8),
        "Data_DiscreteQ": structure_type(integer32, bits8),
        "Data_StateQ": structure_type(bits8, bits8),
        "Data_StateSupplementalQ": structure_type(bits8, bits8),
        "Data_RealQTimeTag": structure_type(real, integer32, bits8),
        "Data_DiscreteQTimeTag": structure_type(integer32, integer32, bits8),
        "Data_StateQTimeTag": structure_type(integer32, bits8),
        "Data_StateSupplementalQTimeTag": structure_type(
            bits8, integer32, bits8
        ),
        "Data_RealExtended": structure_type(
            real, integer32, bits8, unsigned16
        ),
        "Data_DiscreteExtended": structure_type(
            integer32, integer32, bits8, unsigned16
        ),
        "Data_StateExtended": structure_type(integer32, bits8, unsigned16),
        "Data_StateSupplementalExtended": structure_type(
            bits8, integer32, bits8, unsigned16
        ),
        "Data_RealQTimeTagExtended": structure_type(
            real, timestamp_extended, bits8
        ),
        "Data_DiscreteQTimeTagExtended": structure_type(
            integer32, timestamp_extended, bits8
        ),
        "Data_StateQTimeTagExtended": structure_type(
            timestamp_extended, bits8
        ),
        "Data_StateSupplementalQTimeTagExtended": structure_type(
            bits8, timestamp_extended, bits8
        ),
    }
    return descriptions[name]


def gva_type_response(description: bytes, *, deletable: int = 0) -> bytes:
    service = tlv(0xA6, tlv(0x80, bytes((deletable,))) + tlv(0xA2, description))
    return tlv(0xA1, bytes.fromhex("020101") + service)


def report(access: bytes, results: bytes, detail: bytes = b"") -> bytes:
    service = tlv(0xA0, access + tlv(0xA0, results))
    return tlv(0xA3, service + detail)


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


class InformationReportOracleTest(unittest.TestCase):
    GVA_REQUEST = bytes.fromhex("a00f020101a60aa0088006506f696e7431")
    GVA_RESPONSE = gva_type_response(point_type_description("Data_RealQ"))
    GVA_ADDRESS_REQUEST = bytes.fromhex("a00a020101a605a103810141")
    GVA_UNSUPPORTED_RESPONSE = bytes.fromhex(
        "a10d020101a6088001ffa203850108"
    )
    CONFIRMED_ERROR = bytes.fromhex("a20a800101a205a003870103")
    POINT1_REPORT = bytes.fromhex(
        "a31fa01da00c300aa0088006506f696e7431"
        "a00da20b870508412000008402002a"
    )
    POINT2_REPORT = bytes.fromhex(
        "a31fa01da00c300aa0088006506f696e7432"
        "a00da20b870508412000008402002a"
    )
    READ_REQUEST = bytes.fromhex(
        "a015020102a410a10ea00c300aa0088006506f696e7431"
    )
    READ_RESPONSE = bytes.fromhex(
        "a114020102a40fa10da20b870508412000008402002a"
    )
    SELECT_GVA_REQUEST = bytes.fromhex(
        "a014020101a60fa00d800b425245414b45525f53424f"
    )
    SELECT_GVA_RESPONSE = bytes.fromhex(
        "a10d020101a608800100a203850110"
    )
    SELECT_REQUEST = bytes.fromhex(
        "a01a020102a415a113a011300fa00d800b425245414b45525f53424f"
    )
    SELECT_RESPONSE = bytes.fromhex("a10a020102a405a10385012a")
    SELECT_FAILURE = bytes.fromhex("a10a020102a405a103800103")
    TAG_GVA_REQUEST = bytes.fromhex(
        "a014020101a60fa00d800b425245414b45525f544147"
    )
    TAG_GVA_RESPONSE = gva_type_response(
        structure_type(bytes.fromhex("840103"), bytes.fromhex("8a02ff01"))
    )
    TAG_SET_REQUEST = bytes.fromhex(
        "a027020102a522a011300fa00d800b425245414b45525f544147"
        "a00da20b840205608a056d61696e74"
    )
    TAG_SET_RESPONSE = bytes.fromhex("a107020102a5028100")
    TAG_SET_FAILURE = bytes.fromhex("a108020102a503800103")
    TAG_GET_REQUEST = bytes.fromhex(
        "a01a020103a415a113a011300fa00d800b425245414b45525f544147"
    )
    TAG_GET_RESPONSE = bytes.fromhex(
        "a114020103a40fa10da20b840205608a056d61696e74"
    )
    TAG_GET_FAILURE = bytes.fromhex("a10a020103a405a103800103")
    INFORMATION_MESSAGE_REPORT = bytes.fromhex(
        "a326a024a10880064d53475f5453"
        "a018a20c850101850102850103850105"
        "890868656c6c6f000000"
    )

    def data_node(self, encoded: bytes):
        field = ORACLE.read_tlv(encoded)
        self.assertEqual(field.end, len(encoded))
        return ORACLE.decode_data(field)

    def named_type_response(self, named_type: str) -> bytes:
        # The argument remains convenient for table-driven tests, but the wire
        # response correctly contains only an inline TypeDescription. The
        # named type is supplied independently through the site mapping.
        return gva_type_response(point_type_description(named_type))

    def point1_report(self, result: bytes) -> bytes:
        entry = tlv(0x30, tlv(0xA0, tlv(0x80, b"Point1")))
        return report(tlv(0xA0, entry), result)

    def test_named_list_report_and_result_errors(self):
        value = bytes.fromhex("a311a00fa1058003766172a006800103850101")
        decoded = ORACLE.parse_information_report(value)
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded.access_choice, 1)
        self.assertEqual(decoded.named_list.item, "var")
        self.assertEqual(
            [(result.choice, result.error) for result in decoded.results],
            [(0, 3), (5, -1)],
        )

    def test_explicit_variable_and_structured_data(self):
        value = bytes.fromhex(
            "a31ca01aa0093007a0058003766172a00da20b870508412000008402002a"
        )
        decoded = ORACLE.parse_information_report(value)
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded.variable_count, 1)
        self.assertEqual(decoded.first_variable.item, "var")
        self.assertEqual(decoded.results[0].choice, 2)
        assert decoded.results[0].node is not None
        self.assertEqual(
            [child.choice for child in decoded.results[0].node.children], [7, 4]
        )

    def test_domain_specific_object_and_companion_detail(self):
        object_name = tlv(
            0xA1, tlv(0x1A, b"DOM") + tlv(0x1A, b"Item")
        )
        entry = tlv(0x30, tlv(0xA0, object_name))
        value = report(tlv(0xA0, entry), tlv(0x85, b"\x2a"), tlv(b"\xbf\x4f", b""))
        decoded = ORACLE.parse_information_report(value)
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded.first_variable, ORACLE.ObjectName(1, "DOM", "Item"))
        self.assertEqual(decoded.results[0].node.integer, 42)

    def test_information_message_report_wire_shape(self):
        """Decode the production fixture with an independent MMS path."""
        decoded = ORACLE.parse_information_report(self.INFORMATION_MESSAGE_REPORT)
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded.access_choice, 1)
        self.assertEqual(decoded.named_list, ORACLE.ObjectName(0, "", "MSG_TS"))
        self.assertEqual(len(decoded.results), 2)
        header = decoded.results[0].node
        buffer = decoded.results[1].node
        self.assertIsNotNone(header)
        self.assertIsNotNone(buffer)
        assert header is not None and buffer is not None
        self.assertEqual(header.choice, 2)
        self.assertEqual(
            [(child.choice, child.integer) for child in header.children],
            [(5, 1), (5, 2), (5, 3), (5, 5)],
        )
        self.assertEqual(buffer.choice, 9)
        self.assertEqual(buffer.raw, b"hello\x00\x00\x00")

    def test_non_information_report_is_ignored(self):
        self.assertIsNone(ORACLE.parse_information_report(bytes.fromhex("a005020101a300")))
        self.assertIsNone(ORACLE.parse_information_report(bytes.fromhex("a303810100")))

    def test_confirmed_service_discovery_is_independent(self):
        request = bytes.fromhex("a007020101a6028000")
        response = bytes.fromhex("a108020101a603800100")
        self.assertEqual(ORACLE.confirmed_service(request), (0, 6))
        self.assertEqual(ORACLE.confirmed_service(response), (1, 6))
        self.assertEqual(
            ORACLE.confirmed_service(bytes.fromhex("a0050201018200")), (0, 2)
        )

    def test_type_description_explicit_and_implicit_tagging(self):
        floating = ORACLE.read_tlv(bytes.fromhex("a706020120020108"))
        self.assertEqual(ORACLE._validate_type_description(floating), 7)
        with self.assertRaisesRegex(ORACLE.OracleError, "floating-point"):
            ORACLE._validate_type_description(
                ORACLE.read_tlv(bytes.fromhex("a706800120810108"))
            )

        mms_string = ORACLE.read_tlv(bytes.fromhex("b003020120"))
        self.assertEqual(ORACLE._validate_type_description(mms_string), 16)
        with self.assertRaisesRegex(ORACLE.OracleError, "form"):
            ORACLE._validate_type_description(
                ORACLE.read_tlv(bytes.fromhex("900120"))
            )

        array = ORACLE.read_tlv(bytes.fromhex("a107810102a2028300"))
        self.assertEqual(ORACLE._validate_type_description(array), 1)
        structure = ORACLE.read_tlv(
            bytes.fromhex("a20ba1093007800141a1028300")
        )
        self.assertEqual(ORACLE._validate_type_description(structure), 2)
        with self.assertRaisesRegex(ORACLE.OracleError, "wrapper"):
            ORACLE._validate_type_description(
                ORACLE.read_tlv(bytes.fromhex("a1058101028300"))
            )

    def correlated_analysis(
        self, packets: tuple[bytes, ...], contexts,
        configured_type: str | None = "Data_RealQ",
    ):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = pathlib.Path(directory.name)
        capture = root / "mms.pcap"
        with capture.open("wb") as output:
            output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 147))
            for index, packet in enumerate(packets, 1):
                output.write(struct.pack("<IIII", index, 0, len(packet), len(packet)))
                output.write(packet)
        metadata = root / "metadata.tsv"
        with metadata.open("w", encoding="ascii") as output:
            output.write("packet_index\tflow_id\tdirection\tcapture_packet\n")
            for index, (flow_id, direction) in enumerate(contexts, 1):
                output.write(f"{index}\t{flow_id}\t{direction}\t{index}\n")
        mapping = root / "types.tsv"
        if configured_type is not None:
            with mapping.open("w", encoding="ascii") as output:
                output.write(
                    "flow_id\tserver_direction\tscope\tdomain\t"
                    "object_name\tnamed_type\n"
                )
                output.write(f"1\t1\t0\t\tPoint1\t{configured_type}\n")
        return ORACLE.analyze(
            capture, root / "records.tsv", root / "summary.tsv", None,
            metadata, None, mapping if configured_type is not None else None,
        )

    def test_gva_correlation_verifies_exact_object_shape_and_direction(self):
        counters = self.correlated_analysis(
            (self.GVA_REQUEST, self.GVA_RESPONSE, self.POINT1_REPORT),
            ((1, 0), (1, 1), (1, 1)),
        )
        self.assertEqual(counters.get_variable_access_attributes_matched, 1)
        self.assertEqual(counters.tase2_supported_type_discoveries, 1)
        self.assertEqual(counters.tase2_verified_results, 1)
        self.assertEqual(counters.tase2_missing_named_type_results, 0)

    def test_gva_correlation_rejects_same_direction(self):
        counters = self.correlated_analysis(
            (
                self.GVA_REQUEST,
                self.GVA_RESPONSE,
                self.GVA_RESPONSE,
                self.POINT1_REPORT,
            ),
            ((1, 0), (1, 0), (1, 1), (1, 1)),
        )
        self.assertEqual(counters.get_variable_access_attributes_direction_mismatches, 1)
        self.assertEqual(counters.get_variable_access_attributes_matched, 1)
        self.assertEqual(counters.tase2_verified_results, 1)

    def test_gva_correlation_rejects_wrong_invoke_and_object(self):
        wrong_invoke = bytearray(self.GVA_RESPONSE)
        wrong_invoke[4] = 2
        counters = self.correlated_analysis(
            (self.GVA_REQUEST, bytes(wrong_invoke), self.POINT2_REPORT),
            ((1, 0), (1, 1), (1, 1)),
        )
        self.assertEqual(counters.get_variable_access_attributes_unmatched_responses, 1)
        self.assertEqual(counters.tase2_verified_results, 0)
        self.assertEqual(counters.tase2_missing_named_type_results, 1)

        exact_invoke = self.correlated_analysis(
            (self.GVA_REQUEST, self.GVA_RESPONSE, self.POINT2_REPORT),
            ((1, 0), (1, 1), (1, 1)),
        )
        self.assertEqual(exact_invoke.get_variable_access_attributes_matched, 1)
        self.assertEqual(exact_invoke.tase2_verified_results, 0)
        self.assertEqual(exact_invoke.tase2_missing_named_type_results, 1)

    def test_gva_response_before_request_and_cross_flow_do_not_poison_state(self):
        response_first = self.correlated_analysis(
            (
                self.GVA_RESPONSE,
                self.GVA_REQUEST,
                self.GVA_RESPONSE,
                self.POINT1_REPORT,
            ),
            ((1, 1), (1, 0), (1, 1), (1, 1)),
        )
        self.assertEqual(
            response_first.get_variable_access_attributes_unmatched_responses, 1
        )
        self.assertEqual(response_first.get_variable_access_attributes_matched, 1)
        self.assertEqual(response_first.tase2_verified_results, 1)

        cross_flow = self.correlated_analysis(
            (
                self.GVA_REQUEST,
                self.GVA_RESPONSE,
                self.GVA_RESPONSE,
                self.POINT1_REPORT,
            ),
            ((1, 0), (2, 1), (1, 1), (1, 1)),
        )
        self.assertEqual(
            cross_flow.get_variable_access_attributes_unmatched_responses, 1
        )
        self.assertEqual(cross_flow.get_variable_access_attributes_matched, 1)
        self.assertEqual(cross_flow.tase2_verified_results, 1)

    def test_gva_duplicate_invoke_is_ambiguous_then_safely_reusable(self):
        point2_request = self.GVA_REQUEST[:-1] + b"2"
        counters = self.correlated_analysis(
            (
                self.GVA_REQUEST,
                point2_request,
                self.GVA_RESPONSE,
                self.POINT1_REPORT,
                self.POINT2_REPORT,
                self.GVA_REQUEST,
                self.GVA_RESPONSE,
                self.POINT1_REPORT,
            ),
            (
                (1, 0), (1, 0), (1, 1), (1, 1),
                (1, 1), (1, 0), (1, 1), (1, 1),
            ),
        )
        self.assertEqual(counters.get_variable_access_attributes_duplicate_requests, 1)
        self.assertEqual(counters.get_variable_access_attributes_ambiguous_responses, 1)
        self.assertEqual(counters.get_variable_access_attributes_matched, 1)
        self.assertEqual(counters.tase2_supported_type_discoveries, 1)
        self.assertEqual(counters.tase2_verified_results, 1)
        self.assertEqual(counters.tase2_missing_named_type_results, 2)

    def test_gva_confirmed_error_clears_state_without_late_learning(self):
        late_response = self.correlated_analysis(
            (
                self.GVA_REQUEST,
                self.CONFIRMED_ERROR,
                self.GVA_RESPONSE,
                self.POINT1_REPORT,
            ),
            ((1, 0), (1, 1), (1, 1), (1, 1)),
        )
        self.assertEqual(
            late_response.get_variable_access_attributes_errors_cleared, 1
        )
        self.assertEqual(
            late_response.get_variable_access_attributes_unmatched_responses, 1
        )
        self.assertEqual(late_response.tase2_supported_type_discoveries, 0)
        self.assertEqual(late_response.tase2_verified_results, 0)

        same_direction = self.correlated_analysis(
            (
                self.GVA_REQUEST,
                self.CONFIRMED_ERROR,
                self.GVA_RESPONSE,
                self.POINT1_REPORT,
            ),
            ((1, 0), (1, 0), (1, 1), (1, 1)),
        )
        self.assertEqual(
            same_direction.get_variable_access_attributes_errors_cleared, 0
        )
        self.assertEqual(same_direction.get_variable_access_attributes_matched, 1)
        self.assertEqual(same_direction.tase2_verified_results, 1)

        point2_request = self.GVA_REQUEST[:-1] + b"2"
        ambiguous = self.correlated_analysis(
            (
                self.GVA_REQUEST,
                point2_request,
                self.CONFIRMED_ERROR,
                self.GVA_REQUEST,
                self.GVA_RESPONSE,
                self.POINT1_REPORT,
            ),
            ((1, 0), (1, 0), (1, 1), (1, 0), (1, 1), (1, 1)),
        )
        self.assertEqual(ambiguous.get_variable_access_attributes_errors_cleared, 1)
        self.assertEqual(ambiguous.get_variable_access_attributes_matched, 1)
        self.assertEqual(ambiguous.tase2_verified_results, 1)

    def test_gva_address_unsupported_type_and_malformed_response(self):
        address = self.correlated_analysis(
            (self.GVA_ADDRESS_REQUEST, self.GVA_RESPONSE),
            ((1, 0), (1, 1)),
        )
        self.assertEqual(address.get_variable_access_attributes_address_requests, 1)
        self.assertEqual(address.get_variable_access_attributes_unmatched_responses, 1)

        malformed_address = bytes.fromhex("a00a020101a605a103a10100")
        with self.assertRaisesRegex(ORACLE.OracleError, "invalid MMS Address"):
            self.correlated_analysis((malformed_address,), ((1, 0),))

        unsupported = self.correlated_analysis(
            (
                self.GVA_REQUEST,
                self.GVA_UNSUPPORTED_RESPONSE,
                self.POINT1_REPORT,
            ),
            ((1, 0), (1, 1), (1, 1)), configured_type=None,
        )
        self.assertEqual(unsupported.get_variable_access_attributes_matched, 1)
        self.assertEqual(unsupported.tase2_unsupported_type_discoveries, 1)
        self.assertEqual(unsupported.tase2_verified_results, 0)

        malformed = bytes.fromhex("a108020101a6038001ff")
        with self.assertRaisesRegex(
            ORACLE.OracleError, "response is incomplete"
        ):
            self.correlated_analysis(
                (self.GVA_REQUEST, malformed), ((1, 0), (1, 1))
            )

    def test_gva_wire_description_cannot_replace_configured_type(self):
        invoke_two_request = bytearray(self.GVA_REQUEST)
        invoke_two_request[4] = 2
        data_real_response = bytearray(self.GVA_RESPONSE)
        data_real_response[4] = 2
        scalar_report = bytes.fromhex(
            "a319a017a00c300aa0088006506f696e7431a00787050841200000"
        )
        counters = self.correlated_analysis(
            (
                self.GVA_REQUEST,
                self.GVA_RESPONSE,
                self.POINT1_REPORT,
                bytes(invoke_two_request),
                bytes(data_real_response),
                scalar_report,
            ),
            ((1, 0), (1, 1), (1, 1), (1, 0), (1, 1), (1, 1)),
        )
        self.assertEqual(counters.get_variable_access_attributes_matched, 2)
        self.assertEqual(counters.tase2_supported_type_discoveries, 2)
        self.assertEqual(counters.tase2_verified_results, 1)
        self.assertEqual(counters.tase2_named_type_shape_mismatches, 1)

    def test_read_decoding_and_correlation_verifies_first_point(self):
        request = ORACLE.decode_confirmed_pdu(self.READ_REQUEST)
        response = ORACLE.decode_confirmed_pdu(self.READ_RESPONSE)
        assert request is not None and response is not None
        decoded_request = ORACLE.decode_read_request(request.service)
        decoded_response = ORACLE.decode_read_response(response.service)
        self.assertEqual(decoded_request.variables, (ORACLE.ObjectName(0, "", "Point1"),))
        self.assertEqual(len(decoded_response.results), 1)

        counters = self.correlated_analysis(
            (
                self.GVA_REQUEST,
                self.GVA_RESPONSE,
                self.READ_REQUEST,
                self.READ_RESPONSE,
            ),
            ((1, 0), (1, 1), (1, 0), (1, 1)),
        )
        self.assertEqual(counters.read_matched, 1)
        self.assertEqual(counters.tase2_read_shape_candidate_results, 1)
        self.assertEqual(counters.tase2_read_verified_results, 1)
        self.assertEqual(counters.tase2_verified_results, 1)

    def test_empty_read_response_result_list_is_rejected(self):
        confirmed = ORACLE.decode_confirmed_pdu(
            bytes.fromhex("a107020102a402a100")
        )
        self.assertIsNotNone(confirmed)
        assert confirmed is not None
        with self.assertRaisesRegex(ORACLE.OracleError, "result list is empty"):
            ORACLE.decode_read_response(confirmed.service)

    def test_gva_response_accepts_nested_unresolved_type_name(self):
        unresolved_response = bytes.fromhex(
            "a116020101a611800100a20ca10a810101a205a003800154"
        )
        confirmed = ORACLE.decode_confirmed_pdu(unresolved_response)
        self.assertIsNotNone(confirmed)
        assert confirmed is not None
        self.assertEqual(ORACLE.decode_gva_response(confirmed.service), 1)
        attributes = ORACLE.decode_gva_attributes(confirmed.service)
        self.assertEqual(attributes.unresolved_type_names, 1)
        self.assertEqual(
            attributes.signature,
            ((0, 0, 0, 0, False), (1, 1, 0, 1, False)),
        )

        counters = self.correlated_analysis(
            (self.GVA_REQUEST, unresolved_response, self.POINT1_REPORT),
            ((1, 0), (1, 1), (1, 1)),
        )
        self.assertEqual(counters.tase2_supported_type_discoveries, 0)
        self.assertEqual(counters.tase2_unsupported_type_discoveries, 1)
        self.assertEqual(counters.tase2_verified_results, 0)

    def test_gva_configured_name_does_not_override_shape_or_deletable(self):
        wrong_shape = self.correlated_analysis(
            (self.GVA_REQUEST, self.SELECT_GVA_RESPONSE, self.POINT1_REPORT),
            ((1, 0), (1, 1), (1, 1)),
        )
        self.assertEqual(wrong_shape.tase2_supported_type_discoveries, 0)
        self.assertEqual(wrong_shape.tase2_unsupported_type_discoveries, 1)
        self.assertEqual(wrong_shape.tase2_verified_results, 0)

        deletable = gva_type_response(
            point_type_description("Data_RealQ"), deletable=1
        )
        deletable_result = self.correlated_analysis(
            (self.GVA_REQUEST, deletable, self.POINT1_REPORT),
            ((1, 0), (1, 1), (1, 1)),
        )
        self.assertEqual(deletable_result.tase2_supported_type_discoveries, 0)
        self.assertEqual(deletable_result.tase2_unsupported_type_discoveries, 1)
        self.assertEqual(deletable_result.tase2_verified_results, 0)

    def test_select_mapping_is_independently_classified(self):
        gva_request = ORACLE.decode_confirmed_pdu(self.SELECT_GVA_REQUEST)
        gva_response = ORACLE.decode_confirmed_pdu(self.SELECT_GVA_RESPONSE)
        read_request = ORACLE.decode_confirmed_pdu(self.SELECT_REQUEST)
        read_response = ORACLE.decode_confirmed_pdu(self.SELECT_RESPONSE)
        assert gva_request is not None and gva_response is not None
        assert read_request is not None and read_response is not None

        object_name = ORACLE.decode_gva_request(gva_request.service)
        self.assertEqual(ORACLE.decode_gva_response(gva_response.service), 5)
        named_type = ORACLE.ObjectName(0, "", "SBO_CheckBackName")
        request = ORACLE.decode_read_request(read_request.service)
        response = ORACLE.decode_read_response(read_response.service)
        self.assertEqual(object_name, ORACLE.ObjectName(0, "", "BREAKER_SBO"))
        self.assertEqual(request.variables, (object_name,))
        self.assertEqual(
            ORACLE.classify_tase2_select(request, named_type, response),
            ORACLE.SelectClassification("select", "confirmed", 42, None),
        )

        failure_pdu = ORACLE.decode_confirmed_pdu(self.SELECT_FAILURE)
        assert failure_pdu is not None
        failure = ORACLE.decode_read_response(failure_pdu.service)
        self.assertEqual(
            ORACLE.classify_tase2_select(request, named_type, failure),
            ORACLE.SelectClassification("select", "failed", None, 3),
        )

    def test_select_mapping_rejects_missing_type_and_bad_checkback_width(self):
        request_pdu = ORACLE.decode_confirmed_pdu(self.SELECT_REQUEST)
        response_pdu = ORACLE.decode_confirmed_pdu(self.SELECT_RESPONSE)
        assert request_pdu is not None and response_pdu is not None
        request = ORACLE.decode_read_request(request_pdu.service)
        response = ORACLE.decode_read_response(response_pdu.service)
        self.assertEqual(
            ORACLE.classify_tase2_select(request, None, response),
            ORACLE.SelectClassification(
                "select_candidate", "candidate_response", None, None
            ),
        )

        bad_width_pdu = ORACLE.decode_confirmed_pdu(
            bytes.fromhex("a10c020102a407a1058503010000")
        )
        assert bad_width_pdu is not None
        bad_width = ORACLE.decode_read_response(bad_width_pdu.service)
        named_type = ORACLE.ObjectName(0, "", "SBO_CheckBackName")
        self.assertEqual(
            ORACLE.classify_tase2_select(request, named_type, bad_width),
            ORACLE.SelectClassification("select", "invalid_response", None, None),
        )

    def test_get_and_set_tag_mappings_are_independently_classified(self):
        gva_request = ORACLE.decode_confirmed_pdu(self.TAG_GVA_REQUEST)
        gva_response = ORACLE.decode_confirmed_pdu(self.TAG_GVA_RESPONSE)
        set_request_pdu = ORACLE.decode_confirmed_pdu(self.TAG_SET_REQUEST)
        set_response_pdu = ORACLE.decode_confirmed_pdu(self.TAG_SET_RESPONSE)
        get_request_pdu = ORACLE.decode_confirmed_pdu(self.TAG_GET_REQUEST)
        get_response_pdu = ORACLE.decode_confirmed_pdu(self.TAG_GET_RESPONSE)
        assert gva_request is not None and gva_response is not None
        assert set_request_pdu is not None and set_response_pdu is not None
        assert get_request_pdu is not None and get_response_pdu is not None

        object_name = ORACLE.decode_gva_request(gva_request.service)
        self.assertEqual(ORACLE.decode_gva_response(gva_response.service), 2)
        named_type = ORACLE.ObjectName(0, "", "Tag_Value")
        set_request = ORACLE.decode_write_request(set_request_pdu.service)
        set_response = ORACLE.decode_write_response(set_response_pdu.service)
        get_request = ORACLE.decode_read_request(get_request_pdu.service)
        get_response = ORACLE.decode_read_response(get_response_pdu.service)
        self.assertEqual(object_name, ORACLE.ObjectName(0, "", "BREAKER_TAG"))
        self.assertEqual(set_request.variables, (object_name,))
        self.assertEqual(get_request.variables, (object_name,))
        expected = ORACLE.TagClassification(
            "set_tag", "confirmed", 1, "armed", "maint", None
        )
        self.assertEqual(
            ORACLE.classify_tase2_set_tag(
                set_request, named_type, set_response
            ),
            expected,
        )
        self.assertEqual(
            ORACLE.classify_tase2_get_tag(
                get_request, named_type, get_response
            ),
            ORACLE.TagClassification(
                "get_tag", "confirmed", 1, "armed", "maint", None
            ),
        )

    def test_tag_mapping_preserves_failures_and_rejects_reserved_tag(self):
        set_request_pdu = ORACLE.decode_confirmed_pdu(self.TAG_SET_REQUEST)
        set_failure_pdu = ORACLE.decode_confirmed_pdu(self.TAG_SET_FAILURE)
        get_request_pdu = ORACLE.decode_confirmed_pdu(self.TAG_GET_REQUEST)
        get_failure_pdu = ORACLE.decode_confirmed_pdu(self.TAG_GET_FAILURE)
        assert set_request_pdu is not None and set_failure_pdu is not None
        assert get_request_pdu is not None and get_failure_pdu is not None
        named_type = ORACLE.ObjectName(0, "", "Tag_Value")
        set_request = ORACLE.decode_write_request(set_request_pdu.service)
        set_failure = ORACLE.decode_write_response(set_failure_pdu.service)
        self.assertEqual(
            ORACLE.classify_tase2_set_tag(
                set_request, named_type, set_failure
            ),
            ORACLE.TagClassification(
                "set_tag", "partial_or_failed", 1, "armed", "maint", 3
            ),
        )

        get_request = ORACLE.decode_read_request(get_request_pdu.service)
        get_failure = ORACLE.decode_read_response(get_failure_pdu.service)
        self.assertEqual(
            ORACLE.classify_tase2_get_tag(
                get_request, named_type, get_failure
            ),
            ORACLE.TagClassification(
                "get_tag", "failed", None, "", "", 3
            ),
        )

        reserved_pdu = ORACLE.decode_confirmed_pdu(bytes.fromhex(
            "a110020103a40ba109a207840205c08a0178"
        ))
        assert reserved_pdu is not None
        reserved = ORACLE.decode_read_response(reserved_pdu.service)
        self.assertEqual(
            ORACLE.classify_tase2_get_tag(
                get_request, named_type, reserved
            ),
            ORACLE.TagClassification("get_tag", "invalid_response"),
        )
        success_pdu = ORACLE.decode_confirmed_pdu(self.TAG_GET_RESPONSE)
        assert success_pdu is not None
        success = ORACLE.decode_read_response(success_pdu.service)
        self.assertEqual(
            ORACLE.classify_tase2_get_tag(get_request, None, success),
            ORACLE.TagClassification(
                "get_tag_candidate", "candidate_response"
            ),
        )

    def test_read_correlation_rejects_direction_invoke_reuse_and_shape(self):
        same_direction = self.correlated_analysis(
            (
                self.GVA_REQUEST,
                self.GVA_RESPONSE,
                self.READ_REQUEST,
                self.READ_RESPONSE,
            ),
            ((1, 0), (1, 1), (1, 0), (1, 0)),
        )
        self.assertEqual(same_direction.read_direction_mismatches, 1)
        self.assertEqual(same_direction.tase2_read_verified_results, 0)

        wrong_invoke = bytearray(self.READ_RESPONSE)
        wrong_invoke[4] = 3
        unmatched = self.correlated_analysis(
            (
                self.GVA_REQUEST,
                self.GVA_RESPONSE,
                self.READ_REQUEST,
                bytes(wrong_invoke),
            ),
            ((1, 0), (1, 1), (1, 0), (1, 1)),
        )
        self.assertEqual(unmatched.read_unmatched_responses, 1)
        self.assertEqual(unmatched.tase2_read_verified_results, 0)

        reused = self.correlated_analysis(
            (
                self.GVA_REQUEST,
                self.GVA_RESPONSE,
                self.READ_REQUEST,
                self.READ_REQUEST,
                self.READ_RESPONSE,
                self.READ_REQUEST,
                self.READ_RESPONSE,
            ),
            (
                (1, 0), (1, 1), (1, 0), (1, 0),
                (1, 1), (1, 0), (1, 1),
            ),
        )
        self.assertEqual(reused.read_duplicate_requests, 1)
        self.assertEqual(reused.read_ambiguous_responses, 1)
        self.assertEqual(reused.read_matched, 1)
        self.assertEqual(reused.tase2_read_verified_results, 1)

        scalar_real = bytes.fromhex("a10e020102a409a10787050841200000")
        mismatch = self.correlated_analysis(
            (
                self.GVA_REQUEST,
                self.GVA_RESPONSE,
                self.READ_REQUEST,
                scalar_real,
            ),
            ((1, 0), (1, 1), (1, 0), (1, 1)),
        )
        self.assertEqual(mismatch.tase2_read_named_type_shape_mismatches, 1)
        self.assertEqual(mismatch.tase2_read_verified_results, 0)

    def test_read_correlation_requires_cardinality_and_returned_access_agreement(self):
        result = "a20b870508412000008402002a"
        two_results = bytes.fromhex(f"a121020102a41ca11a{result}{result}")
        cardinality = self.correlated_analysis(
            (
                self.GVA_REQUEST,
                self.GVA_RESPONSE,
                self.READ_REQUEST,
                two_results,
            ),
            ((1, 0), (1, 1), (1, 0), (1, 1)),
        )
        self.assertEqual(cardinality.read_cardinality_mismatches, 1)
        self.assertEqual(cardinality.tase2_read_unpaired_candidate_results, 1)

        returned_point2 = bytes.fromhex(
            "a124020102a41fa00ea00c300aa0088006506f696e7432"
            "a10da20b870508412000008402002a"
        )
        returned_access = self.correlated_analysis(
            (
                self.GVA_REQUEST,
                self.GVA_RESPONSE,
                self.READ_REQUEST,
                returned_point2,
            ),
            ((1, 0), (1, 1), (1, 0), (1, 1)),
        )
        self.assertEqual(returned_access.read_returned_access_mismatches, 1)
        self.assertEqual(returned_access.tase2_read_unpaired_candidate_results, 1)

    def test_tase2_timestamped_real_shape_and_old_order(self):
        correct = self.data_node(
            bytes.fromhex("a2118705084120000085046553f1008402002a")
        )
        old_order = self.data_node(
            bytes.fromhex("a211870508412000008402002a85046553f100")
        )
        self.assertEqual(
            ORACLE.tase2_indication_candidates(correct),
            ("Data_RealQTimeTag",),
        )
        self.assertEqual(ORACLE.tase2_indication_candidates(old_order), ())

    def test_tase2_shape_ambiguity_requires_named_type(self):
        value = self.data_node(bytes.fromhex("a2078501018402002a"))
        self.assertEqual(
            ORACLE.tase2_indication_candidates(value),
            ("Data_DiscreteQ", "Data_StateQTimeTag"),
        )

    def test_tase2_rejects_generic_64_bit_real(self):
        value = self.data_node(
            bytes.fromhex("a20f87090b40240000000000008402002a")
        )
        self.assertEqual(ORACLE.tase2_indication_candidates(value), ())

    def test_tase2_structured_extended_timestamp(self):
        value = self.data_node(
            bytes.fromhex(
                "a21787050841200000a20a85046553f100850201f48402002a"
            )
        )
        self.assertEqual(
            ORACLE.tase2_indication_candidates(value),
            ("Data_RealQTimeTagExtended",),
        )

    def test_remaining_core_point_families_require_exact_named_shape(self):
        cases = (
            (
                "Data_StateQ",
                "a2088402006c840200aa",
                "state_q",
            ),
            (
                "Data_StateQTimeTag",
                "a20a85046553f100840200aa",
                "state_q_time",
            ),
            (
                "Data_RealExtended",
                "a2148705084120000085046553f100840200aa86012a",
                "real_extended",
            ),
            (
                "Data_StateExtended",
                "a20d85046553f100840200aa86012a",
                "state_extended",
            ),
            (
                "Data_DiscreteExtended",
                "a21085017b85046553f100840200aa86012a",
                "discrete_extended",
            ),
            (
                "Data_RealQTimeTagExtended",
                "a21687050841200000a20985046553f10085017b840200aa",
                "real_q_time_extended",
            ),
            (
                "Data_StateQTimeTagExtended",
                "a20fa20985046553f10085017b840200aa",
                "state_q_time_extended",
            ),
            (
                "Data_DiscreteQTimeTagExtended",
                "a21285017ba20985046553f10085017b840200aa",
                "discrete_q_time_extended",
            ),
        )
        for named_type, encoded, point_type in cases:
            with self.subTest(named_type=named_type):
                result = bytes.fromhex(encoded)
                candidates = ORACLE.tase2_indication_candidates(
                    self.data_node(result)
                )
                self.assertIn(named_type, candidates)
                counters = self.correlated_analysis(
                    (
                        self.GVA_REQUEST,
                        self.named_type_response(named_type),
                        self.point1_report(result),
                    ),
                    ((1, 0), (1, 1), (1, 1)),
                    configured_type=named_type,
                )
                self.assertEqual(counters.tase2_supported_type_discoveries, 1)
                self.assertEqual(counters.tase2_verified_results, 1)
                self.assertEqual(ORACLE.tase2_point_label(named_type), point_type)

        bad_milliseconds = self.data_node(
            bytes.fromhex(
                "a21787050841200000a20a85046553f100850203e8840200aa"
            )
        )
        bad_cov = self.data_node(
            bytes.fromhex(
                "a21285017b85046553f100840200aa8603010000"
            )
        )
        old_cov_order = self.data_node(
            bytes.fromhex(
                "a21487050841200000840200aa85046553f10086012a"
            )
        )
        self.assertNotIn(
            "Data_RealQTimeTagExtended",
            ORACLE.tase2_indication_candidates(bad_milliseconds),
        )
        self.assertNotIn(
            "Data_DiscreteExtended",
            ORACLE.tase2_indication_candidates(bad_cov),
        )
        self.assertNotIn(
            "Data_RealExtended",
            ORACLE.tase2_indication_candidates(old_cov_order),
        )

    def test_supplemental_state_families_require_exact_named_shape(self):
        cases = (
            (
                "Data_StateSupplemental",
                "8402006c",
                "state_supplemental",
            ),
            (
                "Data_StateSupplementalQ",
                "a2088402006c840200aa",
                "state_supplemental_q",
            ),
            (
                "Data_StateSupplementalQTimeTag",
                "a20e8402006c85046553f100840200aa",
                "state_supplemental_q_time",
            ),
            (
                "Data_StateSupplementalExtended",
                "a2118402006c85046553f100840200aa86012a",
                "state_supplemental_extended",
            ),
            (
                "Data_StateSupplementalQTimeTagExtended",
                "a2138402006ca20985046553f10085017b840200aa",
                "state_supplemental_q_time_extended",
            ),
        )
        for named_type, encoded, point_type in cases:
            with self.subTest(named_type=named_type):
                result = bytes.fromhex(encoded)
                self.assertIn(
                    named_type,
                    ORACLE.tase2_indication_candidates(
                        self.data_node(result)
                    ),
                )
                counters = self.correlated_analysis(
                    (
                        self.GVA_REQUEST,
                        self.named_type_response(named_type),
                        self.point1_report(result),
                    ),
                    ((1, 0), (1, 1), (1, 1)),
                    configured_type=named_type,
                )
                self.assertEqual(counters.tase2_supported_type_discoveries, 1)
                self.assertEqual(counters.tase2_verified_results, 1)
                self.assertEqual(ORACLE.tase2_point_label(named_type), point_type)

        invalid_width = self.data_node(
            bytes.fromhex("a2088402016c840200aa")
        )
        wrong_order = self.data_node(
            bytes.fromhex("a20e85046553f1008402006c840200aa")
        )
        self.assertNotIn(
            "Data_StateSupplementalQ",
            ORACLE.tase2_indication_candidates(invalid_width),
        )
        self.assertNotIn(
            "Data_StateSupplementalQTimeTag",
            ORACLE.tase2_indication_candidates(wrong_order),
        )

    def test_empty_explicit_variable_list_is_rejected(self):
        with self.assertRaisesRegex(ORACLE.OracleError, "variable list is empty"):
            ORACLE.parse_information_report(report(tlv(0xA0, b""), tlv(0x85, b"\x01")))

    def test_out_of_range_access_error_is_rejected(self):
        with self.assertRaisesRegex(ORACLE.OracleError, "out of range"):
            ORACLE.parse_information_report(
                report(tlv(0xA1, tlv(0x80, b"list")), tlv(0x80, b"\x0c"))
            )

    def test_invalid_identifier_and_truncation_are_rejected(self):
        with self.assertRaisesRegex(ORACLE.OracleError, "Identifier repertoire"):
            ORACLE.parse_information_report(
                report(tlv(0xA1, tlv(0x80, b"bad\n")), tlv(0x85, b"\x01"))
            )
        with self.assertRaisesRegex(ORACLE.OracleError, "truncated"):
            ORACLE.parse_information_report(bytes.fromhex("a305a003"))

    def test_data_nesting_is_bounded(self):
        nested = tlv(0x85, b"\x01")
        for _ in range(ORACLE.MAX_NESTING_DEPTH + 2):
            nested = tlv(0xA2, nested)
        with self.assertRaisesRegex(ORACLE.OracleError, "nesting exceeds"):
            ORACLE.parse_information_report(
                report(tlv(0xA1, tlv(0x80, b"list")), nested)
            )

    def test_total_data_elements_are_bounded(self):
        nested_results = tlv(0xA2, tlv(0x85, b"\x01")) * (
            ORACLE.MAX_ELEMENT_COUNT // 2 + 1
        )
        with self.assertRaisesRegex(ORACLE.OracleError, "Data elements exceed"):
            ORACLE.parse_information_report(
                report(tlv(0xA1, tlv(0x80, b"list")), nested_results)
            )

    def test_mixed_success_and_failure_data_elements_share_one_budget(self):
        structured = tlv(0xA2, tlv(0xA1, b"") * 2047)

        exact_results = tlv(0x80, b"\x00") * 2048 + structured
        decoded = ORACLE.parse_information_report(
            report(tlv(0xA1, tlv(0x80, b"list")), exact_results)
        )
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(len(decoded.results), 2049)

        overflowing_results = tlv(0x80, b"\x00") * 2049 + structured
        with self.assertRaisesRegex(ORACLE.OracleError, "Data elements exceed"):
            ORACLE.parse_information_report(
                report(tlv(0xA1, tlv(0x80, b"list")), overflowing_results)
            )

    def test_classic_pcap_analysis_writes_privacy_local_records_and_summary(self):
        first = bytes.fromhex("a311a00fa1058003766172a006800103850101")
        second = bytes.fromhex("a005020101a300")
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            capture = root / "mms.pcap"
            write_pcap(capture, (first, second))
            artifacts = [
                root / name
                for name in (
                    "records.tsv",
                    "summary.tsv",
                    "reports.bin",
                    "classifications.tsv",
                )
            ]
            counters = ORACLE.analyze(
                capture, artifacts[0], artifacts[1], artifacts[2],
                None, artifacts[3],
            )
            self.assertEqual(counters.packets, 2)
            self.assertEqual(counters.reports, 1)
            self.assertEqual(counters.results, 2)
            self.assertEqual((root / "reports.bin").read_bytes(), first)
            self.assertIn("information_report.reports\t1", (root / "summary.tsv").read_text())
            self.assertIn(
                "tase2_profile.type_discovery_records\t0",
                (root / "summary.tsv").read_text(),
            )
            for artifact in artifacts:
                self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)

    def test_analysis_does_not_clobber_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            capture = root / "mms.pcap"
            output = root / "records.tsv"
            write_pcap(capture, (self.POINT1_REPORT,))
            output.write_bytes(b"retain me")

            with self.assertRaises(FileExistsError):
                ORACLE.analyze(capture, output, root / "summary.tsv", None)

            self.assertEqual(output.read_bytes(), b"retain me")
            self.assertFalse((root / "summary.tsv").exists())

    def test_existing_later_output_prevents_all_output_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            capture = root / "mms.pcap"
            records = root / "records.tsv"
            summary = root / "summary.tsv"
            write_pcap(capture, (self.POINT1_REPORT,))
            summary.write_bytes(b"retain me")

            with self.assertRaises(FileExistsError):
                ORACLE.analyze(capture, records, summary, None)

            self.assertFalse(records.exists())
            self.assertEqual(summary.read_bytes(), b"retain me")

    def test_late_failure_publishes_no_partial_final_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            capture = root / "mms.pcap"
            records = root / "records.tsv"
            summary = root / "summary.tsv"
            reports = root / "reports.bin"
            write_pcap(capture, (self.POINT1_REPORT,))

            # The report header/result rows fit; the later summary row exceeds
            # this budget and must abort the entire publication.
            with mock.patch.object(ORACLE, "MAX_OUTPUT_ROWS", 2):
                with self.assertRaisesRegex(ORACLE.OracleError, "output-row"):
                    ORACLE.analyze(capture, records, summary, reports)

            for artifact in (records, summary, reports):
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
            capture = root / "mms.pcap"
            write_pcap(capture, (self.POINT1_REPORT,))
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

    def test_analysis_rejects_auxiliary_input_output_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            capture = root / "mms.pcap"
            metadata = root / "metadata.tsv"
            write_pcap(capture, (self.POINT1_REPORT,))
            metadata.write_text(
                "packet_index\tflow_id\tdirection\tcapture_packet\n"
                "1\t1\t1\t1\n",
                encoding="ascii",
            )
            original = metadata.read_bytes()

            with self.assertRaisesRegex(ORACLE.OracleError, "path collision"):
                ORACLE.analyze(
                    capture, metadata, root / "summary.tsv", None, metadata
                )
            self.assertEqual(metadata.read_bytes(), original)

    def test_pcap_header_snap_truncation_and_budgets_are_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            bad_version = root / "version.pcap"
            write_pcap(bad_version, version=(2, 3))
            with self.assertRaisesRegex(ORACLE.OracleError, "format version"):
                list(ORACLE.pcap_packets(bad_version))

            truncated = root / "truncated.pcap"
            write_pcap(truncated, (self.POINT1_REPORT,), original_extra=1)
            with self.assertRaisesRegex(ORACLE.OracleError, "snap-truncated"):
                list(ORACLE.pcap_packets(truncated))

            capture = root / "bounded.pcap"
            write_pcap(capture, (self.POINT1_REPORT, self.POINT1_REPORT))
            with mock.patch.object(ORACLE, "MAX_CAPTURE_PACKETS", 1):
                with self.assertRaisesRegex(ORACLE.OracleError, "packet count"):
                    list(ORACLE.pcap_packets(capture))
            with mock.patch.object(
                ORACLE, "MAX_CAPTURE_BYTES", len(self.POINT1_REPORT)
            ):
                with self.assertRaisesRegex(ORACLE.OracleError, "captured bytes"):
                    list(ORACLE.pcap_packets(capture))

    def test_sidecar_row_and_byte_budgets_are_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            metadata = root / "metadata.tsv"
            metadata.write_text(
                "packet_index\tflow_id\tdirection\tcapture_packet\n"
                "1\t1\t0\t1\n"
                "2\t1\t1\t2\n",
                encoding="ascii",
            )
            with mock.patch.object(ORACLE, "MAX_METADATA_ROWS", 1):
                with self.assertRaisesRegex(ORACLE.OracleError, "metadata.*row"):
                    ORACLE.packet_metadata(metadata)
            with mock.patch.object(
                ORACLE, "MAX_SIDECAR_BYTES", metadata.stat().st_size - 1
            ):
                with self.assertRaisesRegex(ORACLE.OracleError, "sidecar-byte"):
                    ORACLE.packet_metadata(metadata)

            mappings = root / "types.tsv"
            mappings.write_text(
                "flow_id\tserver_direction\tscope\tdomain\tobject_name\t"
                "named_type\n"
                "1\t1\t0\t\tPoint1\tData_RealQ\n"
                "1\t1\t0\t\tPoint2\tData_RealQ\n",
                encoding="ascii",
            )
            with mock.patch.object(ORACLE, "MAX_TYPE_MAPPINGS", 1):
                with self.assertRaisesRegex(ORACLE.OracleError, "mapping.*row"):
                    ORACLE.configured_type_mappings(mappings)
            with mock.patch.object(
                ORACLE, "MAX_SIDECAR_BYTES", mappings.stat().st_size - 1
            ):
                with self.assertRaisesRegex(ORACLE.OracleError, "sidecar-byte"):
                    ORACLE.configured_type_mappings(mappings)

    def test_corpus_wide_result_and_data_node_budgets_are_enforced(self):
        for limit_name, message in (
            ("MAX_TOTAL_RESULTS", "results exceed"),
            ("MAX_TOTAL_DATA_NODES", "Data nodes exceed"),
        ):
            with self.subTest(limit=limit_name), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                capture = root / "mms.pcap"
                write_pcap(capture, (self.POINT1_REPORT, self.POINT2_REPORT))
                with mock.patch.object(ORACLE, limit_name, 1):
                    with self.assertRaisesRegex(ORACLE.OracleError, message):
                        ORACLE.analyze(
                            capture,
                            root / "records.tsv",
                            root / "summary.tsv",
                            None,
                        )

    def test_classification_and_output_budgets_are_enforced(self):
        with mock.patch.object(ORACLE, "MAX_CLASSIFICATIONS", 0):
            with self.assertRaisesRegex(ORACLE.OracleError, "classifications"):
                self.correlated_analysis(
                    (self.GVA_REQUEST, self.GVA_RESPONSE, self.POINT1_REPORT),
                    ((1, 0), (1, 1), (1, 1)),
                )

        for limit_name, message in (
            ("MAX_OUTPUT_ROWS", "output-row"),
            ("MAX_OUTPUT_BYTES", "output-byte"),
        ):
            with self.subTest(limit=limit_name), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                capture = root / "mms.pcap"
                write_pcap(capture, (self.POINT1_REPORT,))
                with mock.patch.object(ORACLE, limit_name, 0):
                    with self.assertRaisesRegex(ORACLE.OracleError, message):
                        ORACLE.analyze(
                            capture,
                            root / "records.tsv",
                            root / "summary.tsv",
                            root / "reports.bin",
                        )

    def test_pending_correlation_budget_is_enforced(self):
        second_request = bytearray(self.GVA_REQUEST)
        second_request[4] = 2
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            capture = root / "mms.pcap"
            metadata = root / "metadata.tsv"
            write_pcap(capture, (self.GVA_REQUEST, bytes(second_request)))
            metadata.write_text(
                "packet_index\tflow_id\tdirection\tcapture_packet\n"
                "1\t1\t0\t1\n"
                "2\t1\t0\t2\n",
                encoding="ascii",
            )
            with mock.patch.object(ORACLE, "MAX_PENDING_CORRELATIONS", 1):
                with self.assertRaisesRegex(ORACLE.OracleError, "correlation"):
                    ORACLE.analyze(
                        capture,
                        root / "records.tsv",
                        root / "summary.tsv",
                        None,
                        metadata,
                    )


if __name__ == "__main__":
    unittest.main()
