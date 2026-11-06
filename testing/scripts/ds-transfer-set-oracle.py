#!/usr/bin/env python3
"""Independent bounded MMS/TASE.2 DSTransferSet oracle."""

from __future__ import annotations

from typing import NamedTuple


class DecodeError(ValueError):
    pass


class TLV(NamedTuple):
    tag: int
    value: bytes


def read_tlv(data: bytes, offset: int = 0) -> tuple[TLV, int]:
    if offset + 2 > len(data):
        raise DecodeError("truncated TLV")
    tag = data[offset]
    first_length = data[offset + 1]
    offset += 2
    if first_length & 0x80:
        width = first_length & 0x7F
        if width == 0 or width > 2 or offset + width > len(data):
            raise DecodeError("unsupported or truncated length")
        length = int.from_bytes(data[offset : offset + width], "big")
        offset += width
    else:
        length = first_length
    end = offset + length
    if end > len(data):
        raise DecodeError("value exceeds enclosing buffer")
    return TLV(tag, data[offset:end]), end


def children(data: bytes) -> list[TLV]:
    result: list[TLV] = []
    offset = 0
    while offset < len(data):
        item, offset = read_tlv(data, offset)
        result.append(item)
    return result


def one_child(data: bytes, tag: int) -> TLV:
    item, end = read_tlv(data)
    if item.tag != tag or end != len(data):
        raise DecodeError(f"expected one tag 0x{tag:02x}")
    return item


def signed_integer(item: TLV, tag: int, maximum_width: int) -> int:
    if item.tag != tag or not 1 <= len(item.value) <= maximum_width:
        raise DecodeError(f"invalid integer tag/width for 0x{tag:02x}")
    return int.from_bytes(item.value, "big", signed=True)


def identifier(value: bytes) -> str:
    if not 1 <= len(value) <= 32:
        raise DecodeError("identifier width is outside 1..32")
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DecodeError("identifier is not ASCII") from exc
    if not (text[0].isalpha() or text[0] in "_$"):
        raise DecodeError("invalid identifier prefix")
    if any(not (char.isalnum() or char in "_$") for char in text[1:]):
        raise DecodeError("invalid identifier character")
    return text


def parse_dst_transfer_write(pdu: bytes) -> dict[str, object]:
    confirmed = one_child(pdu, 0xA0)
    request = children(confirmed.value)
    if len(request) != 2 or signed_integer(request[0], 0x02, 4) < 0:
        raise DecodeError("invalid confirmed-request envelope")
    if request[1].tag != 0xA5:
        raise DecodeError("request is not MMS Write")

    write = children(request[1].value)
    if len(write) != 2 or write[0].tag != 0xA0 or write[1].tag != 0xA0:
        raise DecodeError("Write must have one access list and one data list")
    variables = children(write[0].value)
    values = children(write[1].value)
    if len(variables) != 1 or len(values) != 1:
        raise DecodeError("DSTransferSet Write cardinality is not one")
    specification = one_child(variables[0].value, 0xA0)
    target = one_child(specification.value, 0xA1)
    target_parts = children(target.value)
    if len(target_parts) != 2 or [item.tag for item in target_parts] != [0x1A, 0x1A]:
        raise DecodeError("DSTransferSet target is not Domain-specific")
    target_domain = identifier(target_parts[0].value)
    target_name = identifier(target_parts[1].value)

    if values[0].tag != 0xA2:
        raise DecodeError("DSTransferSet value is not a structure")
    fields = children(values[0].value)
    expected = [0xA2, 0x85, 0x85, 0x85, 0x85, 0x85,
                0x84, 0x83, 0x83, 0x83, 0x83, 0x83, 0x85]
    if len(fields) != 13 or [field.tag for field in fields] != expected:
        raise DecodeError("DSTransferSet component signature mismatch")

    object_name = children(fields[0].value)
    if len(object_name) != 3 or [item.tag for item in object_name] != [0x86, 0x8A, 0x8A]:
        raise DecodeError("embedded DataSetName signature mismatch")
    scope = signed_integer(object_name[0], 0x86, 1)
    if scope not in (0, 1):
        raise DecodeError("embedded DataSetName scope is invalid")
    domain = identifier(object_name[1].value)
    data_set_name = identifier(object_name[2].value)

    timings = [signed_integer(field, 0x85, 4) for field in fields[1:6]]
    if any(value < 0 for value in timings):
        raise DecodeError("negative transfer timing")
    if len(fields[6].value) != 2 or fields[6].value[0] != 3 or fields[6].value[1] & 0x07:
        raise DecodeError("DSConditions representation is invalid")
    booleans = []
    for field in fields[7:12]:
        if len(field.value) != 1:
            raise DecodeError("Boolean width is not one")
        booleans.append(field.value[0] != 0)
    event_code = signed_integer(fields[12], 0x85, 2)

    flags = fields[6].value[1]
    return {
        "target": target_name,
        "target_domain": target_domain,
        "data_set_scope": scope,
        "data_set_domain": domain,
        "data_set_name": data_set_name,
        "start_time": timings[0],
        "interval": timings[1],
        "tle": timings[2],
        "buffer_time": timings[3],
        "integrity_check": timings[4],
        "condition_mask": flags >> 3,
        "block_data": booleans[0],
        "critical": booleans[1],
        "report_by_exception": booleans[2],
        "all_changes_reported": booleans[3],
        "enabled": booleans[4],
        "event_code_requested": event_code if flags & 0x08 else None,
        "conformance": "parameters_conformant",
        "conformance_reasons": "",
    }
