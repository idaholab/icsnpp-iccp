#!/usr/bin/env python3
"""Independent MMS EventNotification decoder used by tests.

This intentionally shares no BER or classification code with the Spicy/Zeek
implementation. It covers the supported TASE.2 Device action mapping.
"""

from dataclasses import dataclass


class DecodeError(ValueError):
    pass


@dataclass(frozen=True)
class TLV:
    tag: int
    constructed: bool
    value: bytes


@dataclass(frozen=True)
class ObjectName:
    scope: int
    domain: str
    name: str


@dataclass(frozen=True)
class EventNotification:
    enrollment: ObjectName
    condition: ObjectName
    severity: int
    current_state: int | None
    transition_kind: int
    transition_value: int | bytes | None
    notification_lost: bool
    action_result_present: bool


def _tlvs(data: bytes) -> list[TLV]:
    result = []
    offset = 0
    while offset < len(data):
        first = data[offset]
        offset += 1
        if first & 0x1F == 0x1F:
            raise DecodeError("high-tag form is outside oracle scope")
        if offset >= len(data):
            raise DecodeError("missing length")
        length = data[offset]
        offset += 1
        if length & 0x80:
            octets = length & 0x7F
            if octets == 0 or octets > 4 or offset + octets > len(data):
                raise DecodeError("invalid definite length")
            if data[offset] == 0:
                raise DecodeError("non-minimal length")
            length = int.from_bytes(data[offset:offset + octets], "big")
            offset += octets
            if length < 128:
                raise DecodeError("non-minimal long length")
        if offset + length > len(data):
            raise DecodeError("truncated value")
        if first >> 6 != 2:
            raise DecodeError("expected context-specific field")
        result.append(TLV(first & 0x1F, bool(first & 0x20),
                          data[offset:offset + length]))
        offset += length
    return result


def _integer(value: bytes) -> int:
    if not value:
        raise DecodeError("empty integer")
    if len(value) > 1 and ((value[0] == 0 and value[1] < 0x80) or
                           (value[0] == 0xFF and value[1] >= 0x80)):
        raise DecodeError("non-minimal integer")
    return int.from_bytes(value, "big", signed=True)


def _text(value: bytes) -> str:
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DecodeError("non-ASCII identifier") from exc
    if not text:
        raise DecodeError("empty identifier")
    return text


def _object_name(value: bytes) -> ObjectName:
    fields = _tlvs(value)
    if len(fields) != 1:
        raise DecodeError("ObjectName must contain one choice")
    field = fields[0]
    if field.tag in (0, 2) and not field.constructed:
        return ObjectName(field.tag, "", _text(field.value))
    if field.tag == 1 and field.constructed:
        parts = _tlvs(field.value)
        if (len(parts) != 2 or any(part.constructed for part in parts) or
                [part.tag for part in parts] != [0, 1]):
            raise DecodeError("invalid domain-specific ObjectName")
        return ObjectName(1, _text(parts[0].value), _text(parts[1].value))
    raise DecodeError("invalid ObjectName choice")


def decode(data: bytes) -> EventNotification:
    outer = _tlvs(data)
    if len(outer) != 1 or outer[0].tag != 3 or not outer[0].constructed:
        raise DecodeError("not an unconfirmed MMS PDU")
    service = _tlvs(outer[0].value)
    if len(service) != 1 or service[0].tag != 2 or not service[0].constructed:
        raise DecodeError("not EventNotification")
    fields = _tlvs(service[0].value)
    tags = [field.tag for field in fields]
    if tags != sorted(set(tags)) or any(tag not in (0, 1, 2, 3, 4, 6, 7, 8)
                                        for tag in tags):
        raise DecodeError("invalid field order")
    by_tag = {field.tag: field for field in fields}
    if not {0, 1, 2, 4}.issubset(by_tag):
        raise DecodeError("missing mandatory field")
    for tag, field in by_tag.items():
        if field.constructed != (tag in (0, 1, 4, 8)):
            raise DecodeError("invalid field form")
    severity = _integer(by_tag[2].value)
    if not 0 <= severity <= 127:
        raise DecodeError("severity out of range")
    state = _integer(by_tag[3].value) if 3 in by_tag else None
    if state is not None and not 0 <= state <= 2:
        raise DecodeError("state out of range")
    event_time = _tlvs(by_tag[4].value)
    if len(event_time) != 1 or event_time[0].constructed or event_time[0].tag > 2:
        raise DecodeError("invalid EventTime")
    time_field = event_time[0]
    if time_field.tag == 0:
        if len(time_field.value) not in (4, 6):
            raise DecodeError("invalid TimeOfDay")
        time_value: int | bytes | None = time_field.value
    elif time_field.tag == 1:
        time_value = _integer(time_field.value)
        if not 0 <= time_value <= 0xFFFFFFFF:
            raise DecodeError("time sequence out of range")
    else:
        if time_field.value:
            raise DecodeError("invalid undefined EventTime")
        time_value = None
    lost = False
    if 6 in by_tag:
        if len(by_tag[6].value) != 1:
            raise DecodeError("invalid boolean")
        lost = by_tag[6].value != b"\0"
    if 7 in by_tag and not 0 <= _integer(by_tag[7].value) <= 3:
        raise DecodeError("alarm acknowledgement rule out of range")
    return EventNotification(
        _object_name(by_tag[0].value), _object_name(by_tag[1].value),
        severity, state, time_field.tag, time_value, lost, 8 in by_tag)


def classify(event: EventNotification, tase2: bool = True) -> str:
    suffixes = {
        "_time": "device_timeout", "_reset": "device_local_reset",
        "_success": "device_success", "_fail": "device_failure",
    }
    base = "device_action"
    for suffix, classification in suffixes.items():
        if event.condition.name.endswith(suffix) and len(event.condition.name) > len(suffix):
            base = classification
            break
    exact = (tase2 and event.condition.scope == 0 and
             event.condition.domain == "" and
             ((event.enrollment.scope == 0 and event.enrollment.domain == "") or
              (event.enrollment.scope == 1 and event.enrollment.domain != "")) and
             event.enrollment.name != "" and base != "device_action" and
             event.severity == 0 and event.current_state == 2 and
             not event.notification_lost and not event.action_result_present)
    return base if exact else f"{base}_candidate"
