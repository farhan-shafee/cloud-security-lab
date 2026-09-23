"""Strict normalization of a documented synthetic CloudTrail subset.

This is not a general CloudTrail/GuardDuty importer. Event success means no
errorCode; console success additionally requires its explicit Success value.
Missing MFA evidence is unknown, never an inferred absence of MFA.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .errors import FixtureError


@dataclass(frozen=True)
class Ingress:
    protocol: str
    from_port: int | None
    to_port: int | None
    cidrs: tuple[str, ...]


@dataclass(frozen=True)
class CloudEvent:
    event_id: str
    timestamp: datetime
    event_source: str
    event_name: str
    event_type: str
    region: str
    account_id: str
    principal: str
    identity_type: str
    source_ip: str
    request: dict[str, Any]
    response: dict[str, Any]
    additional: dict[str, Any]
    error_code: str | None
    ingress: tuple[Ingress, ...]

    @property
    def successful(self) -> bool:
        return self.error_code is None and (
            self.event_name != "ConsoleLogin" or self.response.get("ConsoleLogin") == "Success"
        )


@dataclass(frozen=True)
class EventBatch:
    fixture_id: str
    source_sha256: str
    events: tuple[CloudEvent, ...]


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FixtureError(f"{label} must be an object")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FixtureError(f"{label} must be a nonempty string")
    if any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value):
        raise FixtureError(f"{label} must not contain control characters")
    return value


def _account(value: Any, label: str) -> str:
    result = _text(value, label)
    if re.fullmatch(r"\d{12}", result) is None:
        raise FixtureError(f"{label} must contain exactly 12 decimal digits")
    return result


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FixtureError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _constant(value: str) -> Any:
    raise FixtureError(f"nonstandard JSON numeric constant: {value}")


def _timestamp(value: Any) -> datetime:
    text = _text(value, "eventTime")
    if not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
        r"(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])",
        text,
    ):
        raise FixtureError("eventTime must be an ISO-8601 timestamp with timezone")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FixtureError("eventTime must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise FixtureError("eventTime must include a timezone offset")
    try:
        return parsed.astimezone(UTC)
    except OverflowError as exc:
        raise FixtureError("eventTime is outside the supported UTC range") from exc


def _items(value: Any, label: str) -> list[Any]:
    obj = _object(value, label)
    items = obj.get("items")
    if not isinstance(items, list):
        raise FixtureError(f"{label}.items must be an array")
    return items


def _ingress(request: dict[str, Any]) -> tuple[Ingress, ...]:
    _text(request.get("groupId"), "requestParameters.groupId")
    result = []
    for value in _items(request.get("ipPermissions"), "requestParameters.ipPermissions"):
        permission = _object(value, "ipPermissions item")
        protocol = _text(permission.get("ipProtocol"), "ipProtocol")
        if protocol not in {"tcp", "6", "udp", "17", "icmp", "1", "icmpv6", "58", "-1"}:
            raise FixtureError(f"unsupported ipProtocol: {protocol}")
        start, end = permission.get("fromPort"), permission.get("toPort")
        if protocol != "-1":
            minimum, maximum = (
                (-1, 255) if protocol in {"icmp", "1", "icmpv6", "58"} else (0, 65535)
            )
            if any(
                type(port) is not int or not minimum <= port <= maximum for port in (start, end)
            ):
                raise FixtureError("fromPort/toPort must be valid integer ports or ICMP type/code")
            if (
                protocol in {"tcp", "6", "udp", "17"}
                and isinstance(start, int)
                and isinstance(end, int)
                and start > end
            ):
                raise FixtureError("fromPort must not exceed toPort")
        elif start is not None or end is not None:
            if any(type(port) is not int for port in (start, end)):
                raise FixtureError("all-protocol port fields must both be integers or omitted")
        cidrs = []
        if not any(key in permission for key in ("ipRanges", "ipv6Ranges")):
            raise FixtureError("supported ingress requires ipRanges or ipv6Ranges")
        for key, field, version in (("ipRanges", "cidrIp", 4), ("ipv6Ranges", "cidrIpv6", 6)):
            if key not in permission:
                continue
            for item in _items(permission[key], key):
                cidr = _text(_object(item, key).get(field), field)
                try:
                    network = ipaddress.ip_network(cidr, strict=True)
                except ValueError as exc:
                    raise FixtureError(f"invalid {field}: {cidr}") from exc
                if network.version != version:
                    raise FixtureError(f"{field} has the wrong IP version")
                cidrs.append(str(network))
        result.append(Ingress(protocol, start, end, tuple(sorted(cidrs))))
    return tuple(result)


def _event(value: Any) -> CloudEvent:
    record = _object(value, "event")
    identity = _object(record.get("userIdentity"), "userIdentity")
    identity_type = _text(identity.get("type"), "userIdentity.type")
    if identity_type not in {"Root", "IAMUser", "AssumedRole", "FederatedUser"}:
        raise FixtureError(f"unsupported userIdentity.type: {identity_type}")
    actor_account = _account(identity.get("accountId"), "userIdentity.accountId")
    principal = _text(identity.get("arn"), "userIdentity.arn")
    arn_suffix = {
        "Root": r"iam::ACCOUNT:root",
        "IAMUser": r"iam::ACCOUNT:user/[^\s]+",
        "AssumedRole": r"sts::ACCOUNT:assumed-role/[^/\s]+/[^/\s]+",
        "FederatedUser": r"sts::ACCOUNT:federated-user/[^\s]+",
    }[identity_type].replace("ACCOUNT", actor_account)
    if re.fullmatch("arn:aws:" + arn_suffix, principal) is None:
        raise FixtureError("userIdentity.arn must match its accountId and identity type")
    event_type = _text(record.get("eventType"), "eventType")
    if event_type not in {"AwsApiCall", "AwsConsoleSignIn"}:
        raise FixtureError(f"unsupported eventType: {event_type}")
    source_ip = _text(record.get("sourceIPAddress"), "sourceIPAddress")
    try:
        ipaddress.ip_address(source_ip)
    except ValueError as exc:
        raise FixtureError("sourceIPAddress must be an IPv4/IPv6 address") from exc
    nested = {}
    for key in ("requestParameters", "responseElements", "additionalEventData"):
        value = record.get(key)
        nested[key] = {} if value is None else _object(value, key)
    request, response, additional = (nested[key] for key in nested)
    error_code = record.get("errorCode")
    if "errorCode" in record:
        error_code = _text(error_code, "errorCode")
    event_name = _text(record.get("eventName"), "eventName")
    event_source = _text(record.get("eventSource"), "eventSource")
    if event_name == "ConsoleLogin":
        if response.get("ConsoleLogin") not in ("Success", "Failure"):
            raise FixtureError("ConsoleLogin response must explicitly be Success or Failure")
        if "MFAUsed" in additional and additional["MFAUsed"] not in ("Yes", "No"):
            raise FixtureError("MFAUsed must be Yes or No when present")
    if event_source == "iam.amazonaws.com":
        if event_name in {"CreatePolicyVersion", "SetDefaultPolicyVersion"}:
            _text(request.get("policyArn"), "requestParameters.policyArn")
        if event_name == "CreateAccessKey" and "userName" in request:
            _text(request["userName"], "requestParameters.userName")
    if event_source == "cloudtrail.amazonaws.com" and event_name in {"StopLogging", "DeleteTrail"}:
        _text(request.get("name"), "requestParameters.name")
    ingress: tuple[Ingress, ...] = ()
    if event_source == "ec2.amazonaws.com" and event_name == "AuthorizeSecurityGroupIngress":
        ingress = _ingress(request)
    return CloudEvent(
        event_id=_text(record.get("eventID"), "eventID"),
        timestamp=_timestamp(record.get("eventTime")),
        event_source=event_source,
        event_name=event_name,
        event_type=event_type,
        region=_text(record.get("awsRegion"), "awsRegion"),
        account_id=_account(record.get("recipientAccountId"), "recipientAccountId"),
        principal=principal,
        identity_type=identity_type,
        source_ip=source_ip,
        request=request,
        response=response,
        additional=additional,
        error_code=error_code,
        ingress=ingress,
    )


def load_events(path: Path) -> EventBatch:
    """Load, validate and sort one versioned synthetic event envelope."""
    try:
        raw = path.read_bytes()
        envelope = _object(
            json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant),
            "event envelope",
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FixtureError(f"cannot load event fixture {path}: {exc}") from exc
    if type(envelope.get("schema_version")) is not int or envelope["schema_version"] != 1:
        raise FixtureError("unsupported event schema_version; expected integer 1")
    if envelope.get("synthetic") is not True:
        raise FixtureError("event envelope must explicitly declare synthetic: true")
    if set(envelope) != {"schema_version", "synthetic", "fixture_id", "events"}:
        raise FixtureError(
            "event envelope requires only schema_version, synthetic, fixture_id, events"
        )
    values = envelope.get("events")
    if not isinstance(values, list):
        raise FixtureError("events must be an array")
    events = tuple(
        sorted((_event(value) for value in values), key=lambda e: (e.timestamp, e.event_id))
    )
    if len({event.event_id for event in events}) != len(events):
        raise FixtureError("duplicate eventID in batch")
    return EventBatch(
        _text(envelope.get("fixture_id"), "fixture_id"), hashlib.sha256(raw).hexdigest(), events
    )
