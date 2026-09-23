"""Strict loader for the versioned, explicitly synthetic snapshot schema.

This schema is an authored observation format, not an AWS API response parser.
Unknown fields and unsupported constructs fail closed before any assessment.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from cloud_security_lab.errors import FixtureError
from cloud_security_lab.iam import parse_policy
from cloud_security_lab.models import (
    BucketResource,
    Encryption,
    IngressRule,
    PolicyResource,
    PublicAccessBlock,
    ResourceInventory,
    RoleResource,
    SecurityGroupResource,
    Snapshot,
    TrailResource,
)

SUPPORTED_REGIONS = frozenset(
    {
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
        "ca-central-1",
        "eu-west-1",
        "eu-west-2",
        "eu-central-1",
        "ap-south-1",
        "ap-northeast-1",
        "ap-southeast-1",
        "ap-southeast-2",
    }
)


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise FixtureError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _constant(value: str) -> object:
    raise FixtureError(f"non-finite JSON number is unsupported: {value}")


def read_json(path: Path) -> tuple[object, str]:
    try:
        source = path.read_bytes()
        value: object = json.loads(
            source.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FixtureError(f"cannot load {path}: {exc}") from exc
    return value, hashlib.sha256(source).hexdigest()


def _object(value: object, fields: set[str], context: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise FixtureError(f"{context} must have exactly these fields: {', '.join(sorted(fields))}")
    return cast(dict[str, object], value)


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise FixtureError(f"{context} must be a nonempty string without surrounding whitespace")
    return value


def _boolean(value: object, context: str) -> bool:
    if type(value) is not bool:
        raise FixtureError(f"{context} must be a boolean")
    return value


def _array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise FixtureError(f"{context} must be an array")
    return value


def _identifier(value: object) -> str:
    identifier = _text(value, "resource id")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}", identifier):
        raise FixtureError("invalid resource identifier")
    return identifier


def _region(value: object) -> str:
    region = _text(value, "region")
    if region not in SUPPORTED_REGIONS:
        raise FixtureError(f"unsupported fixture region: {region}")
    return region


def _regions(value: object, context: str) -> tuple[str, ...]:
    regions = tuple(_region(item) for item in _array(value, context))
    if not regions or len(regions) != len(set(regions)):
        raise FixtureError(f"{context} must contain unique regions and cannot be empty")
    return tuple(sorted(regions))


def _bucket(value: object) -> BucketResource:
    raw = _object(
        value,
        {"id", "region", "sensitive", "block_public_access", "encryption", "versioning"},
        "bucket",
    )
    region = _region(raw["region"])
    bpa_fields = {
        "block_public_acls",
        "ignore_public_acls",
        "block_public_policy",
        "restrict_public_buckets",
    }
    bpa = _object(raw["block_public_access"], bpa_fields, "block_public_access")
    block = PublicAccessBlock(**{key: _boolean(value, key) for key, value in bpa.items()})
    encryption = _object(raw["encryption"], {"algorithm", "key_id", "key_manager"}, "encryption")
    algorithm = _text(encryption["algorithm"], "algorithm")
    key_id, manager = encryption["key_id"], encryption["key_manager"]
    if algorithm == "AES256":
        if key_id is not None or manager is not None:
            raise FixtureError("AES256 encryption must have null key_id and key_manager")
    elif algorithm == "aws:kms":
        key_id = _text(key_id, "KMS key_id")
        if manager not in ("AWS", "CUSTOMER"):
            raise FixtureError("KMS key_manager must be AWS or CUSTOMER")
        if manager == "CUSTOMER" and not re.fullmatch(
            rf"arn:aws:kms:{re.escape(region)}:[0-9]{{12}}:key/[A-Za-z0-9-]+", key_id
        ):
            raise FixtureError("customer KMS key_id must be a key ARN in the bucket region")
        if (
            manager == "AWS"
            and key_id != "alias/aws/s3"
            and not re.fullmatch(
                rf"arn:aws:kms:{re.escape(region)}:[0-9]{{12}}:key/[A-Za-z0-9-]+", key_id
            )
        ):
            raise FixtureError(
                "AWS KMS key_id must be alias/aws/s3 or a key ARN in the bucket region"
            )
    else:
        raise FixtureError("only AES256 and aws:kms encryption are supported")
    return BucketResource(
        _identifier(raw["id"]),
        region,
        _boolean(raw["sensitive"], "sensitive"),
        block,
        Encryption(algorithm, key_id, manager),
        _boolean(raw["versioning"], "versioning"),
    )


def _port(value: object, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise FixtureError(f"port must be an integer in {minimum}..{maximum}")
    return value


def _ingress(value: object) -> IngressRule:
    raw = _object(value, {"protocol", "from_port", "to_port", "cidr"}, "ingress")
    protocol = _text(raw["protocol"], "protocol")
    if protocol not in {"tcp", "udp", "icmp", "icmpv6", "-1"}:
        raise FixtureError("unsupported ingress protocol")
    from_port: int | None
    to_port: int | None
    if protocol == "-1":
        if raw["from_port"] is not None or raw["to_port"] is not None:
            raise FixtureError("all-protocol ingress requires null ports")
        from_port = to_port = None
    elif protocol in {"tcp", "udp"}:
        from_port, to_port = _port(raw["from_port"], 0, 65535), _port(raw["to_port"], 0, 65535)
        if from_port > to_port:
            raise FixtureError("from_port must not exceed to_port")
    else:
        from_port, to_port = _port(raw["from_port"], -1, 255), _port(raw["to_port"], -1, 255)
        if from_port == -1 and to_port != -1:
            raise FixtureError("all ICMP types require all codes")
    cidr = _text(raw["cidr"], "cidr")
    try:
        network = ipaddress.ip_network(cidr, strict=True)
    except ValueError as exc:
        raise FixtureError(f"invalid CIDR network: {cidr}") from exc
    if (
        "/" not in cidr
        or (protocol == "icmpv6" and network.version != 6)
        or (protocol == "icmp" and network.version != 4)
    ):
        raise FixtureError("CIDR must include a prefix and match the ICMP address family")
    return IngressRule(protocol, from_port, to_port, str(network))


def _security_group(value: object) -> SecurityGroupResource:
    raw = _object(value, {"id", "region", "ingress"}, "security_group")
    return SecurityGroupResource(
        _identifier(raw["id"]),
        _region(raw["region"]),
        tuple(_ingress(rule) for rule in _array(raw["ingress"], "ingress")),
    )


def _trail(value: object) -> TrailResource:
    raw = _object(
        value,
        {"id", "home_region", "is_logging", "is_multi_region", "covered_regions", "log_bucket"},
        "trail",
    )
    home = _region(raw["home_region"])
    covered = _regions(raw["covered_regions"], "covered_regions")
    multi = _boolean(raw["is_multi_region"], "is_multi_region")
    if home not in covered or (not multi and covered != (home,)):
        raise FixtureError(
            "trail coverage must include home_region; a single-region trail covers only its home"
        )
    return TrailResource(
        _identifier(raw["id"]),
        home,
        _boolean(raw["is_logging"], "is_logging"),
        multi,
        covered,
        _identifier(raw["log_bucket"]),
    )


def load_snapshot(path: Path) -> Snapshot:
    value, sha256 = read_json(path)
    raw = _object(
        value,
        {
            "schema_version",
            "synthetic",
            "snapshot_id",
            "account_id",
            "captured_at",
            "required_regions",
            "resources",
        },
        "snapshot",
    )
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise FixtureError("only snapshot schema_version 1 is supported")
    if raw["synthetic"] is not True:
        raise FixtureError("snapshots must be explicitly synthetic: true")
    account_id = _text(raw["account_id"], "account_id")
    if not re.fullmatch(r"[0-9]{12}", account_id):
        raise FixtureError("account_id must be a 12-digit synthetic identifier")
    captured = _text(raw["captured_at"], "captured_at")
    if not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
        r"(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])",
        captured,
    ):
        raise FixtureError("captured_at must be an ISO 8601 timestamp with timezone")
    try:
        captured_at = datetime.fromisoformat(captured.replace("Z", "+00:00")).astimezone(UTC)
    except (ValueError, OverflowError) as exc:
        raise FixtureError("captured_at is not a valid timestamp") from exc
    inventory = _object(
        raw["resources"], {"policies", "roles", "buckets", "security_groups", "trails"}, "resources"
    )
    policies = []
    for policy in _array(inventory["policies"], "policies"):
        item = _object(policy, {"id", "document"}, "policy resource")
        policies.append(PolicyResource(_identifier(item["id"]), parse_policy(item["document"])))
    roles = []
    for role in _array(inventory["roles"], "roles"):
        item = _object(role, {"id", "trust_policy"}, "role resource")
        roles.append(
            RoleResource(_identifier(item["id"]), parse_policy(item["trust_policy"], trust=True))
        )
    resources = ResourceInventory(
        tuple(policies),
        tuple(roles),
        tuple(_bucket(bucket) for bucket in _array(inventory["buckets"], "buckets")),
        tuple(
            _security_group(group)
            for group in _array(inventory["security_groups"], "security_groups")
        ),
        tuple(_trail(trail) for trail in _array(inventory["trails"], "trails")),
    )
    all_resources = resources.all_resources()
    if not all_resources:
        raise FixtureError("resource inventory cannot be entirely empty")
    identifiers = [resource.id for resource in all_resources]
    if len(identifiers) != len(set(identifiers)):
        raise FixtureError("duplicate resource identifiers in snapshot")
    bucket_ids = {bucket.id for bucket in resources.buckets}
    if any(trail.log_bucket not in bucket_ids for trail in resources.trails):
        raise FixtureError("trail log_bucket must reference an included bucket")
    return Snapshot(
        1,
        True,
        _identifier(raw["snapshot_id"]),
        account_id,
        captured_at,
        _regions(raw["required_regions"], "required_regions"),
        resources,
        sha256,
    )
