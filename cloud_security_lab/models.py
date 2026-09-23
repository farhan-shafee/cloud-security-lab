"""Typed, immutable records for the deliberately bounded offline schema."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import ClassVar


def timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class Statement:
    sid: str
    effect: str
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    principals: tuple[tuple[str, str], ...]
    conditions: tuple[tuple[str, str, tuple[str, ...]], ...]


@dataclass(frozen=True)
class PolicyDocument:
    statements: tuple[Statement, ...]


@dataclass(frozen=True)
class PolicyResource:
    id: str
    document: PolicyDocument
    resource_type: ClassVar[str] = "iam_policy"


@dataclass(frozen=True)
class RoleResource:
    id: str
    trust_policy: PolicyDocument
    resource_type: ClassVar[str] = "iam_role"


@dataclass(frozen=True)
class PublicAccessBlock:
    block_public_acls: bool
    ignore_public_acls: bool
    block_public_policy: bool
    restrict_public_buckets: bool


@dataclass(frozen=True)
class Encryption:
    algorithm: str
    key_id: str | None
    key_manager: str | None


@dataclass(frozen=True)
class BucketResource:
    id: str
    region: str
    sensitive: bool
    block_public_access: PublicAccessBlock
    encryption: Encryption
    versioning: bool
    resource_type: ClassVar[str] = "s3_bucket"


@dataclass(frozen=True)
class IngressRule:
    protocol: str
    from_port: int | None
    to_port: int | None
    cidr: str


@dataclass(frozen=True)
class SecurityGroupResource:
    id: str
    region: str
    ingress: tuple[IngressRule, ...]
    resource_type: ClassVar[str] = "security_group"


@dataclass(frozen=True)
class TrailResource:
    id: str
    home_region: str
    is_logging: bool
    is_multi_region: bool
    covered_regions: tuple[str, ...]
    log_bucket: str
    resource_type: ClassVar[str] = "cloudtrail"


Resource = PolicyResource | RoleResource | BucketResource | SecurityGroupResource | TrailResource


@dataclass(frozen=True)
class ResourceInventory:
    policies: tuple[PolicyResource, ...]
    roles: tuple[RoleResource, ...]
    buckets: tuple[BucketResource, ...]
    security_groups: tuple[SecurityGroupResource, ...]
    trails: tuple[TrailResource, ...]

    def all_resources(self) -> tuple[Resource, ...]:
        return (*self.policies, *self.roles, *self.buckets, *self.security_groups, *self.trails)


@dataclass(frozen=True)
class Snapshot:
    schema_version: int
    synthetic: bool
    snapshot_id: str
    account_id: str
    captured_at: datetime
    required_regions: tuple[str, ...]
    resources: ResourceInventory
    source_sha256: str

    @property
    def resource_keys(self) -> tuple[tuple[str, str], ...]:
        return tuple(sorted((r.resource_type, r.id) for r in self.resources.all_resources()))


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    severity: str
    resource_type: str
    remediation: str
    references: tuple[str, ...]
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class Finding:
    finding_id: str
    control_id: str
    title: str
    severity: str
    resource_id: str
    resource_type: str
    status: str
    reason: str
    evidence: tuple[dict[str, object], ...]
    remediation: str
    references: tuple[str, ...]
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["evidence"] = list(self.evidence)
        result["references"] = list(self.references)
        result["limitations"] = list(self.limitations)
        return result


@dataclass(frozen=True)
class Evaluation:
    control_id: str
    resource_id: str
    resource_type: str
    status: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class Assessment:
    snapshot_id: str
    account_id: str
    captured_at: datetime
    source_sha256: str
    controls_executed: tuple[str, ...]
    findings: tuple[Finding, ...]
    evaluations: tuple[Evaluation, ...]
    inventory: tuple[tuple[str, str], ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "synthetic": True,
            "snapshot_id": self.snapshot_id,
            "account_id": self.account_id,
            "captured_at": timestamp(self.captured_at),
            "source_sha256": self.source_sha256,
            "controls_executed": list(self.controls_executed),
            "findings": [finding.to_dict() for finding in self.findings],
            "evaluations": [evaluation.to_dict() for evaluation in self.evaluations],
            "inventory": [
                {"resource_type": kind, "resource_id": identifier}
                for kind, identifier in self.inventory
            ],
        }
