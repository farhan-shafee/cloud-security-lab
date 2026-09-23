"""Fourteen bounded configuration controls, evaluated only on supplied inventory."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import asdict

from cloud_security_lab.iam import inspect_policy
from cloud_security_lab.models import (
    Assessment,
    BucketResource,
    Control,
    Evaluation,
    Finding,
    PolicyResource,
    Resource,
    RoleResource,
    SecurityGroupResource,
    Snapshot,
    TrailResource,
)

IAM_REFERENCE = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html"
TRUST_REFERENCE = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html"
)
BPA_REFERENCE = (
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
)
KMS_REFERENCE = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html"
VERSIONING_REFERENCE = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"
NETWORK_REFERENCE = "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html"
TRAIL_REFERENCE = (
    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html"
)
IAM_LIMIT = (
    "Static Allow lint only; conditions, Deny, SCPs, boundaries, sessions and "
    "resource policies are not evaluated as effective permissions."
)
INVENTORY_LIMIT = (
    "Synthetic supplied inventory only; completeness and live AWS state are not verified."
)

CONTROLS = (
    Control(
        "IAM-001",
        "Wildcard action requires least-privilege review",
        "MEDIUM",
        "iam_policy",
        "Replace action wildcards with the operations the workload demonstrably needs.",
        (IAM_REFERENCE,),
        (
            IAM_LIMIT,
            "Both '*' and '?' action patterns are flagged; a read-only pattern is not "
            "itself privilege escalation.",
        ),
    ),
    Control(
        "IAM-002",
        "Universal resource requires scope review",
        "MEDIUM",
        "iam_policy",
        "Scope supported actions to named resources; document actions for which AWS "
        "requires Resource '*'.",
        (IAM_REFERENCE,),
        (
            IAM_LIMIT,
            "Some AWS actions require Resource '*'; this rule does not use a service "
            "authorization database.",
        ),
    ),
    Control(
        "IAM-003",
        "Selected IAM mutation capability requires review",
        "HIGH",
        "iam_policy",
        "Remove unneeded policy, trust and credential mutation permissions; scope and "
        "independently review necessary administration.",
        (IAM_REFERENCE,),
        (
            IAM_LIMIT,
            "The selected action list is bounded; matching a mutation capability does not "
            "prove an exploitable escalation path.",
        ),
    ),
    Control(
        "IAM-004",
        "PassRole includes a wildcard resource",
        "HIGH",
        "iam_policy",
        "Restrict PassRole to explicit role ARNs and review allowed destination services "
        "and downstream permissions.",
        (IAM_REFERENCE,),
        (IAM_LIMIT, "PassRole alone is not sufficient to execute a role's permissions."),
    ),
    Control(
        "IAM-005",
        "Wildcard role trust principal",
        "HIGH",
        "iam_role",
        "Use explicit trusted principals and review trust conditions for the intended callers.",
        (TRUST_REFERENCE,),
        (
            IAM_LIMIT,
            "A wildcard principal is flagged even when a condition exists; conditions may "
            "materially restrict trust.",
        ),
    ),
    Control(
        "IAM-006",
        "External account or root trust lacks a condition",
        "MEDIUM",
        "iam_role",
        "Review delegated external-account trust and add appropriate controls such as a "
        "vendor ExternalId when applicable.",
        (TRUST_REFERENCE,),
        (
            IAM_LIMIT,
            "Only external 12-digit account IDs and account-root ARNs are checked; "
            "condition presence passes this lint but does not establish trust safety.",
        ),
    ),
    Control(
        "S3-001",
        "Bucket public-access guardrail gap",
        "MEDIUM",
        "s3_bucket",
        "Enable all four bucket Block Public Access settings after confirming intended "
        "application access.",
        (BPA_REFERENCE,),
        (
            INVENTORY_LIMIT,
            "Disabled bucket settings do not prove public access; policies, ACLs and "
            "account/organization guardrails are not modeled.",
        ),
    ),
    Control(
        "S3-002",
        "Sensitive bucket lacks required customer-managed SSE-KMS configuration",
        "MEDIUM",
        "s3_bucket",
        "Configure default SSE-KMS using a customer-managed key for this lab's "
        "sensitive-data baseline.",
        (KMS_REFERENCE,),
        (
            INVENTORY_LIMIT,
            "AES256 is encrypted; this checks a lab KMS requirement, not absence of "
            "encryption. Existing objects and key-policy usability are not evaluated.",
        ),
    ),
    Control(
        "S3-003",
        "Bucket versioning is disabled",
        "LOW",
        "s3_bucket",
        "Enable bucket versioning and choose lifecycle retention suitable for recovery "
        "requirements.",
        (VERSIONING_REFERENCE,),
        (
            INVENTORY_LIMIT,
            "Versioning is a recovery setting, not immutable retention or proof that "
            "backups can be restored.",
        ),
    ),
    Control(
        "NET-001",
        "World-address ingress includes administrative TCP ports",
        "HIGH",
        "security_group",
        "Restrict TCP 22 and 3389 to approved source networks or use an authenticated "
        "management path.",
        (NETWORK_REFERENCE,),
        (
            INVENTORY_LIMIT,
            "Checks only /0 IPv4 and IPv6 CIDRs on TCP or all protocols; routing, NACLs, "
            "attached workloads and end-to-end reachability are not modeled.",
        ),
    ),
    Control(
        "NET-002",
        "World-address ingress permits all protocols",
        "HIGH",
        "security_group",
        "Replace world-address all-protocol ingress with the specific source networks, "
        "protocols and ports needed.",
        (NETWORK_REFERENCE,),
        (
            INVENTORY_LIMIT,
            "Checks only explicit /0 CIDRs, not equivalent unions of smaller networks or "
            "security-group references.",
        ),
    ),
    Control(
        "LOG-001",
        "Configured trail logging is disabled",
        "HIGH",
        "cloudtrail",
        "Enable logging for the configured trail and independently confirm log delivery.",
        (TRAIL_REFERENCE,),
        (
            INVENTORY_LIMIT,
            "is_logging is an authored configuration observation; this does not test "
            "actual delivery or management/data event selectors.",
        ),
    ),
    Control(
        "LOG-002",
        "Configured trail omits required regions",
        "MEDIUM",
        "cloudtrail",
        "Configure this trail to cover every region declared in required_regions.",
        (TRAIL_REFERENCE,),
        (
            INVENTORY_LIMIT,
            "Each supplied trail is checked independently against required_regions; other "
            "trails and organization coverage are not inferred.",
        ),
    ),
    Control(
        "LOG-003",
        "Trail destination lacks required storage safeguards",
        "MEDIUM",
        "cloudtrail",
        "Enable all bucket public-access blocks, customer-managed default SSE-KMS and "
        "versioning on the log destination.",
        (TRAIL_REFERENCE, BPA_REFERENCE, KMS_REFERENCE),
        (
            INVENTORY_LIMIT,
            "Only included destination bucket settings are inspected; bucket/key "
            "permissions, delivery, digest validation and Object Lock are outside scope.",
        ),
    ),
)


def _customer_kms(bucket: BucketResource) -> bool:
    return bucket.encryption.algorithm == "aws:kms" and bucket.encryption.key_manager == "CUSTOMER"


def _guardrail_gaps(bucket: BucketResource) -> list[str]:
    return sorted(
        name for name, enabled in asdict(bucket.block_public_access).items() if not enabled
    )


def _issues(resource: Resource, snapshot: Snapshot) -> dict[str, tuple[dict[str, object], ...]]:
    if isinstance(resource, PolicyResource):
        return inspect_policy(resource.document, account_id=snapshot.account_id)
    if isinstance(resource, RoleResource):
        return inspect_policy(resource.trust_policy, account_id=snapshot.account_id, trust=True)
    issues: dict[str, tuple[dict[str, object], ...]] = {}
    if isinstance(resource, BucketResource):
        gaps = _guardrail_gaps(resource)
        if gaps:
            issues["S3-001"] = ({"disabled_bucket_settings": gaps},)
        if resource.sensitive and not _customer_kms(resource):
            issues["S3-002"] = ({"sensitive": True, "encryption": asdict(resource.encryption)},)
        if not resource.versioning:
            issues["S3-003"] = ({"versioning": False},)
    elif isinstance(resource, SecurityGroupResource):
        admin_rules: list[dict[str, object]] = []
        all_rules: list[dict[str, object]] = []
        for rule in resource.ingress:
            if ipaddress.ip_network(rule.cidr).prefixlen != 0:
                continue
            if rule.protocol == "-1":
                all_rules.append(asdict(rule))
                admin_rules.append(asdict(rule))
            elif rule.protocol == "tcp" and rule.from_port is not None and rule.to_port is not None:
                if any(rule.from_port <= port <= rule.to_port for port in (22, 3389)):
                    admin_rules.append(asdict(rule))
        if admin_rules:
            issues["NET-001"] = tuple(admin_rules)
        if all_rules:
            issues["NET-002"] = tuple(all_rules)
    elif isinstance(resource, TrailResource):
        if not resource.is_logging:
            issues["LOG-001"] = ({"is_logging": False},)
        missing = sorted(set(snapshot.required_regions) - set(resource.covered_regions))
        if missing:
            issues["LOG-002"] = (
                {
                    "required_regions": list(snapshot.required_regions),
                    "covered_regions": list(resource.covered_regions),
                    "missing_regions": missing,
                },
            )
        destination = next(
            bucket for bucket in snapshot.resources.buckets if bucket.id == resource.log_bucket
        )
        bucket_gaps = _guardrail_gaps(destination)
        if bucket_gaps or not _customer_kms(destination) or not destination.versioning:
            issues["LOG-003"] = (
                {
                    "log_bucket": destination.id,
                    "disabled_bucket_settings": bucket_gaps,
                    "customer_managed_sse_kms": _customer_kms(destination),
                    "versioning": destination.versioning,
                },
            )
    return issues


def assess(snapshot: Snapshot) -> Assessment:
    findings: list[Finding] = []
    evaluations: list[Evaluation] = []
    for resource in sorted(
        snapshot.resources.all_resources(), key=lambda r: (r.resource_type, r.id)
    ):
        issues = _issues(resource, snapshot)
        for control in CONTROLS:
            if control.resource_type != resource.resource_type:
                continue
            evidence = issues.get(control.id, ())
            evaluations.append(
                Evaluation(
                    control.id, resource.id, resource.resource_type, "FAIL" if evidence else "PASS"
                )
            )
            if not evidence:
                continue
            identity = json.dumps(
                [snapshot.account_id, resource.resource_type, resource.id, control.id],
                separators=(",", ":"),
            )
            finding_id = "finding-" + hashlib.sha256(identity.encode()).hexdigest()[:24]
            findings.append(
                Finding(
                    finding_id,
                    control.id,
                    control.title,
                    control.severity,
                    resource.id,
                    resource.resource_type,
                    "OPEN",
                    control.title + "; observed in the supplied synthetic snapshot.",
                    evidence,
                    control.remediation,
                    control.references,
                    control.limitations,
                )
            )
    return Assessment(
        snapshot.snapshot_id,
        snapshot.account_id,
        snapshot.captured_at,
        snapshot.source_sha256,
        tuple(control.id for control in CONTROLS),
        tuple(
            sorted(
                findings, key=lambda item: (item.control_id, item.resource_type, item.resource_id)
            )
        ),
        tuple(
            sorted(
                evaluations,
                key=lambda item: (item.control_id, item.resource_type, item.resource_id),
            )
        ),
        snapshot.resource_keys,
    )
