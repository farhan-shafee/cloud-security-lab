"""Six transparent, deterministic rules over supported synthetic audit events."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from .events import CloudEvent, EventBatch

CLOUDTRAIL_REFERENCE = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html"
DETECTION_CATALOG = {
    "DET-001": ("Root account API use", "HIGH"),
    "DET-002": ("IAM user console login without MFA signal", "MEDIUM"),
    "DET-003": ("Access key created", "MEDIUM"),
    "DET-004": ("IAM policy version modified", "MEDIUM"),
    "DET-005": ("Security logging disabled or trail deleted", "HIGH"),
    "DET-006": ("Administrative ingress opened to the world", "HIGH"),
}


def stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256(json.dumps(parts, separators=(",", ":")).encode()).hexdigest()[:20]
    return f"{prefix}-{digest}"


@dataclass(frozen=True)
class Alert:
    alert_id: str
    detection_id: str
    title: str
    severity: str
    event_ids: list[str]
    account_id: str
    principal: str
    resource_id: str
    timestamp: str
    reason: str
    evidence: dict[str, Any]
    references: list[str]


@dataclass(frozen=True)
class DetectionResult:
    fixture_id: str
    source_sha256: str
    event_count: int
    alerts: tuple[Alert, ...]
    correlations: tuple[dict[str, Any], ...]
    triage: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "synthetic": True,
            "fixture_id": self.fixture_id,
            "source_sha256": self.source_sha256,
            "event_count": self.event_count,
            "detection_ids": list(DETECTION_CATALOG),
            "correlation_ids": ["COR-001"],
            "alerts": [asdict(alert) for alert in self.alerts],
            "correlations": list(self.correlations),
            "triage": list(self.triage),
        }


def _alert(rule: str, event: CloudEvent, resource: str, reason: str, **evidence: Any) -> Alert:
    title, severity = DETECTION_CATALOG[rule]
    return Alert(
        stable_id("alert", rule, event.account_id, event.event_id),
        rule,
        title,
        severity,
        [event.event_id],
        event.account_id,
        event.principal,
        resource,
        event.timestamp.isoformat().replace("+00:00", "Z"),
        reason,
        {
            "event_name": event.event_name,
            "event_source": event.event_source,
            "source_ip": event.source_ip,
            **evidence,
        },
        [CLOUDTRAIL_REFERENCE],
    )


def _detect_event(event: CloudEvent) -> list[Alert]:
    if not event.successful:
        return []
    alerts = []
    if event.identity_type == "Root" and event.event_type == "AwsApiCall":
        alerts.append(
            _alert(
                "DET-001",
                event,
                event.principal,
                "A successful API call used the root account identity.",
                identity_type=event.identity_type,
            )
        )
    if (
        event.event_source == "signin.amazonaws.com"
        and event.event_name == "ConsoleLogin"
        and event.identity_type == "IAMUser"
        and event.additional.get("MFAUsed") == "No"
    ):
        alerts.append(
            _alert(
                "DET-002",
                event,
                event.principal,
                "A successful IAM-user console login explicitly reports MFAUsed=No.",
                mfa_used="No",
                console_login="Success",
            )
        )
    if event.event_source == "iam.amazonaws.com" and event.event_name == "CreateAccessKey":
        target = event.request.get("userName", event.principal)
        alerts.append(
            _alert(
                "DET-003",
                event,
                target,
                "A successful CreateAccessKey call created a long-lived credential.",
                target_user=target,
            )
        )
    if event.event_source == "iam.amazonaws.com" and event.event_name in {
        "CreatePolicyVersion",
        "SetDefaultPolicyVersion",
    }:
        target = event.request["policyArn"]
        alerts.append(
            _alert(
                "DET-004",
                event,
                target,
                "A successful IAM call created or selected a managed policy version.",
                policy_arn=target,
            )
        )
    if event.event_source == "cloudtrail.amazonaws.com" and event.event_name in {
        "StopLogging",
        "DeleteTrail",
    }:
        target = event.request["name"]
        alerts.append(
            _alert(
                "DET-005",
                event,
                target,
                "A successful call stopped logging or deleted the named trail.",
                trail=target,
            )
        )
    if (
        event.event_source == "ec2.amazonaws.com"
        and event.event_name == "AuthorizeSecurityGroupIngress"
    ):
        exposed = []
        for permission in event.ingress:
            world = [cidr for cidr in permission.cidrs if cidr in {"0.0.0.0/0", "::/0"}]
            admin = permission.protocol == "-1" or (
                permission.protocol in {"tcp", "6"}
                and permission.from_port is not None
                and permission.to_port is not None
                and any(permission.from_port <= port <= permission.to_port for port in (22, 3389))
            )
            if world and admin:
                exposed.append(
                    {
                        "protocol": permission.protocol,
                        "from_port": permission.from_port,
                        "to_port": permission.to_port,
                        "world_cidrs": world,
                    }
                )
        if exposed:
            alerts.append(
                _alert(
                    "DET-006",
                    event,
                    event.request["groupId"],
                    "Successful ingress permits world access to TCP 22/3389 or all protocols.",
                    ingress=exposed,
                )
            )
    return alerts


def detect(batch: EventBatch) -> DetectionResult:
    """Evaluate event rules, correlation and deterministic analyst triage."""
    from .correlation import correlate
    from .triage import build_triage

    alerts = tuple(
        sorted(
            (alert for event in batch.events for alert in _detect_event(event)),
            key=lambda alert: (
                datetime.fromisoformat(alert.timestamp.replace("Z", "+00:00")),
                alert.detection_id,
                alert.alert_id,
            ),
        )
    )
    correlations = correlate(batch)
    return DetectionResult(
        batch.fixture_id,
        batch.source_sha256,
        len(batch.events),
        alerts,
        correlations,
        build_triage(batch, alerts, correlations),
    )
