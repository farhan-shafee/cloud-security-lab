"""One temporal correlation; exact principal ARN preserves assumed-role sessions."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from .detections import stable_id
from .events import CloudEvent, EventBatch

WINDOW = timedelta(minutes=15)


def correlate(batch: EventBatch) -> tuple[dict[str, Any], ...]:
    """Join the nearest strictly earlier policy change to each logging disable.

    A same-time pair has no supported causal order. Events from distinct
    recipient accounts, principals or role sessions never join.
    """
    prior: dict[tuple[str, str], list[CloudEvent]] = {}
    results = []
    for event in sorted(batch.events, key=lambda value: (value.timestamp, value.event_id)):
        if not event.successful:
            continue
        key = (event.account_id, event.principal)
        if event.event_source == "iam.amazonaws.com" and event.event_name in {
            "CreatePolicyVersion",
            "SetDefaultPolicyVersion",
        }:
            prior.setdefault(key, []).append(event)
        if event.event_source != "cloudtrail.amazonaws.com" or event.event_name not in {
            "StopLogging",
            "DeleteTrail",
        }:
            continue
        candidates = [
            candidate
            for candidate in prior.get(key, [])
            if timedelta(0) < event.timestamp - candidate.timestamp <= WINDOW
        ]
        if not candidates:
            continue
        policy = max(candidates, key=lambda value: (value.timestamp, value.event_id))
        event_ids = [policy.event_id, event.event_id]
        results.append(
            {
                "alert_id": stable_id("correlation", "COR-001", *key, *event_ids),
                "correlation_id": "COR-001",
                "title": "IAM policy change followed by security logging disablement",
                "severity": "HIGH",
                "event_ids": event_ids,
                "account_id": event.account_id,
                "principal": event.principal,
                "resource_id": event.request["name"],
                "timestamp": event.timestamp.isoformat().replace("+00:00", "Z"),
                "reason": (
                    "Same account and exact principal/session changed a policy then disabled "
                    "logging within 15 minutes."
                ),
                "evidence": {
                    "policy_event": policy.event_name,
                    "logging_event": event.event_name,
                    "elapsed_seconds": int((event.timestamp - policy.timestamp).total_seconds()),
                    "window_seconds": 900,
                    "policy_arn": policy.request["policyArn"],
                    "trail": event.request["name"],
                },
            }
        )
    return tuple(results)
