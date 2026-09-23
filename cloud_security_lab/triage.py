"""Evidence-preserving triage records; review/escalate never means malicious."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta
from typing import Any

from .detections import Alert, stable_id
from .events import EventBatch


def build_triage(
    batch: EventBatch,
    alerts: tuple[Alert, ...],
    correlations: tuple[dict[str, Any], ...],
) -> tuple[dict[str, Any], ...]:
    records = []
    signals = [(asdict(alert), "REVIEW") for alert in alerts]
    signals.extend((correlation, "ESCALATE") for correlation in correlations)
    for signal, disposition in signals:
        timestamp = datetime.fromisoformat(signal["timestamp"].replace("Z", "+00:00"))
        related = [
            event.event_id
            for event in batch.events
            if event.account_id == signal["account_id"]
            and event.principal == signal["principal"]
            and abs(event.timestamp - timestamp) <= timedelta(minutes=15)
            and event.event_id not in signal["event_ids"]
        ]
        records.append(
            {
                "triage_id": stable_id("triage", signal["alert_id"]),
                "alert_id": signal["alert_id"],
                "rule_id": signal.get("detection_id", signal.get("correlation_id")),
                "source_event_ids": signal["event_ids"],
                "principal": signal["principal"],
                "account_id": signal["account_id"],
                "resource_id": signal["resource_id"],
                "timestamp": signal["timestamp"],
                "reason": signal["reason"],
                "related_event_ids": related,
                "disposition": disposition,
                "recommended_steps": [
                    "Confirm source-event integrity and identity/session attribution.",
                    "Compare the action and target with an authorized change record.",
                    "Inspect related activity and affected configuration before deciding intent.",
                    "Record the human disposition; escalate unauthorized changes for response.",
                ],
            }
        )
    return tuple(
        sorted(
            records,
            key=lambda item: (
                datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00")),
                item["rule_id"],
                item["triage_id"],
            ),
        )
    )
