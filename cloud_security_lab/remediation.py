"""Re-assess source snapshots to prove synthetic remediation closure."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from .errors import FixtureError
from .models import Snapshot
from .posture import assess


def verify(before: Snapshot, after: Snapshot) -> dict[str, Any]:
    """A status edit is never evidence: both snapshots are assessed here."""
    if before.account_id != after.account_id:
        raise FixtureError("Verification requires snapshots from the same account")
    if after.captured_at <= before.captured_at:
        raise FixtureError("Verification requires a strictly later captured_at")
    if before.snapshot_id == after.snapshot_id:
        raise FixtureError("Verification requires distinct snapshot IDs")
    if before.required_regions != after.required_regions:
        raise FixtureError("Verification cannot change required region scope")
    removed = set(before.resource_keys) - set(after.resource_keys)
    if removed:
        raise FixtureError(
            f"Verification cannot prove closure for removed resources: {sorted(removed)}"
        )
    later_resources = {(r.resource_type, r.id): r for r in after.resources.all_resources()}
    for resource in before.resources.all_resources():
        later = later_resources[(resource.resource_type, resource.id)]
        for field in ("region", "home_region", "sensitive"):
            if getattr(resource, field, None) != getattr(later, field, None):
                label = "sensitivity" if field == "sensitive" else "region"
                raise FixtureError(f"Verification cannot change resource {label}: {resource.id}")
    baseline: dict[str, Any] = assess(before).to_dict()
    current: dict[str, Any] = assess(after).to_dict()
    if baseline["controls_executed"] != current["controls_executed"]:
        raise FixtureError("Verification requires the same control catalog")
    current_evaluations = {
        (item["control_id"], item["resource_type"], item["resource_id"]): item
        for item in current["evaluations"]
    }
    records = []
    for finding in baseline["findings"]:
        key = (finding["control_id"], finding["resource_type"], finding["resource_id"])
        evaluation = current_evaluations.get(key)
        if evaluation is None:
            raise FixtureError(f"No later evaluation available for {key}")
        closed = evaluation["status"] == "PASS"
        records.append(
            {
                **finding,
                "status": "VERIFIED_CLOSED" if closed else "OPEN",
                "before_status": "FAIL",
                "after_status": evaluation["status"],
                "after_evaluation": evaluation,
                "after_resource": asdict(
                    later_resources[(finding["resource_type"], finding["resource_id"])]
                ),
            }
        )
    previous_ids = {item["finding_id"] for item in baseline["findings"]}
    new_findings = [item for item in current["findings"] if item["finding_id"] not in previous_ids]
    closed_count = sum(item["status"] == "VERIFIED_CLOSED" for item in records)
    open_count = len(records) - closed_count
    metadata_keys = ("snapshot_id", "account_id", "captured_at", "source_sha256")
    return {
        "schema_version": 1,
        "synthetic": True,
        "workflow": "synthetic configuration remediation verification",
        "before": {key: baseline[key] for key in metadata_keys},
        "after": {key: current[key] for key in metadata_keys},
        "controls_executed": baseline["controls_executed"],
        "findings": records,
        "new_findings": new_findings,
        "verified_closed": closed_count,
        "open": open_count,
        "success": open_count == 0 and not new_findings,
        "limitations": [
            "Fixture timestamps and contents are supplied evidence, not authenticated AWS records.",
            "Hashes identify input bytes; they do not prove their origin or integrity.",
            "Closure proves only that this control no longer detects the modeled condition.",
        ],
    }
