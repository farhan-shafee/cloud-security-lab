"""Fixture acceptance harness; answer keys are never imported by evaluators."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .detections import detect
from .errors import FixtureError
from .events import load_events
from .fixtures import load_snapshot
from .posture import assess


def _truth(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise FixtureError(f"Unsupported ground truth schema: {path}")
    return data


def _coverage(expected: set[str], actual: set[str], lane: str) -> None:
    if expected != actual:
        raise FixtureError(
            f"Ground truth coverage mismatch in {lane}: "
            f"unregistered={sorted(actual - expected)}, missing={sorted(expected - actual)}"
        )


def validate_fixtures(root: Path) -> dict[str, Any]:
    """Compare independent hand-authored expectations with public engine results."""
    fixture_root = root / "fixtures"
    posture_truth = _truth(fixture_root / "ground_truth/posture.json")
    expected_names = set(posture_truth) - {"schema_version"}
    _coverage(
        expected_names, {p.stem for p in (fixture_root / "accounts").glob("*.json")}, "posture"
    )
    for name in sorted(expected_names):
        result = assess(load_snapshot(fixture_root / "accounts" / f"{name}.json"))
        actual = sorted([f.control_id, f.resource_type, f.resource_id] for f in result.findings)
        if actual != sorted(posture_truth[name]):
            raise FixtureError(f"Ground truth mismatch: posture {name}")
    detection_truth = _truth(fixture_root / "ground_truth/detections.json")["scenarios"]
    expected_events = {scenario["file"] for scenario in detection_truth}
    if len(expected_events) != len(detection_truth):
        raise FixtureError("Duplicate event ground truth scenario")
    _coverage(expected_events, {p.name for p in (fixture_root / "events").glob("*.json")}, "events")
    for scenario in detection_truth:
        path = fixture_root / "events" / scenario["file"]
        if path.parent.resolve() != (fixture_root / "events").resolve():
            raise FixtureError("Ground truth scenario must name an event fixture in its directory")
        result_dict = detect(load_events(path)).to_dict()
        for field, identifier in (("alerts", "detection_id"), ("correlations", "correlation_id")):
            actual_items = [
                {identifier: item[identifier], "event_ids": item["event_ids"]}
                for item in result_dict[field]
            ]
            if sorted(actual_items, key=json.dumps) != sorted(scenario[field], key=json.dumps):
                raise FixtureError(f"Ground truth mismatch: {scenario['file']} {field}")
    rejected = 0
    for path in sorted((fixture_root / "invalid").glob("*.json")):
        try:
            load_snapshot(path)
        except FixtureError:
            rejected += 1
        else:
            raise FixtureError(f"Invalid snapshot unexpectedly accepted: {path.name}")
    return {
        "success": True,
        "posture_scenarios": len(expected_names),
        "event_scenarios": len(detection_truth),
        "invalid_snapshots_rejected": rejected,
    }
