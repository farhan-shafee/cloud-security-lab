"""Correlation boundaries are explicit; arrival order is not causal order."""

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "scenario, expected",
    [
        ("sequence-window-boundary", 1),
        ("sequence-outside-window", 0),
        ("sequence-other-principal", 0),
        ("sequence-other-account", 0),
        ("sequence-other-session", 0),
        ("sequence-reversed", 0),
        ("sequence-simultaneous", 0),
        ("sequence-failed-policy", 0),
    ],
)
def test_sequence_requires_exact_identity_account_order_and_window(scenario, expected):
    from cloud_security_lab.detections import detect
    from cloud_security_lab.events import load_events

    result = detect(load_events(ROOT / f"fixtures/events/{scenario}.json")).to_dict()
    assert len(result["correlations"]) == expected
    if expected:
        correlation = result["correlations"][0]
        assert correlation["correlation_id"] == "COR-001"
        assert correlation["event_ids"] == ["sequence-policy", "sequence-logging"]
        assert correlation["evidence"]["elapsed_seconds"] == 900


def test_multiple_policy_edits_choose_nearest_prior_event(tmp_path):
    from cloud_security_lab.detections import detect
    from cloud_security_lab.events import load_events

    data = json.loads((ROOT / "fixtures/events/sequence-window-boundary.json").read_text())
    newer = dict(data["events"][0], eventID="closer-policy", eventTime="2026-01-10T14:14:00Z")
    data["events"].append(newer)
    path = tmp_path / "sequence.json"
    path.write_text(json.dumps(data))
    correlations = detect(load_events(path)).to_dict()["correlations"]
    assert len(correlations) == 1
    assert correlations[0]["event_ids"] == ["closer-policy", "sequence-logging"]
