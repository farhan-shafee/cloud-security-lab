"""Detection truth is declared in fixtures, independently of the detector."""

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TRUTH = json.loads((ROOT / "fixtures/ground_truth/detections.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("scenario", TRUTH["scenarios"], ids=lambda item: item["file"])
def test_detection_ground_truth(scenario):
    from cloud_security_lab.detections import detect
    from cloud_security_lab.events import load_events

    result = detect(load_events(ROOT / "fixtures/events" / scenario["file"])).to_dict()
    actual = sorted((alert["detection_id"], alert["event_ids"]) for alert in result["alerts"])
    expected = sorted((alert["detection_id"], alert["event_ids"]) for alert in scenario["alerts"])
    assert actual == expected
    correlations = [
        {"correlation_id": item["correlation_id"], "event_ids": item["event_ids"]}
        for item in result["correlations"]
    ]
    assert correlations == scenario["correlations"]


def test_detection_ids_evidence_and_serialization_are_stable():
    from cloud_security_lab.detections import detect
    from cloud_security_lab.events import load_events

    batch = load_events(ROOT / "fixtures/events/demo.json")
    result = detect(batch).to_dict()
    assert result == detect(batch).to_dict()
    assert result["synthetic"] is True
    assert result["detection_ids"] == [f"DET-{index:03d}" for index in range(1, 7)]
    assert len({alert["alert_id"] for alert in result["alerts"]}) == 6
    for alert in result["alerts"]:
        assert alert["evidence"] and alert["reason"] and alert["references"]
        assert alert["severity"] in {"HIGH", "MEDIUM"}
    assert json.loads(json.dumps(result)) == result


def test_event_input_order_does_not_change_alerts(tmp_path):
    from cloud_security_lab.detections import detect
    from cloud_security_lab.events import load_events

    path = ROOT / "fixtures/events/demo.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["events"].reverse()
    shuffled = tmp_path / "shuffled.json"
    shuffled.write_text(json.dumps(data), encoding="utf-8")
    first, second = detect(load_events(path)).to_dict(), detect(load_events(shuffled)).to_dict()
    for key in ("alerts", "correlations", "triage"):
        assert first[key] == second[key]
    assert first["source_sha256"] != second["source_sha256"]


def test_fractional_seconds_preserve_chronological_alert_and_triage_order(tmp_path):
    from copy import deepcopy

    from cloud_security_lab.detections import detect
    from cloud_security_lab.events import load_events

    data = json.loads((ROOT / "fixtures/events/policy-version-created.json").read_text())
    later = deepcopy(data["events"][0])
    later.update(eventID="fractional", eventTime="2026-01-10T14:00:00.500000Z")
    data["events"].insert(0, later)
    path = tmp_path / "fractional.json"
    path.write_text(json.dumps(data))
    result = detect(load_events(path)).to_dict()
    assert [alert["event_ids"] for alert in result["alerts"]] == [
        ["policy-version"],
        ["fractional"],
    ]
    assert [record["source_event_ids"] for record in result["triage"]] == [
        ["policy-version"],
        ["fractional"],
    ]
