"""Machine triage records remain reviewable evidence, not a maliciousness verdict."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_triage_retains_sources_and_escalates_only_the_sequence():
    from cloud_security_lab.detections import detect
    from cloud_security_lab.events import load_events

    result = detect(load_events(ROOT / "fixtures/events/demo.json")).to_dict()
    triage = result["triage"]
    assert len(triage) == 7
    assert [item["disposition"] for item in triage].count("ESCALATE") == 1
    assert [item["disposition"] for item in triage].count("REVIEW") == 6
    event_ids = {event_id for alert in result["alerts"] for event_id in alert["event_ids"]}
    for record in triage:
        assert set(record["source_event_ids"]) <= event_ids
        assert record["principal"] and record["reason"] and record["recommended_steps"]
        assert record["disposition"] != "MALICIOUS"


def test_related_events_never_cross_identity_or_account():
    from cloud_security_lab.detections import detect
    from cloud_security_lab.events import load_events

    result = detect(load_events(ROOT / "fixtures/events/sequence-other-principal.json")).to_dict()
    assert all(record["related_event_ids"] == [] for record in result["triage"])
