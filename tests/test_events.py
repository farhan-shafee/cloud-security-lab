"""Contract tests for the intentionally narrow synthetic audit-event format."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EVENTS = ROOT / "fixtures" / "events"


def source():
    return json.loads((EVENTS / "demo.json").read_text(encoding="utf-8"))


def write(tmp_path, data):
    path = tmp_path / "events.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_loader_normalizes_offset_times_and_orders_events(tmp_path):
    from cloud_security_lab.events import load_events

    data = source()
    data["events"][0]["eventTime"] = "2026-01-10T09:00:00-05:00"
    data["events"].reverse()
    batch = load_events(write(tmp_path, data))
    assert batch.events[0].timestamp.isoformat() == "2026-01-10T14:00:00+00:00"
    assert batch.events[0].event_id == "demo-root"
    assert len(batch.source_sha256) == 64


@pytest.mark.parametrize(
    "change",
    [
        "version",
        "synthetic",
        "duplicate",
        "naive_time",
        "bad_time",
        "missing_id",
        "bad_account",
        "bad_principal",
        "bad_request",
        "bad_response",
        "bad_mfa",
        "mfa_object",
        "response_array",
        "identity_arn_mismatch",
        "control_character",
        "utc_underflow",
        "bad_error",
        "bad_ip",
        "bool_version",
    ],
)
def test_malformed_event_envelopes_fail_explicitly(tmp_path, change):
    from cloud_security_lab.errors import FixtureError
    from cloud_security_lab.events import load_events

    data = source()
    event = data["events"][1]
    if change == "version":
        data["schema_version"] = 99
    elif change == "bool_version":
        data["schema_version"] = True
    elif change == "synthetic":
        data["synthetic"] = False
    elif change == "duplicate":
        data["events"].append(deepcopy(event))
    elif change == "naive_time":
        event["eventTime"] = "2026-01-10T14:00:00"
    elif change == "bad_time":
        event["eventTime"] = "not-a-time"
    elif change == "missing_id":
        del event["eventID"]
    elif change == "bad_account":
        event["recipientAccountId"] = 111122223333
    elif change == "bad_principal":
        event["userIdentity"]["arn"] = "not-an-arn"
    elif change == "bad_request":
        event["requestParameters"] = []
    elif change == "bad_response":
        event["responseElements"] = {"ConsoleLogin": True}
    elif change == "bad_mfa":
        event["additionalEventData"]["MFAUsed"] = False
    elif change == "mfa_object":
        event["additionalEventData"]["MFAUsed"] = {}
    elif change == "response_array":
        event["responseElements"]["ConsoleLogin"] = []
    elif change == "identity_arn_mismatch":
        event["userIdentity"]["arn"] = "arn:aws:sts::111122223333:assumed-role/Lab/session"
    elif change == "control_character":
        event["eventID"] = "hidden\u001b[2J"
    elif change == "utc_underflow":
        event["eventTime"] = "0001-01-01T00:00:00+01:00"
    elif change == "bad_error":
        event["errorCode"] = False
    elif change == "bad_ip":
        event["sourceIPAddress"] = "unknown.example"
    with pytest.raises(FixtureError):
        load_events(write(tmp_path, data))


def test_duplicate_json_keys_are_not_silently_overwritten(tmp_path):
    from cloud_security_lab.errors import FixtureError
    from cloud_security_lab.events import load_events

    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    with pytest.raises(FixtureError, match="duplicate"):
        load_events(path)


@pytest.mark.parametrize(
    "change",
    ["bool_port", "reversed_ports", "bad_cidr", "missing_ranges", "bad_protocol", "wrong_items"],
)
def test_malformed_ingress_is_rejected(tmp_path, change):
    from cloud_security_lab.errors import FixtureError
    from cloud_security_lab.events import load_events

    data = source()
    permission = data["events"][4]["requestParameters"]["ipPermissions"]["items"][0]
    if change == "bool_port":
        permission["fromPort"] = True
    elif change == "reversed_ports":
        permission["fromPort"], permission["toPort"] = 23, 22
    elif change == "bad_cidr":
        permission["ipRanges"]["items"][0]["cidrIp"] = "invalid"
    elif change == "missing_ranges":
        del permission["ipRanges"]
    elif change == "bad_protocol":
        permission["ipProtocol"] = "ANY"
    elif change == "wrong_items":
        permission["ipRanges"]["items"] = {}
    with pytest.raises(FixtureError):
        load_events(write(tmp_path, data))


def test_empty_batch_is_valid(tmp_path):
    from cloud_security_lab.events import load_events

    data = {"schema_version": 1, "synthetic": True, "fixture_id": "empty", "events": []}
    assert load_events(write(tmp_path, data)).events == ()


def test_original_guardduty_finding_is_not_a_cloudtrail_batch():
    from cloud_security_lab.errors import FixtureError
    from cloud_security_lab.events import load_events

    with pytest.raises(FixtureError):
        load_events(ROOT / "examples/events/guardduty-credential-access.json")


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-01-10T14:00:00+00:99",
        "2026-01-10T14:00:00+01:99",
        "2026-01-10X14:00:00Z",
        "2026-01-10T14:00:00.1234567Z",
    ],
)
def test_ambiguous_timestamp_syntax_cannot_change_correlation_order(tmp_path, timestamp):
    from cloud_security_lab.errors import FixtureError
    from cloud_security_lab.events import load_events

    data = source()
    data["events"][0]["eventTime"] = timestamp
    with pytest.raises(FixtureError, match="timestamp"):
        load_events(write(tmp_path, data))
