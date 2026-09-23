import json
from pathlib import Path

import pytest

from cloud_security_lab.errors import FixtureError
from cloud_security_lab.fixtures import load_snapshot

ROOT = Path(__file__).resolve().parents[1]


def write(tmp_path, data):
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(data))
    return path


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", 2),
        ("schema_version", True),
        ("synthetic", False),
        ("account_id", "123"),
        ("captured_at", "2026-09-23T12:00:00"),
        ("required_regions", []),
        ("required_regions", ["moon-1"]),
    ],
)
def test_invalid_metadata_is_rejected(tmp_path, field, value):
    data = json.loads((ROOT / "fixtures/accounts/secure-baseline.json").read_text())
    data[field] = value
    with pytest.raises(FixtureError):
        load_snapshot(write(tmp_path, data))


@pytest.mark.parametrize(
    "mutation",
    [
        "extra",
        "missing",
        "duplicate",
        "unknown_bucket",
        "bool_port",
        "backwards_ports",
        "invalid_cidr",
        "unknown_region",
        "invalid_kms",
        "empty_inventory",
    ],
)
def test_malformed_inventory_is_rejected(tmp_path, mutation):
    data = json.loads((ROOT / "fixtures/accounts/secure-baseline.json").read_text())
    resources = data["resources"]
    rule = resources["security_groups"][0]["ingress"][0]
    if mutation == "extra":
        resources["buckets"][0]["not_in_schema"] = True
    elif mutation == "missing":
        del resources["buckets"][0]["sensitive"]
    elif mutation == "duplicate":
        resources["buckets"].append(resources["buckets"][0])
    elif mutation == "unknown_bucket":
        resources["trails"][0]["log_bucket"] = "not-found"
    elif mutation == "bool_port":
        rule["from_port"] = True
    elif mutation == "backwards_ports":
        rule["from_port"], rule["to_port"] = 100, 50
    elif mutation == "invalid_cidr":
        rule["cidr"] = "invalid"
    elif mutation == "unknown_region":
        resources["buckets"][0]["region"] = "moon-1"
    elif mutation == "invalid_kms":
        resources["buckets"][0]["encryption"]["key_id"] = None
    elif mutation == "empty_inventory":
        data["resources"] = {k: [] for k in resources}
    with pytest.raises(FixtureError):
        load_snapshot(write(tmp_path, data))


def test_duplicate_json_keys_rejected(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_version":1,"schema_version":1}')
    with pytest.raises(FixtureError, match="duplicate"):
        load_snapshot(path)


def test_invalid_json_and_nonfinite_numbers_rejected(tmp_path):
    path = tmp_path / "bad.json"
    for text in ["{", '{"schema_version":NaN}', "[]"]:
        path.write_text(text)
        with pytest.raises(FixtureError):
            load_snapshot(path)


def test_missing_file_is_a_fixture_error(tmp_path):
    with pytest.raises(FixtureError):
        load_snapshot(tmp_path / "absent.json")


@pytest.mark.parametrize(
    "captured_at",
    ["0001-01-01T00:00:00+01:00", "9999-12-31T23:00:00-02:00", "2026-09-23T12:00:00+00:99"],
)
def test_timestamp_must_be_representable_in_utc_and_have_a_valid_offset(tmp_path, captured_at):
    data = json.loads((ROOT / "fixtures/accounts/secure-baseline.json").read_text())
    data["captured_at"] = captured_at
    with pytest.raises(FixtureError):
        load_snapshot(write(tmp_path, data))


@pytest.mark.parametrize(
    "name", ["duplicate-resource", "unsupported-iam", "naive-timestamp", "missing-destination"]
)
def test_on_disk_invalid_schema_corpus_is_rejected(name):
    with pytest.raises(FixtureError):
        load_snapshot(ROOT / "fixtures/invalid" / f"{name}.json")
