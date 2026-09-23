import copy
import json

import pytest

from cloud_security_lab.errors import FixtureError
from cloud_security_lab.fixtures import load_snapshot
from cloud_security_lab.remediation import verify


def snapshot_dict():
    return {
        "schema_version": 1,
        "synthetic": True,
        "snapshot_id": "before",
        "account_id": "111122223333",
        "captured_at": "2026-09-22T12:00:00Z",
        "required_regions": ["us-east-1"],
        "resources": {
            "policies": [],
            "roles": [],
            "buckets": [],
            "trails": [],
            "security_groups": [
                {
                    "id": "sg-admin",
                    "region": "us-east-1",
                    "ingress": [
                        {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"}
                    ],
                }
            ],
        },
    }


def pair(tmp_path, change=None):
    before = snapshot_dict()
    after = copy.deepcopy(before)
    after.update(snapshot_id="after", captured_at="2026-09-23T12:00:00Z")
    after["resources"]["security_groups"][0]["ingress"][0]["cidr"] = "192.0.2.0/24"
    if change:
        change(after)
    paths = [tmp_path / "before.json", tmp_path / "after.json"]
    for path, data in zip(paths, [before, after], strict=True):
        path.write_text(json.dumps(data), encoding="utf-8")
    return tuple(load_snapshot(p) for p in paths)


def test_reassessment_closes_only_after_control_pass(tmp_path):
    before, after = pair(tmp_path)
    result = verify(before, after)
    record = result["findings"][0]
    assert result["verified_closed"] == 1
    assert result["open"] == 0
    assert record["control_id"] == "NET-001"
    assert record["before_status"] == "FAIL"
    assert record["after_status"] == "PASS"
    assert record["status"] == "VERIFIED_CLOSED"
    assert result["before"]["source_sha256"] != result["after"]["source_sha256"]


def test_failed_remediation_stays_open(tmp_path):
    def retain(data):
        data["resources"]["security_groups"][0]["ingress"][0]["cidr"] = "0.0.0.0/0"

    before, after = pair(tmp_path, retain)
    result = verify(before, after)
    assert result["open"] == 1
    assert result["findings"][0]["status"] == "OPEN"


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(captured_at="2026-09-21T12:00:00Z"),
        lambda d: d.update(captured_at="2026-09-22T12:00:00Z"),
        lambda d: d.update(account_id="999988887777"),
        lambda d: d.update(snapshot_id="before"),
        lambda d: d["resources"]["security_groups"][0].update(id="sg-renamed"),
    ],
)
def test_invalid_comparison_cannot_close_findings(tmp_path, change):
    before, after = pair(tmp_path, change)
    with pytest.raises(FixtureError):
        verify(before, after)


def test_new_findings_are_reported_even_when_original_closed(tmp_path):
    def add_public_group(data):
        group = copy.deepcopy(snapshot_dict()["resources"]["security_groups"][0])
        group["id"] = "sg-new"
        data["resources"]["security_groups"].append(group)

    before, after = pair(tmp_path, add_public_group)
    result = verify(before, after)
    assert result["verified_closed"] == 1
    assert result["new_findings"][0]["resource_id"] == "sg-new"
    assert result["success"] is False


def test_snapshot_status_field_cannot_forge_closure(tmp_path):
    with pytest.raises(FixtureError):
        pair(tmp_path, lambda d: d.update(status="VERIFIED_CLOSED"))


def test_changing_region_does_not_replace_original_resource(tmp_path):
    before, after = pair(
        tmp_path, lambda d: d["resources"]["security_groups"][0].update(region="us-west-2")
    )
    with pytest.raises(FixtureError, match="region"):
        verify(before, after)


def test_reclassifying_sensitive_bucket_is_not_encryption_remediation(tmp_path):
    from pathlib import Path

    before = load_snapshot(Path("fixtures/accounts/risky-environment.json"))
    after_data = json.loads(Path("fixtures/accounts/remediated-environment.json").read_text())
    after_data["resources"]["buckets"][0]["sensitive"] = False
    after_path = tmp_path / "reclassified.json"
    after_path.write_text(json.dumps(after_data), encoding="utf-8")
    with pytest.raises(FixtureError, match="sensitivity"):
        verify(before, load_snapshot(after_path))
