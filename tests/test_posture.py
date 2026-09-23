import json
from pathlib import Path

import pytest

from cloud_security_lab.fixtures import load_snapshot
from cloud_security_lab.posture import assess

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "name", ["risky-environment", "remediated-environment", "secure-baseline", "edge-cases"]
)
def test_posture_matches_independently_authored_answer_key(name):
    truth = json.loads((ROOT / "fixtures/ground_truth/posture.json").read_text())
    assessment = assess(load_snapshot(ROOT / f"fixtures/accounts/{name}.json"))
    actual = sorted([f.control_id, f.resource_type, f.resource_id] for f in assessment.findings)
    assert actual == sorted(truth[name])
    assert len(assessment.controls_executed) == 14
    assert len(assessment.evaluations) > 0
    assert all(e.status in {"PASS", "FAIL"} for e in assessment.evaluations)


def test_stable_findings_and_source_provenance():
    snapshot = load_snapshot(ROOT / "fixtures/accounts/risky-environment.json")
    first = assess(snapshot).to_dict()
    assert first == assess(snapshot).to_dict()
    assert first["source_sha256"] == snapshot.source_sha256
    assert len(snapshot.source_sha256) == 64
    assert all(
        f["reason"] and f["evidence"] and f["limitations"] and f["remediation"] and f["references"]
        for f in first["findings"]
    )


def test_risky_and_remediated_have_the_same_resource_inventory():
    before = load_snapshot(ROOT / "fixtures/accounts/risky-environment.json")
    after = load_snapshot(ROOT / "fixtures/accounts/remediated-environment.json")
    assert before.resource_keys == after.resource_keys
    assert after.captured_at > before.captured_at


def test_network_boundaries_ipv6_admin_and_udp(tmp_path):
    data = json.loads((ROOT / "fixtures/accounts/secure-baseline.json").read_text())
    data["resources"]["security_groups"][0]["ingress"] = [
        {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "::/0"},
        {"protocol": "udp", "from_port": 3389, "to_port": 3389, "cidr": "0.0.0.0/0"},
    ]
    path = tmp_path / "ipv6.json"
    path.write_text(json.dumps(data))
    findings = assess(load_snapshot(path)).findings
    assert [(f.control_id, f.resource_id) for f in findings] == [("NET-001", "sg-workload")]


def test_public_https_and_private_admin_ports_are_negative(tmp_path):
    data = json.loads((ROOT / "fixtures/accounts/secure-baseline.json").read_text())
    data["resources"]["security_groups"][0]["ingress"] = [
        {"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"},
        {"protocol": "tcp", "from_port": 22, "to_port": 3389, "cidr": "10.0.0.0/8"},
    ]
    path = tmp_path / "negative.json"
    path.write_text(json.dumps(data))
    assert assess(load_snapshot(path)).findings == ()


def test_non_sensitive_aes_bucket_is_not_an_sse_kms_failure(tmp_path):
    data = json.loads((ROOT / "fixtures/accounts/secure-baseline.json").read_text())
    bucket = data["resources"]["buckets"][0]
    bucket["sensitive"] = False
    bucket["encryption"] = {"algorithm": "AES256", "key_id": None, "key_manager": None}
    path = tmp_path / "aes.json"
    path.write_text(json.dumps(data))
    assert assess(load_snapshot(path)).findings == ()


def test_missing_regions_and_destination_settings_fail_separately(tmp_path):
    data = json.loads((ROOT / "fixtures/accounts/secure-baseline.json").read_text())
    trail = data["resources"]["trails"][0]
    trail["is_multi_region"] = False
    trail["covered_regions"] = ["us-east-1"]
    data["resources"]["buckets"][1]["versioning"] = False
    path = tmp_path / "logging.json"
    path.write_text(json.dumps(data))
    assert {f.control_id for f in assess(load_snapshot(path)).findings} == {
        "LOG-002",
        "LOG-003",
        "S3-003",
    }
