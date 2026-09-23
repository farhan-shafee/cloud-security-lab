import json

from cloud_security_lab.reporting import render, write_report


def test_json_is_reproducible_and_round_trips():
    data = {"synthetic": True, "evidence": {"z": 2, "a": [1]}, "findings": []}
    assert render(data, "json") == render(dict(reversed(list(data.items()))), "json")
    assert json.loads(render(data, "json")) == data


def test_markdown_preserves_finding_evidence_and_scope():
    data = {
        "snapshot_id": "risky",
        "findings": [
            {
                "control_id": "NET-001",
                "severity": "HIGH",
                "resource_id": "sg-admin",
                "status": "OPEN",
                "title": "Administrative port publicly exposed",
                "evidence": {"cidr": "0.0.0.0/0", "port": 22},
                "reason": "World CIDR admits TCP/22",
                "remediation": "Restrict source CIDR",
                "references": [],
                "limitations": "No path reachability analysis",
            }
        ],
        "controls_executed": ["NET-001"],
    }
    result = render(data, "markdown")
    for detail in (
        "synthetic",
        "NET-001",
        "HIGH",
        "sg-admin",
        "0.0.0.0/0",
        "22",
        "OPEN",
        "Restrict source CIDR",
        "No path reachability analysis",
    ):
        assert detail in result


def test_report_writer_creates_portable_utf8_and_lf(tmp_path):
    path = tmp_path / "nested" / "evidence.json"
    write_report(path, {"reason": "synthetic → reviewed"}, "json")
    assert b"\r\n" not in path.read_bytes()
    assert json.loads(path.read_text(encoding="utf-8"))["reason"] == "synthetic → reviewed"


def test_fence_in_fixture_cannot_break_markdown_code_block():
    result = render({"findings": [{"evidence": "```\nforged heading"}]}, "markdown")
    assert "\\u0060" in result


def test_terminal_output_shows_escalation_with_source_events():
    data = {
        "event_count": 2,
        "alerts": [],
        "correlations": [{"correlation_id": "COR-001", "event_ids": ["policy", "stop"]}],
        "triage": [{"disposition": "ESCALATE", "event_ids": ["policy", "stop"]}],
    }
    result = render(data, "text")
    assert "COR-001" in result
    assert "ESCALATE" in result
    assert "policy" in result and "stop" in result
