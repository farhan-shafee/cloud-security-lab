import json
import subprocess
import sys

import pytest

from cloud_security_lab.cli import main


def test_cli_help_runs_without_credentials():
    result = subprocess.run(
        [sys.executable, "-m", "cloud_security_lab", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert all(command in result.stdout for command in ("assess", "detect", "verify", "demo"))


@pytest.mark.parametrize("command", ["assess", "detect"])
def test_cli_input_error_is_exit_two_not_traceback(command, capsys):
    assert main([command, "does-not-exist.json"]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_assess_machine_output_and_finding_gate(capsys):
    path = "fixtures/accounts/risky-environment.json"
    assert main(["assess", path, "--format", "json", "--fail-on-findings"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["synthetic"] is True
    assert any(item["control_id"] == "NET-001" for item in result["findings"])


def test_secure_assessment_does_not_fail_gate(capsys):
    assert main(["assess", "fixtures/accounts/secure-baseline.json", "--fail-on-findings"]) == 0
    assert "findings: 0" in capsys.readouterr().out


def test_verify_exit_and_written_evidence(tmp_path, capsys):
    target = tmp_path / "verification.json"
    assert (
        main(
            [
                "verify",
                "fixtures/accounts/risky-environment.json",
                "fixtures/accounts/remediated-environment.json",
                "--format",
                "json",
                "--output",
                str(target),
            ]
        )
        == 0
    )
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["success"] is True
    assert data["verified_closed"] > 0
    assert "VERIFIED_CLOSED" not in capsys.readouterr().out  # Output file stays machine readable.


def test_demo_is_repeatable_and_checks_evidence(tmp_path, capsys):
    out = tmp_path / "demo"
    assert main(["demo", "--output-dir", str(out)]) == 0
    first = {p.name: p.read_bytes() for p in out.iterdir()}
    assert main(["demo", "--output-dir", str(out)]) == 0
    assert first == {p.name: p.read_bytes() for p in out.iterdir()}
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["success"] is True
    assert summary["remediated_findings"] == 0
    assert main(["demo", "--check", str(out)]) == 0
    (out / "before.json").write_text("{}", encoding="utf-8")
    assert main(["demo", "--check", str(out)]) == 2
    assert "differs" in capsys.readouterr().err


def test_detection_cli_produces_triage(capsys):
    assert main(["detect", "fixtures/events/demo.json", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert {record["disposition"] for record in data["triage"]} == {"REVIEW", "ESCALATE"}
