"""One-command, deterministic evidence generation using the public APIs."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .detections import detect
from .errors import FixtureError
from .events import load_events
from .fixtures import load_snapshot
from .posture import assess
from .remediation import verify
from .reporting import render


def build_demo(root: Path) -> dict[str, dict[str, Any]]:
    before = load_snapshot(root / "fixtures/accounts/risky-environment.json")
    after = load_snapshot(root / "fixtures/accounts/remediated-environment.json")
    baseline = load_snapshot(root / "fixtures/accounts/secure-baseline.json")
    reports = {
        "before": assess(before).to_dict(),
        "after": assess(after).to_dict(),
        "detections": detect(load_events(root / "fixtures/events/demo.json")).to_dict(),
        "verification": verify(before, after),
    }
    secure_findings = len(assess(baseline).findings)
    summary = {
        "schema_version": 1,
        "synthetic": True,
        "workflow": "synthetic configuration remediation verification",
        "controls": len(reports["before"]["controls_executed"]),
        "risky_findings": len(reports["before"]["findings"]),
        "remediated_findings": len(reports["after"]["findings"]),
        "secure_findings": secure_findings,
        "alerts": len(reports["detections"]["alerts"]),
        "correlations": len(reports["detections"]["correlations"]),
        "verified_closed": reports["verification"]["verified_closed"],
        "open": reports["verification"]["open"],
        "success": reports["verification"]["success"] and secure_findings == 0,
    }
    if not summary["risky_findings"] or not summary["alerts"] or not summary["success"]:
        raise FixtureError("Demo invariants failed: expected findings, alerts and verified closure")
    reports["summary"] = summary
    return reports


def run_demo(root: Path, output_dir: Path, *, check: bool = False) -> dict[str, Any]:
    reports = build_demo(root)
    expected = {
        f"{name}.{extension}": render(data, format_name)
        for name, data in reports.items()
        for extension, format_name in (("json", "json"), ("md", "markdown"))
    }
    if check:
        for filename, content in expected.items():
            path = output_dir / filename
            if not path.is_file() or path.read_bytes() != content.encode("utf-8"):
                raise FixtureError(f"Generated evidence differs: {path}")
    else:
        output_dir.mkdir(parents=True, exist_ok=True)
        for filename, content in expected.items():
            (output_dir / filename).write_text(content, encoding="utf-8", newline="\n")
    return reports["summary"]
