#!/usr/bin/env python3
"""Compatibility entry point for bounded offline IAM Allow-statement lint.

Exit 1 means a HIGH finding; 2 means invalid or unsupported input; 0 means no
HIGH findings. This is a static review helper, not AWS effective permissions.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Keep direct checkout execution compatible without an installation step.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cloud_security_lab.errors import FixtureError  # noqa: E402
from cloud_security_lab.fixtures import read_json  # noqa: E402
from cloud_security_lab.iam import inspect_policy, parse_policy  # noqa: E402
from cloud_security_lab.posture import CONTROLS  # noqa: E402

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def analyze_policy(path: str | Path) -> list[tuple[str, str]]:
    document, _ = read_json(Path(path))
    issues = inspect_policy(parse_policy(document), account_id="111122223333")
    controls = {control.id: control for control in CONTROLS}
    findings = []
    for identifier, evidence in issues.items():
        control = controls[identifier]
        statements = ", ".join(str(item["statement_id"]) for item in evidence)
        findings.append(
            (control.severity, f"{identifier}: {control.title} (statements: {statements})")
        )
    return sorted(findings, key=lambda finding: (SEVERITIES.index(finding[0]), finding[1]))


def summarize(findings: list[tuple[str, str]]) -> str:
    counts = {severity: sum(level == severity for level, _ in findings) for severity in SEVERITIES}
    detail = ", ".join(
        f"{counts[severity]} {severity.lower()}" for severity in SEVERITIES if counts[severity]
    )
    return f"{len(findings)} finding(s): {detail}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("policy", nargs="+", help="path to an IAM policy JSON document")
    args = parser.parse_args(argv)
    exit_code = 0
    for path in args.policy:
        print(path)
        try:
            findings = analyze_policy(path)
        except FixtureError as exc:
            print(f"  [ERROR] {exc}")
            exit_code = 2
            continue
        if not findings:
            print("  no findings within the supported static checks")
            continue
        for severity, message in findings:
            print(f"  [{severity}] {message}")
            if severity in {"HIGH", "CRITICAL"} and exit_code < 1:
                exit_code = 1
        print("  " + summarize(findings))
        print(
            "  Static Allow review; conditions and Deny are not evaluated. "
            "Resource '*' can be required by AWS."
        )
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
