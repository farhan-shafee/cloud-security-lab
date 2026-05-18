#!/usr/bin/env python3
"""Lint an AWS IAM policy document for over-broad permissions.

Reads one or more policy JSON files and reports statements that grant more
access than they probably should. It is intentionally opinionated: a wildcard
action is flagged whether or not the author meant it.

Exit status is 1 if any HIGH or CRITICAL finding is reported, so it can gate a
CI job. Standard library only -- no install step.

    python3 scripts/analyze_policy.py examples/iam/overprivileged-policy.json
"""
from __future__ import annotations

import argparse
import json
import sys

# Severity order, worst first. Used for sorting and the summary line.
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Service-wide wildcards on these services are escalation-grade, not just broad.
SENSITIVE_SERVICES = {"iam", "sts", "kms", "organizations"}


def as_list(value):
    """IAM lets Action/Resource be a string or a list; normalize to a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def analyze_statement(stmt, index):
    """Return a list of (severity, message) findings for one statement."""
    findings = []

    # Only Allow statements grant access; a Deny can't over-permission.
    if stmt.get("Effect") != "Allow":
        return findings

    sid = stmt.get("Sid") or f"#{index}"
    actions = as_list(stmt.get("Action"))
    resources = as_list(stmt.get("Resource"))
    has_condition = bool(stmt.get("Condition"))

    # Allow + NotAction is a common foot-gun: it grants everything *except* a
    # list, which is the opposite of least privilege.
    if "NotAction" in stmt:
        findings.append(
            ("MEDIUM", f'Statement "{sid}": Allow + NotAction grants every action '
                       f"except a denylist, which is hard to reason about")
        )

    for action in actions:
        if action == "*":
            findings.append(
                ("CRITICAL", f'Statement "{sid}": Action "*" grants every action '
                             f"in the account")
            )
        elif action.endswith(":*"):
            service = action.split(":", 1)[0].lower()
            sev = "HIGH" if service in SENSITIVE_SERVICES else "MEDIUM"
            findings.append(
                (sev, f'Statement "{sid}": Action "{action}" is a service-wide '
                      f"wildcard (includes destructive and policy-changing calls)")
            )
        elif action.lower() == "iam:passrole" and "*" in resources:
            findings.append(
                ("HIGH", f'Statement "{sid}": iam:PassRole on "*" lets the '
                         f"principal hand any role to a service (privilege escalation)")
            )
        elif "*" in action and not action.endswith(":*"):
            # e.g. s3:Get* -- usually fine, but worth surfacing.
            findings.append(
                ("INFO", f'Statement "{sid}": Action "{action}" contains a '
                         f"wildcard; confirm it only matches intended calls")
            )

    if "*" in resources:
        # Resource:* paired with Action:* is already CRITICAL above; on its own
        # it's still the difference between "one bucket" and "everything".
        findings.append(
            ("HIGH", f'Statement "{sid}": Resource "*" applies the grant to '
                     f"every resource")
        )

    # A wildcard with no Condition has nothing scoping it down.
    if not has_condition and any("*" in a for a in actions):
        findings.append(
            ("LOW", f'Statement "{sid}": wildcard action with no Condition; '
                    f"consider scoping with a condition key")
        )

    # If the statement is already CRITICAL/HIGH, drop the low-value advice on
    # it -- nobody needs a "consider a condition" note on a delete-this grant.
    if any(sev in ("CRITICAL", "HIGH") for sev, _ in findings):
        findings = [f for f in findings if f[0] not in ("LOW", "INFO")]

    return findings


def analyze_policy(path):
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)

    statements = as_list(doc.get("Statement"))
    findings = []
    for i, stmt in enumerate(statements, start=1):
        findings.extend(analyze_statement(stmt, i))

    findings.sort(key=lambda f: SEVERITIES.index(f[0]))
    return findings


def summarize(findings):
    counts = {sev: 0 for sev in SEVERITIES}
    for sev, _ in findings:
        counts[sev] += 1
    parts = [f"{counts[s]} {s.lower()}" for s in SEVERITIES if counts[s]]
    return f"{len(findings)} finding(s): " + ", ".join(parts)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("policy", nargs="+", help="path to an IAM policy JSON file")
    args = parser.parse_args(argv)

    worst_seen = None
    for path in args.policy:
        print(path)
        try:
            findings = analyze_policy(path)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"  [ERROR]    could not read policy: {exc}")
            worst_seen = "CRITICAL"
            continue

        if not findings:
            print("  no findings")
            continue

        for sev, msg in findings:
            print(f"  [{sev}]".ljust(13) + msg)
            if worst_seen is None or SEVERITIES.index(sev) < SEVERITIES.index(worst_seen):
                worst_seen = sev
        print("  " + summarize(findings))

    # Fail the run on anything HIGH or worse so CI can depend on it.
    if worst_seen in ("CRITICAL", "HIGH"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
