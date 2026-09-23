# Cloud Security Engineering Lab

Deterministic AWS-style cloud posture assessment, audit-event detection, and remediation verification using synthetic fixtures.

The lab demonstrates IAM least-privilege review, configuration checks, normalized findings, analyst triage, and evidence-backed closure. Everything runs locally without AWS credentials or paid resources. No AWS services are connected.

## Quick demo

From the repository root with Python 3.11+; the same command works in PowerShell and Linux:

```console
python -m cloud_security_lab demo
```

Actual demo summary:

```text
Synthetic demo: 14 controls; 17 findings -> 17 VERIFIED_CLOSED; 6 alerts; 1 correlation(s).
```

JSON and Markdown evidence is written to `artifacts/demo`. `make demo` is an optional equivalent; WSL is unnecessary. See the committed [generated reports](reports/sample-security-report.md) or the [six-minute walkthrough](docs/DEMO.md).

## Workflow

```text
Synthetic snapshot → validation → 14 posture controls → normalized findings
Later snapshot    → re-assessment → verified closure / unresolved / new findings
Synthetic events  → normalization → 6 detections → bounded correlation → triage
Both paths        → deterministic JSON and Markdown evidence
```

Controls cover selected IAM grants/trust, bucket guardrails/encryption/versioning, administrative network exposure, and audit logging. A policy-change → logging-disable sequence correlates only within the same account and exact principal/session, in order, within 15 minutes. [Architecture](docs/architecture.md) · [Control catalog](docs/controls.md) · [Detection predicates](detections/cloud-detections.md).

## Generated example

Selected fields from the demo's `before.json`:

```json
{
  "control_id": "NET-001",
  "severity": "HIGH",
  "resource_id": "sg-workload",
  "status": "OPEN",
  "evidence": [
    {"cidr": "0.0.0.0/0", "from_port": null, "protocol": "-1", "to_port": null},
    {"cidr": "::/0", "from_port": 3389, "protocol": "tcp", "to_port": 3389}
  ]
}
```

Selected fields from `verification.json` after assessing the remediated fixture:

```json
{
  "control_id": "NET-001",
  "resource_id": "sg-workload",
  "before_status": "FAIL",
  "after_status": "PASS",
  "status": "VERIFIED_CLOSED"
}
```

This is **synthetic configuration remediation verification**. Closure is computed from a later compatible snapshot and a passing resource/control evaluation; editing a finding's status cannot close it.

## Commands

```console
python -m cloud_security_lab assess fixtures/accounts/risky-environment.json
python -m cloud_security_lab assess fixtures/accounts/secure-baseline.json --format json
python -m cloud_security_lab detect fixtures/events/demo.json
python -m cloud_security_lab verify fixtures/accounts/risky-environment.json fixtures/accounts/remediated-environment.json
python -m cloud_security_lab validate-fixtures
python scripts/analyze_policy.py examples/iam/subtle-overprivilege-policy.json
```

`assess`, `detect`, and `verify` support `--format text|json|markdown` and `--output PATH`. Assessment/detection exit 0 on valid input, or 1 on findings with `--fail-on-findings`. Verification exits 1 for unresolved/new findings; invalid input exits 2. The standalone policy linter retains its HIGH+ failure gate.

## Validation

```console
python -m pip install -r requirements-dev.lock
python -m pip install -e .
python -m pytest
python scripts/validate_lab.py
```

[CONTRIBUTING.md](CONTRIBUTING.md) lists formatting, lint, typing, security, and dependency-audit commands. CI covers Windows/Linux and Python 3.11/3.14; [VALIDATION.md](docs/VALIDATION.md) records executed results and CI status. Expected outcomes live separately from evaluator code in `fixtures/ground_truth`.

## Scope and limitations

- IAM analysis is bounded static review, not the AWS effective-permission engine. Deny, conditions, other policies, and business requirements can change the meaning of a grant. Unsupported constructs fail explicitly.
- Bucket guardrail gaps do not prove public exposure. SSE-S3 is encrypted; the lab's sensitive-bucket baseline specifically requires customer-managed SSE-KMS.
- Configuration flags do not prove network reachability, log delivery, immutable retention, or deployed remediation. Input hashes identify bytes, not authenticated AWS evidence.
- Alerts request review; correlation escalates priority without declaring an actor malicious. There is no production false-positive-rate claim.
- No live AWS, native security-service integration, compliance certification, graph database, AI service, Terraform deployment, or destructive automation is included. Original Sigma and GuardDuty examples remain labeled references.

[Fixture contracts](docs/fixtures.md) · [Threat model](docs/threat-model.md) · [Triage runbook](docs/triage-runbook.md) · [Interview notes](docs/INTERVIEW_NOTES.md) · [Portfolio summary](docs/PORTFOLIO_SUMMARY.md) · [Related AWS references](compliance-mapping.md).

MIT licensed; see [LICENSE](LICENSE).
