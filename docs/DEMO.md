# Six-minute interview demo

Run commands from the repository root with Python 3.11+. They work in PowerShell and Linux. No cloud account, installation, or credentials are needed for the runtime. For a single command, use `python -m cloud_security_lab demo`; outputs go to `artifacts/demo`.

| Time | Action | Explain |
|---|---|---|
| 00:00–00:45 | Open [architecture](architecture.md). | This is synthetic AWS-style state and audit data. No AWS services are connected. |
| 00:45–01:30 | `python -m cloud_security_lab assess fixtures/accounts/risky-environment.json` | Findings come from explicit controls and fixture fields, with fixed severity and no opaque score. |
| 01:30–02:15 | Inspect an IAM finding in the JSON command below. | Explain actions/resources/trust, evidence, and why this is static review rather than effective IAM authorization. |
| 02:15–03:00 | Inspect NET-001 and LOG-001 in that assessment. | Show world-open administrative ingress and the logging flag; configuration alone does not prove reachability or delivery. |
| 03:00–03:45 | `python -m cloud_security_lab detect fixtures/events/demo.json` | Show a supported alert and its source event ID. Mention negative fixtures for benign/failed activity. |
| 03:45–04:30 | Inspect COR-001 and its triage record. | Same account/session, ordered policy change then logging disablement, within 15 minutes. ESCALATE means investigate, not confirmed compromise. |
| 04:30–05:00 | Open the remediated snapshot; run the assessment below. | This is a change to synthetic input. Resource identity is preserved and captured_at is later. |
| 05:00–05:45 | Run verification below. | Closure requires a passing later control evaluation; a status edit cannot close a finding. |
| 05:45–06:15 | Run the demo and open `artifacts/demo/verification.md`. | Inspect reproducible JSON/Markdown evidence and source hashes. |
| 06:15–06:45 | Open [VALIDATION.md](VALIDATION.md) and [limitations](INTERVIEW_NOTES.md). | State the checks actually run and the limits: no live evidence, full IAM evaluator, compliance claim, or production alert-rate claim. |

```console
python -m cloud_security_lab assess fixtures/accounts/risky-environment.json --format json
python -m cloud_security_lab assess fixtures/accounts/remediated-environment.json
python -m cloud_security_lab verify fixtures/accounts/risky-environment.json fixtures/accounts/remediated-environment.json
python -m cloud_security_lab demo
```

For a failed-remediation demonstration, keep a risky condition in a later compatible snapshot and re-run verification. Use the test suite's negative cases as evidence; do not manufacture a passing result or claim a real AWS change.
