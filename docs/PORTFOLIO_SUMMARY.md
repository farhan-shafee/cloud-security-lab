# Portfolio summary

**One line:** Deterministic AWS-style cloud posture assessment, audit-event detection, and remediation verification using synthetic fixtures.

## Strongest technical evidence

- Typed, versioned snapshots drive explicit IAM, S3, network, and logging checks with normalized findings, source provenance, and separate expected results.
- Re-assessment verifies closure against the same resources and controls in a later snapshot, retains unresolved findings, and reports newly introduced problems.
- Supported audit events produce deterministic alerts and analyst triage; a bounded account/session-aware sequence is tested with negative and boundary cases.

**Technologies:** Python, dataclasses, JSON, pytest, Ruff, mypy, GitHub Actions; Bandit, pip-audit, and Gitleaks as repository quality/security gates. Sigma files remain reference artifacts, not the detection runtime.

**Validation facts:** See [VALIDATION.md](VALIDATION.md) for executed commands, counts, environment, security-check results, commit provenance, and CI status. See [generated evidence](../reports/sample-security-report.md) for the fixture-based workflow. Do not substitute planned checks for recorded outcomes.

**Limitations:** Offline and synthetic; no deployed AWS account, live service integrations, full IAM authorization engine, audited compliance, production false-positive measurements, or automated cloud remediation.

## Suggested résumé bullets

- Built a deterministic Python cloud-security lab that evaluates versioned AWS-style snapshots and produces evidence-backed IAM, storage, network, and logging findings.
- Implemented remediation verification through before/after re-assessment, preserving resource identity and reporting unresolved and newly introduced findings.
- Developed tested audit-event detections and bounded account/session correlation with analyst triage output, reproducible fixtures, and credential-free CI workflows.

**GitHub profile / pinned description:** Deterministic AWS-style cloud posture assessment, audit-event detection, and remediation verification using synthetic fixtures.

Use these statements as descriptions of the repository, not claims of operating the equivalent systems in production.
