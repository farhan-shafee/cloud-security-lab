# Cloud Security Portfolio Lab

> A **hands-on portfolio lab** for demonstrating practical cloud security skills for junior Cloud Security Engineer / SOC Analyst / Security Analyst roles.
>
> This repository is intentionally framed as a learning and demonstration environment, **not** production enterprise experience.

## Purpose
This lab shows how to:
- Build a baseline cloud security architecture.
- Apply IAM least-privilege principles.
- Inspect cloud audit/security events.
- Triage findings and document remediation.
- Produce artifacts that are useful in interviews and technical screens.

## Portfolio Scope (What this is / is not)
### This repo is
- A reproducible lab with documentation, examples, and validation scripts.
- A skills demonstration aligned to entry-level cloud security job expectations.

### This repo is not
- A claim of real-world enterprise ownership.
- A production deployment guide.
- A substitute for cloud-provider official hardening guides.

## Lab Architecture
See `docs/architecture.md` for a full text diagram and trust boundaries.

High-level components:
1. **Cloud Workload Account/Subscription** (simulated app + storage + compute).
2. **Identity Plane** (roles, policies, least privilege constraints).
3. **Audit & Detection Plane** (CloudTrail-style logs, GuardDuty-style findings, alerts).
4. **Security Operations Plane** (triage runbook + remediation checklist + sample report).

## Workflow
1. Read `docs/methodology.md` to understand the assessment approach.
2. Review architecture in `docs/architecture.md` and threat model in `docs/threat-model.md`.
3. Apply IAM baseline and least-privilege examples in `baseline-configs/iam-baseline.md` and `examples/iam/`.
4. Review logging setup and sample events in `examples/logging-setup.md` and `examples/events/`.
5. Use `scripts/validate_lab.sh` to run basic repository validation checks.
6. Review findings + remediation outputs in `reports/`.

## Setup
### Prerequisites
- Linux/macOS shell (or WSL)
- `bash`, `python3`, `jq`
- Optional: AWS CLI for local policy simulation practice

### Quick start
```bash
make validate
make show-tree
```

## Sample Outputs
### Validation script
```text
[PASS] Required file exists: README.md
[PASS] Required file exists: docs/methodology.md
[PASS] Sample event JSON parses correctly
Validation completed successfully.
```

### IAM policy review snippet
```text
Finding: Policy allows s3:* on *
Risk: Excessive privilege and potential data exposure.
Recommendation: Scope actions/resources to required bucket path and read-only actions.
```

### Event triage snippet
```text
Event: ConsoleLogin with MFAUsed="No"
Severity: Medium
Action: Verify user legitimacy, enforce MFA policy, and review related API activity.
```

## Skills Demonstrated
- Cloud security fundamentals (IAM, logging, monitoring, network boundaries).
- Basic threat modeling and control mapping.
- Security event triage and remediation planning.
- Security documentation and report writing.
- Lightweight automation/validation for repeatability.

## Repository Map
- `docs/` - methodology, architecture, threat model, remediation checklist, triage runbook.
- `baseline-configs/` - baseline hardening guidance.
- `examples/iam/` - least-privilege and over-privileged policy examples + analysis.
- `examples/events/` - CloudTrail-style and GuardDuty-style sample events.
- `reports/` - sample findings and assessment report artifacts.
- `detections/` - detection logic and analyst-oriented pseudo-queries.
- `compliance-mapping.md` - conceptual control mappings to common standards.
- `scripts/` - validation helpers.
- `.github/workflows/` - CI checks.


## SOC / Cloud Security Analyst Portfolio Artifacts
- Detection content: `detections/cloud-detections.md`
- Triage runbook: `docs/triage-runbook.md`
- Sample findings/report package: `reports/sample-findings.md`, `reports/sample-security-report.md`
- Control mapping reference: `compliance-mapping.md`

## Limitations
- Uses sample data and representative configurations.
- Does not include live cloud account deployment by default.
- Detection logic is illustrative and should be tuned per environment.

## Suggested Interview Walkthrough
1. Explain architecture and trust boundaries.
2. Compare over-privileged vs least-privilege IAM policies.
3. Walk through one suspicious event and triage steps.
4. Show remediation checklist and final findings report.
