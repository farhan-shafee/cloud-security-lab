# Control mapping

Each control the lab exercises, mapped to the matching CIS AWS Foundations
Benchmark (v1.4.0) recommendation and NIST SP 800-53 Rev 5 control, with a
pointer to the file that demonstrates it.

This is a self-assessment for learning, not an audit assertion. It shows the lab
controls *line up* with recognized references — it doesn't claim a certified
environment.

| Lab control | CIS AWS Foundations v1.4.0 | NIST 800-53 Rev 5 | Evidence |
|---|---|---|---|
| MFA for interactive users | 1.10 | IA-2(1) | `docs/remediation-checklist.md`, detection `sigma/console-login-without-mfa.yml` |
| No full-admin wildcard policies | 1.16 | AC-6, AC-6(1) | `examples/iam/overprivileged-policy.json`, `scripts/analyze_policy.py` |
| Least-privilege IAM policies | 1.15 | AC-6 | `examples/iam/least-privilege-policy.json` |
| Multi-region audit logging | 3.1 | AU-2, AU-12 | `examples/logging-setup.md` |
| Log file integrity / tamper-evidence | 3.2 | AU-9 | `examples/logging-setup.md` |
| Restrict public admin ports | 5.2 | SC-7, AC-4 | `baseline-configs/network-baseline.md` |
| Detection + triage workflow | — | IR-4, SI-4 | `docs/triage-runbook.md`, `detections/cloud-detections.md` |

## Notes

- CIS numbering shifts between benchmark versions; the IDs above are pinned to
  v1.4.0. If you compare against v3.0 the recommendation text is stable but the
  numbers move.
- The triage workflow has no single CIS line because CIS is mostly
  configuration-state; the process controls map more naturally to the NIST IR
  family.
