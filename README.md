# cloud-security-lab

A hands-on lab for practicing the day-to-day work of a cloud security / SOC
analyst: reading IAM policies and spotting the dangerous one, deciding whether a
sign-in event is worth escalating, and writing findings so the person who has to
fix them actually can.

It runs entirely on sample data. There's no live AWS account wired up, so you can
clone it, run the checks, change things, and re-run without spending a cent or
touching anything real. The value is in the analysis and the write-ups, not the
infrastructure.

> **Scope.** This is a learning lab, not a production hardening guide. The
> detections are starting points that need tuning, and the sample events are
> trimmed-down versions of the real records. Treat it as a worked example, not a
> drop-in control set.

## Quick start

```bash
# structure + JSON/policy sanity checks
make validate

# lint an IAM policy for over-broad permissions
python3 scripts/analyze_policy.py examples/iam/overprivileged-policy.json
```

Run against the deliberately-bad policy, `analyze_policy.py` prints:

```
examples/iam/overprivileged-policy.json
  [CRITICAL] Statement "OverPrivileged": Action "*" grants every action in the account
  [HIGH]     Statement "OverPrivileged": Resource "*" applies the grant to every resource
  2 finding(s): 1 critical, 1 high
```

Point it at `least-privilege-policy.json` and it exits 0 with nothing to report.

## Repository layout

| Path | What's there |
|------|--------------|
| `docs/` | Methodology, architecture (with diagram), threat model, triage runbook, remediation checklist |
| `baseline-configs/` | IAM and network baselines the lab assesses against |
| `examples/iam/` | A deliberately over-privileged policy, a least-privilege counterpart, and a written analysis of both |
| `examples/events/` | CloudTrail and GuardDuty sample records used by the detections and the runbook |
| `detections/` | Detection logic in plain English, plus Sigma rules under `detections/sigma/` |
| `reports/` | A worked findings list and an assessment report written the way you'd hand it to a stakeholder |
| `scripts/` | `analyze_policy.py` (IAM linter) and `validate_lab.sh` (repo checks) |
| `compliance-mapping.md` | Each lab control mapped to the relevant CIS / NIST reference |

## Suggested reading order

Going through this cold, this order makes the most sense:

1. `docs/methodology.md` — how the assessment is framed.
2. `docs/architecture.md` — the environment under test and where the trust boundaries sit.
3. `examples/iam/policy-analysis.md` — the over-privileged vs. least-privilege walkthrough.
4. `docs/triage-runbook.md`, with `examples/events/` open alongside, to work an alert end to end.
5. `reports/sample-security-report.md` — where it all lands.

## Requirements

- A POSIX shell (Linux, macOS, or WSL on Windows)
- `python3` 3.8+ and `jq` for the validation script

No cloud credentials or paid services are needed.

## License

MIT — see [`LICENSE`](LICENSE).
