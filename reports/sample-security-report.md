# Cloud security assessment — sample report

**Environment:** lab account (single account, one mock application)
**Assessment date:** 2026-05-20
**Author:** Farhan Shafee
**Status:** sample / portfolio

## Executive summary

A review of the lab account's identity posture and recent activity surfaced one
high-severity and two medium-severity issues, all clustered around identity
hygiene and the monitoring of suspicious activity. None reflects a breach; taken
together they describe an account where a single stolen credential would meet
little resistance.

The highest-impact item — an IAM policy granting full administrative access — is
also the cheapest to fix. Closing the three findings below would meaningfully
reduce the account's exposure without any architectural change.

## Scope

- IAM policy posture (standing policies and least-privilege adherence)
- Authentication events (interactive sign-ins and MFA usage)
- Threat-detection findings requiring analyst triage

Out of scope: application security of the mock app, and anything requiring a
second account.

## Findings at a glance

| ID | Finding | Severity |
|----|---------|----------|
| F-001 | Console login without MFA | Medium |
| F-002 | Over-privileged IAM policy (`Action:* / Resource:*`) | High |
| F-003 | Anomalous IAM behavior, possible credential compromise | Medium-High |

Full detail and evidence pointers are in `reports/sample-findings.md`.

## What the findings have in common

All three live on the identity plane. F-002 is the standing risk — the
over-broad policy that turns any credential leak into a full compromise. F-001
makes a leak more likely by removing MFA. F-003 is what the first two look like
once they're being exploited: an unusual principal taking an unusual action.
They're best read as one story, not three unrelated tickets.

## Recommended next steps

1. **Enforce MFA** on all interactive users and remove non-compliant users from
   privileged groups. (Closes F-001, raises the cost of F-003.)
2. **Eliminate the wildcard policy.** Replace `Action:* / Resource:*` with
   scoped grants; run `analyze_policy.py` in CI so it can't come back. (Closes
   F-002.)
3. **Formalize cloud-identity triage.** Wire the GuardDuty finding type from
   F-003 into the runbook in `docs/triage-runbook.md` so the next one is handled
   in minutes, not discovered later.

## How this was validated

Findings were reproduced against the sample events and policies in this repo;
`make validate` and `scripts/analyze_policy.py` back the F-002 claim
mechanically. Re-running both after remediation is the close-out check.
