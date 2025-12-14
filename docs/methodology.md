# Methodology

The lab follows the same loop a small security team would use to assess one
account: figure out what you're protecting, work out how it could go wrong,
check the controls that are supposed to stop that, practice triaging the alerts
those controls produce, and write the result down so it can be acted on.

## The loop

1. **Scope the environment.** Identify the assets, the identities that can touch
   them, and the boundaries between trust levels. This is `docs/architecture.md`.
2. **Model the threats.** Work top-down from attacker goals (STRIDE as a prompt,
   ATT&CK for the specific techniques) rather than enumerating every control.
   This is `docs/threat-model.md`.
3. **Review the controls.** Compare the actual config against a baseline for IAM,
   logging, and network exposure — see `baseline-configs/` and `examples/`.
4. **Triage.** Take the events the controls generate and decide, for each one,
   whether it's noise, something to watch, or something to escalate. This is
   `docs/triage-runbook.md`.
5. **Write it up.** Every finding gets an observation, an impact, evidence, and a
   fix someone can verify. This is `reports/`.

Steps 3-5 are where most of the time goes, which matches real work: the hard
part is rarely knowing that MFA is good, it's deciding whether *this* login at
*this* time is a problem and writing it up convincingly.

## How findings are rated

Severity is `likelihood x impact`, kept deliberately coarse so it's defensible
in a five-minute conversation rather than precise to two decimal places.

| | Low impact | Medium impact | High impact |
|---|---|---|---|
| **High likelihood** | Low | Medium | High |
| **Medium likelihood** | Low | Medium | High |
| **Low likelihood** | Info | Low | Medium |

A finding that scores High but has a cheap, obvious fix (enable MFA) still gets
written up plainly — severity drives urgency, not how much prose it gets.

## What a finding has to contain

A finding nobody can act on is just an opinion. Each one in this lab carries:

- **Observation** — what was seen, stated plainly.
- **Why it matters** — the impact in terms of the asset, not the control.
- **Evidence** — a specific event or policy snippet, pointed to by file.
- **Recommendation** — a concrete fix.
- **Validation** — how to confirm the fix actually took.

## Mapping to roles

The same artifacts read differently depending on the seat:

- **SOC analyst** lives in the triage runbook and the event samples — speed and
  correct escalation.
- **Security analyst** lives in the findings and the report — risk articulation
  and a write-up a stakeholder will read.
- **Cloud security engineer** lives in the IAM baseline and `analyze_policy.py` —
  getting the control right once so it holds.
