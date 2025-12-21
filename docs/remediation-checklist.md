# Remediation checklist

Ordered roughly by impact-per-effort — the things near the top buy the most
security for the least work, which is usually the order you want to fix them in.
Each item maps to a finding or control elsewhere in the lab.

## Identity (do these first)

- [ ] Enforce MFA for every interactive user. Cheap, high impact, closes F-001.
- [ ] Remove wildcard (`*`) actions from IAM policies unless there's a written
      justification. `analyze_policy.py` flags these for you.
- [ ] Scope IAM `Resource` entries to specific ARNs instead of `*`.
- [ ] Replace long-lived access keys with role assumption where the workload
      allows it.

## Logging and detection

- [ ] Turn on account-level audit logging (CloudTrail equivalent) in every region.
- [ ] Set log retention and a tamper-evidence control (object lock / immutability).
- [ ] Route high-severity findings into an incident workflow instead of an inbox.

## Process

- [ ] Document the break-glass / MFA-exempt account list, so triage step A.2 has
      something to check against.
- [ ] Define change windows for IAM edits, so policy-change alerts have a baseline.

## Closing the loop

- [ ] Re-run `make validate` and `analyze_policy.py` after a policy fix.
- [ ] Confirm the original detection no longer fires on the corrected config.

A fix isn't done when it ships — it's done when the signal that prompted it stops
reproducing.
