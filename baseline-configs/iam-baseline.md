# IAM baseline

The standard the lab measures policies against. Short on purpose — a baseline you
can't recite isn't one you'll apply.

## Principles

Identity is the account boundary in cloud, so the rules here are stricter than
they'd be for, say, a firewall ruleset.

- **Deny by default; grant a named need.** Every `Allow` should trace to a
  specific thing a specific principal has to do.
- **Separate human and workload identities.** People assume roles; workloads use
  roles directly. They don't share credentials.
- **Prefer role assumption over long-lived keys.** Short-lived credentials beat a
  key sitting in a config file for months.
- **MFA on privileged interactive actions**, no exceptions that aren't written
  down.

## Controls the lab checks for

1. No administrative wildcard policies attached to day-to-day users.
2. A read-only `security-audit` role for analysts, separate from anything that
   can change the workload.
3. Explicit deny on destructive actions outside the roles meant to perform them.
4. Scheduled review of stale permissions and unused keys.

## Questions to ask of any policy

- Can this principal do *only* what it's supposed to, or more?
- Are the sensitive actions gated behind a role plus MFA?
- If there's a wildcard, is it on the action, the resource, or both — and is it
  written down why?

`scripts/analyze_policy.py` automates the first and third of these.
