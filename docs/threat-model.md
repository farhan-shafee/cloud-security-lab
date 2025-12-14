# Threat model

Scoped to the account in `docs/architecture.md`. The framing is attacker-goal
first: what someone would actually be trying to do, the technique they'd reach
for, the signal it leaves, and the control that's supposed to catch it. ATT&CK
technique IDs are included where they map cleanly so the detections downstream
have something to anchor to.

## In scope

- IAM misuse and privilege escalation
- Unauthorized or anomalous API activity
- Suspicious interactive sign-ins
- Object-storage exposure

Out of scope for this lab: application-layer vulns in the mock app, supply-chain
compromise of the deployment pipeline, and anything requiring a second account.

## Scenarios

### 1. Stolen credentials, used directly (T1078 — Valid Accounts)

An attacker with a leaked access key or password signs in and operates as a
legitimate user. The tell in this lab is a `ConsoleLogin` with `MFAUsed = "No"`
from an unfamiliar IP — `examples/events/cloudtrail-consolelogin-no-mfa.json`.

- **Control:** enforce MFA on all interactive users; alert on the gap.
- **Why it's nasty:** valid creds blend in. Detection leans on *where* and *when*
  more than *who*.

### 2. Privilege escalation via policy edit (T1098 — Account Manipulation)

A principal with `iam:CreatePolicyVersion` quietly widens a policy it's attached
to, then uses the new permissions. The signal is an IAM write event outside any
change window, especially one that adds `Action: *` or `Resource: *`.

- **Control:** restrict who can edit IAM; diff every policy version; alert on
  wildcard expansion. `analyze_policy.py` is the offline version of that check.

### 3. Reconnaissance (T1580 — Cloud Infrastructure Discovery)

Before doing damage, an attacker enumerates: `ListBuckets`, `ListRoles`,
`GetAccountAuthorizationDetails`, `DescribeInstances`. A burst of `List*` /
`Describe*` calls from one principal in a short window is the pattern.

- **Control:** baseline normal API volume per principal; alert on discovery
  spikes. High-noise on its own, so it's a *correlation* signal, not a page.

### 4. Data exposure (T1530 — Data from Cloud Storage)

A bucket policy or ACL is loosened to public, or a broad `s3:GetObject` grant
lets the wrong principal read application data.

- **Control:** block public access at the account level; scope storage grants to
  a single bucket and prefix, as `least-privilege-policy.json` does.

## Residual risk

Even with every control above in place, compromised *legitimate* credentials
used *carefully* will look like normal activity. There is no clean detection for
"the right user doing the right things for the wrong reason." That gap is why the
lab leans on continuous logging and periodic policy review rather than assuming
any single alert will catch everything.
