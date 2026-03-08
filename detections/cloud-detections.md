# Detections

Three detections, each written twice: once in plain English here (the reasoning),
and once as a Sigma rule under `detections/sigma/` (the portable artifact). Sigma
converts to Splunk SPL, Sentinel KQL, Elastic, and others, so the logic isn't
welded to one backend.

Each one carries false-positive notes, because a detection without them is a
pager that never sleeps. The honest measure of a rule is how well it survives
contact with real traffic, not how cleanly it catches the one event you built it
against.

## 1. Console login without MFA

**File:** `sigma/console-login-without-mfa.yml` · **Severity:** Medium · **T1078**

Fire on a successful `ConsoleLogin` with `additionalEventData.MFAUsed = "No"`.

```sql
-- reference SQL for a CloudTrail table; the Sigma rule is the source of truth
SELECT eventTime, userIdentity.userName, sourceIPAddress
FROM cloudtrail_events
WHERE eventName = 'ConsoleLogin'
  AND responseElements.ConsoleLogin = 'Success'
  AND additionalEventData.MFAUsed = 'No';
```

**Tuning.** The big false-positive source is federated sign-in, where MFA is
enforced at the identity provider and AWS never sees it. If you use SAML/SSO,
scope this rule to IAM-user logins or it will cry wolf on every SSO session. Keep
a reviewed allowlist of any genuine break-glass accounts.

## 2. IAM policy version change

**File:** `sigma/iam-policy-version-change.yml` · **Severity:** Medium · **T1098**

Fire on `CreatePolicyVersion` or `SetDefaultPolicyVersion`, then correlate
against change tickets.

```sql
SELECT eventTime, userIdentity.arn, eventName, sourceIPAddress
FROM cloudtrail_events
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('CreatePolicyVersion', 'SetDefaultPolicyVersion');
```

**Tuning.** Infrastructure-as-code pipelines do this all day. Filter on the
CI/CD principal ARN so the rule only fires on *human* or *unexpected* IAM edits.
The value-add over the raw event is the diff: pair the alert with
`analyze_policy.py` against the new version to flag wildcard expansion
automatically.

## 3. Discovery burst

**File:** `sigma/iam-discovery-burst.yml` · **Severity:** Low · **T1580**

Count `List*` / `Describe*` calls per principal in a short window; alert above a
threshold.

**Tuning.** This one is deliberately noisy and shipped at Low for a reason — it's
a *correlation* signal, not a standalone page. CSPM tools, backup jobs, and the
AWS console itself all enumerate constantly, so the threshold (`> 50` in 5
minutes in the sample) and the allowlist matter more than the rule text. It earns
its keep when it lines up with detection 1 or 2 on the same principal, not on its
own.
