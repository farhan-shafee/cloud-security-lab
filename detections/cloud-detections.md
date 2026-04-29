# Cloud Detection Content (Portfolio Examples)

> These are educational examples for portfolio demonstration.

## Detection 1: Console Login Without MFA (CloudTrail-style)

### Logic
Trigger when a successful `ConsoleLogin` event has `additionalEventData.MFAUsed = "No"`.

### Pseudo-query (SQL-like)
```sql
SELECT eventTime, userIdentity.userName, sourceIPAddress
FROM cloudtrail_events
WHERE eventName = 'ConsoleLogin'
  AND responseElements.ConsoleLogin = 'Success'
  AND additionalEventData.MFAUsed = 'No';
```

### Analyst Notes
- Validate if this is an approved exception account.
- Correlate next 15-30 minutes of API activity.

## Detection 2: IAM Policy Version Change (Potential Privilege Escalation)

### Logic
Alert on `CreatePolicyVersion` or `SetDefaultPolicyVersion`, especially outside change windows.

### Pseudo-query
```sql
SELECT eventTime, userIdentity.arn, eventName, sourceIPAddress
FROM cloudtrail_events
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('CreatePolicyVersion', 'SetDefaultPolicyVersion');
```

### Analyst Notes
- Check whether change request/ticket exists.
- Diff old/new policy document and look for wildcard expansion.

## Detection 3: GuardDuty Credential Access Finding

### Logic
Raise incident-review task for findings where `type` starts with `CredentialAccess:` and severity >= 6.

### Pseudo-query
```sql
SELECT updatedAt, accountId, type, severity, title
FROM guardduty_findings
WHERE type LIKE 'CredentialAccess:%'
  AND severity >= 6.0;
```
