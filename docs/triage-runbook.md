# Cloud Alert Triage Runbook (Portfolio)

## Use Case A: ConsoleLogin without MFA
1. Confirm event integrity and timestamp.
2. Identify principal, source IP, and user agent.
3. Validate if account is exempt (documented break-glass process).
4. Review adjacent API calls for suspicious behavior.
5. Contain (disable keys/session) if unauthorized.
6. Open finding and track remediation.

## Use Case B: IAM Policy Change Alert
1. Identify actor and changed policy ARN.
2. Compare previous and new policy version.
3. Look for privilege expansion (`Action:*`, `Resource:*`, iam:PassRole abuse).
4. Validate change authorization.
5. Roll back if unauthorized and rotate potentially exposed credentials.

## Escalation Criteria
- High severity finding + no approved change window.
- Any evidence of credential compromise.
- Lateral movement indicators or repeated denied auth anomalies.
