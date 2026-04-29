# Sample Findings

## F-001: Console Login Without MFA
- Severity: Medium
- Evidence: `examples/events/cloudtrail-consolelogin-no-mfa.json`
- Risk: Credential abuse harder to detect/prevent.
- Recommendation: Enforce MFA for all console users.

## F-002: Over-Privileged IAM Policy
- Severity: High
- Evidence: `examples/iam/overprivileged-policy.json`
- Risk: Privilege escalation and broad impact potential.
- Recommendation: Replace wildcard permissions with scoped policy.

## F-003: Anomalous IAM Behavior Finding
- Severity: Medium-High
- Evidence: `examples/events/guardduty-credential-access.json`
- Risk: Possible credential compromise or malicious insider activity.
- Recommendation: Investigate principal history and rotate credentials.
