# Findings

Three findings from the lab assessment, in the format the report in this folder
draws on. Each one points at the evidence file so a reviewer can check the claim
rather than take it on trust.

## F-001 — Console login without MFA

- **Severity:** Medium
- **Evidence:** `examples/events/cloudtrail-consolelogin-no-mfa.json`
- **Observation:** A successful console sign-in for `analyst-user` with
  `MFAUsed = "No"` from `198.51.100.24`.
- **Impact:** Without MFA, a single leaked password is enough to sign in. The
  account loses its second line of defense against credential theft.
- **Recommendation:** Enforce MFA for all console users; alert on the gap until
  enforcement is confirmed.
- **Validation:** Re-pull sign-in events for the principal and confirm `MFAUsed`
  is `Yes`; confirm `console-login-without-mfa.yml` no longer fires for it.

## F-002 — Over-privileged IAM policy

- **Severity:** High
- **Evidence:** `examples/iam/overprivileged-policy.json`
- **Observation:** A policy granting `Action: *` on `Resource: *`.
- **Impact:** Any principal holding this can take any action in the account,
  including deleting audit logs and creating new administrators. Maximum blast
  radius.
- **Recommendation:** Remove the wildcard grant; replace with task-scoped actions
  and resource ARNs. See `examples/iam/least-privilege-policy.json` for the shape.
- **Validation:** `python3 scripts/analyze_policy.py` exits clean on the
  replacement policy.

## F-003 — Anomalous IAM behavior (possible credential compromise)

- **Severity:** Medium-High
- **Evidence:** `examples/events/guardduty-credential-access.json`
- **Observation:** A GuardDuty finding (severity 6.5) for `CreatePolicyVersion`
  by `analyst-user` from `203.0.113.77`, an API the principal hadn't used before.
- **Impact:** Consistent with either credential compromise or a malicious insider
  attempting privilege escalation via policy edit.
- **Recommendation:** Investigate the principal's recent activity, diff the policy
  version that was created, and rotate the principal's credentials if the change
  is unexplained.
- **Validation:** Confirm the policy version is reverted and the principal's keys
  are rotated; confirm no further anomalous findings for 24h.
