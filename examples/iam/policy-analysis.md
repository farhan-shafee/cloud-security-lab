# IAM Policy Analysis (Sample)

## Policy A: Over-Privileged
File: `overprivileged-policy.json`

### Observation
- Grants `Action: *` on `Resource: *`.

### Risk
- Full account compromise potential if principal is abused.
- Violates least-privilege principle.

### Recommendation
- Replace wildcard permissions with task-scoped actions and resource ARNs.
- Add explicit deny for destructive actions where possible.

## Policy B: Scoped Read Access
File: `least-privilege-policy.json`

### Observation
- Restricts actions to `s3:GetObject` and `s3:ListBucket` for one bucket/prefix.

### Security Benefit
- Limits blast radius.
- Aligns with read-only analyst or app-log-consumer use case.
