# IAM Baseline Configuration

## Baseline Principles
- Deny by default; grant minimum required permissions.
- Separate human and workload identities.
- Require MFA for privileged interactive actions.
- Use role assumption instead of long-lived keys when possible.

## Baseline Controls
1. No administrative wildcard policies on day-to-day users.
2. Read-only security-audit role for analysts.
3. Explicit deny for destructive actions outside approved roles.
4. Regular policy review for stale permissions.

## Validation Questions
- Can a user perform only expected actions?
- Are sensitive actions gated by role + MFA?
- Are wildcard actions/resources documented and justified?
