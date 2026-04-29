# Threat Model (Portfolio Lab)

## Scope
- IAM misuse
- Unauthorized API activity
- Suspicious sign-in behavior
- Data access misconfiguration

## Threat Scenarios
1. **Credential misuse**: attacker logs in without MFA.
2. **Privilege escalation**: overly broad IAM policy abused.
3. **Recon activity**: excessive API listing calls.
4. **Data exposure**: permissive object storage access.

## Example Controls
- Enforce MFA and conditional access controls.
- Restrict IAM actions/resources.
- Enable audit logs and anomaly detection.
- Alert on suspicious API patterns.

## Residual Risk Notes
Even with controls, compromised legitimate credentials can blend with normal activity. Continuous monitoring and periodic policy review are required.
