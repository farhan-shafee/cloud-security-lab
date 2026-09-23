# IAM review baseline

The executable checks are `IAM-001` through `IAM-006`; their predicates and limits are in the [control catalog](../docs/controls.md).

| Review condition | Check |
|---|---|
| Allow action contains `*` or `?` | IAM-001 |
| Allow resource is exactly `*` | IAM-002 |
| Allow action pattern includes selected sensitive IAM mutations | IAM-003 |
| Allow can match `iam:PassRole` and uses a wildcard resource | IAM-004 |
| Allow trust names wildcard principal | IAM-005 |
| Unconditioned AssumeRole trust delegates to an external account ID/root | IAM-006 |

These are conservative static review rules. A finding is not proof that the grant is usable. Deny statements, boundaries, SCPs, resource policies, and request conditions can change effective authorization. `Resource: *` is required for some AWS actions and is therefore a review signal, not automatically a least-privilege violation.

Human/workload separation, MFA enforcement, unused-key review, and authorization against business requirements remain useful review questions, but are not snapshot controls in this lab. The event detector observes selected MFA/key activity; that does not establish account-wide identity posture.

Run `python -m cloud_security_lab assess fixtures/accounts/risky-environment.json` or use the preserved [policy analyzer](../examples/iam/policy-analysis.md) on standalone documents.
