# Posture control catalog

The evaluator implements 14 controls over supplied resources. Source of truth: [`CONTROLS` and predicates](../cloud_security_lab/posture.py), [IAM checks](../cloud_security_lab/iam.py). Each control has fixed severity, remediation, references, and limitations in generated output.

| ID | Severity | Failing condition | Evidence / remediation direction |
|---|---|---|---|
| IAM-001 | MEDIUM | Allow action contains `*` or `?`. | Statement ID and matched patterns; name required operations. |
| IAM-002 | MEDIUM | Allow resource contains the exact value `*`. | Statement ID and universal resource; scope supported actions and justify actions that require `*`. |
| IAM-003 | HIGH | Allow action pattern matches at least one selected IAM mutation listed below. | Matched operations; remove unnecessary administration and independently review required grants. |
| IAM-004 | HIGH | Allow pattern matches `iam:PassRole` and a resource contains `*` or `?`. | Matched resource patterns; constrain role ARNs and review destination services. |
| IAM-005 | HIGH | Allow role trust includes wildcard Principal `*` or `AWS: *`. | Statement ID and condition presence; review explicit principals and constraints. |
| IAM-006 | MEDIUM | Allow AssumeRole trust delegates to an external 12-digit account ID/root ARN without any supported Condition. | External principals; review delegated trust and applicable conditions. |
| S3-001 | MEDIUM | Any of the four bucket Block Public Access flags is false. | Disabled flags; enable required guardrails. |
| S3-002 | MEDIUM | A bucket marked sensitive lacks `aws:kms` encryption with `key_manager: CUSTOMER`. | Encryption configuration; meet the lab's customer-managed-key baseline. |
| S3-003 | LOW | Bucket versioning is false. | Versioning value; enable version recovery and choose retention separately. |
| NET-001 | HIGH | Explicit IPv4/IPv6 `/0` ingress allows TCP 22 or 3389, or all protocols. | Matching rules; restrict sources and management access. |
| NET-002 | HIGH | Explicit IPv4/IPv6 `/0` ingress allows all protocols. | Matching rules; name required protocols, ports, and sources. |
| LOG-001 | HIGH | A supplied trail has `is_logging: false`. | Logging flag; enable logging and independently verify delivery. |
| LOG-002 | MEDIUM | A supplied trail's covered regions omit any required region. | Required/covered/missing regions; configure complete required coverage. |
| LOG-003 | MEDIUM | Referenced log bucket lacks any BPA flag, customer-managed SSE-KMS, or versioning. | Destination and missing settings; meet the destination baseline. |

`IAM-003` matches these operations case-insensitively, including wildcard expansion against this fixed list: `CreatePolicyVersion`, `SetDefaultPolicyVersion`, `AttachUserPolicy`, `AttachRolePolicy`, `AttachGroupPolicy`, `PutUserPolicy`, `PutRolePolicy`, `PutGroupPolicy`, `UpdateAssumeRolePolicy`, and `CreateAccessKey`, all under `iam:`. It is not a complete privilege-escalation catalog.

## IAM semantics

The parser supports `Allow` and `Deny`, string/list actions/resources, an object or nonempty array of statements, optional unique Sids, and selected structurally validated conditions. Policy `Version`, when supplied, must be `2012-10-17`. Identity policies require Resource and omit Principal; trust policies require Principal and support only `sts:AssumeRole`. Trust supports commercial-partition AWS account/root/user/role principals and service principals.

`NotAction`, `NotResource`, `NotPrincipal`, resource policy variables, federated trust, unsupported fields, unsupported condition keys/operators, and unsupported partitions fail explicitly. Supported condition operators are `StringEquals`, `StringLike`, `ArnEquals`, `ArnLike`, and `Bool`; the bounded key allowlist and structural checks are in [`CONDITION_KEYS`](../cloud_security_lab/iam.py). `aws:SecureTransport` is supported structurally with Bool for the original S3 example. Conditions are preserved as structure, not evaluated against runtime context.

Only Allow statements produce static findings. A standalone Deny does not grant access and does not produce these findings, but a Deny does not suppress a separate broad-Allow warning either. The analyzer does not calculate effective permissions across policies, boundaries, SCPs, sessions, resource policies, or request conditions. A clean result does not prove least privilege.

`Resource: *` is necessary for some AWS actions. IAM-002 is deliberately a MEDIUM review signal, not automatic proof of improper access. Likewise an action wildcard might be read-only, PassRole alone does not prove a usable escalation path, and condition presence passes only IAM-006's missing-condition check. It does not establish safe trust.

## Configuration limits

S3-001 detects a missing bucket guardrail, not actual public access. Other scope-level BPA settings, ACLs, and policies are not modeled. SSE-S3 (`AES256`) is already encryption; S3-002 enforces a stronger lab-specific requirement and does not inspect old objects, key policy, or ciphertext. Versioning is not immutable retention.

Network controls inspect configured ingress only, not routes, NACLs, attached workloads, egress, source security-group references, equivalent unions of narrower CIDRs, or ports beyond 22/3389. An all-protocol `/0` rule intentionally matches NET-001 and NET-002.

Logging checks inspect each supplied trail independently. They do not infer coverage from a different trail or verify event selectors, delivery, signed digests, retention, Object Lock, or bucket/key permissions. A log destination must exist in the input; a dangling reference is an input error.

## Findings and evaluations

Each resource/control receives `PASS` or `FAIL`. At most one finding is emitted for each failing resource/control, with all matching evidence included. A finding contains `finding_id`, `control_id`, title, severity, resource ID/type, status, reason, evidence, remediation, references, and limitations.

The finding ID hashes account, resource type, resource ID, and control ID; changing evidence within the same condition does not create a new identity. Findings and evaluations sort by control, type, and resource. Initial status is `OPEN`; [verification](remediation-checklist.md) can derive `VERIFIED_CLOSED` only from later evidence.

`controls_executed` identifies the catalog considered. Evaluations show which controls actually applied to which resources. Empty resource-type arrays do not establish that the real account has no such resources, and this lab does not detect incomplete inventory.

See [fixture contracts](fixtures.md), [educational AWS references](../compliance-mapping.md), and [executed validation](VALIDATION.md).
