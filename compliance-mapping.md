# Related control references

This is an educational reference map, not a compliance assessment, certification, CIS benchmark implementation, NIST conformity assertion, or substitute for AWS native security services. Only executable checks are listed. References explain relevant AWS behavior; they do not endorse the lab's severity or prove its checks complete.

| Implemented checks | Related reference | Boundary of the check |
|---|---|---|
| IAM-001–IAM-003: broad statements and selected mutations | [AWS policy evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html), [Resource element](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html) | Static statement review; no effective authorization, and some actions require `Resource: *`. |
| IAM-004: wildcard role passing | [AWS PassRole](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html) | Permission-pattern review; no complete escalation-path proof. |
| IAM-005–IAM-006: selected broad trust | [AWS Principal element](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html) | Selected principal/condition patterns, not full trust evaluation. |
| S3-001: missing bucket Block Public Access flags | [S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html) | Guardrail gap; account/organization/access-point settings and policies are not evaluated. |
| S3-002: sensitive bucket encryption policy | [S3 encryption defaults](https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-encryption-faq.html) | Lab requires customer-managed SSE-KMS; SSE-S3 is encrypted, not an unencrypted bucket. |
| S3-003: versioning | [S3 Versioning](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html) | Boolean configuration check; does not prove retention or immutability. |
| NET-001–NET-002: world-open ingress | [VPC security-group rules](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html) | Selected ingress predicates; no end-to-end reachability analysis. |
| LOG-001–LOG-003: trail and destination configuration | [Multi-Region trails](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html), [CloudTrail integrity validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html) | Modeled logging/coverage/bucket baseline; no delivery, selectors, retention, or signed-digest verification. |

Earlier CIS/NIST IDs were removed because several pointed only to prose or broader controls than the code demonstrates. Any future framework mapping needs a versioned source, exact applicability, executable evidence, and a documented gap analysis. [The control catalog](docs/controls.md) is the authoritative description of lab predicates.
