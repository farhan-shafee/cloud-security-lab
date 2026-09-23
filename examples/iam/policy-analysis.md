# IAM policy walkthrough

These three original documents remain standalone teaching inputs. They are evaluated by the same static IAM logic used for snapshot assessment:

```console
python scripts/analyze_policy.py examples/iam/overprivileged-policy.json
python scripts/analyze_policy.py examples/iam/least-privilege-policy.json
python scripts/analyze_policy.py examples/iam/subtle-overprivilege-policy.json
```

## Broad grant

`overprivileged-policy.json` contains Allow `Action: *`, `Resource: *`. This is an administrative grant pattern and also encompasses selected sensitive IAM mutations and role passing. The analyzer reports the statement evidence. It cannot conclude that the holder can perform every account operation: explicit denies, boundaries, Organizations policies, resource policies, and runtime context are not evaluated. [AWS evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html).

## Scoped S3 example

`least-privilege-policy.json` names `s3:GetObject`, `s3:ListBucket`, one bucket, an object prefix, and a TLS condition. Its historical filename is retained; a clean lint result is not proof of least privilege.

The object ARN limits object reads to `app/*`. Bucket listing is not restricted by an `s3:prefix` condition and can reveal names elsewhere in the bucket. The TLS condition constrains this Allow; it is not a global explicit Deny for plaintext requests. The policy is not attached to a modeled analyst role. See [AWS S3 condition examples](https://docs.aws.amazon.com/AmazonS3/latest/userguide/amazon-s3-policy-keys.html).

## Subtle overprivilege

`subtle-overprivilege-policy.json` scopes `s3:*` to a bucket but retains broad action coverage. Its `iam:PassRole` grant on `*` also deserves review. Passing a powerful role becomes dangerous when a principal can use a service with that role; the static check does not prove the complete escalation path. Scope approved roles and consider the `iam:PassedToService` condition. [AWS PassRole guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html).

Review actions, resources, trust, and the task requirement separately. Some AWS operations require wildcard resources. The lab intentionally flags those for review and does not ship a complete service authorization catalog. See [supported IAM semantics](../../docs/controls.md).
