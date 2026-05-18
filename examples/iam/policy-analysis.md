# IAM policy analysis

Three policies, read the way you'd read them in a review: the obviously bad one,
the one that's actually fine, and the one that looks fine and isn't. The third is
the point — the dangerous policies in real accounts rarely say `Action: *`.

Run any of them through the linter to see the same reasoning in tool form:

```bash
python3 scripts/analyze_policy.py examples/iam/subtle-overprivilege-policy.json
```

## Policy A — `overprivileged-policy.json`

```json
{ "Effect": "Allow", "Action": "*", "Resource": "*" }
```

**Read:** this grants every action on every resource. It is administrator access
by another name.

**Risk:** any principal holding this can do anything in the account, including
deleting logs and creating new admin users. If the credential leaks, the whole
account is gone — there's no blast-radius left to contain.

**Fix:** delete it. Replace with task-scoped statements naming the exact actions
and resource ARNs the principal needs. If something genuinely needs broad
access, it should be a tightly controlled role with MFA and a condition, not a
standing user policy.

## Policy B — `least-privilege-policy.json`

```json
{ "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:ListBucket"],
  "Resource": ["arn:aws:s3:::portfolio-lab-app-logs",
               "arn:aws:s3:::portfolio-lab-app-logs/app/*"],
  "Condition": { "Bool": { "aws:SecureTransport": "true" } } }
```

**Read:** read-only access to one bucket and one prefix, and only over TLS.

**Why it's good:** named actions, named resources, and a condition that blocks
plaintext access. This is the shape a log-reader or read-only analyst role should
have. The blast radius if it leaks is "someone can read app logs over HTTPS" —
bad, but bounded.

The linter exits clean on this one. That's the bar.

## Policy C — `subtle-overprivilege-policy.json`

```json
{ "Sid": "AppBucketFullAccess", "Action": "s3:*",
  "Resource": ["arn:aws:s3:::portfolio-lab-app-logs",
               "arn:aws:s3:::portfolio-lab-app-logs/*"] }
{ "Sid": "PassAnyRole", "Action": "iam:PassRole", "Resource": "*" }
```

**Read:** this is the one that passes a casual glance. The resources *are*
scoped to the app bucket, so it looks careful. Two problems:

1. **`s3:*` is a service-wide wildcard.** Scoped to a bucket, yes, but it still
   grants `DeleteBucket`, `PutBucketPolicy`, `PutBucketAcl` — i.e. the holder can
   make the bucket public or delete it. "Scoped resource" is not the same as
   "scoped action."
2. **`iam:PassRole` on `Resource: *`** is the quiet privilege-escalation primitive.
   It lets the principal hand *any* role to a service it can invoke, which is a
   well-worn path from "limited user" to "whatever that role can do."

**Fix:** replace `s3:*` with the specific actions the app needs
(`GetObject`/`PutObject`/`ListBucket`), and constrain `iam:PassRole` to the single
role ARN the workload is supposed to pass, ideally with an
`iam:PassedToService` condition.

**Lesson:** review the *actions* and the *resources* separately. A policy can be
careful about one and reckless about the other, and the reckless half is usually
the one that gets you.
