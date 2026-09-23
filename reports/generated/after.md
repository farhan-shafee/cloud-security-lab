# Synthetic cloud security evidence

Generated from synthetic configuration/audit fixtures. No AWS services were contacted. PASS and closure apply only to modeled predicates.

## Assessment metadata

```json
{
  "account_id": "111122223333",
  "captured_at": "2026-09-23T13:00:00Z",
  "controls_executed": [
    "IAM-001",
    "IAM-002",
    "IAM-003",
    "IAM-004",
    "IAM-005",
    "IAM-006",
    "S3-001",
    "S3-002",
    "S3-003",
    "NET-001",
    "NET-002",
    "LOG-001",
    "LOG-002",
    "LOG-003"
  ],
  "inventory": [
    {
      "resource_id": "account-trail",
      "resource_type": "cloudtrail"
    },
    {
      "resource_id": "workload-policy",
      "resource_type": "iam_policy"
    },
    {
      "resource_id": "workload-role",
      "resource_type": "iam_role"
    },
    {
      "resource_id": "synthetic-data",
      "resource_type": "s3_bucket"
    },
    {
      "resource_id": "synthetic-logs",
      "resource_type": "s3_bucket"
    },
    {
      "resource_id": "sg-workload",
      "resource_type": "security_group"
    }
  ],
  "schema_version": 1,
  "snapshot_id": "remediated-20260923",
  "source_sha256": "049a33d0d9000990a1dcae4843856c8df9a61e5326f4cc1b0946a384c6ede82e",
  "synthetic": true
}
```

## Findings

None.

## Evaluations

```json
{
  "control_id": "IAM-001",
  "resource_id": "workload-policy",
  "resource_type": "iam_policy",
  "status": "PASS"
}
```

```json
{
  "control_id": "IAM-002",
  "resource_id": "workload-policy",
  "resource_type": "iam_policy",
  "status": "PASS"
}
```

```json
{
  "control_id": "IAM-003",
  "resource_id": "workload-policy",
  "resource_type": "iam_policy",
  "status": "PASS"
}
```

```json
{
  "control_id": "IAM-004",
  "resource_id": "workload-policy",
  "resource_type": "iam_policy",
  "status": "PASS"
}
```

```json
{
  "control_id": "IAM-005",
  "resource_id": "workload-role",
  "resource_type": "iam_role",
  "status": "PASS"
}
```

```json
{
  "control_id": "IAM-006",
  "resource_id": "workload-role",
  "resource_type": "iam_role",
  "status": "PASS"
}
```

```json
{
  "control_id": "LOG-001",
  "resource_id": "account-trail",
  "resource_type": "cloudtrail",
  "status": "PASS"
}
```

```json
{
  "control_id": "LOG-002",
  "resource_id": "account-trail",
  "resource_type": "cloudtrail",
  "status": "PASS"
}
```

```json
{
  "control_id": "LOG-003",
  "resource_id": "account-trail",
  "resource_type": "cloudtrail",
  "status": "PASS"
}
```

```json
{
  "control_id": "NET-001",
  "resource_id": "sg-workload",
  "resource_type": "security_group",
  "status": "PASS"
}
```

```json
{
  "control_id": "NET-002",
  "resource_id": "sg-workload",
  "resource_type": "security_group",
  "status": "PASS"
}
```

```json
{
  "control_id": "S3-001",
  "resource_id": "synthetic-data",
  "resource_type": "s3_bucket",
  "status": "PASS"
}
```

```json
{
  "control_id": "S3-001",
  "resource_id": "synthetic-logs",
  "resource_type": "s3_bucket",
  "status": "PASS"
}
```

```json
{
  "control_id": "S3-002",
  "resource_id": "synthetic-data",
  "resource_type": "s3_bucket",
  "status": "PASS"
}
```

```json
{
  "control_id": "S3-002",
  "resource_id": "synthetic-logs",
  "resource_type": "s3_bucket",
  "status": "PASS"
}
```

```json
{
  "control_id": "S3-003",
  "resource_id": "synthetic-data",
  "resource_type": "s3_bucket",
  "status": "PASS"
}
```

```json
{
  "control_id": "S3-003",
  "resource_id": "synthetic-logs",
  "resource_type": "s3_bucket",
  "status": "PASS"
}
```
