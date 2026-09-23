# Fixture contracts and ground truth

Inputs are UTF-8 JSON with integer `schema_version: 1` and literal `synthetic: true`. They are authored observations, not AWS API responses. Duplicate JSON keys, duplicate identities, nonstandard NaN/Infinity numbers, and malformed supported fields are rejected. Source SHA-256 hashes identify exact input bytes, so changing whitespace changes provenance even if the evaluated meaning is unchanged.

## Snapshot envelope

[`fixtures/accounts`](../fixtures/accounts) contains risky, remediated, secure/minimal, and edge-case snapshots. The complete executable contract is [`fixtures.py`](../cloud_security_lab/fixtures.py) with typed records in [`models.py`](../cloud_security_lab/models.py).

| Field | Contract |
|---|---|
| `schema_version`, `synthetic` | Integer 1 and boolean true. |
| `snapshot_id` | Nonempty identifier. |
| `account_id` | Invented 12-digit string. |
| `captured_at` | ISO-8601 timestamp with timezone; verification requires a strictly later timestamp. |
| `required_regions` | Nonempty unique supported-region array. |
| `resources` | Exactly policies, roles, buckets, security_groups, and trails arrays. Arrays may be empty; the entire inventory may not. |

Snapshot/resource objects reject unknown and missing fields. Resource IDs are unique across the inventory. Regions are limited to `us-east-1`, `us-east-2`, `us-west-1`, `us-west-2`, `ca-central-1`, `eu-west-1`, `eu-west-2`, `eu-central-1`, `ap-south-1`, `ap-northeast-1`, `ap-southeast-1`, and `ap-southeast-2`. This explicit subset is a lab contract, not a list of every AWS region.

| Resource array | Required entry fields |
|---|---|
| `policies` | `id`, `document` containing a supported identity policy. |
| `roles` | `id`, `trust_policy` containing supported AssumeRole trust. |
| `buckets` | `id`, `region`, boolean `sensitive`, `block_public_access`, `encryption`, boolean `versioning`. |
| `security_groups` | `id`, `region`, `ingress` array. |
| `trails` | `id`, `home_region`, boolean `is_logging`, boolean `is_multi_region`, `covered_regions`, `log_bucket`. |

Bucket `block_public_access` contains four booleans: `block_public_acls`, `ignore_public_acls`, `block_public_policy`, and `restrict_public_buckets`. Encryption contains `algorithm`, `key_id`, and `key_manager`: `AES256` requires null key fields; `aws:kms` requires an AWS/CUSTOMER manager and a supported key identifier. Customer keys use a key ARN in the bucket region. These are configured observations, not independent KMS resources or key authorization checks.

Ingress entries require `protocol`, `from_port`, `to_port`, and `cidr`. Protocols are `tcp`, `udp`, `icmp`, `icmpv6`, or `-1`. TCP/UDP use integer ports 0–65535 with ordered bounds. All protocols uses null ports. ICMP uses supported type/code ranges. CIDRs must be valid network addresses with a prefix and matching address family where required.

Trail coverage includes its home region; a single-region trail covers only its home. `log_bucket` must refer to an included bucket. Policy documents use the explicitly supported [IAM subset](controls.md), not unrestricted AWS JSON.

## Audit-event envelope

[`fixtures/events`](../fixtures/events) files have exactly `schema_version`, `synthetic`, `fixture_id`, and `events`. Events may be empty. [`events.py`](../cloud_security_lab/events.py) is the executable contract.

Each event requires `eventID`, timezone-aware `eventTime`, `eventSource`, `eventName`, `eventType`, `awsRegion`, 12-digit `recipientAccountId`, IP-literal `sourceIPAddress`, and `userIdentity` with `type`, `accountId`, and `arn`. Timestamps use `YYYY-MM-DDTHH:MM:SS`, optional 1–6 fractional digits, and `Z` or a valid `±HH:MM` offset. Invalid offset minutes and excess fractional precision are rejected rather than silently normalized. IDs must be unique within a batch. Events sort by UTC timestamp and event ID; file order does not establish chronology.

Supported identity types are Root, IAMUser, AssumedRole, and FederatedUser with type/account-consistent commercial-partition ARNs. Event types are AwsApiCall and AwsConsoleSignIn. This is not a general AWSService, GuardDuty, CloudTrail data-event, or organization-wide importer.

`requestParameters`, `responseElements`, and `additionalEventData` may be missing/null and normalize to objects. Wrong non-object types fail. Unlike strict snapshot objects, additional event metadata is tolerated; it does not add detector coverage. No `errorCode` means API success; a present error code must be a nonempty string. ConsoleLogin must explicitly say Success/Failure, and MFAUsed, if present, must be Yes/No.

Selected events require evidence-bearing parameters: policy version operations use `policyArn`, trail changes use `name`, and ingress changes use `groupId` plus CloudTrail-style `ipPermissions.items`. Ingress ranges use `ipRanges.items[].cidrIp` or `ipv6Ranges.items[].cidrIpv6`. TCP/UDP/ICMP/ICMPv6/all-protocol subsets are supported; security-group-reference-only ingress is outside scope. See [detections](../detections/cloud-detections.md) for exact match conditions.

## Ground truth and negative coverage

Expected results in [`fixtures/ground_truth`](../fixtures/ground_truth) are consumed by validation/tests, not assessment or detection evaluators. The risky environment intentionally fails; the remediated environment preserves its inventory and changes offending values. The secure baseline has no expected findings, while edge scenarios exercise selected boundaries.

Event scenarios include positive operations, benign/failed alternatives, explicit versus missing MFA, ingress boundaries, and separate accounts/principals/sessions/windows. Invalid-input fixtures and test mutations prove malformed input is not a successful clean result. Exact fixture/test counts and executed outcomes are recorded in [VALIDATION.md](VALIDATION.md).

Run `python -m cloud_security_lab validate-fixtures` to check the corpus against its ground truth. `python scripts/validate_lab.py` additionally checks original examples and repository YAML/Sigma structure. Neither validator authenticates fixture contents as real cloud evidence.
