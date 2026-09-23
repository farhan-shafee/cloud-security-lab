# Logging review context

This repository consumes synthetic CloudTrail-style events. It does not configure CloudTrail, receive live logs, or run GuardDuty.

Snapshot controls check whether a modeled trail is logging, whether its configured coverage includes required regions, and whether its referenced log bucket meets the lab's public-access, customer-managed SSE-KMS, and versioning baseline. These are configuration checks, not proof of delivery or forensic integrity. See [LOG-001 through LOG-003](../docs/controls.md).

A real collection design would additionally need management/data event selectors, enabled-region coverage, retention, protected delivery, account/organization scope, monitoring of delivery failures, and evidence integrity procedures. [AWS multi-Region trail behavior](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html).

Enabling CloudTrail log-file integrity validation produces digest files; it does not itself validate delivered logs. This lab neither models the setting nor verifies signed digests. Versioning is not Object Lock or immutability. [AWS log-file integrity validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html).

The event lane detects selected successful API operations and emits triage evidence. See [detection predicates](../detections/cloud-detections.md) and the [runbook](../docs/triage-runbook.md).
