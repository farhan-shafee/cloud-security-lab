# Executable cloud-event detections

Run `python -m cloud_security_lab detect fixtures/events/demo.json`. The Python engine reads the versioned [event fixture contract](../docs/fixtures.md), normalizes timestamps, and evaluates the following predicates. It does not connect to CloudTrail or GuardDuty.

For all rules, success means no `errorCode`; ConsoleLogin additionally requires `responseElements.ConsoleLogin: Success`. Supported service/event combinations are explicit. Failed operations do not become successful-change alerts.

| ID | Severity | Exact trigger |
|---|---|---|
| DET-001 | HIGH | Successful event with root identity and `eventType: AwsApiCall`; root console login is outside this rule. |
| DET-002 | MEDIUM | Successful `signin.amazonaws.com` ConsoleLogin by `IAMUser` with explicit `additionalEventData.MFAUsed: No`. Missing MFA data/federated login does not match. |
| DET-003 | MEDIUM | Successful `iam.amazonaws.com` CreateAccessKey. |
| DET-004 | MEDIUM | Successful `iam.amazonaws.com` CreatePolicyVersion or SetDefaultPolicyVersion. |
| DET-005 | HIGH | Successful `cloudtrail.amazonaws.com` StopLogging or DeleteTrail. |
| DET-006 | HIGH | Successful `ec2.amazonaws.com` AuthorizeSecurityGroupIngress adds an IPv4/IPv6 `/0` rule that allows TCP 22/3389 or all protocols. |

Every alert includes source evidence and receives `REVIEW`. Root activity, key creation, or a policy edit can be authorized. The detector does not label actors malicious, diff policy versions, resolve tickets, or infer geography/reputation.

## COR-001 — policy change followed by logging disablement

Join a DET-004 event to a later DET-005 event only when:

- recipient account IDs match;
- exact principal/session ARNs match;
- the logging event is strictly later than the policy event;
- elapsed time is at most 15 minutes, inclusive.

Inputs are sorted by normalized UTC timestamp and event ID before evaluation. Each logging event selects the nearest strictly earlier qualifying policy edit; ties resolve by event ID. Different accounts, principals, role sessions, reverse order, equal timestamps, failed calls, and out-of-window pairs do not correlate. A match is HIGH with `ESCALATE`, supported by both event IDs. It does not prove that the policy expanded access or caused the logging change.

## Tuning and test evidence

Positive, negative, and boundary fixtures live under [fixtures/events](../fixtures/events). Expected detection/correlation results are separate from evaluator code. Tests cover explicit no-MFA versus missing data, unsuccessful operations, IPv6/all-protocol ingress, account/session isolation, and correlation timing.

Approved maintenance can match these rules. A real deployment would need source completeness, field mapping, business context, and measured alert-volume tuning. This lab has no production false-positive rate to report. See [triage](../docs/triage-runbook.md) and [VALIDATION.md](../docs/VALIDATION.md).

## Preserved reference artifacts

The three [Sigma files](sigma/) are educational references and are not the Python detector's source of truth. Console-login and policy-version rules have not been converted or tested against Splunk, Sentinel, or Elastic. Backend portability is therefore unverified.

`iam-discovery-burst.yml` is explicitly `unsupported`: it retains a historical legacy aggregation sketch, not executable coverage. Discovery-burst detection was omitted from the Python engine because the current workflow does not model an authorized enumeration baseline. [Sigma specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html).

The original GuardDuty-shaped example is also illustrative only. Its fixed severity and anomaly text are fixture content, not output from a connected service or this detector.
