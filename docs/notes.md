# Lab journal

Running notes on why the lab is built the way it is. Kept in rough date order;
newest decisions get appended at the bottom. This is the "show your working"
file — the reasoning that didn't fit anywhere else. Entries before September
2026 describe the earlier lab; current behavior is documented in the README and
control catalog. Historical claims of Sigma portability were not verified by
backend conversion or execution.

## 2025-11-29 — starting with identity

Began with IAM rather than network, because in cloud the account boundary *is*
identity. Most of the public post-incident write-ups I read while planning this
came back to an over-permissioned key or role, not an open port. The two
policies in `examples/iam/` (one deliberately terrible, one scoped) are the spine
everything else hangs off.

## 2025-12-14 — threat model before detections

Tempting to jump straight to writing detections, but I wrote the threat model
first so the detections had something to justify them. Anchored each scenario to
an ATT&CK technique ID — partly for rigor, partly because it makes the detection
files easier to explain in an interview ("this rule covers T1098").

## 2026-01-19 — making the event samples realistic

First pass at the CloudTrail sample was three fields. Replaced it with something
closer to a real record (eventID, requestID, recipientAccountId, full
userIdentity block) because the trimmed version taught the wrong lesson: real
triage means knowing which of forty fields actually matter. Kept the GuardDuty
finding aligned to the 2.0 schema for the same reason.

## 2026-03-08 — Sigma instead of prose-only detections

The detection doc started as plain-English logic. Added Sigma rules under
`detections/sigma/` so the logic is portable and not just readable — Sigma
converts to Splunk / Sentinel / Elastic, so the same rule isn't tied to one
backend. The prose stays as the explanation; the YAML is the artifact.

## 2026-05-17 — making validation actually validate

`validate_lab.sh` originally just checked files existed. That's not validation,
it's a file listing. Added `analyze_policy.py` so there's a real check with an
opinion: it reads a policy and fails CI on a wildcard grant. The over-privileged
sample is now also a test fixture — CI confirms the linter still catches it.

## 2026-09-23 — executable evidence

The current design makes assessment and closure reproducible from versioned
snapshots. Typed loaders reject unsupported input; controls produce evidence;
event detections include negative fixtures; and the verifier re-assesses a later
snapshot instead of trusting a manually edited status.

Terraform was intentionally omitted because static JSON already captures the
required state. Cross-account trust is represented by explicit policy principals,
not a deployed second account. A bounded event sequence provides correlation
without a graph database or behavioral claims. The earlier discovery Sigma
aggregation remains an unsupported historical reference.

Future live collection would require an independently reviewed read-only adapter
and authenticated coverage evidence. It is outside the current workflow.
