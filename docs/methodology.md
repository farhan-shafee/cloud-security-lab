# Methodology

The lab demonstrates configuration findings and suspicious event sequences using explicitly synthetic input.

1. Validate a versioned snapshot and assess the implemented [control predicates](controls.md).
2. Produce findings with fixed severity, affected resource, evidence, reason, remediation, and references.
3. Evaluate audit events using documented [detection predicates](../detections/cloud-detections.md). Review the resulting triage records; an alert is not proof of compromise.
4. Correct the modeled configuration in a later snapshot.
5. Re-assess both snapshots and verify the original conditions no longer fail.
6. Preserve generated JSON and Markdown evidence with fixture provenance.

`python -m cloud_security_lab demo` runs this sequence on committed inputs. It writes reports, not changes to AWS. Correcting configuration does not erase historical alerts.

## Severity and scope

Each control/detection assigns a documented severity. Severity expresses the lab's prioritization policy for that condition, not a numeric breach probability. There is no aggregate score, certification, or claim that a zero-finding snapshot is universally secure.

Static IAM findings describe statement patterns even when another policy or condition could constrain effective access. Passing the analyzer does not prove least privilege: task requirements, other policies, service authorization, and runtime context remain outside the model.

## Evidence standard

A reviewer must be able to identify the input, repeat the command, inspect the condition, and understand the limits. Expected results are separate from evaluators. Rejected input is an error, not a passing assessment.

See [VALIDATION.md](VALIDATION.md) for executed checks, [remediation verification](remediation-checklist.md) for closure rules, and the [threat model](threat-model.md) for coverage limits.
