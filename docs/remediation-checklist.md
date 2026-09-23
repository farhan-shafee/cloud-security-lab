# Synthetic remediation verification

This workflow corrects fixture data and re-runs controls. It does not change AWS, revoke sessions, or close historical event alerts.

```text
ASSESS → OPEN FINDING → CORRECT SNAPSHOT → RE-ASSESS → VERIFY
```

```console
python -m cloud_security_lab assess fixtures/accounts/risky-environment.json
python -m cloud_security_lab assess fixtures/accounts/remediated-environment.json
python -m cloud_security_lab verify fixtures/accounts/risky-environment.json fixtures/accounts/remediated-environment.json
```

The verifier takes source snapshots, not edited finding statuses. It requires the same account and required regions, distinct snapshot IDs, a strictly later timestamp, and preservation of the original resources, their regions/home regions, and bucket sensitivity classification. These guards prevent an apparent fix made by shrinking scope or reclassifying the evidence.

A later assessment must successfully evaluate the affected resource/control before an original finding becomes `VERIFIED_CLOSED`. A persisting failure stays `OPEN`. Missing evidence cannot establish closure; new findings are reported separately. Verification records include the later resource configuration for inspection.

## Review checklist

- Inspect the resource, evidence, reason, and guidance in each finding.
- Review the change against the intended baseline, including IPv6, trust, region coverage, and encryption policy where modeled.
- Preserve resource identity and provide a later snapshot timestamp.
- Inspect unresolved findings and newly introduced findings after verification.
- Preserve both assessments and the verification report.
- Explain that closure applies only to the modeled synthetic condition.

`verify` exits 0 when verification succeeds, 1 for unresolved/new findings, and 2 for invalid input. See [controls](controls.md) for limitations and the [demo](DEMO.md) for a walkthrough.
