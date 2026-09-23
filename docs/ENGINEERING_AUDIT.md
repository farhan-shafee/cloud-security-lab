# Engineering audit and implementation plan

Audit date: 2026-09-23. Starting commit: `caf0ac8`. All 32 tracked files,
the 17-commit history, existing workflow, public metadata and baseline commands
were reviewed before implementation changes.

## Initial findings

1. **Strong work:** honest offline scope, readable IAM examples, useful manual
   triage/remediation guidance, synthetic identifiers, and preserved history.
2. **Documentation without execution:** architecture, network/logging baselines,
   detections, report findings and closure assertions have no running pipeline.
3. **Implemented controls:** the single policy script inspects Allow statements
   for action/resource wildcards, broad PassRole, and missing conditions. Deny
   statements are skipped. It is not an effective-permissions evaluator.
4. **Executable detections:** none. Three Sigma references and SQL/prose examples
   have no backend validation or negative-event tests.
5. **Untested:** malformed IAM, trust, NotResource, condition semantics, every
   configuration control, event parsing, false positives, lifecycle and reports.
   Manual probes returned no findings for an empty statement and NotResource.
6. **Claims beyond evidence:** diagrammed services do not exist; manually written
   findings imply reproduced configuration checks and correlation. Resource `*`
   is described too categorically. CIS/NIST mappings lack sufficient support.
7. **Engineering standard:** typed validated fixtures, explainable controls,
   separate answer keys, negative tests, deterministic outputs, strict
   reassessment closure, Windows/Linux CI and recorded executed validation.
8. **Exclude:** live AWS, SDKs, Terraform lane, UI, graph database, AI, arbitrary
   risk scores, automatic AWS remediation and compliance certification claims.

Baseline execution: three IAM examples behaved as documented. The POSIX
validator failed on this Windows host (`dirname`/`python3` unavailable) yet
reported a bad-policy PASS when the interpreter failed. Existing latest GitHub
CI run 27141054134 succeeded, but only checks files, JSON and the legacy linter.

## Design and execution plan

The supplied brief authorizes implementation, full validation, metadata update,
and a final commit/push to main. Work stays in this initially clean checkout;
commit occurs only after validation. No cloud access is authorized or needed.

- [x] Build `cloud_security_lab` with a versioned strict snapshot loader, typed
  dataclasses, catalog metadata, IAM inspection and roughly 14 posture controls.
  Preserve the old script as a compatibility entry point. Tests must reject
  unsupported IAM rather than silently treating it as safe.
- [x] Build a separate event loader, six deterministic detections and a bounded
  policy-change → logging-disable correlation using the same account and exact
  principal/session, ordered within 15 minutes. Single signals mean REVIEW;
  correlation means ESCALATE, never proven malicious.
- [x] Add risky/remediated/secure and malformed/edge fixtures, independently
  authored ground truth, positive and negative control/detection tests.
- [x] Implement CLI assessment/detection/verification/demo and JSON/Markdown
  reports. Verification re-evaluates both snapshots; it requires a later snapshot
  in the same account and a PASS for the same resource/control. Missing resources
  must not yield closure. Report newly introduced findings separately.
- [x] Replace stale docs/reports with exact implemented behavior; retain useful
  IAM/Sigma/GuardDuty examples labeled by scope. Primary AWS references replace
  unsupported certification-style mappings. Add interview and portfolio guides.
- [x] Run formatting, lint, typing, tests, fixture truth, demo, Bandit, dependency
  audit and secret scan. CI covers Windows/Linux. Record actual results, inspect
  diff and generated evidence, independently review, fix defects, then commit,
  push, update focused metadata, and verify GitHub CI.

Review focus: malformed/unknown fields and IAM complements; Deny/condition
overstatement; timestamps/identity boundaries; missing-resource false closure;
ground-truth independence and reproducible reports. Each is tested at its owning
boundary. Runtime remains standard library only; development tools are bounded
and locked separately. Terraform is omitted because it would introduce a second
parser without strengthening this focused assessment/verification proof.

Completion evidence is recorded in [VALIDATION.md](VALIDATION.md), including the
implementation commit and successful six-job GitHub CI run. Independent review
identified malformed event timezone handling; the fix was verified with failing
regression tests followed by a passing full suite. Verification also rejects
classification/location changes so changing assessment scope cannot stand in
for synthetic remediation.
