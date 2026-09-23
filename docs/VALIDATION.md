# Executed validation record

Local validation: **2026-09-23 20:03 UTC**, Windows PowerShell, CPython **3.14.7**.
Starting commit: `caf0ac8263056cd8cb5584b6e9bf3d618b1af426`. Local results below
were executed against the candidate subsequently committed and pushed as
[`93cbdab11643ba6c485ca63091ea09ff7da1fb08`](https://github.com/farhan-shafee/cloud-security-lab/commit/93cbdab11643ba6c485ca63091ea09ff7da1fb08).
This documentation follow-up records the observed remote result without changing
the tested implementation.

The interpreter for development checks was `.venv/Scripts/python.exe`. The
credential-free runtime was also exercised using system `python -S`, which
disables site packages. Tool versions are pinned in `requirements-dev.lock`.

| Executed check | Observed result |
|---|---|
| `python -m ruff format --check .` | Passed; no formatting changes required. |
| `python -m ruff check .` | Passed. |
| `python -m mypy` | Passed: 16 package modules. |
| `python -m pytest -q` | **190 passed**, zero failures/skips. |
| `python scripts/validate_lab.py` | Passed: 53 JSON files, 4 YAML files; independent posture/event truth matched. |
| `python -m cloud_security_lab demo --output-dir reports/generated` | Generated the committed JSON/Markdown evidence. |
| `python -m cloud_security_lab demo --check reports/generated` | Byte-for-byte comparison passed. |
| `python -S -m cloud_security_lab demo` | Passed without third-party runtime packages. |
| `python -m bandit -q -r cloud_security_lab scripts` | Passed. Narrow subprocess suppressions document trusted local scanner/Git invocations without a shell. |
| `python -m pip_audit -r requirements-dev.lock --progress-spinner off --cache-dir artifacts/pip-audit-cache` | No known vulnerabilities found in the pinned development-tool dependency set at execution time. |
| `python -m pip check` | No broken requirements. |
| `python scripts/secret_scan.py --gitleaks .tools/gitleaks/gitleaks.exe` | Gitleaks 8.30.1: no leaks in the 17-commit existing history or the nonignored working source snapshot. |
| `python -m build` | Built source distribution and wheel successfully. |
| Extracted source-distribution tests | 190 passed. A sandbox cache-directory warning did not affect execution. |
| `git diff --check` | Passed. |

Gitleaks Windows x64 archive was checked against the upstream release SHA-256:
`d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e`.
CI pins its Linux x64 archive separately and pins GitHub Actions by commit SHA.

## Behavioral evidence

- **14 posture controls**, each exercised by risky and clean fixture outcomes.
- **6 detections**, with positive/negative cases and selected boundaries.
- **1 correlation**, ordered policy change then logging disablement within
  15 minutes, with account/principal/session and timestamp boundary tests.
- **41 source scenarios:** 4 valid snapshots (risky, remediated, secure, edge),
  4 deliberately invalid snapshots, and 33 event fixtures. Two separate JSON
  answer keys are not counted as scenarios. Five legacy JSON examples are kept
  separately; GuardDuty is illustrative and is not accepted as an event batch.
- Demo: **17 findings → 17 VERIFIED_CLOSED**, zero unresolved/new findings,
  zero findings in remediated and secure snapshots, **6 alerts**, **1 correlation**,
  and **7 triage records**. Ten generated artifacts: five JSON/Markdown pairs.
- Input line endings were normalized to LF before report generation so byte
  hashes and committed evidence reproduce across Windows and Linux.

The independent final review found malformed event timezone offsets could be
normalized silently by Python. Four regression cases failed before the fix;
strict timestamp syntax then passed the entire 190-test suite. Other tested
closure guards reject status fields, removed/renamed resources, altered
classification/location, changed region scope, stale time, and another account.

## Scope of these results

These are executed local results, not claims of AWS deployment, native service
integration, audited conformity, production detection quality, or full IAM
evaluation. Dependency advisories are time-dependent and require network access;
the assessment, detection, fixture truth and demo workflows remain offline.
Sigma YAML checks verify reference-file structure, not backend conversion or
runtime execution. Fixture hashes do not authenticate authors or AWS state.

## Verified GitHub CI and publication

[CI run 35913883851](https://github.com/farhan-shafee/cloud-security-lab/actions/runs/35913883851)
completed successfully for implementation commit `93cbdab11643ba6c485ca63091ea09ff7da1fb08`.
All six jobs passed: Quality, Dependencies and secrets, and tests on Ubuntu and
Windows with Python 3.11 and 3.14. The test jobs also validate fixtures, compare
committed generated evidence byte-for-byte, and execute the offline demo.

The implementation was pushed to `origin/main`; the remote SHA was read back and
matched the local commit. Repository metadata was updated and read back:

- Description: "Deterministic AWS-style cloud posture assessment, audit-event
  detection, and remediation verification using synthetic fixtures."
- Topics: `cloud-security`, `aws-iam`, `least-privilege`, `security-automation`, `python`.

CI subsequently reported deprecated Action runtimes. The workflow was updated
to commit-pinned `actions/checkout` v7.0.1 and `actions/setup-python` v7.0.0 in
`812454f09034b554930d27899fed22ec66b1ba5c`.
[CI run 35914295043](https://github.com/farhan-shafee/cloud-security-lab/actions/runs/35914295043)
then passed all six jobs with the updated runtime pins. The Python implementation
and generated evidence are unchanged from the implementation commit above.

No profile repository or AWS account was changed. These run links identify the
exact revisions verified; later documentation commits have their own CI runs.
