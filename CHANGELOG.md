# Changelog

Notable changes to the lab. Dates are when the work actually landed; versions are
just milestones, not releases of anything.

## [0.6.0] - 2026-06-08

### Fixed
- Added `.gitattributes` to normalize line endings. Editing on Windows/OneDrive
  was rewriting every file to CRLF and producing enormous, meaningless diffs.

### Changed
- Reworked the docs for a more direct voice and less hedging; trimmed the
  repeated "portfolio/conceptual" qualifiers down to one honest scope note.
- Replaced the `notes.md` stub with a real lab journal of the decisions behind
  the build.

## [0.5.0] - 2026-05-17

### Added
- `scripts/analyze_policy.py`: a standalone IAM policy linter that flags wildcard
  actions, `iam:PassRole` on `*`, service-wide wildcards, and missing conditions.
  Exits non-zero on HIGH+ so CI can gate on it.
- A "subtle" over-privilege sample policy that passes a casual glance but isn't,
  used to show the linter catching the non-obvious case.

### Changed
- `validate_lab.sh` now runs a real self-test of the linter against the known-good
  and known-bad policies instead of only checking that files exist.
- CI byte-compiles the linter and asserts it still catches the bad policy.

## [0.4.0] - 2026-03-08

### Added
- Sigma rules under `detections/sigma/` for the three detections, so the logic is
  portable across Splunk / Sentinel / Elastic instead of living only in prose.

### Changed
- Detection doc now carries false-positive and tuning notes for each rule.

## [0.3.0] - 2026-01-19

### Changed
- Replaced the trimmed-down event samples with realistic CloudTrail and GuardDuty
  records (full `userIdentity`, `eventID`, GuardDuty 2.0 schema), so triage
  practice involves deciding which fields matter.

## [0.2.0] - 2025-12-14

### Added
- Threat model anchored to MITRE ATT&CK technique IDs.
- Methodology doc describing the assess → triage → report loop.

## [0.1.0] - 2025-11-29

### Added
- Initial scaffold: README, IAM and network baselines, logging-setup notes, and
  the first over-privileged vs. least-privilege policy pair.
