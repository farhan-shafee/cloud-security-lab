#!/usr/bin/env bash
# Repo health check: structure, JSON validity, and a real self-test of the
# IAM linter against the known-good and known-bad sample policies.
set -euo pipefail

cd "$(dirname "$0")/.."

fail=0
pass() { echo "[PASS] $1"; }
fault() { echo "[FAIL] $1"; fail=1; }

# --- 1. required files exist -------------------------------------------------
required=(
  "README.md"
  "docs/methodology.md"
  "docs/threat-model.md"
  "docs/triage-runbook.md"
  "detections/cloud-detections.md"
  "detections/sigma/console-login-without-mfa.yml"
  "scripts/analyze_policy.py"
  "examples/iam/least-privilege-policy.json"
  "examples/events/cloudtrail-consolelogin-no-mfa.json"
)
for f in "${required[@]}"; do
  [[ -f "$f" ]] && pass "exists: $f" || fault "missing: $f"
done

# --- 2. every JSON file parses ----------------------------------------------
while IFS= read -r -d '' j; do
  if python3 -m json.tool "$j" >/dev/null 2>&1; then
    pass "valid JSON: $j"
  else
    fault "invalid JSON: $j"
  fi
done < <(find examples -name '*.json' -print0)

# --- 3. linter self-test -----------------------------------------------------
# The bad policy MUST be flagged (linter exits non-zero); the good one must pass.
if python3 scripts/analyze_policy.py examples/iam/overprivileged-policy.json >/dev/null; then
  fault "linter did not flag the over-privileged policy"
else
  pass "linter flags the over-privileged policy"
fi

if python3 scripts/analyze_policy.py examples/iam/least-privilege-policy.json >/dev/null; then
  pass "linter passes the least-privilege policy"
else
  fault "linter wrongly flagged the least-privilege policy"
fi

echo
if [[ "$fail" -eq 0 ]]; then
  echo "Validation completed successfully."
else
  echo "Validation FAILED."
  exit 1
fi
