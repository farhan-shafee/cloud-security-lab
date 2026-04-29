#!/usr/bin/env bash
set -euo pipefail

required_files=(
  "README.md"
  "docs/methodology.md"
  "docs/threat-model.md"
  "examples/iam/least-privilege-policy.json"
  "examples/events/cloudtrail-consolelogin-no-mfa.json"
)

for f in "${required_files[@]}"; do
  if [[ -f "$f" ]]; then
    echo "[PASS] Required file exists: $f"
  else
    echo "[FAIL] Missing required file: $f"
    exit 1
  fi
done

python3 -m json.tool examples/iam/least-privilege-policy.json >/dev/null
python3 -m json.tool examples/events/cloudtrail-consolelogin-no-mfa.json >/dev/null
python3 -m json.tool examples/events/guardduty-credential-access.json >/dev/null

echo "[PASS] Sample event JSON parses correctly"
echo "Validation completed successfully."
