#!/usr/bin/env bash
# Optional POSIX convenience wrapper. Core workflow is portable Python.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python scripts/validate_lab.py
