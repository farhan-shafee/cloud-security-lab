"""Portable repository check; install development dependencies for YAML validation."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cloud_security_lab.iam import parse_policy  # noqa: E402
from cloud_security_lab.validation import validate_fixtures  # noqa: E402


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    result = validate_fixtures(root)
    json_count = 0
    for directory in ("fixtures", "examples", "reports/generated"):
        for path in sorted((root / directory).rglob("*.json")):
            # Invalid-schema specimens are still syntactically valid JSON.
            json.loads(path.read_text(encoding="utf-8"))
            json_count += 1
    for path in sorted((root / "examples/iam").glob("*.json")):
        parse_policy(json.loads(path.read_text(encoding="utf-8")))
    yaml_count = 0
    for directory in ("detections/sigma", ".github"):
        for path in sorted((root / directory).rglob("*.yml")):
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                raise ValueError(f"YAML mapping expected: {path}")
            if directory == "detections/sigma":
                required = {"title", "id", "status", "logsource", "detection", "level"}
                if not required <= document.keys():
                    raise ValueError(f"Missing Sigma reference fields: {path}")
            yaml_count += 1
    print(
        json.dumps({**result, "json_files": json_count, "yaml_files": yaml_count}, sort_keys=True)
    )


if __name__ == "__main__":
    main()
