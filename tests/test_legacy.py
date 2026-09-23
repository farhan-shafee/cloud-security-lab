import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("filename", "exit_code"),
    [
        ("least-privilege-policy.json", 0),
        ("overprivileged-policy.json", 1),
        ("subtle-overprivilege-policy.json", 1),
    ],
)
def test_legacy_entry_point_preserves_examples(filename, exit_code):
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/analyze_policy.py"),
            str(ROOT / "examples/iam" / filename),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == exit_code, result.stdout + result.stderr


def test_legacy_invalid_policy_returns_error_not_clean(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text('{"Statement":{"Effect":"Allow","NotAction":"s3:GetObject","Resource":"*"}}')
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/analyze_policy.py"), str(path)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "ERROR" in result.stdout
    assert "no findings" not in result.stdout
