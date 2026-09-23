import json
import shutil
from pathlib import Path

import pytest

from cloud_security_lab.errors import FixtureError
from cloud_security_lab.validation import validate_fixtures


def test_corpus_matches_separate_ground_truth():
    result = validate_fixtures(Path("."))
    assert result["posture_scenarios"] >= 3
    assert result["event_scenarios"] >= 18
    assert result["success"] is True


def test_truth_tampering_is_detected_without_changing_evaluator(tmp_path):
    shutil.copytree("fixtures", tmp_path / "fixtures")
    path = tmp_path / "fixtures/ground_truth/detections.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["scenarios"][0]["alerts"] = []
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(FixtureError, match="Ground truth mismatch"):
        validate_fixtures(tmp_path)


def test_unregistered_scenario_is_rejected(tmp_path):
    shutil.copytree("fixtures", tmp_path / "fixtures")
    shutil.copyfile(
        tmp_path / "fixtures/events/demo.json", tmp_path / "fixtures/events/orphan.json"
    )
    with pytest.raises(FixtureError, match="coverage"):
        validate_fixtures(tmp_path)
