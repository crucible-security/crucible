"""Tests for Phase 13 — Official GitHub Action."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
ACTION_YML = Path(__file__).parent.parent / "action.yml"


# ── Structural tests ──────────────────────────────────────────────────────────


def test_action_yml_exists() -> None:
    """action.yml exists at repo root."""
    assert ACTION_YML.exists(), "action.yml not found at repo root"


def test_action_yml_is_valid_yaml() -> None:
    """action.yml parses as valid YAML."""
    import yaml  # PyYAML is already a dev dep via pytest indirectly

    data = yaml.safe_load(ACTION_YML.read_text(encoding="utf-8"))
    assert data is not None
    assert "name" in data
    assert "inputs" in data
    assert "outputs" in data
    assert "runs" in data
    assert data["runs"]["using"] == "composite"


def test_action_yml_has_required_inputs() -> None:
    """action.yml defines all required inputs."""
    import yaml

    data = yaml.safe_load(ACTION_YML.read_text(encoding="utf-8"))
    inputs = data["inputs"]
    assert "target" in inputs, "Missing required input: target"
    assert "fail_on_grade" in inputs
    assert "format_preset" in inputs
    assert "model" in inputs
    assert "headers" in inputs
    assert "upload_artifact" in inputs


def test_action_yml_has_required_outputs() -> None:
    """action.yml defines grade, score, failed_count, total_count outputs."""
    import yaml

    data = yaml.safe_load(ACTION_YML.read_text(encoding="utf-8"))
    outputs = data["outputs"]
    assert "grade" in outputs
    assert "score" in outputs
    assert "failed_count" in outputs
    assert "total_count" in outputs


def test_run_scan_script_exists() -> None:
    """scripts/run_scan.py exists."""
    assert (SCRIPTS_DIR / "run_scan.py").exists()


def test_parse_results_script_exists() -> None:
    """scripts/parse_results.py exists."""
    assert (SCRIPTS_DIR / "parse_results.py").exists()


def test_example_workflow_exists() -> None:
    """examples/github_action_scan.yml exists."""
    example = Path(__file__).parent.parent / "examples" / "github_action_scan.yml"
    assert example.exists()


# ── parse_results.py unit tests ───────────────────────────────────────────────


def _make_scan_report(
    tmp_path: Path, grade: str = "B", score: float = 75.0, failed: int = 5
) -> Path:
    """Helper to create a minimal scan JSON report for testing."""
    data = {
        "grade": grade,
        "overall_score": score,
        "started_at": "2026-07-11T12:00:00Z",
        "target": {"name": "test-agent", "url": "http://localhost:8000"},
        "modules": [
            {
                "module_name": "prompt_injection",
                "findings": [
                    {
                        "attack_name": f"PI-{i:03d}",
                        "severity": "HIGH",
                        "passed": i >= failed,
                        "execution_error": False,
                    }
                    for i in range(10)
                ],
            }
        ],
    }
    report = tmp_path / "scan.json"
    report.write_text(json.dumps(data), encoding="utf-8")
    return report


def test_parse_results_passes_on_grade_A(tmp_path: Path) -> None:
    """parse_results.py exits 0 when grade A meets fail_on_grade=B."""
    report = _make_scan_report(tmp_path, grade="A", score=95.0, failed=0)
    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "parse_results.py"), str(report), "B"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"


def test_parse_results_fails_on_grade_below_threshold(tmp_path: Path) -> None:
    """parse_results.py exits 1 when grade D is below fail_on_grade=B."""
    report = _make_scan_report(tmp_path, grade="D", score=30.0, failed=8)
    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "parse_results.py"), str(report), "B"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert result.returncode == 1, f"Expected exit 1, got {result.returncode}"


def test_parse_results_never_fails_on_grade_F_threshold(tmp_path: Path) -> None:
    """parse_results.py exits 0 when fail_on_grade=F (never fails on grade)."""
    report = _make_scan_report(tmp_path, grade="F", score=0.0, failed=10)
    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "parse_results.py"), str(report), "F"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert result.returncode == 0


def test_parse_results_emits_correct_outputs(tmp_path: Path) -> None:
    """parse_results.py writes correct grade and score to GITHUB_OUTPUT."""
    report = _make_scan_report(tmp_path, grade="C", score=55.5, failed=3)
    github_output_file = tmp_path / "github_output.txt"

    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "parse_results.py"), str(report), "F"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "GITHUB_OUTPUT": str(github_output_file)},
    )
    assert result.returncode == 0

    output_text = github_output_file.read_text(encoding="utf-8")
    assert "grade=C" in output_text
    assert "score=55.5" in output_text
    assert "failed_count=3" in output_text
    assert "total_count=10" in output_text


def test_parse_results_missing_report_exits_2(tmp_path: Path) -> None:
    """parse_results.py exits 2 when report file does not exist."""
    missing = tmp_path / "nonexistent.json"
    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "parse_results.py"), str(missing), "F"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert result.returncode == 2


def test_parse_results_invalid_json_exits_2(tmp_path: Path) -> None:
    """parse_results.py exits 2 when report file contains invalid JSON."""
    bad_report = tmp_path / "bad.json"
    bad_report.write_text("not valid json{{{", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "parse_results.py"), str(bad_report), "F"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert result.returncode == 2


def test_parse_results_writes_step_summary(tmp_path: Path) -> None:
    """parse_results.py writes markdown summary to GITHUB_STEP_SUMMARY."""
    report = _make_scan_report(tmp_path, grade="B", score=80.0, failed=2)
    step_summary_file = tmp_path / "step_summary.md"

    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "parse_results.py"), str(report), "F"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "GITHUB_STEP_SUMMARY": str(step_summary_file)},
    )
    assert result.returncode == 0

    summary_text = step_summary_file.read_text(encoding="utf-8")
    assert "Crucible Security Scan Results" in summary_text
    assert "Grade" in summary_text
    assert "Score" in summary_text
