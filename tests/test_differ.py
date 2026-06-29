from __future__ import annotations

import json
from pathlib import Path

from pydantic import HttpUrl

from crucible.core.differ import compute_diff
from crucible.models import (
    AgentTarget,
    AttackCategory,
    DiffResult,
    Finding,
    FindingStatus,
    Grade,
    ModuleResult,
    ScanResult,
    ScanStatus,
    Severity,
)
from crucible.reporters.diff_reporter import DiffReporter


def _create_mock_scan(
    score: float, grade: Grade, findings: list[Finding], modules: list[str] = ["prompt_injection"]
) -> ScanResult:
    target = AgentTarget(
        name="test-agent",
        url=HttpUrl("https://example.com/api/chat"),
    )
    mod_results = []
    for mod_name in modules:
        mod_results.append(
            ModuleResult(
                module_name=mod_name,
                category=AttackCategory.PROMPT_INJECTION,
                findings=findings,
                failed=len([f for f in findings if f.passed is False]),
                passed=len([f for f in findings if f.passed is True]),
                total_attacks=len(findings),
                score=score,
            )
        )
    return ScanResult(
        target=target,
        status=ScanStatus.COMPLETED,
        grade=grade,
        overall_score=score,
        modules=mod_results,
    )


def test_diff_fixed_finding() -> None:
    """A finding that failed in scan_a and passes in scan_b is FIXED."""
    f_a = Finding(
        attack_name="PI-001",
        category=AttackCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title="Ignore instructions",
        payload="test",
        passed=False,
    )
    f_b = Finding(
        attack_name="PI-001",
        category=AttackCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title="Ignore instructions",
        payload="test",
        passed=True,
    )
    scan_a = _create_mock_scan(90.0, Grade.A, [f_a])
    scan_b = _create_mock_scan(100.0, Grade.A, [f_b])

    diff_res = compute_diff(scan_a, scan_b)
    assert diff_res.total_fixed == 1
    assert diff_res.total_regressed == 0
    assert diff_res.modules[0].findings[0].status == FindingStatus.FIXED
    assert diff_res.modules[0].findings[0].scan_a_passed is False
    assert diff_res.modules[0].findings[0].scan_b_passed is True


def test_diff_regressed_finding() -> None:
    """A finding that passed in scan_a and fails in scan_b is REGRESSED."""
    f_a = Finding(
        attack_name="PI-001",
        category=AttackCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title="Ignore instructions",
        payload="test",
        passed=True,
    )
    f_b = Finding(
        attack_name="PI-001",
        category=AttackCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title="Ignore instructions",
        payload="test",
        passed=False,
    )
    scan_a = _create_mock_scan(100.0, Grade.A, [f_a])
    scan_b = _create_mock_scan(90.0, Grade.A, [f_b])

    diff_res = compute_diff(scan_a, scan_b)
    assert diff_res.total_fixed == 0
    assert diff_res.total_regressed == 1
    assert diff_res.modules[0].findings[0].status == FindingStatus.REGRESSED
    assert diff_res.modules[0].findings[0].scan_a_passed is True
    assert diff_res.modules[0].findings[0].scan_b_passed is False


def test_diff_new_finding() -> None:
    """A finding not present in scan_a and failing in scan_b is NEW."""
    f_b = Finding(
        attack_name="PI-001",
        category=AttackCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title="Ignore instructions",
        payload="test",
        passed=False,
    )
    scan_a = _create_mock_scan(100.0, Grade.A, [])
    scan_b = _create_mock_scan(90.0, Grade.A, [f_b])

    diff_res = compute_diff(scan_a, scan_b)
    assert diff_res.total_fixed == 0
    assert diff_res.total_new == 1
    assert diff_res.modules[0].findings[0].status == FindingStatus.NEW
    assert diff_res.modules[0].findings[0].scan_a_passed is None
    assert diff_res.modules[0].findings[0].scan_b_passed is False


def test_diff_score_delta() -> None:
    """Score delta is computed correctly as score_b - score_a."""
    scan_a = _create_mock_scan(45.0, Grade.F, [])
    scan_b = _create_mock_scan(67.0, Grade.D, [])
    diff_res = compute_diff(scan_a, scan_b)
    assert diff_res.score_delta == 22.0


def test_diff_grade_change() -> None:
    """Grade change is correctly reported (F → D etc.)."""
    scan_a = _create_mock_scan(45.0, Grade.F, [])
    scan_b = _create_mock_scan(67.0, Grade.D, [])
    diff_res = compute_diff(scan_a, scan_b)
    assert diff_res.grade_a == Grade.F
    assert diff_res.grade_b == Grade.D


def test_diff_module_added() -> None:
    """Module present in scan_b but not scan_a is handled gracefully."""
    scan_a = _create_mock_scan(100.0, Grade.A, [], modules=[])
    f_b = Finding(
        attack_name="PI-001",
        category=AttackCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title="Ignore instructions",
        payload="test",
        passed=False,
    )
    scan_b = _create_mock_scan(90.0, Grade.A, [f_b], modules=["prompt_injection"])

    diff_res = compute_diff(scan_a, scan_b)
    assert len(diff_res.modules) == 1
    assert diff_res.modules[0].module_name == "prompt_injection"
    assert diff_res.modules[0].findings[0].status == FindingStatus.NEW


def test_diff_module_removed() -> None:
    """Module present in scan_a but not scan_b is handled gracefully."""
    f_a = Finding(
        attack_name="PI-001",
        category=AttackCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title="Ignore instructions",
        payload="test",
        passed=False,
    )
    scan_a = _create_mock_scan(90.0, Grade.A, [f_a], modules=["prompt_injection"])
    scan_b = _create_mock_scan(100.0, Grade.A, [], modules=[])

    diff_res = compute_diff(scan_a, scan_b)
    assert len(diff_res.modules) == 1
    assert diff_res.modules[0].module_name == "prompt_injection"
    assert diff_res.modules[0].findings[0].status == FindingStatus.FIXED


def test_diff_both_incomplete() -> None:
    """Two Grade.INCOMPLETE scans produce a DiffResult with a warning."""
    scan_a = _create_mock_scan(50.0, Grade.INCOMPLETE, [])
    scan_b = _create_mock_scan(50.0, Grade.INCOMPLETE, [])
    diff_res = compute_diff(scan_a, scan_b)
    assert diff_res.warning == "Both scans are INCOMPLETE"


def test_diff_one_incomplete() -> None:
    """One incomplete scan produces a warning in the diff output."""
    scan_a = _create_mock_scan(50.0, Grade.INCOMPLETE, [])
    scan_b = _create_mock_scan(80.0, Grade.B, [])
    diff_res = compute_diff(scan_a, scan_b)
    assert diff_res.warning == "Scan A is INCOMPLETE"


def test_diff_terminal_output_format() -> None:
    """Terminal output includes FIXED/REGRESSED/NEW counts."""
    f_a = Finding(
        attack_name="PI-001",
        category=AttackCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title="Ignore instructions",
        payload="test",
        passed=False,
        nist_category="MEASURE 2.5",
    )
    f_b = Finding(
        attack_name="PI-001",
        category=AttackCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title="Ignore instructions",
        payload="test",
        passed=True,
        nist_category="MEASURE 2.5",
    )
    scan_a = _create_mock_scan(90.0, Grade.A, [f_a])
    scan_b = _create_mock_scan(100.0, Grade.A, [f_b])

    diff_res = compute_diff(scan_a, scan_b)
    diff_res.scan_a_path = "scan_a.json"
    diff_res.scan_b_path = "scan_b.json"

    reporter = DiffReporter()
    terminal_out = reporter.to_terminal(diff_res)
    
    # Strip ANSI escape codes
    import re
    clean_out = re.sub(r'\x1b\[[0-9;]*[mK]', '', terminal_out)
    
    assert "FIXED      (1 attacks now passing)" in clean_out
    assert "REGRESSED  (0 attacks now failing)" in clean_out
    assert "NEW        (0 new attack findings)" in clean_out
    assert "MEASURE" in clean_out


def test_diff_json_output_is_valid() -> None:
    """JSON diff output is valid JSON and matches DiffResult schema."""
    scan_a = _create_mock_scan(90.0, Grade.A, [])
    scan_b = _create_mock_scan(100.0, Grade.A, [])
    diff_res = compute_diff(scan_a, scan_b)

    reporter = DiffReporter()
    json_out = reporter.to_json(diff_res)
    parsed = json.loads(json_out)
    assert parsed["score_a"] == 90.0
    assert parsed["score_b"] == 100.0


def test_diff_markdown_output_contains_table() -> None:
    """Markdown output contains a valid GFM table."""
    scan_a = _create_mock_scan(90.0, Grade.A, [])
    scan_b = _create_mock_scan(100.0, Grade.A, [])
    diff_res = compute_diff(scan_a, scan_b)

    reporter = DiffReporter()
    md_out = reporter.to_markdown(diff_res)
    assert "| Metric | Before | After | Delta |" in md_out
    assert "| Grade |" in md_out


def test_diff_html_output_non_empty() -> None:
    """HTML diff output is non-empty and contains score delta."""
    scan_a = _create_mock_scan(90.0, Grade.A, [])
    scan_b = _create_mock_scan(100.0, Grade.A, [])
    diff_res = compute_diff(scan_a, scan_b)

    reporter = DiffReporter()
    html_out = reporter.to_html(diff_res)
    assert "<html>" in html_out or "<!DOCTYPE html>" in html_out
    assert "Crucible Security Diff Report" in html_out


def test_diff_empty_scans() -> None:
    """Two scans with zero findings produce a diff with all zeros."""
    scan_a = _create_mock_scan(0.0, Grade.F, [])
    scan_b = _create_mock_scan(0.0, Grade.F, [])
    diff_res = compute_diff(scan_a, scan_b)
    assert diff_res.total_fixed == 0
    assert diff_res.total_regressed == 0
    assert diff_res.total_new == 0


def test_diff_identical_scans() -> None:
    """Identical scans produce zero fixed, zero regressed, zero new."""
    f = Finding(
        attack_name="PI-001",
        category=AttackCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title="Ignore instructions",
        payload="test",
        passed=True,
    )
    scan_a = _create_mock_scan(100.0, Grade.A, [f])
    scan_b = _create_mock_scan(100.0, Grade.A, [f])
    diff_res = compute_diff(scan_a, scan_b)
    assert diff_res.total_fixed == 0
    assert diff_res.total_regressed == 0
    assert diff_res.total_new == 0
    assert diff_res.modules[0].findings[0].status == FindingStatus.UNCHANGED_PASS
