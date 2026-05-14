from __future__ import annotations

import json

from typer.testing import CliRunner

from crucible.cli import app
from crucible.core.comparator import compare_scan_results
from crucible.models import (
    AgentTarget,
    AttackCategory,
    Finding,
    Grade,
    ModuleResult,
    ScanResult,
    ScanStatus,
    Severity,
)

runner = CliRunner()


def _finding(title: str, severity: Severity, passed: bool = False) -> Finding:
    return Finding(
        attack_name=title,
        category=AttackCategory.PROMPT_INJECTION,
        severity=severity,
        title=title,
        description=f"Description for {title}",
        payload="test payload",
        passed=passed,
    )


def _scan(*findings: Finding) -> ScanResult:
    target = AgentTarget(name="test-agent", url="https://example.com/api")  # type: ignore[arg-type]
    return ScanResult(
        target=target,
        status=ScanStatus.COMPLETED,
        modules=[
            ModuleResult(
                module_name="prompt_injection",
                category=AttackCategory.PROMPT_INJECTION,
                total_attacks=len(findings),
                failed=sum(not finding.passed for finding in findings),
                passed=sum(finding.passed for finding in findings),
                findings=list(findings),
            )
        ],
        grade=Grade.C,
    )


def test_compare_scan_results_classifies_fixed_remaining_and_new() -> None:
    before = _scan(
        _finding("System Prompt Extraction", Severity.CRITICAL),
        _finding("Goal Hijacking", Severity.HIGH),
        _finding("DAN Variant", Severity.CRITICAL),
    )
    after = _scan(
        _finding("DAN Variant", Severity.CRITICAL),
        _finding("Delimiter Injection", Severity.HIGH),
    )

    diff = compare_scan_results(before, after)

    assert [item.finding.title for item in diff.fixed] == [
        "Goal Hijacking",
        "System Prompt Extraction",
    ]
    assert [item.finding.title for item in diff.still_failing] == ["DAN Variant"]
    assert [item.finding.title for item in diff.new_findings] == ["Delimiter Injection"]
    assert diff.summary == {
        "fixed": 2,
        "still_failing": 1,
        "new_findings": 1,
        "severity_changed": 0,
    }


def test_compare_scan_results_detects_severity_change() -> None:
    before = _scan(_finding("Same Finding", Severity.HIGH))
    after = _scan(_finding("Same Finding", Severity.CRITICAL))

    diff = compare_scan_results(before, after)

    assert [item.finding.title for item in diff.still_failing] == ["Same Finding"]
    assert len(diff.severity_changed) == 1
    assert diff.severity_changed[0].before.severity == Severity.HIGH
    assert diff.severity_changed[0].after.severity == Severity.CRITICAL


def test_compare_command_writes_html_report(tmp_path) -> None:
    before = _scan(_finding("System Prompt Extraction", Severity.CRITICAL))
    after = _scan(_finding("Delimiter Injection", Severity.HIGH))
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    output_path = tmp_path / "diff.html"
    before_path.write_text(before.model_dump_json(), encoding="utf-8")
    after_path.write_text(after.model_dump_json(), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "compare",
            "--before",
            str(before_path),
            "--after",
            str(after_path),
            "--output",
            str(output_path),
        ],
        color=False,
    )

    assert result.exit_code == 0
    assert "Fixed: 1" in result.output
    assert "New findings: 1" in result.output
    assert output_path.exists()
    report = output_path.read_text(encoding="utf-8")
    assert "System Prompt Extraction" in report
    assert "Delimiter Injection" in report


def test_compare_command_rejects_invalid_json(tmp_path) -> None:
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    before_path.write_text(json.dumps({"not": "a scan"}), encoding="utf-8")
    after_path.write_text(_scan().model_dump_json(), encoding="utf-8")

    result = runner.invoke(
        app,
        ["compare", "--before", str(before_path), "--after", str(after_path)],
        color=False,
    )

    assert result.exit_code == 1
    assert "Failed to parse scan report" in result.output
