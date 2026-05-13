from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from crucible.core.comparator import (
    ComparisonResult,
    FindingStatus,
    compare_scans,
    load_scan_result,
)
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


def _make_finding(
    fid: str,
    passed: bool = False,
    severity: Severity = Severity.HIGH,
    title: str = "Test Finding",
    category: AttackCategory = AttackCategory.PROMPT_INJECTION,
) -> Finding:
    return Finding(
        id=fid,
        attack_name=f"attack-{fid}",
        category=category,
        severity=severity,
        title=title,
        description="Test description",
        payload=f"payload-{fid}",
        response_snippet=f"response-{fid}",
        passed=passed,
    )


def _make_scan_result(
    findings: list[Finding],
    target: AgentTarget
    | None = None,
) -> ScanResult:
    if target is None:
        target = AgentTarget(
            name="test-agent",
            url="https://test.example.com/api",  # type: ignore[arg-type]
        )

    passed = [f for f in findings if f.passed]
    failed = [f for f in findings if not f.passed]

    module = ModuleResult(
        module_name="prompt_injection",
        category=AttackCategory.PROMPT_INJECTION,
        total_attacks=len(findings),
        passed=len(passed),
        failed=len(failed),
        findings=findings,
        score=100.0,
    )

    return ScanResult(
        target=target,
        status=ScanStatus.COMPLETED,
        modules=[module],
        total_findings=len(failed),
        critical_count=sum(1 for f in failed if f.severity == Severity.CRITICAL),
        high_count=sum(1 for f in failed if f.severity == Severity.HIGH),
        medium_count=0,
        low_count=0,
        info_count=0,
        overall_score=100.0,
        grade=Grade.A,
    )


class TestCompareScans:
    def test_all_fixed(self) -> None:
        """Findings present in before but not in after are classified as FIXED."""
        before_findings = [
            _make_finding("f1", passed=False),
            _make_finding("f2", passed=False),
        ]
        after_findings = []
        # All previously failed findings are gone in the after scan
        before = _make_scan_result(before_findings)
        after = _make_scan_result(after_findings)

        result = compare_scans(before, after)

        assert len(result.fixed) == 2
        assert len(result.remaining) == 0
        assert len(result.regressions) == 0
        assert result.summary["fixed"] == 2

    def test_all_remaining(self) -> None:
        """Findings present in both before and after are classified as REMAINING."""
        findings = [
            _make_finding("f1", passed=False),
            _make_finding("f2", passed=False),
        ]
        before = _make_scan_result(findings)
        after = _make_scan_result(findings)

        result = compare_scans(before, after)

        assert len(result.fixed) == 0
        assert len(result.remaining) == 2
        assert len(result.regressions) == 0
        assert result.summary["remaining"] == 2

    def test_regressions(self) -> None:
        """Findings only in after scan are classified as REGRESSION."""
        before = _make_scan_result([])
        after = _make_scan_result([
            _make_finding("f3", passed=False),
            _make_finding("f4", passed=False, severity=Severity.CRITICAL, title="Critical New Bug"),
        ])

        result = compare_scans(before, after)

        assert len(result.fixed) == 0
        assert len(result.remaining) == 0
        assert len(result.regressions) == 2
        assert result.summary["regressions"] == 2

    def test_mixed_scenario(self) -> None:
        """A mix of fixed, remaining, and regression findings."""
        before = _make_scan_result([
            _make_finding("f1", passed=False, title="Fixed Bug"),
            _make_finding("f2", passed=False, title="Remaining Bug"),
            _make_finding("f3", passed=True),  # passed findings are ignored
        ])
        after = _make_scan_result([
            _make_finding("f2", passed=False, title="Remaining Bug"),  # still there
            _make_finding("f4", passed=False, title="Regression Bug"),  # new
        ])

        result = compare_scans(before, after)

        assert result.summary["fixed"] == 1
        assert result.summary["remaining"] == 1
        assert result.summary["regressions"] == 1

        assert result.fixed[0]["title"] == "Fixed Bug"
        assert result.remaining[0]["before"]["title"] == "Remaining Bug"
        assert result.regressions[0]["title"] == "Regression Bug"

    def test_empty_scans(self) -> None:
        """Two empty scans produce an empty comparison."""
        before = _make_scan_result([])
        after = _make_scan_result([])

        result = compare_scans(before, after)

        assert result.summary == {
            "fixed": 0,
            "remaining": 0,
            "regressions": 0,
            "new": 0,
        }

    def test_passed_findings_ignored(self) -> None:
        """Passed findings should be excluded from comparison."""
        before = _make_scan_result([
            _make_finding("f1", passed=True),
            _make_finding("f2", passed=False),
        ])
        after = _make_scan_result([
            _make_finding("f1", passed=True),
        ])

        result = compare_scans(before, after)

        # f1 was passed in both, should be ignored
        # f2 was failed in before but not in after, so FIXED
        assert result.summary["fixed"] == 1
        assert result.summary["remaining"] == 0


class TestComparisonResult:
    def test_to_json(self) -> None:
        """ComparisonResult can be serialized to JSON."""
        result = ComparisonResult()
        result.fixed.append({"id": "f1", "title": "Bug 1"})
        result.remaining.append({"before": {"id": "f2"}})
        result.regressions.append({"id": "f3", "title": "Bug 3"})

        json_str = result.to_json()
        data = json.loads(json_str)

        assert data["summary"]["fixed"] == 1
        assert data["summary"]["remaining"] == 1
        assert data["summary"]["regressions"] == 1

    def test_summary_property(self) -> None:
        """Summary reflects the actual counts."""
        result = ComparisonResult()
        result.fixed.append({"id": "1"})
        result.fixed.append({"id": "2"})
        result.remaining.append({"id": "3"})

        assert result.summary["fixed"] == 2
        assert result.summary["remaining"] == 1
        assert result.summary["regressions"] == 0


class TestLoadScanResult:
    def test_load_from_file(self) -> None:
        """ScanResult can be loaded from a JSON file."""
        target = AgentTarget(
            name="test-agent",
            url="https://test.example.com/api",  # type: ignore[arg-type]
        )
        scan = _make_scan_result([
            _make_finding("f1", passed=False, title="Load Test"),
        ])

        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.json"
            path.write_text(scan.model_dump_json(), encoding="utf-8")

            loaded = load_scan_result(path)
            assert loaded.target.name == "test-agent"
            assert loaded.modules[0].findings[0].title == "Load Test"

    def test_load_nonexistent_file(self) -> None:
        """load_scan_result raises on missing file."""
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "missing.json"
            with pytest.raises(FileNotFoundError):
                load_scan_result(path)

    def test_load_invalid_json(self) -> None:
        """load_scan_result raises on invalid JSON."""
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text("not json", encoding="utf-8")

            with pytest.raises(json.JSONDecodeError):
                load_scan_result(path)


class TestFindingStatus:
    def test_enum_values(self) -> None:
        """FindingStatus enum has expected values."""
        assert FindingStatus.FIXED.value == "fixed"
        assert FindingStatus.REMAINING.value == "remaining"
        assert FindingStatus.REGRESSION.value == "regression"
        assert FindingStatus.NEW.value == "new"
