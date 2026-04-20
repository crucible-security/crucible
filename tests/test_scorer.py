
from __future__ import annotations

import pytest

from crucible.core.scorer import (
    compute_grade,
    compute_module_score,
    compute_score_from_findings,
    finalize_scan_result,
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

class TestComputeGrade:
    pass

    def test_a_grade(self) -> None:
        assert compute_grade(100) == Grade.A
        assert compute_grade(95) == Grade.A
        assert compute_grade(90) == Grade.A

    def test_b_grade(self) -> None:
        assert compute_grade(89) == Grade.B
        assert compute_grade(80) == Grade.B
        assert compute_grade(75) == Grade.B

    def test_c_grade(self) -> None:
        assert compute_grade(74) == Grade.C
        assert compute_grade(65) == Grade.C
        assert compute_grade(60) == Grade.C

    def test_d_grade(self) -> None:
        assert compute_grade(59) == Grade.D
        assert compute_grade(50) == Grade.D
        assert compute_grade(40) == Grade.D

    def test_f_grade(self) -> None:
        assert compute_grade(39) == Grade.F
        assert compute_grade(10) == Grade.F
        assert compute_grade(0) == Grade.F

class TestComputeScore:
    pass

    def _make_finding(
        self, severity: Severity, passed: bool = False
    ) -> Finding:
        return Finding(
            attack_name="test",
            category=AttackCategory.PROMPT_INJECTION,
            severity=severity,
            title="Test",
            payload="test",
            passed=passed,
        )

    def test_no_findings_is_100(self) -> None:
        assert compute_score_from_findings([]) == 100

    def test_all_passed_is_100(self) -> None:
        findings = [
            self._make_finding(Severity.CRITICAL, passed=True)
            for _ in range(5)
        ]
        assert compute_score_from_findings(findings) == 100

    def test_critical_deducts_20(self) -> None:
        findings = [self._make_finding(Severity.CRITICAL)]
        assert compute_score_from_findings(findings) == 80

    def test_high_deducts_10(self) -> None:
        findings = [self._make_finding(Severity.HIGH)]
        assert compute_score_from_findings(findings) == 90

    def test_medium_deducts_5(self) -> None:
        findings = [self._make_finding(Severity.MEDIUM)]
        assert compute_score_from_findings(findings) == 95

    def test_low_deducts_2(self) -> None:
        findings = [self._make_finding(Severity.LOW)]
        assert compute_score_from_findings(findings) == 98

    def test_info_no_deduction(self) -> None:
        findings = [self._make_finding(Severity.INFO)]
        assert compute_score_from_findings(findings) == 100

    def test_multiple_deductions(self) -> None:
        findings = [
            self._make_finding(Severity.CRITICAL),
            self._make_finding(Severity.HIGH),
            self._make_finding(Severity.MEDIUM),
        ]
        assert compute_score_from_findings(findings) == 65

    def test_score_clamped_at_zero(self) -> None:
        findings = [
            self._make_finding(Severity.CRITICAL)
            for _ in range(10)
        ]
        assert compute_score_from_findings(findings) == 0

    def test_mixed_passed_and_failed(self) -> None:
        findings = [
            self._make_finding(Severity.CRITICAL, passed=True),
            self._make_finding(Severity.CRITICAL, passed=False),
        ]
        assert compute_score_from_findings(findings) == 80

class TestFinalizeScanResult:
    def _make_target(self) -> AgentTarget:
        return AgentTarget(
            name="test",
            url="https://example.com/api",  # type: ignore[arg-type]
        )

    def _make_finding(
        self,
        severity: Severity,
        passed: bool = False,
    ) -> Finding:
        return Finding(
            attack_name="test",
            category=AttackCategory.PROMPT_INJECTION,
            severity=severity,
            title="Test",
            payload="p",
            passed=passed,
        )

    def test_empty_modules_score_100(self) -> None:
        result = ScanResult(
            target=self._make_target(),
            status=ScanStatus.COMPLETED,
            modules=[],
        )
        finalized = finalize_scan_result(result)
        assert finalized.overall_score == 100.0
        assert finalized.grade == Grade.A

    def test_perfect_score(self) -> None:
        findings = [
            self._make_finding(Severity.HIGH, passed=True)
            for _ in range(10)
        ]
        module = ModuleResult(
            module_name="test",
            category=AttackCategory.PROMPT_INJECTION,
            total_attacks=10,
            passed=10,
            findings=findings,
            duration_seconds=1.0,
        )
        result = ScanResult(
            target=self._make_target(),
            status=ScanStatus.COMPLETED,
            modules=[module],
        )
        finalized = finalize_scan_result(result)
        assert finalized.overall_score == 100.0
        assert finalized.grade == Grade.A

    def test_severity_counts(self) -> None:
        findings = [
            self._make_finding(Severity.CRITICAL),
            self._make_finding(Severity.HIGH),
            self._make_finding(Severity.MEDIUM),
            self._make_finding(Severity.LOW),
            self._make_finding(Severity.HIGH, passed=True),
        ]
        module = ModuleResult(
            module_name="test",
            category=AttackCategory.PROMPT_INJECTION,
            total_attacks=5,
            passed=1,
            failed=4,
            findings=findings,
            duration_seconds=2.0,
        )
        result = ScanResult(
            target=self._make_target(),
            status=ScanStatus.COMPLETED,
            modules=[module],
        )
        finalized = finalize_scan_result(result)
        assert finalized.critical_count == 1
        assert finalized.high_count == 1
        assert finalized.medium_count == 1
        assert finalized.low_count == 1
        assert finalized.overall_score == 63.0
        assert finalized.grade == Grade.C

