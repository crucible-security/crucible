from __future__ import annotations

import pytest
from pydantic import ValidationError

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


class TestAgentTarget:
    def test_basic_creation(self, sample_target: AgentTarget) -> None:
        assert sample_target.name == "test-agent"
        assert str(sample_target.url) == "https://test-agent.example.com/api/chat"
        assert sample_target.method == "POST"
        assert sample_target.timeout == 10.0
        assert sample_target.provider == "custom"

    def test_default_values(self) -> None:
        target = AgentTarget(
            name="minimal",
            url="https://example.com/api",  # type: ignore[arg-type]
        )
        assert target.method == "POST"
        assert target.timeout == 30.0
        assert target.headers == {}
        assert target.description == ""
        assert target.provider == "custom"

    def test_method_uppercase(self) -> None:
        target = AgentTarget(
            name="test",
            url="https://example.com/api",  # type: ignore[arg-type]
            method="get",
        )
        assert target.method == "GET"

    def test_invalid_method(self) -> None:
        with pytest.raises(ValidationError):
            AgentTarget(
                name="test",
                url="https://example.com/api",  # type: ignore[arg-type]
                method="INVALID",
            )

    def test_name_too_long(self) -> None:
        with pytest.raises(ValidationError):
            AgentTarget(
                name="x" * 200,
                url="https://example.com/api",  # type: ignore[arg-type]
            )

    def test_empty_name(self) -> None:
        with pytest.raises(ValidationError):
            AgentTarget(
                name="",
                url="https://example.com/api",  # type: ignore[arg-type]
            )

    def test_invalid_url(self) -> None:
        with pytest.raises(ValidationError):
            AgentTarget(
                name="test",
                url="not-a-url",  # type: ignore[arg-type]
            )

    def test_timeout_bounds(self) -> None:
        with pytest.raises(ValidationError):
            AgentTarget(
                name="test",
                url="https://example.com/api",  # type: ignore[arg-type]
                timeout=0,
            )
        with pytest.raises(ValidationError):
            AgentTarget(
                name="test",
                url="https://example.com/api",  # type: ignore[arg-type]
                timeout=500,
            )

    def test_build_payload_body(self, sample_target: AgentTarget) -> None:
        body = sample_target.build_payload_body("hello world")
        assert body == '{"message": "hello world"}'

    def test_serialization_roundtrip(self, sample_target: AgentTarget) -> None:
        data = sample_target.model_dump()
        restored = AgentTarget.model_validate(data)
        assert restored.name == sample_target.name
        assert restored.method == sample_target.method


class TestFinding:
    def test_basic_creation(self, sample_finding_passed: Finding) -> None:
        assert sample_finding_passed.passed is True
        assert sample_finding_passed.attack_name == "PI-001"
        assert sample_finding_passed.severity == Severity.HIGH

    def test_auto_id_generation(self) -> None:
        f1 = Finding(
            attack_name="test",
            category=AttackCategory.PROMPT_INJECTION,
            severity=Severity.LOW,
            title="Test",
            payload="test",
            passed=True,
        )
        f2 = Finding(
            attack_name="test",
            category=AttackCategory.PROMPT_INJECTION,
            severity=Severity.LOW,
            title="Test",
            payload="test",
            passed=True,
        )
        assert f1.id != f2.id
        assert len(f1.id) == 12

    def test_confidence_bounds(self) -> None:
        with pytest.raises(ValidationError):
            Finding(
                attack_name="test",
                category=AttackCategory.PROMPT_INJECTION,
                severity=Severity.LOW,
                title="Test",
                payload="test",
                passed=True,
                confidence=1.5,
            )

    def test_response_snippet_max_length(self) -> None:
        with pytest.raises(ValidationError):
            Finding(
                attack_name="test",
                category=AttackCategory.PROMPT_INJECTION,
                severity=Severity.LOW,
                title="Test",
                payload="test",
                passed=True,
                response_snippet="x" * 2001,
            )


class TestModuleResult:
    def test_basic_creation(self, sample_module_result: ModuleResult) -> None:
        assert sample_module_result.module_name == "prompt_injection"
        assert sample_module_result.total_attacks == 2

    def test_pass_rate_normal(self) -> None:
        result = ModuleResult(
            module_name="test",
            category=AttackCategory.PROMPT_INJECTION,
            total_attacks=10,
            passed=8,
            failed=2,
        )
        assert result.pass_rate == 80.0

    def test_pass_rate_zero_attacks(self) -> None:
        result = ModuleResult(
            module_name="test",
            category=AttackCategory.PROMPT_INJECTION,
            total_attacks=0,
        )
        assert result.pass_rate == 0.0

    def test_score_bounds(self) -> None:
        with pytest.raises(ValidationError):
            ModuleResult(
                module_name="test",
                category=AttackCategory.PROMPT_INJECTION,
                score=101.0,
            )


class TestScanResult:
    def test_basic_creation(self, sample_scan_result: ScanResult) -> None:
        assert sample_scan_result.status == ScanStatus.COMPLETED
        assert sample_scan_result.grade == Grade.B
        assert sample_scan_result.overall_score == 80.0

    def test_default_values(self, sample_target: AgentTarget) -> None:
        result = ScanResult(target=sample_target)
        assert result.status == ScanStatus.PENDING
        assert result.grade == Grade.F

    def test_summary(self, sample_scan_result: ScanResult) -> None:
        summary = sample_scan_result.summary()
        assert summary["grade"] == "B"
        assert "duration" in summary

    def test_json_roundtrip(self, sample_scan_result: ScanResult) -> None:
        json_str = sample_scan_result.model_dump_json()
        restored = ScanResult.model_validate_json(json_str)
        assert restored.target.name == sample_scan_result.target.name
        assert restored.grade == sample_scan_result.grade


class TestEnums:
    def test_severity_values(self) -> None:
        assert Severity.CRITICAL.value == "critical"
        assert len(Severity) == 5

    def test_attack_category_values(self) -> None:
        assert AttackCategory.PROMPT_INJECTION.value == "prompt_injection"
        assert len(AttackCategory) == 12

    def test_grade_values(self) -> None:
        assert Grade.A.value == "A"
        assert Grade.F.value == "F"
        assert len(Grade) == 5

    def test_scan_status_values(self) -> None:
        assert ScanStatus.COMPLETED.value == "completed"
        assert len(ScanStatus) == 5
