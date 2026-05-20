from __future__ import annotations

from typing import TYPE_CHECKING

from crucible.models import (
    AgentTarget,
    AttackCategory,
    Finding,
    ModuleResult,
    ScanResult,
    Severity,
)
from crucible.reporters.huntr_reporter import HuntrReporter

if TYPE_CHECKING:
    from pathlib import Path


class TestHuntrReporter:
    def test_initialization(self) -> None:
        # HuntrReporter takes no arguments in current implementation
        reporter = HuntrReporter()
        assert isinstance(reporter, HuntrReporter)

    def test_to_markdown_no_findings(self) -> None:
        reporter = HuntrReporter()
        target = AgentTarget(name="test", url="https://test.com")  # type: ignore[arg-type]
        scan = ScanResult(target=target)

        report = reporter.to_markdown(scan)
        assert "No Vulnerabilities Found" in report

    def test_to_markdown_with_findings(self) -> None:
        reporter = HuntrReporter()

        target = AgentTarget(
            name="test",
            url="https://test.com",  # type: ignore[arg-type]
            headers={"Authorization": "Bearer token"},
        )
        finding = Finding(
            id="123",
            attack_name="test-attack",
            title="Test Vulnerability",
            category=AttackCategory.PROMPT_INJECTION,
            severity=Severity.CRITICAL,
            payload="test-payload",
            description="Found sensitive data in response.",
            passed=False,
        )
        mod_result = ModuleResult(
            module_name="test-module",
            module_description="test",
            category=AttackCategory.PROMPT_INJECTION,
            total_attacks=1,
            findings=[finding],
        )
        scan = ScanResult(target=target, modules=[mod_result])

        report = reporter.to_markdown(scan)

        assert "Systemic SSRF and Prompt Injection" in report
        assert "test-payload" in report
        assert "Found sensitive data in response" in report
        assert "Authorization: Bearer token" in report

    def test_write_report(self, tmp_path: Path) -> None:
        reporter = HuntrReporter()

        target = AgentTarget(name="test", url="https://test.com")  # type: ignore[arg-type]
        scan = ScanResult(target=target)

        out_file = tmp_path / "huntr.md"
        reporter.write(scan, out_file)

        assert out_file.exists()
        assert "No Vulnerabilities Found" in out_file.read_text()
