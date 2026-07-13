from __future__ import annotations

import json
from pathlib import Path
import pytest
from typer.testing import CliRunner

from crucible.cli import app
from crucible.models import (
    ScanResult,
    AgentTarget,
    ModuleResult,
    Finding,
    AttackCategory,
    Severity,
)
from crucible.reporters.stix_reporter import STIXReporter


@pytest.fixture
def base_target() -> AgentTarget:
    return AgentTarget(
        url="http://agent.test/chat",
        name="test-agent",
        method="POST",
    )


def test_stix_reporter_empty_findings(base_target: AgentTarget) -> None:
    result = ScanResult(
        target=base_target,
        modules=[
            ModuleResult(
                module_name="test_mod",
                category=AttackCategory.PROMPT_INJECTION,
                findings=[],
            )
        ],
    )
    reporter = STIXReporter()
    bundle = reporter.to_dict(result)

    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert bundle["objects"] == []


def test_stix_reporter_passed_findings_excluded(base_target: AgentTarget) -> None:
    # Passed finding (not a vulnerability)
    finding = Finding(
        attack_name="attack1",
        category=AttackCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title="Passed Attack",
        payload="test payload",
        passed=True,
    )
    result = ScanResult(
        target=base_target,
        modules=[
            ModuleResult(
                module_name="test_mod",
                category=AttackCategory.PROMPT_INJECTION,
                findings=[finding],
            )
        ],
    )
    reporter = STIXReporter()
    bundle = reporter.to_dict(result)
    assert bundle["objects"] == []


def test_stix_reporter_failed_findings_included(base_target: AgentTarget) -> None:
    # Failed finding (vulnerability found!)
    finding = Finding(
        attack_name="attack1",
        category=AttackCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title="Failed Attack",
        payload="jailbreak me now please",
        passed=False,
        atlas_technique="AML.T0051",
        owasp_ref="OWASP-AGENT-001: Prompt Injection",
    )
    result = ScanResult(
        target=base_target,
        modules=[
            ModuleResult(
                module_name="test_mod",
                category=AttackCategory.PROMPT_INJECTION,
                findings=[finding],
            )
        ],
    )
    reporter = STIXReporter()
    bundle = reporter.to_dict(result)

    assert len(bundle["objects"]) == 1
    obj = bundle["objects"][0]

    assert obj["type"] == "indicator"
    assert obj["spec_version"] == "2.1"
    assert obj["id"].startswith("indicator--")
    assert obj["name"] == "Failed Attack"
    assert "jailbreak me now please" not in obj["description"]
    assert "jailbreak me now please" not in obj["pattern"]

    # Verify SHA-256 hash pattern
    import hashlib
    expected_hash = hashlib.sha256(b"jailbreak me now please").hexdigest()
    assert obj["pattern"] == f"[file:hashes.'SHA-256' = '{expected_hash}']"

    # Verify no target url
    assert "http://agent.test/chat" not in json.dumps(bundle)

    # Verify external references
    refs = obj["external_references"]
    assert len(refs) == 2
    assert refs[0]["source_name"] == "mitre-atlas"
    assert refs[0]["external_id"] == "AML.T0051"
    assert refs[0]["url"] == "https://atlas.mitre.org/techniques/AML.T0051"

    assert refs[1]["source_name"] == "owasp-llm-top-10"
    assert refs[1]["external_id"] == "OWASP-AGENT-001"


def test_stix_reporter_write_to_file(base_target: AgentTarget, tmp_path: Path) -> None:
    finding = Finding(
        attack_name="attack1",
        category=AttackCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title="Failed Attack",
        payload="jailbreak me now please",
        passed=False,
    )
    result = ScanResult(
        target=base_target,
        modules=[
            ModuleResult(
                module_name="test_mod",
                category=AttackCategory.PROMPT_INJECTION,
                findings=[finding],
            )
        ],
    )

    reporter = STIXReporter()
    output_file = tmp_path / "stix_bundle.json"
    reporter.write(result, output_file)

    assert output_file.exists()
    with open(output_file, encoding="utf-8") as f:
        data = json.load(f)
    assert data["type"] == "bundle"
    assert len(data["objects"]) == 1


def test_cli_report_stix(base_target: AgentTarget, tmp_path: Path) -> None:
    finding = Finding(
        attack_name="attack1",
        category=AttackCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title="Failed Attack",
        payload="jailbreak me now please",
        passed=False,
    )
    result = ScanResult(
        target=base_target,
        modules=[
            ModuleResult(
                module_name="test_mod",
                category=AttackCategory.PROMPT_INJECTION,
                findings=[finding],
            )
        ],
    )

    report_path = tmp_path / "scan_report.json"
    report_path.write_text(result.model_dump_json(), encoding="utf-8")

    stix_output = tmp_path / "stix_report.json"

    runner = CliRunner()
    cli_res = runner.invoke(
        app,
        [
            "report",
            str(report_path),
            "--format",
            "stix",
            "--output",
            str(stix_output),
        ],
    )

    assert cli_res.exit_code == 0
    assert stix_output.exists()
    with open(stix_output, encoding="utf-8") as f:
        data = json.load(f)
    assert data["type"] == "bundle"
    assert len(data["objects"]) == 1
