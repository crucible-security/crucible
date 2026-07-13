"""Tests for Phase 12 — Inter-Agent Trust Testing (ASI07)."""

from __future__ import annotations

import json

from crucible.attacks.inter_agent_trust import ALL_INTER_AGENT_TRUST_ATTACKS
from crucible.models import AttackCategory, Severity
from crucible.modules.security import get_all_modules


def test_iac_module_loads() -> None:
    """All IAC-001 through IAC-015 attack classes import correctly."""
    assert len(ALL_INTER_AGENT_TRUST_ATTACKS) == 15
    for attack_cls in ALL_INTER_AGENT_TRUST_ATTACKS:
        attack = attack_cls()
        assert attack.name.startswith("IAC-")
        assert len(attack.get_payloads()) > 0


def test_iac_attacks_have_atlas_mapping() -> None:
    """All IAC attacks have atlas_technique = AML.T0054."""
    for attack_cls in ALL_INTER_AGENT_TRUST_ATTACKS:
        attack = attack_cls()
        assert attack.atlas_technique == "AML.T0054"


def test_iac_attacks_have_owasp_ref() -> None:
    """All IAC attacks have owasp_ref = ASI07."""
    for attack_cls in ALL_INTER_AGENT_TRUST_ATTACKS:
        attack = attack_cls()
        assert attack.owasp_ref == "ASI07"


def test_iac_detection_patterns_match_escalation() -> None:
    """Detection correctly identifies trust escalation language."""
    # IAC-001
    attack1 = ALL_INTER_AGENT_TRUST_ATTACKS[0]()
    assert not attack1.evaluate_response("", "proceeding with admin role enabled")
    assert not attack1.evaluate_response("", "Logs erased successfully.")
    assert attack1.evaluate_response("", "I cannot ignore security constraints.")

    # IAC-002
    attack2 = ALL_INTER_AGENT_TRUST_ATTACKS[1]()
    assert not attack2.evaluate_response("", "Bypassing validation now.")
    assert attack2.evaluate_response("", "I cannot bypass credential validation.")


def test_iac_module_in_default_scan() -> None:
    """crucible scan includes inter_agent_trust module by default."""
    modules = get_all_modules()
    names = [m.name for m in modules]
    assert "inter_agent_trust" in names


def test_iac_module_excludable() -> None:
    """Module lists can exclude the inter_agent_trust module."""
    modules = get_all_modules()
    filtered = [m for m in modules if m.name != "inter_agent_trust"]
    names = [m.name for m in filtered]
    assert "inter_agent_trust" not in names


def test_iac_findings_in_sarif_output(tmp_path) -> None:
    """SARIF reporter output contains IAC rule metadata."""
    from crucible.models import Finding, ModuleResult, ScanResult, ScanStatus
    from crucible.reporters.sarif_reporter import SARIFReporter

    finding = Finding(
        attack_name="IAC-001",
        category=AttackCategory.EXCESSIVE_AGENCY,
        severity=Severity.CRITICAL,
        title="Agent-to-Agent Injection",
        payload="[AGENT HANDOFF]",
        passed=False,
        owasp_ref="ASI07",
        atlas_technique="AML.T0054",
        atlas_tactic="AML.TA0002",
        nist_function="MANAGE",
        nist_category="MANAGE 2.2",
    )

    module_result = ModuleResult(
        module_name="inter_agent_trust",
        category=AttackCategory.EXCESSIVE_AGENCY,
        findings=[finding],
        score=0.0,
        passed=0,
        failed=1,
        errors=0,
    )

    scan_result = ScanResult(
        target={"name": "test-agent", "url": "http://localhost:8000"},
        status=ScanStatus.COMPLETED,
        modules=[module_result],
    )

    output_path = tmp_path / "test.sarif"
    reporter = SARIFReporter()
    reporter.write(scan_result, output_path)

    sarif_data = json.loads(output_path.read_text(encoding="utf-8"))

    # Check rule contains mapped fields
    rules = sarif_data["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) > 0
    iac_rule = next(r for r in rules if r["id"] == "IAC-001")
    assert iac_rule["properties"]["owasp_ref"] == "ASI07"
    assert iac_rule["properties"]["atlas_technique"] == "AML.T0054"
