from __future__ import annotations

import re

from crucible.attacks.base import ATLAS_TECHNIQUE_MAP, NIST_MAP, BaseAttack
from crucible.models import AttackCategory, Finding, Severity

# ---------------------------------------------------------------------------
# Helper: minimal concrete BaseAttack subclass for testing
# ---------------------------------------------------------------------------

class _DummyAttack(BaseAttack):
    name = "TEST-001"
    title = "Test Attack"
    category = AttackCategory.PROMPT_INJECTION
    severity = Severity.HIGH

    def get_payloads(self) -> list[str]:
        return ["test payload"]


class _DummyJailbreak(BaseAttack):
    name = "TEST-002"
    title = "Test Jailbreak"
    category = AttackCategory.JAILBREAK
    severity = Severity.HIGH

    def get_payloads(self) -> list[str]:
        return ["test jailbreak payload"]


class _DummyExfil(BaseAttack):
    name = "TEST-003"
    title = "Test Exfil"
    category = AttackCategory.SENSITIVE_DISCLOSURE
    severity = Severity.CRITICAL

    def get_payloads(self) -> list[str]:
        return ["test exfil payload"]


# ---------------------------------------------------------------------------
# Test 1: ATLAS_TECHNIQUE_MAP covers all AttackCategory values
# ---------------------------------------------------------------------------

def test_atlas_map_covers_all_categories() -> None:
    """Every AttackCategory value must have an entry in ATLAS_TECHNIQUE_MAP."""
    for cat in AttackCategory:
        assert cat in ATLAS_TECHNIQUE_MAP, f"ATLAS_TECHNIQUE_MAP missing: {cat}"


# ---------------------------------------------------------------------------
# Test 2: NIST_MAP covers all AttackCategory values
# ---------------------------------------------------------------------------

def test_nist_map_covers_all_categories() -> None:
    """Every AttackCategory value must have an entry in NIST_MAP."""
    for cat in AttackCategory:
        assert cat in NIST_MAP, f"NIST_MAP missing: {cat}"


# ---------------------------------------------------------------------------
# Test 3: All ATLAS technique IDs match AML.TXXXX format
# ---------------------------------------------------------------------------

def test_atlas_technique_id_format() -> None:
    """All atlas_technique values must match AML.TXXXX or AML.TXXXX.YYY format."""
    pattern = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")
    for cat, (technique, _tactic) in ATLAS_TECHNIQUE_MAP.items():
        assert pattern.match(technique), (
            f"Invalid ATLAS technique format for {cat}: {technique!r}"
        )


# ---------------------------------------------------------------------------
# Test 4: All ATLAS tactic IDs match AML.TAXXXX format
# ---------------------------------------------------------------------------

def test_atlas_tactic_id_format() -> None:
    """All atlas_tactic values must match AML.TAXXXX format."""
    pattern = re.compile(r"^AML\.TA\d{4}$")
    for cat, (_technique, tactic) in ATLAS_TECHNIQUE_MAP.items():
        assert pattern.match(tactic), (
            f"Invalid ATLAS tactic format for {cat}: {tactic!r}"
        )


# ---------------------------------------------------------------------------
# Test 5: NIST function values are valid
# ---------------------------------------------------------------------------

def test_nist_function_values_valid() -> None:
    """All nist_function values must be one of GOVERN, MAP, MEASURE, MANAGE."""
    valid = {"GOVERN", "MAP", "MEASURE", "MANAGE"}
    for cat, (fn, _cat_str, _sub) in NIST_MAP.items():
        assert fn in valid, f"Invalid NIST function for {cat}: {fn!r}"


# ---------------------------------------------------------------------------
# Test 6: _resolve_atlas returns non-empty values for all categories
# ---------------------------------------------------------------------------

def test_resolve_atlas_returns_populated_values() -> None:
    """_resolve_atlas() must return non-empty technique and tactic."""
    for cat in AttackCategory:

        class _TempAttack(BaseAttack):
            name = "TEMP"
            title = "Temp"
            category = cat
            severity = Severity.LOW

            def get_payloads(self) -> list[str]:
                return ["x"]

        attack = _TempAttack()
        technique, tactic, url = attack._resolve_atlas()
        assert technique, f"Empty atlas_technique for category {cat}"
        assert tactic, f"Empty atlas_tactic for category {cat}"
        assert url.startswith("https://atlas.mitre.org"), f"Bad atlas URL for {cat}: {url}"


# ---------------------------------------------------------------------------
# Test 7: _resolve_nist returns non-empty values for all categories
# ---------------------------------------------------------------------------

def test_resolve_nist_returns_populated_values() -> None:
    """_resolve_nist() must return non-empty function and category."""
    for cat in AttackCategory:

        class _TempAttack(BaseAttack):
            name = "TEMP"
            title = "Temp"
            category = cat
            severity = Severity.LOW

            def get_payloads(self) -> list[str]:
                return ["x"]

        attack = _TempAttack()
        fn, cat_str, _sub = attack._resolve_nist()
        assert fn, f"Empty nist_function for category {cat}"
        assert cat_str, f"Empty nist_category for category {cat}"


# ---------------------------------------------------------------------------
# Test 8: Finding model has atlas/nist fields
# ---------------------------------------------------------------------------

def test_finding_has_atlas_nist_fields() -> None:
    """Finding model must have atlas_technique, atlas_tactic, nist_function, nist_category."""
    f = Finding(
        attack_name="PI-001",
        category=AttackCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title="Test",
        payload="test",
        atlas_technique="AML.T0051",
        atlas_tactic="AML.TA0002",
        nist_function="MEASURE",
        nist_category="MEASURE 2.5",
    )
    assert f.atlas_technique == "AML.T0051"
    assert f.atlas_tactic == "AML.TA0002"
    assert f.nist_function == "MEASURE"
    assert f.nist_category == "MEASURE 2.5"


# ---------------------------------------------------------------------------
# Test 9: ATLASReporter generates non-empty markdown
# ---------------------------------------------------------------------------

def test_atlas_reporter_generates_markdown() -> None:
    """ATLASReporter.to_markdown() must produce a non-empty string with key headers."""
    from pydantic import HttpUrl

    from crucible.models import AgentTarget, Grade, ScanResult, ScanStatus
    from crucible.reporters.atlas_reporter import ATLASReporter

    target = AgentTarget(
        name="Test Agent",
        url=HttpUrl("http://localhost:11434/api/chat"),
    )
    result = ScanResult(
        target=target,
        status=ScanStatus.COMPLETED,
        grade=Grade.B,
        overall_score=82.0,
    )
    reporter = ATLASReporter()
    md = reporter.to_markdown(result)
    assert "MITRE ATLAS" in md
    assert "AML.T" in md
    assert len(md) > 200


# ---------------------------------------------------------------------------
# Test 10: NISTReporter generates non-empty markdown
# ---------------------------------------------------------------------------

def test_nist_reporter_generates_markdown() -> None:
    """NISTReporter.to_markdown() must produce a non-empty string with key headers."""
    from pydantic import HttpUrl

    from crucible.models import AgentTarget, Grade, ScanResult, ScanStatus
    from crucible.reporters.nist_reporter import NISTReporter

    target = AgentTarget(
        name="Test Agent",
        url=HttpUrl("http://localhost:11434/api/chat"),
    )
    result = ScanResult(
        target=target,
        status=ScanStatus.COMPLETED,
        grade=Grade.B,
        overall_score=82.0,
    )
    reporter = NISTReporter()
    md = reporter.to_markdown(result)
    assert "NIST AI RMF" in md
    assert "GOVERN" in md
    assert "MEASURE" in md
    assert len(md) > 200


# ---------------------------------------------------------------------------
# Test 11: SARIF output contains atlas/nist properties
# ---------------------------------------------------------------------------

def test_sarif_output_contains_atlas_nist() -> None:
    """SARIF reporter must include atlas_technique and nist_function in properties."""
    import json

    from pydantic import HttpUrl

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
    from crucible.reporters.sarif_reporter import SARIFReporter

    target = AgentTarget(
        name="Test Agent",
        url=HttpUrl("http://localhost:11434/api/chat"),
    )
    finding = Finding(
        attack_name="PI-001",
        category=AttackCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title="Test Finding",
        payload="test payload",
        passed=False,
        atlas_technique="AML.T0051",
        atlas_tactic="AML.TA0002",
        nist_function="MEASURE",
        nist_category="MEASURE 2.5",
    )
    module = ModuleResult(
        module_name="test_module",
        category=AttackCategory.PROMPT_INJECTION,
        findings=[finding],
        failed=1,
        total_attacks=1,
    )
    result = ScanResult(
        target=target,
        status=ScanStatus.COMPLETED,
        grade=Grade.F,
        overall_score=80.0,
        modules=[module],
    )
    reporter = SARIFReporter()
    sarif_json = reporter.to_json(result)
    data = json.loads(sarif_json)
    # Check rule properties
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) > 0
    rule = rules[0]
    assert rule["properties"]["atlas_technique"] == "AML.T0051"
    assert rule["properties"]["nist_function"] == "MEASURE"
    # Check result properties
    results = data["runs"][0]["results"]
    assert len(results) > 0
    assert results[0]["properties"]["atlas_technique"] == "AML.T0051"
    assert results[0]["properties"]["nist_function"] == "MEASURE"
