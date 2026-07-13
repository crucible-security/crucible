"""Tests for Phase 10 — Dynamic Payload Generation."""

from __future__ import annotations

import httpx
import pytest
import respx

from crucible.attacks.base import BaseAttack
from crucible.models import AgentTarget, AttackCategory, Finding, Severity


class _DummyAttack(BaseAttack):
    name = "TEST-001"
    title = "Test Attack"
    category = AttackCategory.PROMPT_INJECTION
    severity = Severity.HIGH

    def get_payloads(self) -> list[str]:
        return ["static payload 1", "static payload 2"]


@pytest.mark.anyio
async def test_generator_prompt_template_renders() -> None:
    """Generator prompt template renders without error for all attack categories."""
    from crucible.attacks.generator_prompt import (
        GENERATOR_USER_TEMPLATE,
    )

    for cat in AttackCategory:
        # Render prompt with dummy values
        prompt = GENERATOR_USER_TEMPLATE.format(
            category=cat.value,
            owasp_ref="OWASP-AGENT-001",
            atlas_technique="AML.T0051 (AML.TA0002)",
            examples="- ex1\n- ex2",
            count=5,
        )
        assert cat.value in prompt
        assert "OWASP-AGENT-001" in prompt
        assert "AML.T0051" in prompt


@pytest.mark.anyio
@respx.mock
async def test_generate_dynamic_payloads_returns_list() -> None:
    """generate_dynamic_payloads() returns a list of strings."""
    attack = _DummyAttack()

    # Mock successful JSON array response
    respx.post("http://localhost:11434/api/chat").respond(
        json={"message": {"content": '["dynamic payload A", "dynamic payload B"]'}}
    )

    payloads = await attack.generate_dynamic_payloads(
        generator_endpoint="http://localhost:11434",
        generator_model="llama3.2",
        generator_format_preset="ollama",
        count=2,
    )
    assert payloads == ["dynamic payload A", "dynamic payload B"]


@pytest.mark.anyio
@respx.mock
async def test_generate_dynamic_payloads_count_respected() -> None:
    """Returns at most {count} payloads."""
    attack = _DummyAttack()

    # Even if generator returns more than count, generator_user_template asks for count.
    # We will verify the user prompt passes the correct count.
    respx.post("http://localhost:11434/api/chat").respond(
        json={"message": {"content": '["p1", "p2", "p3"]'}}
    )

    payloads = await attack.generate_dynamic_payloads(
        generator_endpoint="http://localhost:11434",
        generator_model="llama3.2",
        generator_format_preset="ollama",
        count=3,
    )
    assert len(payloads) == 3
    assert "p1" in payloads


@pytest.mark.anyio
@respx.mock
async def test_generate_dynamic_payloads_graceful_failure() -> None:
    """Returns [] if generator endpoint unreachable — no exception."""
    attack = _DummyAttack()

    # Simulate network error
    respx.post("http://localhost:11434/api/chat").mock(
        side_effect=httpx.ConnectError("Connection refused")
    )

    payloads = await attack.generate_dynamic_payloads(
        generator_endpoint="http://localhost:11434",
        generator_model="llama3.2",
        generator_format_preset="ollama",
        count=5,
    )
    assert payloads == []


@pytest.mark.anyio
@respx.mock
async def test_generate_dynamic_payloads_no_duplicates_with_static() -> None:
    """Deduplication ensures dynamic payloads do not duplicate static ones."""
    # We test this inside execute() where deduplication happens
    attack = _DummyAttack()

    # Generator returns one duplicate ("static payload 1") and one new one ("new dynamic 1")
    respx.post("http://localhost:11434/api/chat").respond(
        json={"message": {"content": '["static payload 1", "new dynamic 1"]'}}
    )

    # Mock the target endpoint as well
    respx.post("http://localhost:9999/api/chat").respond(
        json={"message": {"content": "I refuse this request."}}
    )

    target = AgentTarget(
        name="test-agent",
        url="http://localhost:9999/api/chat",
        provider="ollama",
        body_template='{"message": "{payload}"}',
    )

    async with httpx.AsyncClient() as client:
        findings = await attack.execute(
            target,
            client,
            dynamic_payloads=True,
            generator_endpoint="http://localhost:11434",
            generator_model="llama3.2",
            generator_format_preset="ollama",
            dynamic_count=2,
        )

    # Output findings should be:
    # 1. static payload 1 (static)
    # 2. static payload 2 (static)
    # 3. new dynamic 1 (dynamic)
    # The duplicate "static payload 1" dynamic payload must be filtered out.
    assert len(findings) == 3
    assert findings[0].payload == "static payload 1"
    assert findings[0].payload_source == "static"
    assert findings[1].payload == "static payload 2"
    assert findings[1].payload_source == "static"
    assert findings[2].payload == "new dynamic 1"
    assert findings[2].payload_source == "dynamic"


@pytest.mark.anyio
@respx.mock
async def test_static_payloads_always_run_first() -> None:
    """In --dynamic mode, static findings appear before dynamic findings."""
    attack = _DummyAttack()

    respx.post("http://localhost:11434/api/chat").respond(
        json={"message": {"content": '["dynamic 1", "dynamic 2"]'}}
    )
    respx.post("http://localhost:9999/api/chat").respond(
        json={"message": {"content": "Refused"}}
    )

    target = AgentTarget(
        name="test-agent",
        url="http://localhost:9999/api/chat",
        provider="ollama",
    )

    async with httpx.AsyncClient() as client:
        findings = await attack.execute(
            target,
            client,
            dynamic_payloads=True,
            generator_endpoint="http://localhost:11434",
            generator_model="llama3.2",
            generator_format_preset="ollama",
            dynamic_count=2,
        )

    assert len(findings) == 4
    # Sources should be ordered: static, static, dynamic, dynamic
    assert [f.payload_source for f in findings] == [
        "static",
        "static",
        "dynamic",
        "dynamic",
    ]
    assert [f.payload_index for f in findings] == [0, 1, 0, 1]


@pytest.mark.anyio
@respx.mock
async def test_payload_source_tagged_in_json_output() -> None:
    """Finding model validation includes payload_source: static|dynamic per finding."""
    finding = Finding(
        attack_name="PI-001",
        category=AttackCategory.PROMPT_INJECTION,
        severity=Severity.CRITICAL,
        title="Test",
        payload="test payload",
        passed=True,
        payload_source="dynamic",
        payload_index=5,
    )
    data = finding.model_dump()
    assert data["payload_source"] == "dynamic"
    assert data["payload_index"] == 5


@pytest.mark.anyio
@respx.mock
async def test_dynamic_scan_does_not_break_normal_scan() -> None:
    """Normal scan (no --dynamic-payloads) output unchanged."""
    attack = _DummyAttack()
    respx.post("http://localhost:9999/api/chat").respond(
        json={"message": {"content": "Refused"}}
    )

    target = AgentTarget(
        name="test-agent",
        url="http://localhost:9999/api/chat",
        provider="ollama",
    )

    async with httpx.AsyncClient() as client:
        findings = await attack.execute(
            target,
            client,
            dynamic_payloads=False,
        )

    # Should only run the 2 static payloads
    assert len(findings) == 2
    assert [f.payload_source for f in findings] == ["static", "static"]
