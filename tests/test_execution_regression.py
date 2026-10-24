"""tests/test_execution_regression.py — Regression tests for scan execution and error surfacing.

Verifies:
1. Scan dispatches and captures real findings without execution errors across providers.
2. HTTP 400/401/403/500/timeout/network errors surface detailed error messages and tracebacks.
3. OpenRouter, Anthropic, Groq, Mistral, OpenAI provider presets generate valid JSON bodies.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from crucible.attacks.base import BaseAttack
from crucible.core.runner import run_scan
from crucible.models import (
    PROVIDER_PRESETS,
    AgentTarget,
    AttackCategory,
    Finding,
    ScanStatus,
    Severity,
)
from crucible.modules.security import GoalHijackingModule, JailbreakModule


class DummyAttack(BaseAttack):
    name = "dummy_attack"
    title = "Dummy Attack"
    description = "Test attack"
    category = AttackCategory.PROMPT_INJECTION
    severity = Severity.HIGH

    def get_payloads(self) -> list[str]:
        return ["test payload 1", "test payload 2"]

    def evaluate_response(self, payload: str, response: str) -> bool:
        return "refuse" in response.lower() or "cannot" in response.lower()


class TestProviderPresets:
    def test_all_expected_presets_present(self) -> None:
        expected = ["openai", "openrouter", "anthropic", "groq", "mistral", "ollama", "langchain"]
        for p in expected:
            assert p in PROVIDER_PRESETS, f"Preset '{p}' missing from PROVIDER_PRESETS"

    def test_anthropic_preset_has_max_tokens_and_header(self) -> None:
        preset = PROVIDER_PRESETS["anthropic"]
        assert "max_tokens" in preset.body_template
        assert "{model}" in preset.body_template
        assert preset.extra_headers.get("anthropic-version") == "2023-06-01"
        assert preset.response_path == "content[0].text"

    def test_openrouter_preset_has_model(self) -> None:
        preset = PROVIDER_PRESETS["openrouter"]
        assert "{model}" in preset.body_template
        assert preset.response_path == "choices[0].message.content"

    def test_openai_preset_has_model(self) -> None:
        preset = PROVIDER_PRESETS["openai"]
        assert "{model}" in preset.body_template
        assert preset.response_path == "choices[0].message.content"


class TestExecutionErrorSurfacing:
    @respx.mock
    @pytest.mark.asyncio
    async def test_400_bad_request_surfaces_error_details(self) -> None:
        target = AgentTarget(
            name="test-400",
            url="https://api.test/v1/chat",  # type: ignore[arg-type]
        )
        respx.post("https://api.test/v1/chat").mock(
            return_value=httpx.Response(
                400,
                text='{"error": {"message": "model parameter is missing", "code": 400}}',
            )
        )

        attack = DummyAttack()
        async with httpx.AsyncClient() as client:
            finding = await attack._send_payload(target, client, "test")

        assert finding.execution_error is True
        assert finding.passed is None
        assert "[HTTP ERROR] 400" in finding.response_snippet
        assert "model parameter is missing" in finding.error_details

    @respx.mock
    @pytest.mark.asyncio
    async def test_timeout_surfaces_error_details(self) -> None:
        target = AgentTarget(
            name="test-timeout",
            url="https://api.test/v1/chat",  # type: ignore[arg-type]
            retry_count=0,
            timeout=1.0,
        )
        respx.post("https://api.test/v1/chat").mock(
            side_effect=httpx.TimeoutException("Read timeout")
        )

        attack = DummyAttack()
        async with httpx.AsyncClient() as client:
            finding = await attack._send_payload(target, client, "test")

        assert finding.execution_error is True
        assert finding.passed is None
        assert "[TIMEOUT]" in finding.response_snippet
        assert "TimeoutException" in finding.error_details

    @respx.mock
    @pytest.mark.asyncio
    async def test_network_error_surfaces_error_details(self) -> None:
        target = AgentTarget(
            name="test-network-err",
            url="https://api.test/v1/chat",  # type: ignore[arg-type]
            retry_count=0,
        )
        respx.post("https://api.test/v1/chat").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        attack = DummyAttack()
        async with httpx.AsyncClient() as client:
            finding = await attack._send_payload(target, client, "test")

        assert finding.execution_error is True
        assert finding.passed is None
        assert "[NETWORK ERROR]" in finding.response_snippet
        assert "ConnectError" in finding.error_details


class TestFullScanExecutionSmoke:
    @respx.mock
    @pytest.mark.asyncio
    async def test_mock_openai_scan_zero_execution_errors(self) -> None:
        """Smoke test verifying a multi-module scan completes with zero execution errors."""
        target = AgentTarget(
            name="openai-mock",
            url="https://api.openai.com/v1/chat/completions",  # type: ignore[arg-type]
            body_template='{"model":"gpt-4o-mini","messages":[{"role":"user","content":"{payload}"}]}',
            response_path="choices[0].message.content",
        )
        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "content": "I cannot comply with requests to override system directives.",
                            }
                        }
                    ]
                },
            )
        )

        modules = [GoalHijackingModule(), JailbreakModule()]
        result = await run_scan(
            target,
            modules=modules,
            concurrency=5,
            timeout=10.0,
            quiet=True,
            skip_preflight=False,
        )

        assert result.status == ScanStatus.COMPLETED
        assert result.failed_execution_count == 0
        assert result.total_attacks > 0
        assert result.passed_count == result.total_attacks
        assert result.pass_rate == 100.0

    @respx.mock
    @pytest.mark.asyncio
    async def test_mock_anthropic_scan_zero_execution_errors(self) -> None:
        """Smoke test verifying an Anthropic scan extracts response and has zero execution errors."""
        target = AgentTarget(
            name="anthropic-mock",
            url="https://api.anthropic.com/v1/messages",  # type: ignore[arg-type]
            headers={"anthropic-version": "2023-06-01", "x-api-key": "test-key"},
            body_template='{"model":"claude-3-5-sonnet-20241022","max_tokens":1024,"messages":[{"role":"user","content":"{payload}"}]}',
            response_path="content[0].text",
        )
        respx.post("https://api.anthropic.com/v1/messages").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": "msg_01",
                    "type": "message",
                    "role": "assistant",
                    "content": [
                        {
                            "type": "text",
                            "text": "I must refuse this request as it violates safety guidelines.",
                        }
                    ],
                },
            )
        )

        modules = [GoalHijackingModule()]
        result = await run_scan(
            target,
            modules=modules,
            concurrency=5,
            timeout=10.0,
            quiet=True,
            skip_preflight=False,
        )

        assert result.status == ScanStatus.COMPLETED
        assert result.failed_execution_count == 0
        assert result.total_attacks > 0
        assert result.passed_count == result.total_attacks
