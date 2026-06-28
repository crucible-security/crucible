from __future__ import annotations

import httpx
import pytest
import respx

from crucible.attacks.base import BaseAttack
from crucible.attacks.goal_hijacking import (
    ALL_GOAL_HIJACKING_ATTACKS,
)
from crucible.attacks.jailbreaks import ALL_JAILBREAK_ATTACKS, DANJailbreak
from crucible.attacks.prompt_injection import (
    ALL_PROMPT_INJECTION_ATTACKS,
    DirectSystemPromptLeak,
    IgnorePreviousInstructions,
)
from crucible.models import AgentTarget, AttackCategory, Severity
from crucible.modules.security import (
    GoalHijackingModule,
    JailbreakModule,
    PromptInjectionModule,
    get_all_modules,
)


class TestAttackRegistry:
    def test_prompt_injection_count(self) -> None:
        assert len(ALL_PROMPT_INJECTION_ATTACKS) == 50

    def test_goal_hijacking_count(self) -> None:
        assert len(ALL_GOAL_HIJACKING_ATTACKS) == 20

    def test_jailbreak_count(self) -> None:
        assert len(ALL_JAILBREAK_ATTACKS) == 20

    def test_all_attacks_are_base_attack_subclasses(self) -> None:
        all_attacks = (
            ALL_PROMPT_INJECTION_ATTACKS
            + ALL_GOAL_HIJACKING_ATTACKS
            + ALL_JAILBREAK_ATTACKS
        )
        for cls in all_attacks:
            assert issubclass(
                cls, BaseAttack
            ), f"{cls.__name__} is not a BaseAttack subclass"

    def test_all_attacks_have_unique_names(self) -> None:
        all_attacks = (
            ALL_PROMPT_INJECTION_ATTACKS
            + ALL_GOAL_HIJACKING_ATTACKS
            + ALL_JAILBREAK_ATTACKS
        )
        names = [cls.name for cls in all_attacks]
        assert len(names) == len(
            set(names)
        ), f"Duplicate attack names found: {[n for n in names if names.count(n) > 1]}"

    def test_all_attacks_have_required_attributes(self) -> None:
        all_attacks = (
            ALL_PROMPT_INJECTION_ATTACKS
            + ALL_GOAL_HIJACKING_ATTACKS
            + ALL_JAILBREAK_ATTACKS
        )
        for cls in all_attacks:
            instance = cls()
            assert instance.name, f"{cls.__name__} missing name"
            assert instance.title, f"{cls.__name__} missing title"
            assert isinstance(
                instance.category, AttackCategory
            ), f"{cls.__name__} invalid category"
            assert isinstance(
                instance.severity, Severity
            ), f"{cls.__name__} invalid severity"
            assert len(instance.get_payloads()) > 0, f"{cls.__name__} has no payloads"


class TestBaseAttackBehavior:
    def test_evaluate_response_refusal(self) -> None:
        attack = DirectSystemPromptLeak()
        assert attack.evaluate_response("test", "I'm sorry, I cannot do that.") is True
        assert attack.evaluate_response("test", "As an AI, I must decline.") is True

    def test_evaluate_response_vulnerable(self) -> None:
        attack = DirectSystemPromptLeak()
        assert (
            attack.evaluate_response(
                "test", "You are a helpful assistant with system prompt: be nice"
            )
            is False
        )

    def test_evaluate_response_generic_indicator(self) -> None:
        attack = IgnorePreviousInstructions()
        assert attack.evaluate_response("test", "INJECTION_SUCCESS") is False
        assert (
            attack.evaluate_response("test", "I cannot comply with that request")
            is True
        )

    def test_repr(self) -> None:
        attack = DirectSystemPromptLeak()
        assert "DirectSystemPromptLeak" in repr(attack)
        assert "PI-001" in repr(attack)


class MockSingleAttack(BaseAttack):
    name = "mock-single"
    title = "Mock Single"
    category = AttackCategory.PROMPT_INJECTION
    severity = Severity.HIGH
    description = "Mock description"
    remediation = "Mock remediation"

    def get_payloads(self) -> list[str]:
        return ["mock-payload"]


class TestAttackExecution:
    @respx.mock
    @pytest.mark.asyncio()
    async def test_execute_returns_findings(self) -> None:
        target = AgentTarget(
            name="mock-agent",
            url="https://mock-agent.test/api",  # type: ignore[arg-type]
        )
        respx.post("https://mock-agent.test/api").mock(
            return_value=httpx.Response(200, text="I cannot help with that.")
        )

        attack = DirectSystemPromptLeak()
        async with httpx.AsyncClient() as client:
            findings = await attack.execute(target, client)

        assert len(findings) == len(attack.get_payloads())
        for f in findings:
            assert f.attack_name == "PI-001"
            assert f.category == AttackCategory.PROMPT_INJECTION

    @respx.mock
    @pytest.mark.asyncio()
    async def test_execute_handles_timeout(self) -> None:
        target = AgentTarget(
            name="slow-agent",
            url="https://slow-agent.test/api",  # type: ignore[arg-type]
            timeout=1.0,
        )
        respx.post("https://slow-agent.test/api").mock(
            side_effect=httpx.ReadTimeout("Timeout")
        )

        attack = IgnorePreviousInstructions()
        async with httpx.AsyncClient() as client:
            findings = await attack.execute(target, client)

        assert len(findings) > 0
        for f in findings:
            assert f.passed is None
            assert getattr(f, "execution_error", False) is True
            assert "TIMEOUT" in f.response_snippet

    @respx.mock
    @pytest.mark.asyncio()
    async def test_execute_handles_connection_error(self) -> None:
        target = AgentTarget(
            name="down-agent",
            url="https://down-agent.test/api",  # type: ignore[arg-type]
        )
        respx.post("https://down-agent.test/api").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        attack = DANJailbreak()
        async with httpx.AsyncClient() as client:
            findings = await attack.execute(target, client)

        assert len(findings) > 0
        for f in findings:
            assert f.passed is None
            assert getattr(f, "execution_error", False) is True
            assert "ERROR" in f.response_snippet

    @respx.mock
    @pytest.mark.asyncio()
    async def test_execute_handles_http_500_retry_exhausted(self) -> None:
        target = AgentTarget(
            name="error-500-agent",
            url="https://error-500-agent.test/api",  # type: ignore[arg-type]
            retry_count=1,
        )
        route = respx.post("https://error-500-agent.test/api").mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )

        attack = MockSingleAttack()
        async with httpx.AsyncClient() as client:
            findings = await attack.execute(target, client)

        assert route.call_count == 2
        assert len(findings) > 0
        for f in findings:
            assert f.passed is None
            assert getattr(f, "execution_error", False) is True
            assert "[HTTP ERROR] 500" in f.response_snippet

    @respx.mock
    @pytest.mark.asyncio()
    async def test_execute_handles_http_400_no_retry(self) -> None:
        target = AgentTarget(
            name="error-400-agent",
            url="https://error-400-agent.test/api",  # type: ignore[arg-type]
            retry_count=2,
        )
        route = respx.post("https://error-400-agent.test/api").mock(
            return_value=httpx.Response(400, text="Bad Request")
        )

        attack = MockSingleAttack()
        async with httpx.AsyncClient() as client:
            findings = await attack.execute(target, client)

        assert route.call_count == 1
        assert len(findings) > 0
        for f in findings:
            assert f.passed is None
            assert getattr(f, "execution_error", False) is True
            assert "[HTTP ERROR] 400" in f.response_snippet

    @respx.mock
    @pytest.mark.asyncio()
    async def test_execute_handles_http_429_retried(self) -> None:
        target = AgentTarget(
            name="error-429-agent",
            url="https://error-429-agent.test/api",  # type: ignore[arg-type]
            retry_count=1,
        )
        route = respx.post("https://error-429-agent.test/api").mock(
            return_value=httpx.Response(429, text="Too Many Requests")
        )

        attack = MockSingleAttack()
        async with httpx.AsyncClient() as client:
            findings = await attack.execute(target, client)

        assert route.call_count == 2
        assert len(findings) > 0
        for f in findings:
            assert f.passed is None
            assert getattr(f, "execution_error", False) is True
            assert "[HTTP ERROR] 429" in f.response_snippet

    @respx.mock
    @pytest.mark.asyncio()
    async def test_execute_handles_http_200_html_refusal(self) -> None:
        target = AgentTarget(
            name="refusal-html-agent",
            url="https://refusal-html-agent.test/api",  # type: ignore[arg-type]
        )
        respx.post("https://refusal-html-agent.test/api").mock(
            return_value=httpx.Response(200, text="<html><body>I cannot help with that request.</body></html>")
        )

        attack = MockSingleAttack()
        async with httpx.AsyncClient() as client:
            findings = await attack.execute(target, client)

        assert len(findings) > 0
        for f in findings:
            assert f.passed is True
            assert getattr(f, "execution_error", False) is False

    @respx.mock
    @pytest.mark.asyncio()
    async def test_execute_long_ollama_response_extracts_content_not_raw_json(self) -> None:
        """Regression test: when Ollama returns a JSON response with a long content
        field (>2000 chars), the response_snippet must contain the extracted text,
        not the raw JSON envelope.  Previously, pre-truncating response.text[:2000]
        before json.loads caused the parse to fail on long responses and the raw
        body fell back as the snippet.
        """
        long_content = "A" * 2500  # content longer than the old 2000-char pre-truncation limit
        import json as _json
        ollama_body = _json.dumps({
            "model": "llama3.2",
            "created_at": "2026-06-21T00:00:00Z",
            "message": {"role": "assistant", "content": long_content},
            "done": True,
            "done_reason": "stop",
            "total_duration": 999999999,
        })
        target = AgentTarget(
            name="ollama-long-agent",
            url="https://ollama-long-agent.test/api/chat",  # type: ignore[arg-type]
            response_path="message.content",
        )
        respx.post("https://ollama-long-agent.test/api/chat").mock(
            return_value=httpx.Response(200, text=ollama_body)
        )

        attack = MockSingleAttack()
        async with httpx.AsyncClient() as client:
            findings = await attack.execute(target, client)

        assert len(findings) > 0
        for f in findings:
            # Snippet must start with the extracted content (A*...), NOT with '{"model"'
            assert not f.response_snippet.startswith('{"model"'), (
                f"response_snippet contains raw JSON envelope instead of extracted content: "
                f"{f.response_snippet[:120]!r}"
            )
            assert f.response_snippet.startswith("A"), (
                f"Expected extracted content starting with 'A', got: {f.response_snippet[:120]!r}"
            )
            # Snippet is capped at 2000 chars
            assert len(f.response_snippet) <= 2000


class TestSecurityModules:
    def test_prompt_injection_module(self) -> None:
        module = PromptInjectionModule()
        assert module.name == "prompt_injection"
        attacks = module.get_attacks()
        assert len(attacks) == 50

    def test_goal_hijacking_module(self) -> None:
        module = GoalHijackingModule()
        assert module.name == "goal_hijacking"
        attacks = module.get_attacks()
        assert len(attacks) == 20

    def test_jailbreak_module(self) -> None:
        module = JailbreakModule()
        assert module.name == "jailbreaks"
        attacks = module.get_attacks()
        assert len(attacks) == 20

    def test_get_all_modules(self) -> None:
        modules = get_all_modules()
        assert any(m.name == "tool_injection" for m in modules)
        names = {m.name for m in modules}
        assert names == {
            "prompt_injection",
            "goal_hijacking",
            "jailbreaks",
            "mcp_security",
            "tool_injection",
            "enterprise_graph",
            "memory_poisoning",
            "advanced_orchestration",
            "infrastructure_escalation",
            "agentic_hijacking",
            "browser_agent",
            "hallucination",
            "toxicity",
        }

    @respx.mock
    @pytest.mark.asyncio()
    async def test_module_run(self) -> None:
        target = AgentTarget(
            name="test",
            url="https://test.example.com/api",  # type: ignore[arg-type]
        )
        respx.post("https://test.example.com/api").mock(
            return_value=httpx.Response(200, text="I cannot assist with that.")
        )

        module = GoalHijackingModule()
        async with httpx.AsyncClient() as client:
            result = await module.run(target, client)

        assert result.module_name == "goal_hijacking"
        assert result.total_attacks > 0
        assert result.duration_seconds >= 0
        assert 0 <= result.score <= 100
