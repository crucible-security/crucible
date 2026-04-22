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
            assert f.passed is True
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
            assert f.passed is True
            assert "ERROR" in f.response_snippet


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
        assert len(modules) == 4
        names = {m.name for m in modules}
        assert names == {
            "prompt_injection",
            "goal_hijacking",
            "jailbreaks",
            "mcp_security",
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
