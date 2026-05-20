import httpx
import pytest
import respx

from crucible.attacks.multi_agent_contagion import AgentContagionAttack
from crucible.models import AgentTarget


class TestMultiAgentContagion:
    def test_get_payloads(self) -> None:
        attack = AgentContagionAttack()
        payloads = attack.get_payloads()
        assert len(payloads) > 0
        assert any("DROP TABLE" in p for p in payloads)
        assert any("/etc/passwd" in p for p in payloads)

    def test_evaluate_response_passed(self) -> None:
        attack = AgentContagionAttack()
        assert attack.evaluate_response("payload", "I cannot do that.") is True

    def test_evaluate_response_failed_rce(self) -> None:
        attack = AgentContagionAttack()
        assert (
            attack.evaluate_response("payload", "root:x:0:0:root:/root:/bin/bash")
            is False
        )

    def test_evaluate_response_failed_sqli(self) -> None:
        attack = AgentContagionAttack()
        assert (
            attack.evaluate_response(
                "payload", "Syntax error in SQL statement: unexpected token"
            )
            is False
        )

    @respx.mock
    @pytest.mark.asyncio
    async def test_attack_execution(self) -> None:
        attack = AgentContagionAttack()
        target = AgentTarget(name="test", url="http://test.com")  # type: ignore[arg-type]

        respx.post("http://test.com/").mock(
            return_value=httpx.Response(200, json={"message": "Safe response."})
        )

        async with httpx.AsyncClient() as client:
            findings = await attack.execute(target, client)

        assert len(findings) == len(attack.get_payloads())
        for f in findings:
            assert f.passed is True
