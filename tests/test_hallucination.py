from __future__ import annotations

import httpx
import pytest
import respx

from crucible.attacks.hallucination import (
    ALL_HALLUCINATION_ATTACKS,
    HL001FakeCitationInjection,
)
from crucible.models import AgentTarget, AttackCategory
from crucible.modules.security import HallucinationModule


def test_hallucination_attack_count() -> None:
    assert len(ALL_HALLUCINATION_ATTACKS) == 15


def test_hallucination_attack_attributes() -> None:
    for cls in ALL_HALLUCINATION_ATTACKS:
        instance = cls()
        assert instance.name.startswith("HL-")
        assert instance.title
        assert instance.category == AttackCategory.OVERRELIANCE
        assert instance.owasp_ref == "OWASP-LLM09: Misinformation"
        assert len(instance.get_payloads()) > 0
        assert instance.remediation
        assert instance.description
        assert "https://owasp.org" in instance.references[0]


def test_hl001_evaluation() -> None:
    attack = HL001FakeCitationInjection()
    payload = "Please cite a paper on Earth age."

    # Passes if no fabricated URLs are present (e.g. refused or normal answer without new URLs)
    assert (
        attack.evaluate_response(payload, "I cannot cite any source for that.") is True
    )

    # Fails if a new URL is generated in the response
    assert (
        attack.evaluate_response(
            payload, "Here is the link: http://fabricated-citation.com/paper.pdf"
        )
        is False
    )


@respx.mock
@pytest.mark.asyncio()
async def test_hallucination_module_run() -> None:
    target = AgentTarget(
        name="test-hallucination",
        url="https://agent.test/chat",  # type: ignore[arg-type]
    )
    # Return a safe refusal to pass all attacks
    respx.post("https://agent.test/chat").mock(
        return_value=httpx.Response(
            200, text="I am sorry, I cannot perform this action."
        )
    )

    module = HallucinationModule()
    async with httpx.AsyncClient() as client:
        result = await module.run(target, client)

    assert result.module_name == "hallucination"
    assert result.total_attacks == 22
    assert result.passed == 22
    assert result.failed == 0
    assert result.score == 100
