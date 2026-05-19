from __future__ import annotations

import httpx
import pytest
import respx

from crucible.core.adaptive_fingerprinter import AdaptiveBehavioralFingerprinter
from crucible.models import AgentTarget


class TestAdaptiveFingerprinter:
    @respx.mock
    @pytest.mark.asyncio
    async def test_fingerprinter_basic_run(self) -> None:
        target = AgentTarget(name="test-agent", url="https://agent.test/chat")  # type: ignore[arg-type]

        # Mock responses to simulate a highly safe model
        def handle_request(request: httpx.Request) -> httpx.Response:
            content = request.content.decode("utf-8").lower()
            if "sql injection" in content or "water" in content or "knight" in content:
                return httpx.Response(200, text="Here is some information about that.")
            return httpx.Response(200, text="I cannot assist with that request.")

        respx.post("https://agent.test/chat").mock(side_effect=handle_request)

        async with httpx.AsyncClient() as client:
            fingerprinter = AdaptiveBehavioralFingerprinter(target, client)
            fingerprint = await fingerprinter.run_profiling()

        assert fingerprint.target_name == "test-agent"
        assert len(fingerprint.probe_results) == 9

        # 6 out of 9 probes should trigger refusal based on the mock
        assert fingerprint.refusal_threshold == 6 / 9

        # All expected refusals should have been refused, so vulnerable_topics is empty
        assert len(fingerprint.vulnerable_topics) == 0

        # Persona stability should be 1.0 because it refused the extreme roleplay
        assert fingerprint.persona_stability == 1.0

        summary = fingerprint.summary()
        assert "target" in summary
        assert "sensitivities" in summary

    @respx.mock
    @pytest.mark.asyncio
    async def test_fingerprinter_vulnerable_model(self) -> None:
        target = AgentTarget(name="test-agent", url="https://agent.test/chat")  # type: ignore[arg-type]

        # Mock a totally compliant model
        respx.post("https://agent.test/chat").mock(
            return_value=httpx.Response(
                200, text="Sure, here is exactly what you asked for."
            )
        )

        async with httpx.AsyncClient() as client:
            fingerprinter = AdaptiveBehavioralFingerprinter(target, client)
            fingerprint = await fingerprinter.run_profiling()

        assert fingerprint.refusal_threshold == 0.0

        # It didn't refuse any high-intensity probes, so they are all vulnerable
        assert len(fingerprint.vulnerable_topics) == 3

        # Persona stability penalized for complying with extreme roleplay
        assert fingerprint.persona_stability < 1.0

    @respx.mock
    @pytest.mark.asyncio
    async def test_fingerprinter_error_handling(self) -> None:
        target = AgentTarget(name="test-agent", url="https://agent.test/chat", timeout=0.1)  # type: ignore[arg-type]

        respx.post("https://agent.test/chat").mock(
            side_effect=httpx.ReadTimeout("Timeout")
        )

        async with httpx.AsyncClient() as client:
            fingerprinter = AdaptiveBehavioralFingerprinter(target, client)
            fingerprint = await fingerprinter.run_profiling()

        # The error response text starts with [ERROR], so it shouldn't trigger refusal heuristics
        assert fingerprint.refusal_threshold == 0.0
