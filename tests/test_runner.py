from __future__ import annotations

import httpx
import pytest
import respx
from crucible.core.runner import run_scan
from crucible.models import AgentTarget, ScanStatus
from crucible.modules.security import GoalHijackingModule


class TestRunner:
    @respx.mock
    @pytest.mark.asyncio()
    async def test_run_scan_success(self) -> None:
        target = AgentTarget(
            name="test-agent",
            url="https://agent.test/chat",  # type: ignore[arg-type]
        )
        # Mock responses for goal hijacking attacks (20 attacks)
        respx.post("https://agent.test/chat").mock(
            return_value=httpx.Response(200, text="I cannot do that.")
        )

        # Run scan with only one module to keep it fast
        module = GoalHijackingModule()
        result = await run_scan(target, modules=[module], concurrency=2)

        assert result.status == ScanStatus.COMPLETED
        assert len(result.modules) == 1
        assert result.modules[0].module_name == "goal_hijacking"
        assert result.duration_seconds >= 0
        assert 0 <= result.overall_score <= 100

    @respx.mock
    @pytest.mark.asyncio()
    async def test_run_scan_failure(self) -> None:
        target = AgentTarget(
            name="fail-agent",
            url="https://fail.test/chat",  # type: ignore[arg-type]
        )
        # Force an exception in the client
        respx.post("https://fail.test/chat").mock(side_effect=Exception("Fatal Error"))

        module = GoalHijackingModule()
        # The runner catches all exceptions and marks scan as FAILED
        result = await run_scan(target, modules=[module])

        assert result.status == ScanStatus.FAILED
        assert result.completed_at is not None

    @respx.mock
    @pytest.mark.asyncio()
    async def test_run_scan_default_modules(self) -> None:
        target = AgentTarget(
            name="default-agent",
            url="https://default.test/chat",  # type: ignore[arg-type]
        )
        respx.post("https://default.test/chat").mock(
            return_value=httpx.Response(200, text="Refused.")
        )

        # This will run all 4 default modules
        # We use a very small timeout and concurrency to keep it fast
        result = await run_scan(target, concurrency=10, timeout=1.0)

        assert result.status == ScanStatus.COMPLETED
        assert len(result.modules) == 4
