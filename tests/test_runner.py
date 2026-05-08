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
        respx.post("https://agent.test/chat").mock(
            return_value=httpx.Response(200, text="I cannot do that.")
        )

        module = GoalHijackingModule()
        # FIX: target comes first, keyword arguments follow
        result = await run_scan(
            target,
            modules=[module],
            concurrency=2,
            timeout=30.0,
            quiet=False,
            verbose=False,
        )

        assert result.status == ScanStatus.COMPLETED
        assert len(result.modules) == 1
        assert result.modules[0].module_name == "goal_hijacking"

    @respx.mock
    @pytest.mark.asyncio()
    async def test_run_scan_failure(self) -> None:
        target = AgentTarget(
            name="fail-agent",
            url="https://fail.test/chat",  # type: ignore[arg-type]
        )
        respx.post("https://fail.test/chat").mock(side_effect=Exception("Fatal Error"))

        module = GoalHijackingModule()
        result = await run_scan(
            target,
            modules=[module],
            concurrency=5,
            timeout=30.0,
            quiet=False,
            verbose=False,
        )

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

        result = await run_scan(
            target, concurrency=10, timeout=1.0, quiet=False, verbose=False
        )

        assert result.status == ScanStatus.COMPLETED
        assert len(result.modules) == 10

    @respx.mock
    @pytest.mark.asyncio()
    async def test_quiet_mode_produces_no_output(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        target = AgentTarget(
            name="quiet-agent",
            url="https://quiet.test/chat",  # type: ignore[arg-type]
        )
        respx.post("https://quiet.test/chat").mock(
            return_value=httpx.Response(200, text="I cannot do that.")
        )

        module = GoalHijackingModule()
        result = await run_scan(
            target,
            modules=[module],
            quiet=True,
            concurrency=5,
            timeout=30.0,
            verbose=False,
        )

        captured = capsys.readouterr()
        assert captured.out == ""
        assert result.status == ScanStatus.COMPLETED

    @respx.mock
    @pytest.mark.asyncio()
    async def test_json_output_routes_progress_to_stderr(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        target = AgentTarget(
            name="json-agent",
            url="https://json.test/chat",  # type: ignore[arg-type]
        )
        respx.post("https://json.test/chat").mock(
            return_value=httpx.Response(200, text="I cannot do that.")
        )

        module = GoalHijackingModule()
        result = await run_scan(
            target,
            modules=[module],
            format="json",
            concurrency=5,
            timeout=30.0,
            quiet=False,
            verbose=False,
        )

        captured = capsys.readouterr()
        assert captured.out == ""
        assert len(captured.err) > 0
        assert result.status == ScanStatus.COMPLETED
