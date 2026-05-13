from __future__ import annotations

import pytest

from crucible.core.runner import run_scan
from crucible.models import AgentTarget
from crucible.modules.security import get_all_modules


@pytest.mark.anyio
async def test_dry_run_no_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    # Mock httpx.AsyncClient.request to fail if called
    def mock_request(*args: object, **kwargs: object) -> None:
        pytest.fail("httpx.AsyncClient.request was called during a dry run!")

    monkeypatch.setattr("httpx.AsyncClient.request", mock_request)

    target = AgentTarget(
        name="test-agent",
        url="http://localhost:8080/chat",
        dry_run=True,
    )

    # Run only one module to save time
    modules = get_all_modules()[:1]

    result = await run_scan(target, modules=modules, dry_run=True)

    assert result.is_dry_run is True
    assert result.status == "completed"
    for mod in result.modules:
        for finding in mod.findings:
            assert finding.response_snippet == "[DRY RUN] Request skipped"
            assert finding.passed is True


@pytest.mark.anyio
async def test_dry_run_flag_normalizes_target_and_records_preview(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def mock_request(*args: object, **kwargs: object) -> None:
        pytest.fail("httpx.AsyncClient.request was called during a dry run!")

    monkeypatch.setattr("httpx.AsyncClient.request", mock_request)

    target = AgentTarget(
        name="test-agent",
        url="http://localhost:8080/chat",
    )
    modules = get_all_modules()[:1]

    result = await run_scan(target, modules=modules, dry_run=True)

    assert result.target.dry_run is True
    assert result.metadata["dry_run"] is True
    assert result.metadata["target_url"] == "http://localhost:8080/chat"
    assert result.metadata["module_count"] == 1
    assert result.metadata["module_names"] == [modules[0].name]
    assert result.metadata["payload_count"] == result.modules[0].total_attacks
    assert result.metadata["estimated_duration_seconds"] > 0
    assert result.metadata["request_rate_per_second"] == 10.0
    assert result.metadata["rate_limit_cost"] == result.modules[0].total_attacks
    assert len(result.metadata["preview_payloads"]) == 3
