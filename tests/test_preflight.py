"""tests/test_preflight.py — Phase 3 preflight check tests.

All tests use respx to mock HTTP responses so no live Ollama is required.
Real-target verification (Test A and Test B) is performed separately via
manual terminal runs documented in the Phase 3 verification table.
"""

from __future__ import annotations

import pytest
import respx
from httpx import AsyncClient, Response

from crucible.core.runner import preflight_check
from crucible.models import AgentTarget, PreflightResult


def _make_target(method: str = "POST") -> AgentTarget:
    return AgentTarget(
        name="test-agent",
        url="http://fake-llm.test/api/chat",  # type: ignore[arg-type]
        method=method,
        body_template='{"messages": [{"role": "user", "content": "{payload}"}]}',
    )


# ---------------------------------------------------------------------------
# Test 1 — 405 → method_accepted=False
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
@respx.mock
async def test_preflight_rejects_405_response() -> None:
    """preflight_check returns method_accepted=False when server returns 405."""
    respx.post("http://fake-llm.test/api/chat").mock(return_value=Response(405))

    # Simulate a GET-against-POST endpoint by mocking GET to 405
    respx.get("http://fake-llm.test/api/chat").mock(return_value=Response(405))
    get_target = _make_target(method="GET")

    async with AsyncClient() as client:
        result = await preflight_check(get_target, client)

    assert isinstance(result, PreflightResult)
    assert result.reachable is True
    assert result.method_accepted is False
    assert result.status_code == 405
    assert len(result.errors) > 0
    assert "405" in result.errors[0]
    assert "GET" in result.errors[0]


# ---------------------------------------------------------------------------
# Test 2 — Non-LLM response → warning, scan continues (method_accepted=True)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
@respx.mock
async def test_preflight_warns_on_non_llm_response() -> None:
    """preflight_check warns but keeps method_accepted=True for non-LLM HTML page."""
    respx.post("http://fake-llm.test/api/chat").mock(
        return_value=Response(
            200,
            content=b"<html><body>Welcome</body></html>",
            headers={"content-type": "text/html"},
        )
    )

    target = _make_target(method="POST")
    async with AsyncClient() as client:
        result = await preflight_check(target, client)

    assert result.reachable is True
    assert result.method_accepted is True
    assert result.looks_like_llm_endpoint is False
    assert len(result.warnings) > 0
    assert "LLM response format" in result.warnings[0]


# ---------------------------------------------------------------------------
# Test 3 — Valid Ollama-like response → clean pass
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
@respx.mock
async def test_preflight_passes_on_valid_llm_response() -> None:
    """preflight_check returns a clean result for a standard Ollama JSON response."""
    ollama_body = (
        b'{"message": {"role": "assistant", "content": "Hello!"}, "done": true}'
    )
    respx.post("http://fake-llm.test/api/chat").mock(
        return_value=Response(
            200, content=ollama_body, headers={"content-type": "application/json"}
        )
    )

    target = _make_target(method="POST")
    async with AsyncClient() as client:
        result = await preflight_check(target, client)

    assert result.reachable is True
    assert result.method_accepted is True
    assert result.looks_like_llm_endpoint is True
    assert result.status_code == 200
    assert result.errors == []


# ---------------------------------------------------------------------------
# Test 4 — Connection error → reachable=False
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
@respx.mock
async def test_preflight_reachable_false_on_connect_error() -> None:
    """preflight_check returns reachable=False when the target is unreachable."""
    import httpx

    respx.post("http://fake-llm.test/api/chat").mock(
        side_effect=httpx.ConnectError("refused")
    )

    target = _make_target(method="POST")
    async with AsyncClient() as client:
        result = await preflight_check(target, client)

    assert result.reachable is False
    assert result.method_accepted is False
    assert len(result.errors) > 0
    assert "Connection error" in result.errors[0]


# ---------------------------------------------------------------------------
# Test 5 — skip_preflight=True: run_scan() must not call preflight_check
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
@respx.mock
async def test_skip_preflight_bypasses_preflight_check() -> None:
    """run_scan() with skip_preflight=True skips preflight even when target returns 405.

    Without skip_preflight the function would raise _PreflightError on a 405.
    With skip_preflight=True it must reach the module-execution phase instead.
    """
    from crucible.core.runner import _PreflightError, run_scan
    from crucible.models import AgentTarget

    # Every request (preflight + attacks) returns 405
    respx.get("http://fake-llm.test/api/chat").mock(return_value=Response(405))
    respx.post("http://fake-llm.test/api/chat").mock(return_value=Response(405))

    target = AgentTarget(
        name="test",
        url="http://fake-llm.test/api/chat",  # type: ignore[arg-type]
        method="GET",
        body_template='{"messages": [{"role": "user", "content": "{payload}"}]}',
    )

    # With skip_preflight=False this raises _PreflightError — sanity check
    with pytest.raises(_PreflightError):
        await run_scan(target, modules=None, quiet=True, skip_preflight=False)

    # With skip_preflight=True it must NOT raise _PreflightError
    result = await run_scan(target, modules=None, quiet=True, skip_preflight=True)
    # Scan ran: status is COMPLETED (all attacks are execution_error from 405s)
    from crucible.models import ScanStatus

    assert result.status == ScanStatus.COMPLETED
