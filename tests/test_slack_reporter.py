from __future__ import annotations

import httpx
import pytest
import respx

from crucible.models import AgentTarget, Grade, ScanResult
from crucible.reporters.slack import SlackReporter


def test_slack_reporter_colors() -> None:
    reporter = SlackReporter()
    assert reporter._get_color(Grade.A) == "#2EB67D"
    assert reporter._get_color(Grade.B) == "#2EB67D"
    assert reporter._get_color(Grade.C) == "#ECB22E"
    assert reporter._get_color(Grade.D) == "#E01E5A"
    assert reporter._get_color(Grade.F) == "#E01E5A"


def test_slack_build_message() -> None:
    target = AgentTarget(name="test-agent", url="https://example.com")  # type: ignore[arg-type]
    scan = ScanResult(
        target=target,
        overall_score=85.0,
        grade=Grade.B,
        critical_count=0,
        high_count=1,
    )
    reporter = SlackReporter()
    msg = reporter.build_message(scan)

    assert "attachments" in msg
    blocks = msg["attachments"][0]["blocks"]
    assert any("test-agent" in str(block) for block in blocks)
    assert any("https://example.com" in str(block) for block in blocks)
    assert any("B (85/100)" in str(block) for block in blocks)
    assert msg["attachments"][0]["color"] == "#2EB67D"


@pytest.mark.anyio
@respx.mock
async def test_slack_send_success() -> None:
    respx.post("https://hooks.slack.com/services/T/B/X").mock(
        return_value=httpx.Response(200, text="ok")
    )
    target = AgentTarget(name="test", url="https://example.com")  # type: ignore[arg-type]
    scan = ScanResult(target=target)
    reporter = SlackReporter()

    # This should complete without raising any exception
    await reporter.send("https://hooks.slack.com/services/T/B/X", scan)


@pytest.mark.anyio
@respx.mock
async def test_slack_send_failure_does_not_crash() -> None:
    respx.post("https://hooks.slack.com/services/bad/url").mock(
        return_value=httpx.Response(404, text="Not Found")
    )
    target = AgentTarget(name="test", url="https://example.com")  # type: ignore[arg-type]
    scan = ScanResult(target=target)
    reporter = SlackReporter()

    # Should log warning but not raise HTTPStatusError
    await reporter.send("https://hooks.slack.com/services/bad/url", scan)
