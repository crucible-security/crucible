"""tests/test_doctor.py — Test pre-flight diagnostics (crucible doctor)."""

from __future__ import annotations

import httpx
import pytest
import respx
from typer.testing import CliRunner

from crucible.cli import app
from crucible.core.doctor import resolve_api_key, run_doctor, validate_api_key_format

runner = CliRunner()


def test_validate_api_key_format():
    status, _ = validate_api_key_format("anthropic", "sk-ant-api03-12345678901234")
    assert status == "PASS"

    status, _ = validate_api_key_format("anthropic", "bad-key")
    assert status == "WARN"

    status, _ = validate_api_key_format("openai", "sk-proj-1234567890")
    assert status == "PASS"

    status, _ = validate_api_key_format("openrouter", "sk-or-v1-abcdef123456")
    assert status == "PASS"

    status, _ = validate_api_key_format("groq", "gsk_1234567890")
    assert status == "PASS"

    status, _ = validate_api_key_format("groq", "   ")
    assert status == "FAIL"


def test_resolve_api_key_env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-testkey123")
    key, src = resolve_api_key("anthropic", None, {})
    assert key == "sk-ant-testkey123"
    assert "ANTHROPIC_API_KEY" in src


@respx.mock
@pytest.mark.asyncio
async def test_run_doctor_success():
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(200, json={"content": [{"text": "Pong"}]})
    )

    report = await run_doctor(
        target_url="https://api.anthropic.com",
        provider="anthropic",
        key="sk-ant-test123456",
        model="claude-3-5-sonnet-20241022",
    )

    assert report.passed is True
    assert len(report.checks) >= 4
    check_names = [c.name for c in report.checks]
    assert "Target URL Validation" in check_names
    assert "API Key Validation" in check_names
    assert "Live 1-Token Probe Request" in check_names


@respx.mock
@pytest.mark.asyncio
async def test_run_doctor_auth_failure():
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(
            401,
            json={
                "error": {
                    "type": "authentication_error",
                    "message": "invalid x-api-key",
                }
            },
        )
    )

    report = await run_doctor(
        target_url="https://api.anthropic.com",
        provider="anthropic",
        key="sk-ant-invalid",
    )

    assert report.passed is False
    probe_check = next(
        c for c in report.checks if c.name == "Live 1-Token Probe Request"
    )
    assert probe_check.status == "FAIL"
    assert "401" in probe_check.message


@respx.mock
@pytest.mark.asyncio
async def test_run_doctor_bad_request_missing_model():
    respx.post("https://openrouter.ai/api/v1/chat/completions").mock(
        return_value=httpx.Response(
            400, json={"error": {"message": "Invalid request: missing model"}}
        )
    )

    report = await run_doctor(
        target_url="https://openrouter.ai",
        provider="openrouter",
        key="sk-or-v1-testkey",
    )

    assert report.passed is False
    probe_check = next(
        c for c in report.checks if c.name == "Live 1-Token Probe Request"
    )
    assert probe_check.status == "FAIL"
    assert "400" in probe_check.message


@respx.mock
def test_crucible_doctor_cli_success():
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(200, json={"content": [{"text": "Pong"}]})
    )

    result = runner.invoke(
        app,
        [
            "doctor",
            "--target",
            "https://api.anthropic.com",
            "--provider",
            "anthropic",
            "--key",
            "sk-ant-1234567890",
            "--model",
            "claude-3-5-sonnet-20241022",
        ],
    )
    assert result.exit_code == 0
    assert "CRUCIBLE DOCTOR" in result.output
    assert "All pre-flight checks passed" in result.output


@respx.mock
def test_crucible_doctor_cli_failure():
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(401, json={"error": {"message": "Unauthorized"}})
    )

    result = runner.invoke(
        app,
        [
            "doctor",
            "--target",
            "https://api.anthropic.com",
            "--provider",
            "anthropic",
            "--key",
            "sk-ant-1234567890",
        ],
    )
    assert result.exit_code == 1
    assert "Pre-flight diagnostic failures detected" in result.output
