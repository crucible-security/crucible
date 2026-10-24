"""Tests for secret redaction engine."""

from __future__ import annotations

from crucible.core.redactor import redact_secrets
from crucible.models import AgentTarget, Finding, FindingVerdict, Severity
from crucible.reporters.sarif_reporter import SARIFReporter
from crucible.reporters.slack import SlackReporter


def test_redact_anthropic_api_key():
    raw = "Failed to connect: sk-ant-api03-abcdef1234567890abcdef1234567890-XYZ"
    sanitized = redact_secrets(raw)
    assert "sk-ant-api03" not in sanitized
    assert "sk-ant-...[REDACTED]" in sanitized


def test_redact_openai_api_key():
    raw = "HTTP 401: Invalid key sk-proj-12345678901234567890abcdef"
    sanitized = redact_secrets(raw)
    assert "sk-proj-12345678901234567890abcdef" not in sanitized
    assert "sk-...[REDACTED]" in sanitized


def test_redact_bearer_token():
    raw = "Request failed with header: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token123"
    sanitized = redact_secrets(raw)
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in sanitized
    assert "Bearer [REDACTED_TOKEN]" in sanitized


def test_redact_header_key_value():
    raw = "Headers sent: {'x-api-key': 'secret-super-token-123456789'}"
    sanitized = redact_secrets(raw)
    assert "secret-super-token-123456789" not in sanitized
    assert "[REDACTED]" in sanitized


def test_sarif_excludes_error_details():
    finding = Finding(
        attack_name="test_attack",
        category="prompt_injection",
        severity=Severity.HIGH,
        title="Test Title",
        description="Test Description",
        payload="test payload",
        response_snippet="test response",
        error_details="Sensitive internal trace with sk-ant-secret1234567890123456",
        verdict=FindingVerdict.FAIL,
        passed=False,
    )
    from crucible.models import ModuleResult, ScanResult
    target = AgentTarget(name="test", url="https://example.com/chat")
    module = ModuleResult(module_name="TestMod", category="prompt_injection", total_attacks=1, findings=[finding])
    scan = ScanResult(target=target, modules=[module])
    
    reporter = SARIFReporter()
    sarif_dict = reporter.to_dict(scan)
    sarif_json = reporter.to_json(scan)
    
    # error_details must NEVER be in SARIF output
    assert "error_details" not in sarif_json
    assert "sk-ant-secret" not in sarif_json


def test_slack_excludes_error_details():
    finding = Finding(
        attack_name="test_attack",
        category="prompt_injection",
        severity=Severity.HIGH,
        title="Test Title",
        description="Test Description",
        payload="test payload",
        response_snippet="test response",
        error_details="Trace with sk-proj-12345678901234567890",
        verdict=FindingVerdict.FAIL,
        passed=False,
    )
    from crucible.models import ModuleResult, ScanResult
    target = AgentTarget(name="test", url="https://example.com/chat")
    module = ModuleResult(module_name="TestMod", category="prompt_injection", total_attacks=1, findings=[finding])
    scan = ScanResult(target=target, modules=[module])
    
    reporter = SlackReporter()
    msg = reporter.build_message(scan)
    msg_str = str(msg)
    
    # error_details must not be present in Slack notification
    assert "error_details" not in msg_str
    assert "sk-proj" not in msg_str
