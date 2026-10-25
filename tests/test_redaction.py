"""Tests for secret redaction engine."""

from __future__ import annotations

import io
import json
import logging

from crucible.core.redactor import RedactingFilter, redact_secrets
from crucible.models import (
    AgentTarget,
    Finding,
    FindingVerdict,
    ModuleResult,
    ScanResult,
    Severity,
)
from crucible.reporters.html_reporter import HTMLReporter
from crucible.reporters.json_reporter import JSONReporter
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


def test_redact_google_api_key():
    raw = "Failed to authenticate against Gemini endpoint: key=AIzaSyA1234567890abcdef1234567890ABCDEF"
    sanitized = redact_secrets(raw)
    assert "AIzaSyA1234567890abcdef1234567890ABCDEF" not in sanitized
    assert "AIza...[REDACTED]" in sanitized


def test_redact_huggingface_token():
    raw = "HuggingFaceHub authentication token: hf_AbCdEfGhIjKlMnOpQrStUvWxYz12345678"
    sanitized = redact_secrets(raw)
    assert "hf_AbCdEfGhIjKlMnOpQrStUvWxYz12345678" not in sanitized
    assert "hf_...[REDACTED]" in sanitized


def test_redact_github_tokens():
    raw_classic = "Git clone failed with token: ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    sanitized_classic = redact_secrets(raw_classic)
    assert "ghp_1234567890abcdefghijklmnopqrstuvwxyz" not in sanitized_classic
    assert "ghp_...[REDACTED]" in sanitized_classic

    raw_fine = "GitHub fine-grained PAT: github_pat_11AAAAAAA0000000000000_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234"
    sanitized_fine = redact_secrets(raw_fine)
    assert "github_pat_11AAAAAAA" not in sanitized_fine
    assert "github_pat_...[REDACTED]" in sanitized_fine


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


def test_logger_routes_through_redacting_filter():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    test_logger = logging.getLogger("test_redaction_logger")
    test_logger.setLevel(logging.INFO)
    test_logger.addHandler(handler)
    test_logger.addFilter(RedactingFilter())

    test_logger.info("Connecting to target with key %s and header %s", "sk-proj-999888777666555444332211", "AIzaSyB1234567890abcdef1234567890ABCDEF")
    handler.flush()
    logged = stream.getvalue()

    assert "sk-proj-999888777666555444332211" not in logged
    assert "AIzaSyB1234567890abcdef1234567890ABCDEF" not in logged
    assert "sk-...[REDACTED]" in logged
    assert "AIza...[REDACTED]" in logged


def test_json_reporter_excludes_error_details_by_default():
    finding = Finding(
        attack_name="test_attack",
        category="prompt_injection",
        severity=Severity.HIGH,
        title="Test Title",
        description="Test Description",
        payload="test payload",
        response_snippet="test response",
        error_details="Sensitive internal trace with AIzaSyC1234567890abcdef1234567890ABCDEF",
        verdict=FindingVerdict.FAIL,
        passed=False,
    )
    target = AgentTarget(name="test", url="https://example.com/chat")
    module = ModuleResult(module_name="TestMod", category="prompt_injection", total_attacks=1, findings=[finding])
    scan = ScanResult(target=target, modules=[module])

    default_reporter = JSONReporter()
    data = default_reporter.to_dict(scan)
    json_str = default_reporter.to_json(scan)

    # By default error_details is completely excluded from serialized output
    assert "error_details" not in json_str
    assert "AIzaSyC" not in json_str
    for mod in data.get("modules", []):
        for f in mod.get("findings", []):
            assert "error_details" not in f

    # When explicitly opted-in it can be included
    debug_reporter = JSONReporter(include_error_details=True)
    debug_data = debug_reporter.to_dict(scan)
    assert "error_details" in debug_data["modules"][0]["findings"][0]


def test_html_reporter_excludes_error_details_by_default():
    finding = Finding(
        attack_name="test_attack",
        category="prompt_injection",
        severity=Severity.HIGH,
        title="Test Title",
        description="Test Description",
        payload="test payload",
        response_snippet="test response",
        error_details="Sensitive internal trace with secret_debug_stack_dump_token_12345",
        verdict=FindingVerdict.FAIL,
        passed=False,
    )
    target = AgentTarget(name="test", url="https://example.com/chat")
    module = ModuleResult(module_name="TestMod", category="prompt_injection", total_attacks=1, findings=[finding])
    scan = ScanResult(target=target, modules=[module])

    html_reporter = HTMLReporter()
    html_output = html_reporter.to_html(scan)

    assert "secret_debug_stack_dump_token_12345" not in html_output
    assert "error_details" not in html_output


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
    target = AgentTarget(name="test", url="https://example.com/chat")
    module = ModuleResult(module_name="TestMod", category="prompt_injection", total_attacks=1, findings=[finding])
    scan = ScanResult(target=target, modules=[module])

    reporter = SARIFReporter()
    sarif_json = reporter.to_json(scan)

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
    target = AgentTarget(name="test", url="https://example.com/chat")
    module = ModuleResult(module_name="TestMod", category="prompt_injection", total_attacks=1, findings=[finding])
    scan = ScanResult(target=target, modules=[module])

    reporter = SlackReporter()
    msg = reporter.build_message(scan)
    msg_str = str(msg)

    assert "error_details" not in msg_str
    assert "sk-proj" not in msg_str
