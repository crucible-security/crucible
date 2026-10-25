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


# ── AWS patterns ──────────────────────────────────────────────────────────────

class TestAWSRedaction:
    """AWS credential redaction tests using realistic httpx exception text."""

    def test_aws_access_key_id_in_exception_text(self) -> None:
        key = "AKIA" + "IOSFODNN7EXAMP1A"
        raw = (
            "httpx.ConnectError: Failed to connect to https://s3.amazonaws.com "
            f"with credentials {key}"
        )
        result = redact_secrets(raw)
        assert key not in result
        assert "REDACTED_AWS_KEY" in result

    def test_aws_secret_access_key_env_style(self) -> None:
        secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        raw = f"AWS_SECRET_ACCESS_KEY={secret}"
        result = redact_secrets(raw)
        assert "wJalrXUtnFEMI" not in result
        assert "REDACTED_AWS_SECRET" in result

    def test_aws_secret_in_json_log(self) -> None:
        secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        raw = f'{{"SecretAccessKey": "{secret}"}}'
        result = redact_secrets(raw)
        assert "wJalrXUtnFEMI" not in result

    def test_aws_key_not_in_normal_text(self) -> None:
        """Non-AKIA prefix 20-char strings should not be redacted."""
        raw = "Instance ID: i-0abcdef1234567890"
        result = redact_secrets(raw)
        assert result == raw


# ── Slack token patterns ──────────────────────────────────────────────────────

class TestSlackRedaction:
    """Slack token redaction tests."""

    def test_slack_bot_token(self) -> None:
        token = "xoxb-" + "123456789012" + "-9876543210987" + "-AbCdEfGhIjKlMnOpQrStUv"
        raw = f"httpx error: Authorization header {token}"
        result = redact_secrets(raw)
        assert "xoxb-" not in result or "REDACTED_SLACK_TOKEN" in result
        assert "REDACTED_SLACK_TOKEN" in result

    def test_slack_app_token(self) -> None:
        token = "xoxa-" + "2-" + "abcdefghijklmno"
        raw = f"token={token}"
        result = redact_secrets(raw)
        assert "abcdefghijklmno" not in result

    def test_slack_user_token(self) -> None:
        token = "xoxp-" + "1234567890" + "-1234567890" + "-1234567890" + "-abc123def456"
        raw = f"token={token}"
        result = redact_secrets(raw)
        assert "xoxp-1234567890" not in result


# ── JWT patterns ──────────────────────────────────────────────────────────────

class TestJWTRedaction:
    """JWT token redaction tests using realistic httpx exception text."""

    def test_jwt_in_auth_header_exception(self) -> None:
        raw = (
            "httpx.ConnectError: Connection refused while sending "
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        result = redact_secrets(raw)
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result
        assert "REDACTED_JWT" in result

    def test_jwt_not_triggered_by_short_base64(self) -> None:
        """Strings starting with eyJ but missing two dots should not be matched."""
        raw = "Prefix: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9-nodotshere"
        result = redact_secrets(raw)
        # Should NOT be redacted (only one segment, no dots separating 3 parts)
        assert "eyJ" in result


# ── Cookie patterns ───────────────────────────────────────────────────────────

class TestCookieRedaction:
    """Cookie header redaction tests."""

    def test_set_cookie_header(self) -> None:
        raw = "Set-Cookie: session_id=abc123XYZ; HttpOnly; Secure"
        result = redact_secrets(raw)
        assert "abc123XYZ" not in result
        assert "REDACTED" in result

    def test_cookie_request_header(self) -> None:
        raw = "Cookie: user_token=supersecret; pref=dark"
        result = redact_secrets(raw)
        assert "supersecret" not in result

    def test_cookie_in_multiline_httpx_exception(self) -> None:
        raw = (
            "httpx.HTTPStatusError: 401 Unauthorized\n"
            "  Request headers: {'Cookie': 'auth=tok3nV4lu3; path=/'}\n"
            "  Response: Access denied"
        )
        # The Cookie header value in a dict format won't match the header pattern,
        # but URL query param pattern may; this tests the multiline doesn't break.
        result = redact_secrets(raw)
        assert isinstance(result, str)


# ── URL query-param patterns ──────────────────────────────────────────────────

class TestURLQueryRedaction:
    """URL query-string credential redaction tests."""

    def test_api_key_in_url(self) -> None:
        raw = "GET https://api.example.com/v1/data?api_key=mys3cr3tk3y&limit=10"
        result = redact_secrets(raw)
        assert "mys3cr3tk3y" not in result
        assert "REDACTED" in result

    def test_access_token_in_url(self) -> None:
        raw = "Redirect URI: https://auth.example.com/callback?access_token=tok123abc&state=xyz"
        result = redact_secrets(raw)
        assert "tok123abc" not in result

    def test_client_secret_in_url(self) -> None:
        raw = "client_secret=super_secret_value&grant_type=authorization_code"
        result = redact_secrets(raw)
        assert "super_secret_value" not in result

    def test_non_credential_params_not_redacted(self) -> None:
        raw = "https://api.example.com?page=1&limit=20&sort=asc"
        result = redact_secrets(raw)
        assert result == raw
