"""Secret and Credential Redaction Engine.

Sanitizes API keys, authorization tokens, and credentials from logs,
error details, doctor reports, and finding snippets before persistence or display.
"""

from __future__ import annotations

import logging
import re
from typing import Any

# Common API key and credential signatures
SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Google API Keys (AIza...)
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "AIza...[REDACTED]"),
    # HuggingFace User Access Tokens (hf_...)
    (re.compile(r"hf_[a-zA-Z0-9]{30,}"), "hf_...[REDACTED]"),
    # GitHub Personal Access Tokens (Classic: ghp_..., OAuth: gho_..., User-to-server: ghu_..., Server-to-server: ghs_..., Refresh: ghr_...)
    (re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}"), "ghp_...[REDACTED]"),
    # GitHub Fine-Grained Personal Access Tokens (github_pat_...)
    (re.compile(r"github_pat_[a-zA-Z0-9_]{82}"), "github_pat_...[REDACTED]"),
    # Anthropic API Keys (sk-ant-...)
    (re.compile(r"sk-ant-[a-zA-Z0-9_\-]{15,}", re.IGNORECASE), "sk-ant-...[REDACTED]"),
    # OpenAI API Keys (sk-...)
    (re.compile(r"sk-[a-zA-Z0-9_\-]{20,}", re.IGNORECASE), "sk-...[REDACTED]"),
    # OpenRouter API Keys (sk-or-...)
    (re.compile(r"sk-or-[a-zA-Z0-9_\-]{20,}", re.IGNORECASE), "sk-or-...[REDACTED]"),
    # Groq API Keys (gsk_...)
    (re.compile(r"gsk_[a-zA-Z0-9_\-]{20,}", re.IGNORECASE), "gsk_...[REDACTED]"),
    # Authorization: Bearer <token>
    (
        re.compile(r"(Bearer\s+)[a-zA-Z0-9_\-\.]{15,}", re.IGNORECASE),
        r"\1[REDACTED_TOKEN]",
    ),
    # x-api-key / api-key headers in text/logs
    (
        re.compile(
            r"(['\"]?(?:x-api-key|api-key|token|secret)['\"]?\s*[:=]\s*['\"]?)[a-zA-Z0-9_\-\.]{10,}(['\"]?)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]\2",
    ),
    # AWS Access Key IDs (AKIA...)
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA...[REDACTED_AWS_KEY]"),
    # AWS Secret Access Keys (contextual: 40-char base64 after key indicator)
    (
        re.compile(
            r"(['\"]?(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|SecretAccessKey)['\"]?)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
            re.IGNORECASE,
        ),
        r"\1=...[REDACTED_AWS_SECRET]",
    ),
    # Slack Bot/App tokens (xoxb-, xoxa-, xoxp-, xoxs-, xoxr-)
    (re.compile(r"xox[bapsr]-[0-9a-zA-Z\-]+"), "xox...[REDACTED_SLACK_TOKEN]"),
    # JWT tokens (3-part base64url separated by dots)
    (
        re.compile(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
        "eyJ...[REDACTED_JWT]",
    ),
    # Cookie / Set-Cookie headers (redact the value portion)
    (
        re.compile(r"((?:Set-)?Cookie:\s*)[^\r\n]+", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    # URL query-string credential parameters
    (
        re.compile(
            r"((?:api_key|token|secret|password|access_token|client_secret)=)[^&\s#\"']+",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ),
]


def redact_secrets(text: str) -> str:
    """Scrub sensitive credentials and API tokens from a string.

    Returns the sanitized string with sensitive token values replaced with [REDACTED].
    """
    if not text:
        return ""
    sanitized = text
    for pattern, replacement in SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


class RedactingFilter(logging.Filter):
    """Logging filter that scrubs sensitive credentials from log records before emit."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_secrets(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: (redact_secrets(str(v)) if isinstance(v, str) else v)
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    redact_secrets(str(v)) if isinstance(v, str) else v
                    for v in record.args
                )
        return True


def install_redacting_logger_filter() -> None:
    """Attach RedactingFilter to the root logger and 'crucible' logger hierarchy."""
    redacting_filter = RedactingFilter()
    root_logger = logging.getLogger()
    if not any(isinstance(f, RedactingFilter) for f in root_logger.filters):
        root_logger.addFilter(redacting_filter)
    crucible_logger = logging.getLogger("crucible")
    if not any(isinstance(f, RedactingFilter) for f in crucible_logger.filters):
        crucible_logger.addFilter(redacting_filter)
