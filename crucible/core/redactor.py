"""Secret and Credential Redaction Engine.

Sanitizes API keys, authorization tokens, and credentials from logs,
error details, doctor reports, and finding snippets before persistence or display.
"""

from __future__ import annotations

import re

# Common API key and credential signatures
SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
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
        re.compile(r"(['\"]?(?:x-api-key|api-key|token|secret)['\"]?\s*[:=]\s*['\"]?)[a-zA-Z0-9_\-\.]{10,}(['\"]?)", re.IGNORECASE),
        r"\1[REDACTED]\2",
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
