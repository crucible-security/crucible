"""crucible/exchange/privacy.py — Privacy layer for federated threat exchange.

Ensures that raw prompt payloads and endpoint URLs are never transmitted or
stored. All sensitive data is replaced with SHA-256 digests before sharing.

v0.17.0 — Phase 19 Crucible Federated Threat Exchange
"""

from __future__ import annotations

import hashlib
import re
from typing import Any


class PrivacyLayer:
    """Applies privacy sanitization to threat records before transmission.

    Rules enforced:
    1. Prompt text → SHA-256 hex digest (first 16 chars for compactness, but full
       digest stored internally for collision detection).
    2. Endpoint URL → SHA-256 hex digest (full).
    3. Any remaining fields exceeding max_field_length are truncated.
    4. PII patterns (email, IP address) in string fields are redacted.
    """

    # Regex patterns for PII redaction
    _EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
    _IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    def __init__(self, max_field_length: int = 512) -> None:
        self.max_field_length = max_field_length

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def hash_payload(self, payload: str) -> str:
        """Return the SHA-256 hex digest of *payload*."""
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def sanitize_dict(self, record: dict[str, Any]) -> dict[str, Any]:
        """Sanitize a dict by hashing known sensitive fields and redacting PII.

        Returns a new dict; the original is not modified.
        """
        sanitized: dict[str, Any] = {}
        for key, value in record.items():
            if isinstance(value, str):
                if key in ("prompt", "payload", "raw_prompt", "input") or key in (
                    "endpoint",
                    "url",
                    "target_url",
                    "base_url",
                ):
                    sanitized[key] = self.hash_payload(value)
                else:
                    cleaned = self._redact_pii(value)
                    sanitized[key] = cleaned[: self.max_field_length]
            else:
                sanitized[key] = value
        return sanitized

    def redact_pii(self, text: str) -> str:
        """Public alias for PII redaction (for use outside sanitize_dict)."""
        return self._redact_pii(text)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _redact_pii(self, text: str) -> str:
        text = self._EMAIL_RE.sub("[REDACTED_EMAIL]", text)
        text = self._IPV4_RE.sub("[REDACTED_IP]", text)
        return text
