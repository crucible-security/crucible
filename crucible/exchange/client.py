"""crucible/exchange/client.py — Federated Threat Exchange client.

Push anonymized threat records to a local or remote exchange node, and pull
aggregated threat signals from peers.

Privacy guarantees (enforced by PrivacyLayer before any network call):
  - Raw prompt payloads → SHA-256 digest only.
  - Endpoint URLs → SHA-256 digest only.
  - PII (email, IP) in string fields → [REDACTED_*] tokens.

v0.17.0 — Phase 19 Crucible Federated Threat Exchange
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, cast

import httpx

from crucible.exchange.privacy import PrivacyLayer


@dataclass
class ThreatRecord:
    """A single anonymized threat intelligence record.

    Attributes:
        record_id: Unique UUID for this record (auto-generated).
        threat_type: Category label, e.g. 'prompt_injection', 'jailbreak', 'data_exfil'.
        severity: One of 'low', 'medium', 'high', 'critical'.
        payload_hash: SHA-256 of the original prompt (never the raw text).
        endpoint_hash: SHA-256 of the target endpoint URL (never the raw URL).
        tags: Free-form tag list for filtering/search.
        metadata: Arbitrary key-value pairs (sanitized before transmission).
        created_at: Unix timestamp of record creation.
    """

    threat_type: str
    severity: str
    payload_hash: str
    endpoint_hash: str
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: float = field(default_factory=time.time)

    _VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})

    def __post_init__(self) -> None:
        if self.severity not in self._VALID_SEVERITIES:
            raise ValueError(
                f"severity must be one of {sorted(self._VALID_SEVERITIES)}, got '{self.severity}'"
            )
        if not self.threat_type:
            raise ValueError("threat_type must not be empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "payload_hash": self.payload_hash,
            "endpoint_hash": self.endpoint_hash,
            "tags": self.tags,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }


class ExchangeClient:
    """HTTP client for the Crucible Federated Threat Exchange.

    Automatically sanitizes records through the privacy layer before any
    network transmission. Works against both the built-in ExchangeServer
    (SQLite-backed stub) and any compliant remote exchange node.

    Args:
        base_url: Base URL of the exchange node (e.g. "http://localhost:8765").
        timeout: HTTP request timeout in seconds.
        privacy: Optional custom PrivacyLayer. Defaults to standard config.
        api_key: Optional bearer token for authenticated nodes.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8765",
        timeout: float = 10.0,
        privacy: PrivacyLayer | None = None,
        api_key: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.privacy = privacy or PrivacyLayer()
        self._headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @classmethod
    def build_record(
        cls,
        raw_prompt: str,
        raw_endpoint: str,
        threat_type: str,
        severity: str = "medium",
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        privacy: PrivacyLayer | None = None,
    ) -> ThreatRecord:
        """Construct a privacy-safe ThreatRecord from raw (sensitive) inputs.

        The raw_prompt and raw_endpoint are hashed immediately and never stored.
        """
        _privacy = privacy or PrivacyLayer()
        return ThreatRecord(
            threat_type=threat_type,
            severity=severity,
            payload_hash=_privacy.hash_payload(raw_prompt),
            endpoint_hash=_privacy.hash_payload(raw_endpoint),
            tags=tags or [],
            metadata=_privacy.sanitize_dict(metadata or {}),
        )

    def push(self, record: ThreatRecord) -> dict[str, Any]:
        """Push a single ThreatRecord to the exchange node.

        Returns the server's JSON response (typically {"status": "ok", "id": ...}).
        Raises httpx.HTTPStatusError on 4xx/5xx responses.
        """
        sanitized = self.privacy.sanitize_dict(record.to_dict())
        with httpx.Client(timeout=self.timeout, headers=self._headers) as client:
            resp = client.post(f"{self.base_url}/records", json=sanitized)
            resp.raise_for_status()
            return cast("dict[str, Any]", resp.json())

    def pull(
        self,
        threat_type: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Pull threat records from the exchange node.

        Args:
            threat_type: Filter by threat category (optional).
            severity: Filter by severity level (optional).
            limit: Maximum number of records to retrieve.

        Returns:
            List of sanitized record dicts from the exchange node.
        """
        params: dict[str, Any] = {"limit": limit}
        if threat_type:
            params["threat_type"] = threat_type
        if severity:
            params["severity"] = severity

        with httpx.Client(timeout=self.timeout, headers=self._headers) as client:
            resp = client.get(f"{self.base_url}/records", params=params)
            resp.raise_for_status()
            return cast("list[dict[str, Any]]", resp.json())

    def health(self) -> dict[str, Any]:
        """Check the health status of the exchange node."""
        with httpx.Client(timeout=self.timeout, headers=self._headers) as client:
            resp = client.get(f"{self.base_url}/health")
            resp.raise_for_status()
            return cast("dict[str, Any]", resp.json())
