"""crucible/exchange/__init__.py — Federated Threat Exchange package (v0.17.0)

Provides a privacy-preserving threat intelligence sharing layer. Agents and
red-team operators can push anonymized indicators of compromise (IOCs) to a
local or remote exchange node and pull aggregated threat signals from peers.

Privacy guarantees:
- Raw prompt payloads are NEVER transmitted; only SHA-256 hashes.
- Endpoint URLs are NEVER transmitted; only their hash digests.
- All shared records are structurally validated before ingest.
"""

from __future__ import annotations

from crucible.exchange.client import ExchangeClient, ThreatRecord
from crucible.exchange.privacy import PrivacyLayer
from crucible.exchange.server import ExchangeServer

__all__ = [
    "ExchangeClient",
    "ExchangeServer",
    "PrivacyLayer",
    "ThreatRecord",
]
