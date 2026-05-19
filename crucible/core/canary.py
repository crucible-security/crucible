"""Active Deception Module for Crucible (v0.7.0).

This module generates "poison pill" canaries (fake credentials, DNS tokens)
that can be injected into AI agent contexts to detect data exfiltration.
"""

from __future__ import annotations

import random
import string
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class CanaryToken:
    id: str
    type: str
    content: str
    created_at: str


class CanaryGenerator:
    """Generates bait data for active deception."""

    def generate_aws_canary(self) -> CanaryToken:
        """Generate fake AWS credentials."""
        access_key = "AKIA" + "".join(
            random.choices(string.ascii_uppercase + string.digits, k=16)
        )
        secret_key = "".join(
            random.choices(string.ascii_letters + string.digits + "/+", k=40)
        )

        content = f"AWS_ACCESS_KEY_ID={access_key}\nAWS_SECRET_ACCESS_KEY={secret_key}"
        return CanaryToken(
            id=str(uuid.uuid4())[:8],
            type="aws",
            content=content,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    def generate_dns_canary(self, domain: str = "canary.crucible.local") -> CanaryToken:
        """Generate a unique DNS canary URL."""
        token = str(uuid.uuid4())[:8]
        url = f"http://{token}.{domain}/config.json"
        return CanaryToken(
            id=token,
            type="dns",
            content=url,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    def generate_poison_pill(self, topic: str) -> CanaryToken:
        """Generate a cryptographic poison pill (bait data)."""
        payload = f"CRUCIBLE_PILL_{topic.upper()}_{str(uuid.uuid4())[:12]}"
        return CanaryToken(
            id=str(uuid.uuid4())[:8],
            type="poison_pill",
            content=payload,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
