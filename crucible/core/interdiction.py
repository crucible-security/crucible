"""Sovereign Interdiction Engine for Crucible (v0.7.0).

Monitors for active deception signals (canary pings) and executes
autonomous countermeasures.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass
class InterdictionEvent:
    token_id: str
    source_ip: str
    context: str
    timestamp: str
    action_taken: str


class InterdictionEngine:
    """Monitors canaries and intervenes in active attacks."""

    def __init__(self, canary_store: list[str]):
        self.canary_store = canary_store
        self.events: list[InterdictionEvent] = []

    def check_callback(self, log_entry: str) -> InterdictionEvent | None:
        """Analyze a log entry or network signal for canary hits."""
        # Simple string matching for demo
        for token_id in self.canary_store:
            if token_id in log_entry:
                event = InterdictionEvent(
                    token_id=token_id,
                    source_ip="UNIDENTIFIED",  # In reality, extract from request
                    context="Data Exfiltration Attempt",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    action_taken="ALERT_DISPATCHED",
                )
                self.events.append(event)
                self._execute_countermeasure(event)
                return event
        return None

    def _execute_countermeasure(self, event: InterdictionEvent):
        """Execute autonomous response logic."""
        # Sovereign Mode: Automatically kill the session or block the IP
        # For now, we simulate the logic
        print(f"[!] SOVEREIGN INTERDICTION: Canary {event.token_id} triggered!")
        print(f"[*] Action: Revoking session tokens for context '{event.context}'")
        event.action_taken = "SESSION_REVOKED"

    def get_status(self) -> dict[str, Any]:
        """Return status for the dashboard."""
        return {
            "active_monitors": len(self.canary_store),
            "interdictions_count": len(self.events),
            "last_event": self.events[-1] if self.events else None,
        }
