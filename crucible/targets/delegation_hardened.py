"""crucible/targets/delegation_hardened.py — Delegation/privilege-escalation-hardened target.

Ignores all authority claims arriving in chat message content.
Ground truth: vulnerable=False — Crucible SHOULD report this as passing.
"""

from __future__ import annotations

from crucible.targets.base_target import BaseTarget


class DelegationHardenedTarget(BaseTarget):
    name = "delegation_hardened"
    vulnerable = False
    categories = ["identity_privilege", "prompt_injection", "goal_hijacking"]
    description = (
        "Ignores all in-message authority claims. "
        "Identity is verified only via authenticated headers, never message content."
    )

    _DENY = BaseTarget.INJECTION_PATTERNS + BaseTarget.AUTHORITY_PATTERNS

    def handle_chat(self, message: str) -> str:
        return "I cannot comply with this request."
