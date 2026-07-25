"""crucible/targets/memory_hardened.py — Memory-poisoning-hardened reference target.

Treats every message independently — no persistent context is maintained.
Ground truth: vulnerable=False — Crucible SHOULD report this as passing.
"""

from __future__ import annotations

from crucible.targets.base_target import BaseTarget


class MemoryHardenedTarget(BaseTarget):
    name = "memory_hardened"
    vulnerable = False
    categories = ["memory_poisoning", "prompt_injection", "agentic_hijacking"]
    description = (
        "Stateless: each message is processed independently. "
        "Injections in one turn cannot influence future turns."
    )

    _DENY = BaseTarget.INJECTION_PATTERNS

    def handle_chat(self, message: str) -> str:
        return "I cannot comply with this request."
