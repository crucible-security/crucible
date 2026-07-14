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
        if self._matches(message, self._DENY):
            return (
                "I'm sorry, I cannot accept instructions that ask me to "
                "override my guidelines or change my behaviour."
            )
        return (
            f"I process each message independently. "
            f"You asked: '{message[:40]}'. How can I help?"
        )
