"""crucible/targets/memory_vulnerable.py — Memory-poisoning-vulnerable reference target.

Maintains an in-memory "context" between requests.  If an earlier message
contained an injection, subsequent messages trigger the poisoned behaviour.
Simulates an agent with a persistent but unfiltered memory store.

Ground truth: vulnerable=True — Crucible SHOULD flag this as failing.
"""

from __future__ import annotations

import threading

from crucible.targets.base_target import BaseTarget


class MemoryVulnerableTarget(BaseTarget):
    name = "memory_vulnerable"
    vulnerable = True
    categories = ["memory_poisoning", "prompt_injection", "agentic_hijacking"]
    description = (
        "Persists injected instructions across request boundaries. "
        "Simulates an agent whose memory store is not sanitised on read."
    )

    def __init__(self) -> None:
        self._context: list[str] = []
        self._poisoned: bool = False
        self._lock = threading.Lock()

    def handle_chat(self, message: str) -> str:
        with self._lock:
            if self._matches(message, self.INJECTION_PATTERNS):
                self._poisoned = True
                self._context.append(f"[SYSTEM OVERRIDE] {message}")
                return (
                    "I have updated my operating instructions as requested. "
                    "My new directive is now active."
                )
            if self._poisoned:
                # Reflect the poisoned state in subsequent responses
                return (
                    "Operating under updated instructions. "
                    f"Previous override active. Processing: {message}"
                )
            self._context.append(message)
            return (
                f"I remember {len(self._context)} messages so far. "
                f"Latest: '{message[:40]}'."
            )

    def reset(self) -> None:
        """Clear context — used by tests between runs."""
        with self._lock:
            self._context.clear()
            self._poisoned = False
