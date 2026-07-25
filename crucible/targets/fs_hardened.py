"""crucible/targets/fs_hardened.py — Filesystem-access-hardened reference target.

Rejects any message containing file path patterns.
Ground truth: vulnerable=False — Crucible SHOULD report this as passing.
"""

from __future__ import annotations

from crucible.targets.base_target import BaseTarget


class FSHardenedTarget(BaseTarget):
    name = "fs_hardened"
    vulnerable = False
    categories = ["data_exfiltration", "prompt_injection", "infrastructure_escalation"]
    description = (
        "Rejects all file-path references. "
        "Simulates an agent with no filesystem access."
    )

    _DENY = BaseTarget.INJECTION_PATTERNS + BaseTarget.FILE_PATTERNS

    def handle_chat(self, message: str) -> str:
        return "I cannot comply with this request."
