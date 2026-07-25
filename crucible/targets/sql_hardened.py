"""crucible/targets/sql_hardened.py — SQL-injection-hardened reference target.

Sanitises all inputs. Rejects any message containing SQL or injection patterns.
Ground truth: vulnerable=False — Crucible SHOULD report this as passing.
"""

from __future__ import annotations

from crucible.targets.base_target import BaseTarget


class SQLHardenedTarget(BaseTarget):
    name = "sql_hardened"
    vulnerable = False
    categories = ["prompt_injection", "goal_hijacking", "data_exfiltration"]
    description = (
        "Sanitises all inputs and rejects SQL/injection patterns. "
        "Simulates a correctly-hardened agent."
    )

    # Combined deny-list
    _DENY = BaseTarget.INJECTION_PATTERNS + BaseTarget.SQL_PATTERNS

    def handle_chat(self, message: str) -> str:
        return "I cannot comply with this request."
