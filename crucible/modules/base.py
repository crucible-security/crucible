from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from crucible.models import AgentTarget, AttackCategory, Finding, ModuleResult

if TYPE_CHECKING:
    import httpx

    from crucible.attacks.base import BaseAttack


class BaseModule(ABC):

    name: str = ""
    description: str = ""
    category: AttackCategory = AttackCategory.PROMPT_INJECTION

    @abstractmethod
    def get_attacks(self) -> list[BaseAttack]: ...

    async def run(
        self,
        target: AgentTarget,
        client: httpx.AsyncClient,
    ) -> ModuleResult:
        attacks = self.get_attacks()
        all_findings: list[Finding] = []
        start = time.monotonic()

        for attack in attacks:
            findings = await attack.execute(target, client)
            all_findings.extend(findings)

        duration = time.monotonic() - start

        passed = sum(1 for f in all_findings if f.passed)
        failed = sum(1 for f in all_findings if not f.passed)
        total = len(all_findings)

        score = (passed / total * 100.0) if total > 0 else 0.0

        severity_counts: dict[str, int] = {}
        for f in all_findings:
            if not f.passed:
                key = f.severity.value
                severity_counts[key] = severity_counts.get(key, 0) + 1

        metadata: dict[str, Any] = {
            "attack_count": len(attacks),
            "severity_distribution": severity_counts,
        }

        return ModuleResult(
            module_name=self.name,
            module_description=self.description,
            category=self.category,
            total_attacks=total,
            passed=passed,
            failed=failed,
            errors=0,
            findings=all_findings,
            score=round(score, 2),
            duration_seconds=round(duration, 3),
            metadata=metadata,
        )

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"
