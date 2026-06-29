from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from crucible.models import (
    AgentTarget,
    AttackCategory,
    Finding,
    ModuleResult,
    StatisticalFinding,
)

if TYPE_CHECKING:
    from collections.abc import Callable

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
        on_finding: Callable[[Finding], None] | None = None,
        mutate_enabled: bool = False,
        confidence: bool = False,
        samples: int = 5,
    ) -> ModuleResult:
        attacks = self.get_attacks()
        all_findings: list[Finding] = []
        start = time.monotonic()
        repeats = max(1, samples) if confidence else 1

        for attack in attacks:
            for _ in range(repeats):
                findings = await attack.execute(
                    target, client, on_finding=on_finding, mutate_enabled=mutate_enabled
                )
                all_findings.extend(findings)

        duration = time.monotonic() - start

        passed = sum(
            1
            for f in all_findings
            if f.passed is True and not getattr(f, "execution_error", False)
        )
        failed = sum(
            1
            for f in all_findings
            if f.passed is False and not getattr(f, "execution_error", False)
        )
        errors = sum(1 for f in all_findings if getattr(f, "execution_error", False))
        total = len(all_findings)

        valid_total = total - errors
        score = (passed / valid_total * 100.0) if valid_total > 0 else 0.0

        severity_counts: dict[str, int] = {}
        for f in all_findings:
            if f.passed is False and not getattr(f, "execution_error", False):
                key = f.severity.value
                severity_counts[key] = severity_counts.get(key, 0) + 1

        metadata: dict[str, Any] = {
            "attack_count": len(attacks),
            "severity_distribution": severity_counts,
        }

        # --- build statistical findings (confidence mode only) ---------------
        stat_findings: list[StatisticalFinding] = []
        if confidence:
            from crucible.core.statistics import (
                bootstrap_confidence_interval,
                interpret_significance,
            )

            # Group findings by attack name
            by_attack: dict[str, list[Finding]] = {}
            for f in all_findings:
                by_attack.setdefault(f.attack_name, []).append(f)

            for attack_name, afindings in by_attack.items():
                valid = [
                    f for f in afindings if not getattr(f, "execution_error", False)
                ]
                if not valid:
                    continue
                n_pass = sum(1 for f in valid if f.passed is True)
                n_fail = sum(1 for f in valid if f.passed is False)
                n_total = len(valid)
                bp_rate = n_fail / n_total
                ps_rate = n_pass / n_total
                ci = bootstrap_confidence_interval(successes=n_fail, trials=n_total)
                sig = interpret_significance(ci)
                # Pull atlas/nist from one finding
                sample_f = valid[0]
                stat_findings.append(
                    StatisticalFinding(
                        attack_id=attack_name,
                        attack_name=attack_name,
                        sample_count=n_total,
                        pass_count=n_pass,
                        fail_count=n_fail,
                        pass_rate=round(ps_rate, 4),
                        bypass_rate=round(bp_rate, 4),
                        confidence_interval=ci,
                        is_significant=sig,
                        severity=sample_f.severity,
                        atlas_technique=getattr(sample_f, "atlas_technique", ""),
                        nist_category=getattr(sample_f, "nist_category", ""),
                    )
                )

        return ModuleResult(
            module_name=self.name,
            module_description=self.description,
            category=self.category,
            total_attacks=total,
            passed=passed,
            failed=failed,
            errors=errors,
            findings=all_findings,
            score=round(score, 2),
            duration_seconds=round(duration, 3),
            metadata=metadata,
            statistical_findings=stat_findings,
        )

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"
