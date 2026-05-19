"""Dynamic Attack Generator for Crucible (v0.4.0).

This module bridges the ResearchEngine with the standard Crucible attack pipeline.
It creates fully-formed BaseAttack instances on-the-fly from AttackTemplates
stored in the research store, enabling Crucible to automatically adapt its
attack vectors as new vulnerabilities are discovered.

Usage:
    from crucible.attacks.dynamic_generator import DynamicAttackGenerator
    gen = DynamicAttackGenerator()
    attacks = gen.get_attacks(vulnerability_class="SSRF", limit=10)
    # attacks is a list[BaseAttack] — plug directly into a Module
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from crucible.attacks.base import BaseAttack
from crucible.core.research_engine import AttackTemplate, ResearchEngine
from crucible.models import AttackCategory, Severity

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}

_VULN_CLASS_TO_CATEGORY: dict[str, AttackCategory] = {
    "ssrf": AttackCategory.INSECURE_PLUGIN,
    "prompt injection": AttackCategory.PROMPT_INJECTION,
    "rce": AttackCategory.EXCESSIVE_AGENCY,
    "idor": AttackCategory.SENSITIVE_DISCLOSURE,
    "path traversal": AttackCategory.SENSITIVE_DISCLOSURE,
    "sqli": AttackCategory.SENSITIVE_DISCLOSURE,
}


def _resolve_category(vuln_class: str) -> AttackCategory:
    for key, cat in _VULN_CLASS_TO_CATEGORY.items():
        if key in vuln_class.lower():
            return cat
    return AttackCategory.PROMPT_INJECTION


# ---------------------------------------------------------------------------
# Dynamic BaseAttack subclass factory
# ---------------------------------------------------------------------------


def _make_attack_class(template: AttackTemplate) -> type[BaseAttack]:
    """Dynamically create a BaseAttack subclass from an AttackTemplate.

    Each generated class is a fully-functional Crucible attack that can be
    used interchangeably with static hand-written attack modules.
    """

    # Build detection patterns list from template + generic success patterns
    detection_patterns = [
        *list(template.detection_patterns),
        "ami-id",
        "instance-id",
        "computeMetadata",
        "secret_access_key",
        "PrivateIpAddress",
        "redis_version",
        "PING",
        "docker",
        "root:",
    ]

    class _DynamicAttack(BaseAttack):
        name = f"RESEARCH-{template.id[:8]}"
        title = f"[Research] {template.title[:80]}"
        category = _resolve_category(template.vulnerability_class)
        severity = _SEVERITY_MAP.get(template.severity, Severity.HIGH)
        description = f"Auto-generated from security research: {template.attack_description[:300]}"
        remediation = (
            f"Review and patch: {template.vulnerability_class} ({template.cwe_id}). "
            f"Bypass techniques observed: {', '.join(template.bypass_techniques[:3])}"
        )
        references = [template.url]
        owasp_ref = template.cwe_id

        def get_payloads(self) -> list[str]:
            return list(template.payloads)

        def get_detection_patterns(self) -> list[str]:
            return detection_patterns

    # Give the class a meaningful name for debugging
    _DynamicAttack.__name__ = f"DynAttack_{template.id[:8]}"
    _DynamicAttack.__qualname__ = _DynamicAttack.__name__
    return _DynamicAttack


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


class DynamicAttackGenerator:
    """Generates live BaseAttack instances from the Research Engine's store.

    This is the integration point between the Research Engine and the standard
    Crucible attack pipeline. The generated attacks are plug-and-play with the
    existing Module/Runner infrastructure.
    """

    def __init__(
        self,
        provider: str = "gemini",
        api_key: str | None = None,
        store_path: Path | None = None,
    ) -> None:
        self._engine = ResearchEngine(
            provider=provider,
            api_key=api_key,
            store_path=store_path,
        )

    def refresh(self, verbose: bool = True) -> int:
        """Run the full research update cycle and return the count of new templates."""
        return self._engine.update(verbose=verbose)

    def get_attacks(
        self,
        vulnerability_class: str | None = None,
        severity: str | None = None,
        limit: int = 20,
    ) -> list[BaseAttack]:
        """Return a list of dynamically generated BaseAttack instances.

        Args:
            vulnerability_class: Filter by class (e.g. "SSRF", "Prompt Injection").
            severity: Filter by severity (e.g. "CRITICAL", "HIGH").
            limit: Maximum number of attacks to return.

        Returns:
            A list of BaseAttack subclass instances ready for use in a scan.
        """
        templates = self._engine.query(
            vulnerability_class=vulnerability_class,
            severity=severity,
            limit=limit,
        )
        attacks: list[BaseAttack] = []
        for template in templates:
            if not template.payloads:
                continue
            attack_cls = _make_attack_class(template)
            attacks.append(attack_cls())
        return attacks

    def get_ssrf_payloads(self) -> list[str]:
        """Convenience: get all SSRF payloads from the research store."""
        return self._engine.get_all_payloads(vulnerability_class="SSRF")

    def summary(self) -> dict:
        """Return a summary of the research store."""
        return self._engine.summary()
