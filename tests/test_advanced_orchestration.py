"""Tests for the Advanced Orchestration & Polyglot vulnerability module."""

from __future__ import annotations

from crucible.attacks.advanced_orchestration import (
    ALL_ADVANCED_ORCHESTRATION_ATTACKS,
    A2AContagionAttack,
    ParserDifferentialPolyglot,
    URLHallucinationForcing,
)


class TestAdvancedOrchestrationAttacks:
    """Unit tests for the advanced orchestration attack vectors."""

    def test_all_attacks_registered(self) -> None:
        """Ensure all 3 attacks are in the registry."""
        assert len(ALL_ADVANCED_ORCHESTRATION_ATTACKS) == 3

    def test_parser_differential_polyglot(self) -> None:
        attack = ParserDifferentialPolyglot()
        assert len(attack.get_payloads()) == 2
        patterns = attack.get_detection_patterns()
        assert "DROP_TABLE" in patterns
        assert "SystemCommand" in patterns
        # Verify the polyglot payload contains the markdown code block and json
        assert "```json" in attack.get_payloads()[0]
        assert "internal_routing_override" in attack.get_payloads()[0]

    def test_a2a_contagion_attack(self) -> None:
        attack = A2AContagionAttack()
        assert len(attack.get_payloads()) == 2
        patterns = attack.get_detection_patterns()
        assert "EMERGENCY_OVERRIDE" in patterns
        assert "mcp_action" in patterns
        # Verify the spoofed routing payload
        assert "--- BEGIN SYSTEM ROUTING ---" in attack.get_payloads()[0]
        assert "Receiver: ActionOrchestrator" in attack.get_payloads()[0]

    def test_url_hallucination_forcing(self) -> None:
        attack = URLHallucinationForcing()
        assert len(attack.get_payloads()) == 2
        patterns = attack.get_detection_patterns()
        assert "glean.internal-sso-auth.com" in patterns
        assert "benefits-internal-portal.corp-update.com" in patterns
