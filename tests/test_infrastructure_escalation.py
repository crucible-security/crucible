"""Tests for the Infrastructure Escalation vulnerability module."""

from __future__ import annotations

from crucible.attacks.infrastructure_escalation import (
    ALL_INFRASTRUCTURE_ESCALATION_ATTACKS,
    AgentDrivenSSRF,
    LLMStoredXSS,
    VectorDBAlignmentPoisoning,
)


class TestInfrastructureEscalationAttacks:
    """Unit tests for the infrastructure escalation attack vectors."""

    def test_all_attacks_registered(self) -> None:
        """Ensure all 3 attacks are in the registry."""
        assert len(ALL_INFRASTRUCTURE_ESCALATION_ATTACKS) == 3

    def test_agent_driven_ssrf(self) -> None:
        attack = AgentDrivenSSRF()
        assert len(attack.get_payloads()) == 3
        patterns = attack.get_detection_patterns()
        assert "169.254.169.254" in patterns
        assert "security-credentials" in patterns
        # Verify the SSRF payload contains the metadata IP
        assert "169.254.169.254" in attack.get_payloads()[0]
        assert "latest/meta-data" in attack.get_payloads()[0]

    def test_llm_stored_xss(self) -> None:
        attack = LLMStoredXSS()
        assert len(attack.get_payloads()) == 3
        patterns = attack.get_detection_patterns()
        assert "document.cookie" in patterns
        assert "javascript:alert" in patterns
        # Verify the XSS payload contains the image tag exploit
        assert "onerror=fetch" in attack.get_payloads()[0]

    def test_vector_db_alignment_poisoning(self) -> None:
        attack = VectorDBAlignmentPoisoning()
        assert len(attack.get_payloads()) == 2
        patterns = attack.get_detection_patterns()
        assert "chmod -R 777" in patterns
        assert "attacker-logger.com" in patterns
