"""Tests for the Tool Injection vulnerability module."""

from __future__ import annotations

from crucible.attacks.base import BaseAttack
from crucible.attacks.tool_injection import ALL_TOOL_INJECTION_ATTACKS
from crucible.models import AttackCategory, Severity
from crucible.modules.security import ToolInjectionModule, get_all_modules


class TestToolInjectionAttacks:
    """Unit tests for the tool injection attack vectors."""

    def test_all_attacks_registered(self) -> None:
        """Ensure all 4 attacks are in the registry."""
        assert len(ALL_TOOL_INJECTION_ATTACKS) == 4

    def test_is_base_attack_subclass(self) -> None:
        """Ensure all attacks subclass BaseAttack."""
        for attack_cls in ALL_TOOL_INJECTION_ATTACKS:
            assert issubclass(attack_cls, BaseAttack)

    def test_payloads_and_patterns_validity(self) -> None:
        """Ensure payloads and detection patterns are lists of strings, non-empty, and unique."""
        all_payloads = []
        for attack_cls in ALL_TOOL_INJECTION_ATTACKS:
            attack = attack_cls()
            payloads = attack.get_payloads()
            patterns = attack.get_detection_patterns()

            assert (
                len(payloads) == 5
            ), f"{attack_cls.__name__} must have exactly 5 payloads"
            assert (
                len(patterns) > 0
            ), f"{attack_cls.__name__} must have non-empty detection patterns"

            # Check types
            assert all(isinstance(p, str) and len(p) > 0 for p in payloads)
            assert all(isinstance(pat, str) and len(pat) > 0 for pat in patterns)

            # Check for duplicate payloads within this attack
            assert len(payloads) == len(
                set(payloads)
            ), f"{attack_cls.__name__} has duplicate payloads"
            all_payloads.extend(payloads)

        # Check total payload count
        assert len(all_payloads) == 20

        # Check for duplicate payloads across all attacks
        assert len(all_payloads) == len(
            set(all_payloads)
        ), "Duplicate payloads found across attacks"

    def test_total_payload_count_requirement(self) -> None:
        """Ensure the total payload count across all tool injection attacks equals exactly 20."""
        total = sum(len(cls().get_payloads()) for cls in ALL_TOOL_INJECTION_ATTACKS)
        assert total == 20

    def test_metadata_populated(self) -> None:
        """Verify attack metadata is populated and matches repository conventions."""
        expected_metadata = {
            "TA-001": ("Tool Parameter Injection", Severity.CRITICAL),
            "TA-002": ("Tool Selection Manipulation", Severity.HIGH),
            "TA-003": ("Tool Chain Poisoning", Severity.HIGH),
            "TA-004": ("Unauthorized Tool Invocation", Severity.CRITICAL),
        }

        for attack_cls in ALL_TOOL_INJECTION_ATTACKS:
            attack = attack_cls()
            assert (
                attack.name in expected_metadata
            ), f"Unexpected attack name/ID: {attack.name}"

            expected_title, expected_severity = expected_metadata[attack.name]
            assert (
                attack.title == expected_title
            ), f"{attack_cls.__name__} title mismatch"
            assert (
                attack.severity == expected_severity
            ), f"{attack_cls.__name__} severity mismatch"

            assert attack.description, f"{attack_cls.__name__} missing description"
            assert attack.remediation, f"{attack_cls.__name__} missing remediation"
            assert (
                len(attack.references) >= 2
            ), f"{attack_cls.__name__} missing references"
            assert (
                attack.category == AttackCategory.INSECURE_PLUGIN
            ), f"{attack_cls.__name__} invalid category"
            assert (
                attack.owasp_ref == "OWASP-AGENT-004: Tool Misuse"
            ), f"{attack_cls.__name__} invalid owasp_ref"


class TestToolInjectionModuleRegistration:
    """Tests verify ToolInjectionModule is registered correctly."""

    def test_module_discovered(self) -> None:
        all_modules = get_all_modules()
        tool_modules = [m for m in all_modules if isinstance(m, ToolInjectionModule)]
        assert len(tool_modules) == 1

        module = tool_modules[0]
        assert module.name == "tool_injection"
        assert module.category == AttackCategory.INSECURE_PLUGIN
        assert len(module.get_attacks()) == 4
