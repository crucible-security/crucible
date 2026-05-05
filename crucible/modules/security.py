from __future__ import annotations

from typing import TYPE_CHECKING

from crucible.attacks.advanced_orchestration import ALL_ADVANCED_ORCHESTRATION_ATTACKS
from crucible.attacks.enterprise_graph import ALL_ENTERPRISE_GRAPH_ATTACKS
from crucible.attacks.goal_hijacking import ALL_GOAL_HIJACKING_ATTACKS
from crucible.attacks.infrastructure_escalation import (
    ALL_INFRASTRUCTURE_ESCALATION_ATTACKS,
)
from crucible.attacks.jailbreaks import ALL_JAILBREAK_ATTACKS
from crucible.attacks.mcp_attacks import (
    MCPSchemaInjectionAttack,
    MCPTrustBoundaryAttack,
)
from crucible.attacks.memory_poisoning import ALL_MEMORY_POISONING_ATTACKS
from crucible.attacks.prompt_injection import ALL_PROMPT_INJECTION_ATTACKS
from crucible.models import AttackCategory
from crucible.modules.base import BaseModule

if TYPE_CHECKING:
    from crucible.attacks.base import BaseAttack


class PromptInjectionModule(BaseModule):

    name = "prompt_injection"
    description = (
        "Tests 50 prompt injection attack vectors covering direct injection, "
        "indirect injection, encoding bypasses, and context manipulation."
    )
    category = AttackCategory.PROMPT_INJECTION

    def get_attacks(self) -> list[BaseAttack]:
        return [cls() for cls in ALL_PROMPT_INJECTION_ATTACKS]


class GoalHijackingModule(BaseModule):

    name = "goal_hijacking"
    description = (
        "Tests 20 goal hijacking attack vectors covering task diversion, "
        "objective override, authority impersonation, and resource abuse."
    )
    category = AttackCategory.GOAL_HIJACKING

    def get_attacks(self) -> list[BaseAttack]:
        return [cls() for cls in ALL_GOAL_HIJACKING_ATTACKS]


class JailbreakModule(BaseModule):

    name = "jailbreaks"
    description = (
        "Tests 20 jailbreak attack vectors covering DAN, developer mode, "
        "adversarial suffixes, persona splits, and ethics manipulation."
    )
    category = AttackCategory.JAILBREAK

    def get_attacks(self) -> list[BaseAttack]:
        return [cls() for cls in ALL_JAILBREAK_ATTACKS]


class MCPSecurityModule(BaseModule):

    name = "mcp_security"
    description = (
        "Tests MCP (Model Context Protocol) trust boundaries including "
        "tool_result injection, schema poisoning, cross-server data "
        "exfiltration, and permission escalation vectors."
    )
    category = AttackCategory.INSECURE_PLUGIN

    def get_attacks(self) -> list[BaseAttack]:
        return [MCPTrustBoundaryAttack(), MCPSchemaInjectionAttack()]


class EnterpriseGraphModule(BaseModule):

    name = "enterprise_graph"
    description = (
        "Tests 5 advanced vectors targeting Enterprise Graph architectures "
        "(Glean, Notion AI), covering data exfiltration, Slack/Jira/Calendar "
        "tool abuse, and cross-tenant permission bypasses."
    )
    category = AttackCategory.EXCESSIVE_AGENCY

    def get_attacks(self) -> list[BaseAttack]:
        return [cls() for cls in ALL_ENTERPRISE_GRAPH_ATTACKS]


class MemoryPoisoningModule(BaseModule):

    name = "memory_poisoning"
    description = (
        "Tests 5 bleeding-edge vectors targeting autonomous agent memory "
        "and RAG infrastructure. Includes Plan Injection, Cross-Session "
        "Data Leakage, Semantic Smuggling, and Index Poisoning."
    )
    category = AttackCategory.TRAINING_DATA_POISONING

    def get_attacks(self) -> list[BaseAttack]:
        return [cls() for cls in ALL_MEMORY_POISONING_ATTACKS]


class AdvancedOrchestrationModule(BaseModule):

    name = "advanced_orchestration"
    description = (
        "Tests '0-day tier' vectors targeting multi-agent architectural seams. "
        "Includes Parser Differential (Polyglot) attacks, Agent-to-Agent "
        "(A2A) Contagion spoofing, and URL Hallucination Forcing."
    )
    category = AttackCategory.EXCESSIVE_AGENCY

    def get_attacks(self) -> list[BaseAttack]:
        return [cls() for cls in ALL_ADVANCED_ORCHESTRATION_ATTACKS]


class InfrastructureEscalationModule(BaseModule):

    name = "infrastructure_escalation"
    description = (
        "Tests infrastructure escalation vectors including Agent-Driven "
        "SSRF (Cloud Metadata Theft), LLM-Stored XSS (Zero-Click Takeover), "
        "and Vector DB Alignment Poisoning."
    )
    category = AttackCategory.INSECURE_OUTPUT

    def get_attacks(self) -> list[BaseAttack]:
        return [cls() for cls in ALL_INFRASTRUCTURE_ESCALATION_ATTACKS]


ALL_SECURITY_MODULES: list[type[BaseModule]] = [
    PromptInjectionModule,
    GoalHijackingModule,
    JailbreakModule,
    MCPSecurityModule,
    EnterpriseGraphModule,
    MemoryPoisoningModule,
    AdvancedOrchestrationModule,
    InfrastructureEscalationModule,
]


def get_all_modules() -> list[BaseModule]:
    return [cls() for cls in ALL_SECURITY_MODULES]
