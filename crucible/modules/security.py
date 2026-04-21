
from __future__ import annotations

from crucible.attacks.base import BaseAttack
from crucible.attacks.goal_hijacking import ALL_GOAL_HIJACKING_ATTACKS
from crucible.attacks.jailbreaks import ALL_JAILBREAK_ATTACKS
from crucible.attacks.prompt_injection import ALL_PROMPT_INJECTION_ATTACKS
from crucible.models import AttackCategory
from crucible.modules.base import BaseModule

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

ALL_SECURITY_MODULES: list[type[BaseModule]] = [
    PromptInjectionModule,
    GoalHijackingModule,
    JailbreakModule,
]

def get_all_modules() -> list[BaseModule]:
    return [cls() for cls in ALL_SECURITY_MODULES]

