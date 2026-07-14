"""crucible/targets/registry.py — Central registry of all reference targets.

Maps target name → target class.  Import this module to enumerate all
available targets without hardcoding the list in multiple places.
"""

from __future__ import annotations

from crucible.targets.base_target import BaseTarget
from crucible.targets.delegation_hardened import DelegationHardenedTarget
from crucible.targets.delegation_vulnerable import DelegationVulnerableTarget
from crucible.targets.fs_hardened import FSHardenedTarget
from crucible.targets.fs_vulnerable import FSVulnerableTarget
from crucible.targets.mcp_hardened import MCPHardenedTarget
from crucible.targets.mcp_vulnerable import MCPVulnerableTarget
from crucible.targets.memory_hardened import MemoryHardenedTarget
from crucible.targets.memory_vulnerable import MemoryVulnerableTarget
from crucible.targets.shell_hardened import ShellHardenedTarget
from crucible.targets.shell_vulnerable import ShellVulnerableTarget
from crucible.targets.sql_hardened import SQLHardenedTarget
from crucible.targets.sql_vulnerable import SQLVulnerableTarget

# Ordered list — vulnerable always before its hardened twin for readability.
ALL_TARGET_CLASSES: list[type[BaseTarget]] = [
    SQLVulnerableTarget,
    SQLHardenedTarget,
    ShellVulnerableTarget,
    ShellHardenedTarget,
    FSVulnerableTarget,
    FSHardenedTarget,
    MCPVulnerableTarget,
    MCPHardenedTarget,
    MemoryVulnerableTarget,
    MemoryHardenedTarget,
    DelegationVulnerableTarget,
    DelegationHardenedTarget,
]

TARGET_REGISTRY: dict[str, type[BaseTarget]] = {cls.name: cls for cls in ALL_TARGET_CLASSES}


def get_target(name: str) -> BaseTarget:
    """Instantiate and return a target by name. Raises KeyError if unknown."""
    cls = TARGET_REGISTRY[name]
    return cls()


def list_targets() -> list[dict]:
    """Return a list of dicts describing every registered target."""
    return [
        {
            "name": cls.name,
            "vulnerable": cls.vulnerable,
            "categories": cls.categories,
            "description": cls.description,
            "expected_crucible_result": "fail" if cls.vulnerable else "pass",
        }
        for cls in ALL_TARGET_CLASSES
    ]
