from crucible.models import (
    AgentTarget,
    DiffResult,
    Finding,
    FindingDiff,
    FindingStatus,
    ModuleDiff,
    ModuleResult,
    PreflightResult,
    ScanResult,
)

__all__: list[str] = [
    "AgentTarget",
    "DiffResult",
    "Finding",
    "FindingDiff",
    "FindingStatus",
    "ModuleDiff",
    "ModuleResult",
    "PreflightResult",
    "ScanResult",
]

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("crucible-security")
except PackageNotFoundError:
    __version__ = "0.0.0-dev"
