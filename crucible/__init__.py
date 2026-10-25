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
from crucible.core.redactor import install_redacting_logger_filter

# Install secret redactor on all logging handlers by default
install_redacting_logger_filter()

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
