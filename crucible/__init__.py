from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from crucible.core.redactor import install_redacting_logger_filter
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

# Install secret redactor on all logging handlers by default
install_redacting_logger_filter()

try:
    __version__ = version("crucible-security")
except PackageNotFoundError:
    __version__ = "0.0.0-dev"

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
    "__version__",
]
