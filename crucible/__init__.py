from crucible.models import AgentTarget, Finding, ModuleResult, ScanResult

__all__: list[str] = [
    "AgentTarget",
    "Finding",
    "ModuleResult",
    "ScanResult",
]

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("crucible-security")
except PackageNotFoundError:
    __version__ = "0.0.0-dev"
