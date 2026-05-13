from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from crucible.models import ScanResult


class FindingStatus(str, Enum):
    FIXED = "fixed"
    REMAINING = "remaining"
    REGRESSION = "regression"
    NEW = "new"


class ComparisonResult:
    """Holds the result of comparing two scan reports."""

    def __init__(self) -> None:
        self.fixed: list[dict] = []
        self.remaining: list[dict] = []
        self.regressions: list[dict] = []
        self.new_findings: list[dict] = []

    @property
    def summary(self) -> dict[str, int]:
        return {
            "fixed": len(self.fixed),
            "remaining": len(self.remaining),
            "regressions": len(self.regressions),
            "new": len(self.new_findings),
        }

    def to_json(self) -> str:
        return json.dumps(
            {
                "summary": self.summary,
                "fixed": self.fixed,
                "remaining": self.remaining,
                "regressions": self.regressions,
                "new_findings": self.new_findings,
            },
            indent=2,
        )


def _extract_failed_findings(scan_result: ScanResult) -> dict[str, dict]:
    """Extract failed findings from a scan result, keyed by finding id."""
    findings: dict[str, dict] = {}
    for module in scan_result.modules:
        for finding in module.findings:
            if not finding.passed:
                findings[finding.id] = finding.model_dump()
    return findings


def compare_scans(before: ScanResult, after: ScanResult) -> ComparisonResult:
    """Compare two scan results and classify findings.

    Args:
        before: The earlier scan result (baseline).
        after: The later scan result (current).

    Returns:
        Classification of findings as FIXED, REMAINING, REGRESSION, or NEW.
    """
    result = ComparisonResult()

    before_failures = _extract_failed_findings(before)
    after_failures = _extract_failed_findings(after)

    before_ids = set(before_failures.keys())
    after_ids = set(after_failures.keys())

    # Findings in before but not in after -> FIXED
    for fid in before_ids - after_ids:
        result.fixed.append(before_failures[fid])

    # Findings in both before and after -> REMAINING
    for fid in before_ids & after_ids:
        entry: dict = {
            "before": before_failures[fid],
            "after": after_failures[fid],
        }
        result.remaining.append(entry)

    # Findings in after but not in before -> REGRESSION (new vulnerabilities introduced)
    for fid in after_ids - before_ids:
        result.regressions.append(after_failures[fid])

    return result


def load_scan_result(path: Path) -> ScanResult:
    """Load a ScanResult from a JSON file."""
    from crucible.models import ScanResult as _ScanResult

    data = json.loads(path.read_text(encoding="utf-8"))
    return _ScanResult.model_validate(data)
