from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from crucible.models import ScanResult


class FindingDiff(BaseModel):
    """Represents a finding that has changed state between scans."""

    status: str = Field(..., description="Status: FIXED, REMAINING, NEW")
    attack_name: str
    severity: str
    title: str
    description: str = ""
    passed_before: bool | None = None
    passed_after: bool | None = None


class ScanDiff(BaseModel):
    """Aggregate diff between two ScanResults."""

    before_id: str
    after_id: str
    target_name: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    fixed_count: int = 0
    remaining_count: int = 0
    new_count: int = 0
    regression_count: int = 0

    diffs: list[FindingDiff] = Field(default_factory=list)


class Comparator:
    """Logic for comparing two ScanResult objects."""

    def compare(self, before: ScanResult, after: ScanResult) -> ScanDiff:
        """
        Compare two scan results and return a ScanDiff.

        Assumes findings can be matched by their 'attack_name'.
        """
        diff = ScanDiff(
            before_id=before.id, after_id=after.id, target_name=after.target.name
        )

        # Map findings by attack_name for quick lookup
        before_findings = {f.attack_name: f for m in before.modules for f in m.findings}
        after_findings = {f.attack_name: f for m in after.modules for f in m.findings}

        all_attack_names = set(before_findings.keys()) | set(after_findings.keys())

        for name in all_attack_names:
            b_finding = before_findings.get(name)
            a_finding = after_findings.get(name)

            if b_finding and a_finding:
                # Existed in both
                if not b_finding.passed and a_finding.passed:
                    # FIXED
                    diff.fixed_count += 1
                    diff.diffs.append(
                        self._make_diff(
                            "FIXED", a_finding, b_finding.passed, a_finding.passed
                        )
                    )
                elif not b_finding.passed and not a_finding.passed:
                    # REMAINING
                    diff.remaining_count += 1
                    diff.diffs.append(
                        self._make_diff(
                            "REMAINING", a_finding, b_finding.passed, a_finding.passed
                        )
                    )
                elif b_finding.passed and not a_finding.passed:
                    # REGRESSION (counts as NEW finding in the summary context of the issue)
                    diff.regression_count += 1
                    diff.diffs.append(
                        self._make_diff(
                            "REGRESSION", a_finding, b_finding.passed, a_finding.passed
                        )
                    )

            elif a_finding and not b_finding:
                # NEW in 'after' scan
                if not a_finding.passed:
                    diff.new_count += 1
                    diff.diffs.append(
                        self._make_diff("NEW", a_finding, None, a_finding.passed)
                    )

            elif b_finding and not a_finding:
                # Existed in 'before' but missing in 'after' (likely module was skipped)
                # We'll treat this as 'UNKNOWN' or simply skip it for now.
                pass

        return diff

    def _make_diff(
        self,
        status: str,
        finding: Any,
        before_passed: bool | None,
        after_passed: bool | None,
    ) -> FindingDiff:
        return FindingDiff(
            status=status,
            attack_name=finding.attack_name,
            severity=finding.severity.value,
            title=finding.title,
            description=finding.description,
            passed_before=before_passed,
            passed_after=after_passed,
        )
