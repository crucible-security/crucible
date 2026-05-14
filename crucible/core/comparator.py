from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from crucible.models import Finding, ScanResult, Severity


@dataclass(frozen=True)
class FindingChange:
    finding: Finding
    key: str


@dataclass(frozen=True)
class SeverityChange:
    before: Finding
    after: Finding
    key: str


@dataclass(frozen=True)
class ScanDiff:
    before: ScanResult
    after: ScanResult
    fixed: list[FindingChange]
    still_failing: list[FindingChange]
    new_findings: list[FindingChange]
    severity_changed: list[SeverityChange]

    @property
    def summary(self) -> dict[str, int]:
        return {
            "fixed": len(self.fixed),
            "still_failing": len(self.still_failing),
            "new_findings": len(self.new_findings),
            "severity_changed": len(self.severity_changed),
        }

    @property
    def has_regressions(self) -> bool:
        return bool(self.new_findings or self.severity_changed)


def load_scan_result(path: str | Path) -> ScanResult:
    """Load a Crucible JSON report from disk."""
    import json

    report_path = Path(path)
    data: Any = json.loads(report_path.read_text(encoding="utf-8"))
    return ScanResult.model_validate(data)


def compare_scan_results(before: ScanResult, after: ScanResult) -> ScanDiff:
    """Compare two Crucible scan reports by failing findings.

    Passed findings are intentionally ignored: the comparison answers what still
    needs attention after a fix, which findings were fixed, and whether new
    failing findings appeared.
    """

    before_findings = _failing_findings_by_key(before)
    after_findings = _failing_findings_by_key(after)

    fixed = [
        FindingChange(finding=finding, key=key)
        for key, finding in before_findings.items()
        if key not in after_findings
    ]
    still_failing = [
        FindingChange(finding=after_findings[key], key=key)
        for key in before_findings.keys() & after_findings.keys()
    ]
    new_findings = [
        FindingChange(finding=finding, key=key)
        for key, finding in after_findings.items()
        if key not in before_findings
    ]
    severity_changed = [
        SeverityChange(
            before=before_findings[key],
            after=after_findings[key],
            key=key,
        )
        for key in before_findings.keys() & after_findings.keys()
        if before_findings[key].severity != after_findings[key].severity
    ]

    return ScanDiff(
        before=before,
        after=after,
        fixed=sorted(fixed, key=lambda item: item.finding.title),
        still_failing=sorted(still_failing, key=lambda item: item.finding.title),
        new_findings=sorted(new_findings, key=lambda item: item.finding.title),
        severity_changed=sorted(severity_changed, key=lambda item: item.after.title),
    )


def _failing_findings_by_key(result: ScanResult) -> dict[str, Finding]:
    findings: dict[str, Finding] = {}
    seen_keys: Counter[str] = Counter()

    for module in result.modules:
        for finding in module.findings:
            if finding.passed:
                continue
            key = _finding_key(module.module_name, finding)
            seen_keys[key] += 1
            if seen_keys[key] > 1:
                key = f"{key}#{seen_keys[key]}"
            findings[key] = finding

    return findings


def _finding_key(module_name: str, finding: Finding) -> str:
    return "|".join(
        [
            module_name.strip().lower(),
            finding.category.value,
            finding.attack_name.strip().lower(),
            finding.title.strip().lower(),
        ]
    )


def format_terminal_summary(diff: ScanDiff) -> str:
    """Return a concise terminal-friendly summary for a scan diff."""
    lines = [
        "Crucible scan diff",
        f"Fixed: {len(diff.fixed)}",
        f"Still failing: {len(diff.still_failing)}",
        f"New findings: {len(diff.new_findings)}",
        f"Severity changes: {len(diff.severity_changed)}",
        "",
    ]
    lines.extend(_format_section("FIXED", diff.fixed, "✅"))
    lines.extend(_format_section("STILL FAILING", diff.still_failing, "🔴"))
    lines.extend(_format_section("NEW FINDINGS", diff.new_findings, "🆕"))
    if diff.severity_changed:
        lines.append("SEVERITY CHANGES")
        for change in diff.severity_changed:
            lines.append(
                "⚠️ "
                f"{change.after.title}: "
                f"{_severity_label(change.before.severity)} -> "
                f"{_severity_label(change.after.severity)}"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _format_section(
    title: str,
    changes: list[FindingChange],
    marker: str,
) -> list[str]:
    if not changes:
        return []
    lines = [title]
    for change in changes:
        finding = change.finding
        lines.append(f"{marker} {finding.title} ({_severity_label(finding.severity)})")
    lines.append("")
    return lines


def _severity_label(severity: Severity) -> str:
    return severity.value.upper()
