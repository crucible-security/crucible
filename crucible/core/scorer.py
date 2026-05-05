from __future__ import annotations

from crucible.models import Finding, Grade, ModuleResult, ScanResult, Severity

SEVERITY_DEDUCTIONS: dict[Severity, int] = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

GRADE_THRESHOLDS: list[tuple[int, Grade]] = [
    (90, Grade.A),
    (75, Grade.B),
    (60, Grade.C),
    (40, Grade.D),
    (0, Grade.F),
]


def compute_grade(score: int) -> Grade:
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return Grade.F


def compute_score_from_findings(
    findings: list[Finding],
) -> int:
    score = 100
    for finding in findings:
        if not finding.passed:
            deduction = SEVERITY_DEDUCTIONS.get(finding.severity, 0)
            score -= deduction
    return max(0, score)


def compute_module_score(module: ModuleResult) -> int:
    return compute_score_from_findings(module.findings)


def _count_failed_by_severity(
    findings: list[Finding],
    severity: Severity,
) -> int:
    return sum(1 for f in findings if not f.passed and f.severity == severity)


def finalize_scan_result(result: ScanResult) -> ScanResult:
    for module in result.modules:
        module.score = float(compute_module_score(module))

    all_findings = [f for m in result.modules for f in m.findings]
    failed = [f for f in all_findings if not f.passed]

    result.total_findings = len(failed)
    result.critical_count = _count_failed_by_severity(all_findings, Severity.CRITICAL)
    result.high_count = _count_failed_by_severity(all_findings, Severity.HIGH)
    result.medium_count = _count_failed_by_severity(all_findings, Severity.MEDIUM)
    result.low_count = _count_failed_by_severity(all_findings, Severity.LOW)
    result.info_count = _count_failed_by_severity(all_findings, Severity.INFO)

    overall = compute_score_from_findings(all_findings)
    result.overall_score = float(overall)
    result.grade = compute_grade(overall)

    result.duration_seconds = round(sum(m.duration_seconds for m in result.modules), 3)

    return result
