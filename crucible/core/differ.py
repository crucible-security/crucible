from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from crucible.models import (
    DiffResult,
    FindingDiff,
    FindingStatus,
    Grade,
    ModuleDiff,
)

if TYPE_CHECKING:
    from crucible.models import Finding, ScanResult


def compute_diff(scan_a: ScanResult, scan_b: ScanResult) -> DiffResult:
    """
    Compare two ScanResult objects and produce a DiffResult.
    """
    # 1. Determine warnings if scans are incomplete
    warning = None
    if scan_a.grade == Grade.INCOMPLETE and scan_b.grade == Grade.INCOMPLETE:
        warning = "Both scans are INCOMPLETE"
    elif scan_a.grade == Grade.INCOMPLETE:
        warning = "Scan A is INCOMPLETE"
    elif scan_b.grade == Grade.INCOMPLETE:
        warning = "Scan B is INCOMPLETE"

    # Map modules by name
    modules_a = {m.module_name: m for m in scan_a.modules}
    modules_b = {m.module_name: m for m in scan_b.modules}
    all_module_names = sorted(list(set(modules_a.keys()) | set(modules_b.keys())))

    module_diffs: list[ModuleDiff] = []
    total_fixed = 0
    total_regressed = 0
    total_new = 0
    total_unchanged_fail = 0

    for mod_name in all_module_names:
        mod_a = modules_a.get(mod_name)
        mod_b = modules_b.get(mod_name)

        score_a = mod_a.score if mod_a is not None else 0.0
        score_b = mod_b.score if mod_b is not None else 0.0

        # Group findings by attack_name within this module
        findings_by_attack_a: dict[str, list[Finding]] = {}
        if mod_a is not None:
            for f in mod_a.findings:
                findings_by_attack_a.setdefault(f.attack_name, []).append(f)

        findings_by_attack_b: dict[str, list[Finding]] = {}
        if mod_b is not None:
            for f in mod_b.findings:
                findings_by_attack_b.setdefault(f.attack_name, []).append(f)

        all_attacks = sorted(
            list(set(findings_by_attack_a.keys()) | set(findings_by_attack_b.keys()))
        )

        mod_findings_diff: list[FindingDiff] = []
        mod_fixed = 0
        mod_regressed = 0
        mod_new = 0

        for attack_id in all_attacks:
            findings_a = findings_by_attack_a.get(attack_id, [])
            findings_b = findings_by_attack_b.get(attack_id, [])

            # Get reference finding for metadata (severity, title, etc.)
            ref_f = findings_b[0] if findings_b else findings_a[0]

            # Aggregate state for Scan A
            state_a_exists = len(findings_a) > 0
            state_a_error = any(
                getattr(f, "execution_error", False) for f in findings_a
            )
            scan_a_passed = (
                None
                if state_a_error or not state_a_exists
                else all(f.passed is True for f in findings_a)
            )

            # Aggregate state for Scan B
            state_b_exists = len(findings_b) > 0
            state_b_error = any(
                getattr(f, "execution_error", False) for f in findings_b
            )
            scan_b_passed = (
                None
                if state_b_error or not state_b_exists
                else all(f.passed is True for f in findings_b)
            )

            # Status assignment rules
            if state_a_error or state_b_error:
                status = FindingStatus.EXECUTION_ERROR
            elif state_a_exists and state_b_exists:
                if scan_a_passed is False and scan_b_passed is True:
                    status = FindingStatus.FIXED
                elif scan_a_passed is True and scan_b_passed is False:
                    status = FindingStatus.REGRESSED
                elif scan_a_passed is False and scan_b_passed is False:
                    status = FindingStatus.UNCHANGED_FAIL
                else:
                    status = FindingStatus.UNCHANGED_PASS
            elif not state_a_exists and state_b_exists:
                if scan_b_passed is False:
                    status = FindingStatus.NEW
                else:
                    status = FindingStatus.RESOLVED
            else:  # state_a_exists and not state_b_exists
                if scan_a_passed is False:
                    status = FindingStatus.FIXED
                else:
                    status = FindingStatus.RESOLVED

            # Counters
            if status == FindingStatus.FIXED:
                mod_fixed += 1
                total_fixed += 1
            elif status == FindingStatus.REGRESSED:
                mod_regressed += 1
                total_regressed += 1
            elif status == FindingStatus.NEW:
                mod_new += 1
                total_new += 1
            elif status == FindingStatus.UNCHANGED_FAIL:
                total_unchanged_fail += 1

            finding_diff = FindingDiff(
                attack_id=attack_id,
                attack_name=ref_f.title or attack_id,
                status=status,
                severity=ref_f.severity,
                scan_a_passed=scan_a_passed,
                scan_b_passed=scan_b_passed,
                atlas_technique=getattr(ref_f, "atlas_technique", ""),
                nist_category=getattr(ref_f, "nist_category", ""),
                module=mod_name,
            )
            mod_findings_diff.append(finding_diff)

        module_diffs.append(
            ModuleDiff(
                module_name=mod_name,
                score_a=score_a,
                score_b=score_b,
                score_delta=round(score_b - score_a, 2),
                fixed_count=mod_fixed,
                regressed_count=mod_regressed,
                new_count=mod_new,
                findings=mod_findings_diff,
            )
        )

    # Global scores & grades
    score_a = scan_a.overall_score
    score_b = scan_b.overall_score
    score_delta = round(score_b - score_a, 2)

    return DiffResult(
        scan_a_path="",  # Filled by CLI caller
        scan_b_path="",  # Filled by CLI caller
        scan_a_version=scan_a.crucible_version or "0.0.0",
        scan_b_version=scan_b.crucible_version or "0.0.0",
        scan_a_timestamp=scan_a.started_at.isoformat() if scan_a.started_at else None,
        scan_b_timestamp=scan_b.started_at.isoformat() if scan_b.started_at else None,
        score_a=score_a,
        score_b=score_b,
        score_delta=score_delta,
        grade_a=scan_a.grade,
        grade_b=scan_b.grade,
        total_fixed=total_fixed,
        total_regressed=total_regressed,
        total_new=total_new,
        total_unchanged_fail=total_unchanged_fail,
        modules=module_diffs,
        generated_at=datetime.now(timezone.utc).isoformat(),
        warning=warning,
    )
