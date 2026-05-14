from crucible.core.comparator import Comparator
from crucible.models import (
    AgentTarget,
    AttackCategory,
    Finding,
    ModuleResult,
    ScanResult,
    ScanStatus,
    Severity,
)


def create_mock_scan(id: str, findings_configs: list[dict]) -> ScanResult:
    target = AgentTarget(name="TestAgent", url="http://localhost:8080")

    findings = []
    for cfg in findings_configs:
        findings.append(
            Finding(
                attack_name=cfg["name"],
                category=AttackCategory.JAILBREAK,
                severity=cfg["severity"],
                title=f"Test Finding {cfg['name']}",
                payload="test payload",
                passed=cfg["passed"],
            )
        )

    module = ModuleResult(
        module_name="TestModule",
        category=AttackCategory.JAILBREAK,
        findings=findings,
        total_attacks=len(findings),
        passed=sum(1 for f in findings if f.passed),
        failed=sum(1 for f in findings if not f.passed),
    )

    return ScanResult(
        id=id, target=target, status=ScanStatus.COMPLETED, modules=[module]
    )


def test_comparator_logic():
    # Before scan: 2 failed findings
    before_cfg = [
        {"name": "ATTACK-1", "severity": Severity.CRITICAL, "passed": False},
        {"name": "ATTACK-2", "severity": Severity.HIGH, "passed": False},
    ]
    # After scan: ATTACK-1 fixed, ATTACK-2 still failing, NEW ATTACK-3 failing
    after_cfg = [
        {"name": "ATTACK-1", "severity": Severity.CRITICAL, "passed": True},
        {"name": "ATTACK-2", "severity": Severity.HIGH, "passed": False},
        {"name": "ATTACK-3", "severity": Severity.MEDIUM, "passed": False},
    ]

    before = create_mock_scan("before-id", before_cfg)
    after = create_mock_scan("after-id", after_cfg)

    comp = Comparator()
    diff = comp.compare(before, after)

    assert diff.fixed_count == 1  # ATTACK-1
    assert diff.remaining_count == 1  # ATTACK-2
    assert diff.new_count == 1  # ATTACK-3
    assert diff.regression_count == 0

    print("\n[Comparator Test] Passed logic checks.")


def test_regression_logic():
    # Before scan: Passed
    before_cfg = [{"name": "REG-1", "severity": Severity.CRITICAL, "passed": True}]
    # After scan: Failed
    after_cfg = [{"name": "REG-1", "severity": Severity.CRITICAL, "passed": False}]

    before = create_mock_scan("before-id", before_cfg)
    after = create_mock_scan("after-id", after_cfg)

    comp = Comparator()
    diff = comp.compare(before, after)

    assert diff.regression_count == 1
    assert diff.diffs[0].status == "REGRESSION"
    print("[Comparator Test] Passed regression check.")


def generate_sample_report():
    from crucible.reporters.diff_reporter import DiffReporter

    before_cfg = [
        {"name": "PI-001", "severity": Severity.CRITICAL, "passed": False},
        {"name": "GH-005", "severity": Severity.HIGH, "passed": False},
        {"name": "JB-012", "severity": Severity.MEDIUM, "passed": True},
    ]
    after_cfg = [
        {"name": "PI-001", "severity": Severity.CRITICAL, "passed": True},  # Fixed
        {"name": "GH-005", "severity": Severity.HIGH, "passed": False},  # Remaining
        {"name": "JB-012", "severity": Severity.MEDIUM, "passed": False},  # Regression
        {"name": "NEW-001", "severity": Severity.LOW, "passed": False},  # New
    ]

    before = create_mock_scan("v1", before_cfg)
    after = create_mock_scan("v2", after_cfg)

    comp = Comparator()
    diff = comp.compare(before, after)

    reporter = DiffReporter()
    report_path = reporter.write(diff, "tests/sample_diff.html")
    print(f"[Sample Report] Generated at: {report_path}")


if __name__ == "__main__":
    test_comparator_logic()
    test_regression_logic()
    generate_sample_report()
