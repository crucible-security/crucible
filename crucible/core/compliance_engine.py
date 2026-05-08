from __future__ import annotations

from crucible.models import (
    AttackCategory,
    ComplianceReport,
    ComplianceRequirement,
    ComplianceStatus,
    RiskClassification,
    ScanResult,
)


class ComplianceEngine:
    def __init__(self, scan_result: ScanResult) -> None:
        self.scan_result = scan_result

    def _map_to_eu_ai_act(self) -> list[ComplianceRequirement]:
        requirements = [
            ComplianceRequirement(
                article="Article 15: Accuracy, robustness and cybersecurity",
                description="High-risk AI systems shall be designed to achieve an appropriate level of accuracy, robustness and cybersecurity, and perform consistently.",
                risk_classification=RiskClassification.HIGH,
                status=ComplianceStatus.COMPLIANT,
            ),
            ComplianceRequirement(
                article="Article 10: Data and data governance",
                description="High-risk AI systems must have appropriate data governance and management practices.",
                risk_classification=RiskClassification.HIGH,
                status=ComplianceStatus.COMPLIANT,
            ),
            ComplianceRequirement(
                article="Article 14: Human oversight",
                description="High-risk AI systems shall be designed so they can be effectively overseen by natural persons.",
                risk_classification=RiskClassification.HIGH,
                status=ComplianceStatus.COMPLIANT,
            ),
            ComplianceRequirement(
                article="Article 50: Transparency obligations",
                description="Providers must ensure AI systems interacting with persons are designed and developed in such a way that persons are informed they are interacting with an AI system.",
                risk_classification=RiskClassification.LIMITED,
                status=ComplianceStatus.COMPLIANT,
            ),
        ]

        # Map findings to articles
        for module in self.scan_result.modules:
            for finding in module.findings:
                if not finding.passed:
                    cat = finding.category
                    if cat in [
                        AttackCategory.PROMPT_INJECTION,
                        AttackCategory.JAILBREAK,
                        AttackCategory.GOAL_HIJACKING,
                    ]:
                        requirements[0].status = ComplianceStatus.NON_COMPLIANT
                        requirements[0].related_findings.append(finding.id)
                        requirements[0].remediation = (
                            "Implement robust prompt guardrails and behavioral monitoring."
                        )
                    elif cat in [
                        AttackCategory.TRAINING_DATA_POISONING,
                        AttackCategory.SENSITIVE_DISCLOSURE,
                    ]:
                        requirements[1].status = ComplianceStatus.NON_COMPLIANT
                        requirements[1].related_findings.append(finding.id)
                        requirements[1].remediation = (
                            "Implement strict data boundaries and access controls for the knowledge base."
                        )
                    elif cat in [
                        AttackCategory.EXCESSIVE_AGENCY,
                        AttackCategory.INSECURE_PLUGIN,
                    ]:
                        requirements[2].status = ComplianceStatus.NON_COMPLIANT
                        requirements[2].related_findings.append(finding.id)
                        requirements[2].remediation = (
                            "Require human-in-the-loop for all state-mutating plugin actions."
                        )

        return requirements

    def generate_report(self) -> ComplianceReport:
        requirements = self._map_to_eu_ai_act()

        overall = ComplianceStatus.COMPLIANT
        if any(req.status == ComplianceStatus.NON_COMPLIANT for req in requirements):
            overall = ComplianceStatus.NON_COMPLIANT

        return ComplianceReport(
            scan_id=self.scan_result.id,
            target_name=self.scan_result.target.name,
            standard="EU AI Act 2024",
            requirements=requirements,
            overall_status=overall,
        )
