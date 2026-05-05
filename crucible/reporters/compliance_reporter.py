from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from crucible.models import ComplianceReport


class ComplianceReporter:

    def to_json(self, report: ComplianceReport) -> str:
        return report.model_dump_json(indent=2)

    def to_markdown(self, report: ComplianceReport) -> str:
        lines = [
            f"# Compliance Report: {report.standard}",
            f"**Target:** {report.target_name}",
            f"**Scan ID:** {report.scan_id}",
            f"**Overall Status:** {report.overall_status.value.upper()}",
            f"**Generated:** {report.generated_at.isoformat()}",
            "\n## Requirements\n",
        ]

        for req in report.requirements:
            icon = "✅" if req.status == "compliant" else "❌"
            lines.extend(
                [
                    f"### {icon} {req.article}",
                    f"**Risk Classification:** {req.risk_classification.value.upper()}",
                    f"**Description:** {req.description}",
                    f"**Status:** {req.status.value.upper()}",
                ]
            )
            if req.status == "non_compliant":
                lines.append(f"**Failed Findings:** {len(req.related_findings)}")
                lines.append(f"**Required Remediation:** {req.remediation}")
            lines.append("")

        return "\n".join(lines)

    def write(self, report: ComplianceReport, output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.suffix == ".json":
            output_path.write_text(self.to_json(report), encoding="utf-8")
        else:
            output_path.write_text(self.to_markdown(report), encoding="utf-8")
        return output_path
