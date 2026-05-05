"""Bug Bounty Report Generator.

Takes successful findings and automatically formats them into a Markdown
Proof of Concept (PoC) report suitable for submission to HackerOne or Bugcrowd.
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from crucible.models import ScanResult


class BugBountyReportGenerator:
    """Generates Markdown reports from scan results."""

    def __init__(self, output_dir: str | Path = ".") -> None:
        self.output_dir = Path(output_dir)

    def generate(self, result: ScanResult) -> str | None:
        """Generates a report if there are vulnerable findings.

        Returns the path to the generated report, or None if no vulnerabilities were found.
        """
        vulnerabilities = []
        if result.modules:
            for module in result.modules:
                vulnerabilities.extend([f for f in module.findings if not f.passed])

        if not vulnerabilities:
            return None

        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y%m%d_%H%M%S"
        )
        report_path = self.output_dir / f"crucible_bounty_report_{timestamp}.md"

        with open(report_path, "w", encoding="utf-8") as f:
            f.write("# Crucible Security Vulnerability Report\n\n")
            f.write("## Submission Summary\n")
            f.write(f"- **Target URL:** `{result.target.url}`\n")
            f.write(
                f"- **Date:** {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            )
            f.write(f"- **Total Findings:** {len(vulnerabilities)}\n")

            # Helper to calculate highest severity
            sev_order = ["low", "medium", "high", "critical"]
            highest_sev = "LOW"
            if vulnerabilities:
                highest_sev = max(
                    (v.severity.value for v in vulnerabilities),
                    key=lambda x: sev_order.index(x.lower()),
                ).upper()

            f.write(f"- **Highest Severity:** {highest_sev}\n\n")
            f.write("## Executive Summary\n")
            f.write(
                "A comprehensive security audit using the Crucible Agentic AI Security Framework has identified multiple high-impact vulnerabilities in the target system. These findings range from bypassable safety guardrails (Jailbreaks) to unauthorized goal manipulation (Goal Hijacking).\n\n"
            )
            f.write("---\n\n")

            for i, finding in enumerate(vulnerabilities, 1):
                f.write(
                    f"## [{i}] {finding.title or finding.attack_name} ({finding.attack_name})\n\n"
                )
                f.write(f"**Severity:** {finding.severity.value.upper()}\n")
                f.write(f"**Category:** {finding.category.value.upper()}\n")
                f.write(f"**OWASP Ref:** {finding.owasp_ref or 'N/A'}\n\n")

                f.write("### Impact\n")
                impact = (
                    finding.description
                    or "Exploitation allows for unauthorized state manipulation or data exfiltration from the AI agent context."
                )
                f.write(f"{impact}\n\n")

                f.write("### Proof of Concept (PoC)\n")
                f.write(
                    "Using the Crucible CLI, the following adversarial payload was delivered:\n\n"
                )
                f.write("```text\n")
                f.write(f"{finding.payload}\n")
                f.write("```\n\n")

                f.write("### Observed Response\n")
                f.write(
                    "The agent processed the payload and returned the following (indicating a successful bypass/hijack):\n\n"
                )
                f.write("```text\n")
                f.write(f"{finding.response_snippet}\n")
                f.write("```\n\n")

                f.write("### Remediation Recommendation\n")
                remediation = (
                    finding.remediation
                    or "Implement strict input validation and output sanitization. Enforce a robust instruction hierarchy to prevent goal hijacking."
                )
                f.write(f"{remediation}\n\n")
                f.write("---\n\n")

        return str(report_path)
