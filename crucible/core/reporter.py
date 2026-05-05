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
            f.write("# Crucible Security Vulnerability Report\\n\\n")
            f.write(f"**Target:** `{result.target.url}`\\n")
            f.write(
                f"**Date Generated:** {datetime.datetime.now(datetime.timezone.utc).isoformat()}\\n"
            )
            f.write(f"**Total Vulnerabilities Found:** {len(vulnerabilities)}\\n\\n")
            f.write("---\\n\\n")

            for finding in vulnerabilities:
                f.write(f"## Vulnerability: {finding.attack_name}\\n\\n")
                f.write(f"**Category:** {finding.category.value.upper()}\\n")
                f.write(f"**Severity:** {finding.severity.value.upper()}\\n\\n")

                f.write("### Description\\n")
                # Fallback description if not provided in the finding
                f.write(
                    f"{finding.description or 'A security boundary violation was detected.'}\\n\\n"
                )

                f.write("### Proof of Concept (PoC)\\n")
                f.write("The following payload was sent to the target:\\n\\n")
                f.write("```text\\n")
                f.write(f"{finding.payload}\\n")
                f.write("```\\n\\n")

                f.write("### Target Response\\n")
                f.write(
                    "The target responded with the following, indicating successful exploitation:\\n\\n"
                )
                f.write("```text\\n")
                f.write(f"{finding.response_snippet}\\n")
                f.write("```\\n\\n")

                f.write("### Remediation\\n")
                f.write(
                    f"{finding.remediation or 'Please review the input validation and output encoding mechanisms.'}\\n\\n"
                )
                f.write("---\\n\\n")

        return str(report_path)
