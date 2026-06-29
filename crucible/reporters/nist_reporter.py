from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from crucible.models import Finding, ScanResult

_FUNCTION_DESCRIPTIONS = {
    "GOVERN": "Policies, processes, roles, and responsibilities for AI risk management.",
    "MAP": "Context, categorization, and AI risk identification.",
    "MEASURE": "Analysis, assessment, and tracking of AI risks.",
    "MANAGE": "Allocation of resources to treat AI risks.",
}


class NISTReporter:
    """Generates a NIST AI RMF 1.0 coverage report from a ScanResult."""

    def to_markdown(self, result: ScanResult) -> str:
        lines = [
            "# NIST AI RMF 1.0 Compliance Report",
            f"**Target:** {result.target.name}",
            f"**Scan ID:** {result.id}",
            f"**Overall Score:** {result.overall_score:.1f} / Grade {result.grade.value}",
            "",
            "## Framework Overview",
            "This report maps Crucible findings to the "
            "[NIST AI Risk Management Framework 1.0](https://airc.nist.gov/RMF) "
            "across four core functions: GOVERN, MAP, MEASURE, and MANAGE.",
            "",
            "## Findings by NIST Function",
            "",
        ]

        failed = result.get_failed_findings()
        by_function: dict[str, list[Finding]] = defaultdict(list)
        for f in failed:
            fn = f.nist_function or "UNMAPPED"
            by_function[fn].append(f)

        for fn in ["GOVERN", "MAP", "MEASURE", "MANAGE", "UNMAPPED"]:
            findings_in_fn = by_function.get(fn, [])
            desc = _FUNCTION_DESCRIPTIONS.get(fn, "")
            status = "❌ NON-COMPLIANT" if findings_in_fn else "✅ COMPLIANT"
            lines += [
                f"### {fn} — {status}",
                f"*{desc}*" if desc else "",
                f"**Affected findings:** {len(findings_in_fn)}",
                "",
            ]
            if findings_in_fn:
                lines.append("| NIST Category | Finding | Severity |")
                lines.append("|---|---|---|")
                for f in findings_in_fn:
                    lines.append(
                        f"| {f.nist_category} | {f.title} | {f.severity.value.upper()} |"
                    )
                lines.append("")

        lines += [
            "## NIST AI RMF References",
            "- [NIST AI RMF 1.0](https://airc.nist.gov/RMF)",
            "- [NIST AI RMF Playbook](https://airc.nist.gov/Docs/2)",
        ]
        return "\n".join(lines)

    def to_html(self, result: ScanResult) -> str:
        md = self.to_markdown(result)
        escaped = md.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>NIST AI RMF Report — {result.target.name}</title>
  <style>
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a;
           color: #e2e8f0; padding: 2rem; max-width: 1100px; margin: 0 auto; }}
    pre {{ white-space: pre-wrap; }}
  </style>
</head>
<body><pre>{escaped}</pre></body>
</html>"""

    def write(self, result: ScanResult, output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.suffix == ".html":
            output_path.write_text(self.to_html(result), encoding="utf-8")
        else:
            output_path.write_text(self.to_markdown(result), encoding="utf-8")
        return output_path
