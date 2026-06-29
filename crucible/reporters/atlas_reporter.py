from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from crucible.models import ScanResult


class ATLASReporter:
    """Generates a MITRE ATLAS technique coverage report from a ScanResult."""

    def to_markdown(self, result: ScanResult) -> str:
        from crucible.attacks.base import ATLAS_TECHNIQUE_MAP

        lines = [
            "# MITRE ATLAS Technique Coverage Report",
            f"**Target:** {result.target.name}",
            f"**Scan ID:** {result.id}",
            f"**Overall Score:** {result.overall_score:.1f} / Grade {result.grade.value}",
            "",
            "## Atlas Framework",
            "This report maps Crucible findings to the "
            "[MITRE ATLAS](https://atlas.mitre.org) adversarial threat landscape framework "
            "for Artificial-Intelligence Systems (current as of 2026).",
            "",
            "## Triggered Techniques",
            "",
            "| ATLAS Technique | Tactic | Findings | Status |",
            "|---|---|---|---|",
        ]

        # Group failed findings by atlas_technique
        failed = result.get_failed_findings()
        by_technique: dict[str, list[str]] = defaultdict(list)
        tactic_for: dict[str, str] = {}
        for f in failed:
            if f.atlas_technique:
                by_technique[f.atlas_technique].append(f.title)
                tactic_for[f.atlas_technique] = f.atlas_tactic

        if by_technique:
            for tech, titles in sorted(by_technique.items()):
                tactic = tactic_for.get(tech, "")
                url = f"https://atlas.mitre.org/techniques/{tech}/"
                lines.append(
                    f"| [{tech}]({url}) | {tactic} | {len(titles)} failed | ❌ TRIGGERED |"
                )
        else:
            lines.append("| — | — | 0 | ✅ NONE TRIGGERED |")

        lines += [
            "",
            "## All Categories Tested",
            "",
            "| Attack Category | ATLAS Technique | ATLAS Tactic | URL |",
            "|---|---|---|---|",
        ]
        for cat, (tech, tactic) in ATLAS_TECHNIQUE_MAP.items():
            url = f"https://atlas.mitre.org/techniques/{tech}/"
            lines.append(f"| {cat.value} | {tech} | {tactic} | {url} |")

        return "\n".join(lines)

    def to_html(self, result: ScanResult) -> str:
        md = self.to_markdown(result)
        # Simple HTML wrapper around the markdown text
        escaped = md.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>MITRE ATLAS Report — {result.target.name}</title>
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
