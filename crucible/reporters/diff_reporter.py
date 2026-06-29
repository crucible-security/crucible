from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from crucible.models import FindingStatus, Severity

if TYPE_CHECKING:
    from crucible.models import DiffResult, FindingDiff

ATLAS_NAMES = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0054": "Indirect Prompt Injection",
    "AML.T0051.000": "Direct Prompt Injection",
    "AML.T0048": "Erroneous ML Output",
    "AML.T0020": "Poison Training Data",
    "AML.T0043": "Craft Adversarial Data",
    "AML.T0037": "Data from ML Model",
    "AML.T0040": "ML Model Theft",
    "AML.T0029": "Denial of Service",
    "AML.T0010": "Supply Chain",
}

SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class DiffReporter:
    """Generates various diff report formats from a DiffResult."""

    def __init__(
        self,
        show_unchanged: bool = False,
        module_filter: str | None = None,
        min_severity: Severity | None = None,
    ) -> None:
        self.show_unchanged = show_unchanged
        self.module_filter = module_filter
        self.min_severity = min_severity

    def _should_include(self, f: FindingDiff) -> bool:
        # Module filter
        if self.module_filter and f.module != self.module_filter:
            return False

        # Severity filter
        if self.min_severity:
            f_sev_val = SEVERITY_ORDER.get(f.severity, 0)
            min_sev_val = SEVERITY_ORDER.get(self.min_severity, 0)
            if f_sev_val < min_sev_val:
                return False

        # Unchanged filter
        return not (
            not self.show_unchanged
            and f.status
            in (
                FindingStatus.UNCHANGED_PASS,
                FindingStatus.UNCHANGED_FAIL,
                FindingStatus.RESOLVED,
            )
        )

    def to_terminal(self, result: DiffResult) -> str:
        from rich.align import Align
        from rich.console import Console
        from rich.panel import Panel

        # Create a separate console to capture string output
        capture_console = Console(color_system="truecolor", width=80)
        with capture_console.capture() as capture:
            title_text = (
                f"CRUCIBLE SECURITY DIFF REPORT\n"
                f"{Path(result.scan_a_path).name}  →  {Path(result.scan_b_path).name}"
            )
            panel = Panel(
                title_text,
                style="bold magenta",
                expand=False,
            )
            capture_console.print(Align.center(panel))

            # Score delta formatting
            score_delta_str = f"{result.score_delta:+.1f}"
            if result.score_delta > 0:
                score_delta_str = f"[green]+{result.score_delta:.1f}[/green]"
            elif result.score_delta < 0:
                score_delta_str = f"[red]{result.score_delta:.1f}[/red]"

            capture_console.print(
                f"\n[bold]Score:[/bold]    {result.score_a:.1f} → {result.score_b:.1f}  ({score_delta_str} points)"
            )
            capture_console.print(
                f"[bold]Grade:[/bold]    {result.grade_a.value}    → {result.grade_b.value}"
            )

            if result.warning:
                capture_console.print(
                    f"\n[bold yellow]⚠️  WARNING: {result.warning}[/bold yellow]"
                )

            capture_console.print(
                f"\n[green]✅ FIXED      ({result.total_fixed} attacks now passing)[/green]"
            )
            capture_console.print(
                f"[red]🔴 REGRESSED  ({result.total_regressed} attacks now failing)[/red]"
            )
            capture_console.print(
                f"[yellow]🆕 NEW        ({result.total_new} new attack findings)[/yellow]"
            )
            capture_console.print("─" * 60)

            # Module breakdown
            for mod in result.modules:
                if self.module_filter and mod.module_name != self.module_filter:
                    continue

                filtered_findings = [f for f in mod.findings if self._should_include(f)]
                if not filtered_findings and not self.show_unchanged:
                    continue

                score_delta_mod_str = f"{mod.score_delta:+.1f}"
                if mod.score_delta > 0:
                    score_delta_mod_str = f"[green]+{mod.score_delta:.1f}[/green]"
                elif mod.score_delta < 0:
                    score_delta_mod_str = f"[red]{mod.score_delta:.1f}[/red]"

                capture_console.print(
                    f"\n[bold cyan]MODULE: {mod.module_name}[/bold cyan]  ({mod.score_a:.1f} → {mod.score_b:.1f}, {score_delta_mod_str})"
                )

                for f in filtered_findings:
                    if f.status == FindingStatus.FIXED:
                        status_symbol = "[green]✅ FIXED[/green]"
                    elif f.status == FindingStatus.REGRESSED:
                        status_symbol = "[red]🔴 REGRESSED[/red]"
                    elif f.status == FindingStatus.NEW:
                        status_symbol = "[yellow]🆕 NEW[/yellow]"
                    elif f.status == FindingStatus.EXECUTION_ERROR:
                        status_symbol = "[bold yellow]⚠️ ERROR[/bold yellow]"
                    elif f.status == FindingStatus.UNCHANGED_FAIL:
                        status_symbol = "[red]❌ UNCHANGED[/red]"
                    elif f.status == FindingStatus.UNCHANGED_PASS:
                        status_symbol = "[green]✔ UNCHANGED[/green]"
                    else:
                        status_symbol = f"[dim]{f.status.value.upper()}[/dim]"

                    capture_console.print(
                        f"  {status_symbol:<15} {f.attack_id:<8} {f.attack_name} [{f.severity.value.upper()}]"
                    )

            capture_console.print("─" * 60)

            # ATLAS mapping of regressions
            regressions = [
                f
                for mod in result.modules
                for f in mod.findings
                if f.status == FindingStatus.REGRESSED
            ]
            if regressions:
                capture_console.print(
                    "[bold]ATLAS TECHNIQUES TRIGGERED IN REGRESSION:[/bold]"
                )
                atlas_counts: dict[str, int] = {}
                for r in regressions:
                    if r.atlas_technique:
                        atlas_counts[r.atlas_technique] = (
                            atlas_counts.get(r.atlas_technique, 0) + 1
                        )
                for tech, count in sorted(atlas_counts.items()):
                    name = ATLAS_NAMES.get(tech, "Unknown Technique")
                    suffix_s = "regression" if count == 1 else "regressions"
                    capture_console.print(f"  {tech} — {name} ({count} {suffix_s})")
                capture_console.print()

            # NIST functions affected
            # Count fixed/regressed per NIST function
            nist_stats: dict[str, dict[str, int]] = {}
            for mod in result.modules:
                for f in mod.findings:
                    if not f.nist_category:
                        continue
                    fn = f.nist_category.split()[0]
                    nist_stats.setdefault(fn, {"fixed": 0, "regressed": 0})
                    if f.status == FindingStatus.FIXED:
                        nist_stats[fn]["fixed"] += 1
                    elif f.status == FindingStatus.REGRESSED:
                        nist_stats[fn]["regressed"] += 1

            # Only print if there's any stats
            has_nist = any(
                stats["fixed"] > 0 or stats["regressed"] > 0
                for stats in nist_stats.values()
            )
            if has_nist:
                capture_console.print("[bold]NIST FUNCTIONS AFFECTED:[/bold]")
                for fn in sorted(nist_stats.keys()):
                    stats = nist_stats[fn]
                    if stats["fixed"] > 0 or stats["regressed"] > 0:
                        parts = []
                        if stats["fixed"] > 0:
                            parts.append(f"{stats['fixed']} fixed")
                        if stats["regressed"] > 0:
                            parts.append(f"{stats['regressed']} regressed")
                        capture_console.print(f"  {fn:<8} ({', '.join(parts)})")

        return capture.get()

    def to_json(self, result: DiffResult) -> str:
        # Serializes the DiffResult to JSON
        return result.model_dump_json(indent=2)

    def to_markdown(self, result: DiffResult) -> str:
        # Grade trend indicator
        trend = "→"
        if (
            result.grade_b > result.grade_a
        ):  # Note: Grade Enum ordering is A < B < C < D < F
            trend = "↓"  # Worsened
        elif result.grade_b < result.grade_a:
            trend = "↑"  # Improved

        lines = [
            "## 🔒 Crucible Security Diff",
            "",
            "| Metric | Before | After | Delta |",
            "|---|---|---|---|",
            f"| Score | {result.score_a:.1f} | {result.score_b:.1f} | {result.score_delta:+.1f} |",
            f"| Grade | {result.grade_a.value} | {result.grade_b.value} | {trend} |",
            "",
        ]

        if result.warning:
            lines.append(f"⚠️  **Warning:** {result.warning}\n")

        # Collect FIXED findings
        fixed_findings = []
        regressed_findings = []
        new_findings = []

        for mod in result.modules:
            for f in mod.findings:
                if f.status == FindingStatus.FIXED:
                    fixed_findings.append(f)
                elif f.status == FindingStatus.REGRESSED:
                    regressed_findings.append(f)
                elif f.status == FindingStatus.NEW:
                    new_findings.append(f)

        if fixed_findings:
            lines.append(f"### ✅ Fixed ({len(fixed_findings)})")
            for f in fixed_findings:
                lines.append(
                    f"- {f.attack_id} {f.attack_name} ({f.severity.value.upper()})"
                )
            lines.append("")

        if regressed_findings:
            lines.append(f"### 🔴 Regressed ({len(regressed_findings)}) ⚠️")
            for f in regressed_findings:
                lines.append(
                    f"- {f.attack_id} {f.attack_name} ({f.severity.value.upper()})"
                )
            lines.append("")

        if new_findings:
            lines.append(f"### 🆕 New Findings ({len(new_findings)})")
            for f in new_findings:
                lines.append(
                    f"- {f.attack_id} {f.attack_name} ({f.severity.value.upper()})"
                )
            lines.append("")

        return "\n".join(lines)

    def to_html(self, result: DiffResult) -> str:
        # Visual HTML side-by-side report
        grade_trend_indicator = "→"
        if result.grade_b > result.grade_a:
            grade_trend_indicator = "↓"
        elif result.grade_b < result.grade_a:
            grade_trend_indicator = "↑"

        score_color = "#34d399" if result.score_delta >= 0 else "#f87171"

        # Generate findings table rows
        rows = []
        for mod in result.modules:
            for f in mod.findings:
                if not self._should_include(f):
                    continue

                if f.status == FindingStatus.FIXED:
                    status_class = "status-fixed"
                    status_text = "FIXED"
                elif f.status == FindingStatus.REGRESSED:
                    status_class = "status-regressed"
                    status_text = "REGRESSED"
                elif f.status == FindingStatus.NEW:
                    status_class = "status-new"
                    status_text = "NEW"
                elif f.status == FindingStatus.UNCHANGED_FAIL:
                    status_class = "status-fail"
                    status_text = "UNCHANGED FAIL"
                elif f.status == FindingStatus.UNCHANGED_PASS:
                    status_class = "status-pass"
                    status_text = "UNCHANGED PASS"
                else:
                    status_class = "status-info"
                    status_text = f.status.value.upper()

                atlas = f.atlas_technique or "—"
                nist = f.nist_category or "—"

                rows.append(
                    f"""
            <tr>
              <td><strong>{mod.module_name}</strong></td>
              <td><code>{f.attack_id}</code></td>
              <td>{f.attack_name}</td>
              <td><span class="status-badge {status_class}">{status_text}</span></td>
              <td>{f.severity.value.upper()}</td>
              <td>{atlas}</td>
              <td>{nist}</td>
            </tr>"""
                )

        table_body = (
            "".join(rows)
            if rows
            else "<tr><td colspan='7' style='text-align:center;'>No matching findings to display</td></tr>"
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Crucible Security Diff Report</title>
  <style>
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; max-width: 1200px; margin: 0 auto; }}
    h1 {{ font-size: 2rem; margin-bottom: 0.5rem; }}
    .meta {{ font-size: 0.9rem; color: #64748b; margin-bottom: 2rem; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
    .card {{ background: #1e293b; border-radius: 0.75rem; padding: 1.25rem; border: 1px solid #334155; }}
    .card .label {{ font-size: 0.75rem; color: #64748b; text-transform: uppercase; margin-bottom: 0.5rem; }}
    .card .value {{ font-size: 1.75rem; font-weight: 700; }}
    .status-badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }}
    .status-fixed {{ background: #064e3b; color: #6ee7b7; }}
    .status-regressed {{ background: #7f1d1d; color: #fca5a5; }}
    .status-new {{ background: #78350f; color: #fde047; }}
    .status-fail {{ background: #450a0a; color: #fca5a5; }}
    .status-pass {{ background: #14532d; color: #86efac; }}
    .status-info {{ background: #1e293b; color: #94a3b8; }}
    table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 0.75rem; overflow: hidden; border: 1px solid #334155; margin-top: 1.5rem; }}
    th {{ background: #0f172a; text-align: left; padding: 0.75rem 1rem; font-size: 0.75rem; text-transform: uppercase; color: #64748b; border-bottom: 1px solid #334155; }}
    td {{ padding: 0.75rem 1rem; border-bottom: 1px solid #1e293b; font-size: 0.875rem; }}
    tr:hover td {{ background: #263348; }}
    .warning-banner {{ background: #78350f; color: #fde047; padding: 1rem; border-radius: 0.5rem; margin-bottom: 1.5rem; border: 1px solid #d97706; font-weight: 600; }}
  </style>
</head>
<body>
  <h1>Crucible Security Diff Report</h1>
  <div class="meta">Generated at {result.generated_at} UTC</div>

  {f'<div class="warning-banner">⚠️ WARNING: {result.warning}</div>' if result.warning else ''}

  <div class="summary-grid">
    <div class="card">
      <div class="label">Score Change</div>
      <div class="value" style="color: {score_color};">{result.score_a:.1f} &rarr; {result.score_b:.1f} ({result.score_delta:+.1f})</div>
    </div>
    <div class="card">
      <div class="label">Grade Change</div>
      <div class="value">{result.grade_a.value} &rarr; {result.grade_b.value} ({grade_trend_indicator})</div>
    </div>
    <div class="card">
      <div class="label">Fixed</div>
      <div class="value" style="color: #34d399;">{result.total_fixed}</div>
    </div>
    <div class="card">
      <div class="label">Regressed</div>
      <div class="value" style="color: #f87171;">{result.total_regressed}</div>
    </div>
    <div class="card">
      <div class="label">New Findings</div>
      <div class="value" style="color: #fbbf24;">{result.total_new}</div>
    </div>
  </div>

  <h2>Findings Diff</h2>
  <table>
    <thead>
      <tr>
        <th>Module</th>
        <th>Attack ID</th>
        <th>Attack Name</th>
        <th>Status</th>
        <th>Severity</th>
        <th>ATLAS</th>
        <th>NIST</th>
      </tr>
    </thead>
    <tbody>
      {table_body}
    </tbody>
  </table>
</body>
</html>"""

    def write(self, result: DiffResult, path: str | Path, format: str) -> Path:
        output_path = Path(path).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format == "json":
            content = self.to_json(result)
        elif format == "html":
            content = self.to_html(result)
        elif format == "markdown":
            content = self.to_markdown(result)
        else:
            content = self.to_terminal(result)

        output_path.write_text(content, encoding="utf-8")
        return output_path
