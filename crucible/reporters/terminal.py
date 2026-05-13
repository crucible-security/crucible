from __future__ import annotations

from typing import Any

from rich.columns import Columns
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from crucible.models import Grade, ScanResult, Severity
from crucible.reporters.base import BaseReporter

SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "yellow",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

GRADE_COLORS: dict[Grade, str] = {
    Grade.A: "green",
    Grade.B: "blue",
    Grade.C: "yellow",
    Grade.D: "yellow",
    Grade.F: "bold red",
}

GRADE_LABELS: dict[Grade, str] = {
    Grade.A: "[A] EXCELLENT",
    Grade.B: "[B] GOOD",
    Grade.C: "[C] MODERATE",
    Grade.D: "[D] WEAK",
    Grade.F: "[F] CRITICAL",
}


class TerminalReporter(BaseReporter):

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def render(self, result: ScanResult) -> None:
        self._render_header(result)
        if result.is_dry_run:
            self._render_dry_run_summary(result)
            return

        self._render_score_panel(result)
        self._render_module_results(result)
        self._render_findings_table(result)
        self._render_summary(result)
        self._render_footer(result)

    def _render_header(self, result: ScanResult) -> None:
        banner = Text()
        banner.append("CRUCIBLE SECURITY SCAN", style="bold magenta")

        self.console.print()
        self.console.print(
            Panel(
                banner,
                border_style="magenta",
                padding=(1, 2),
                subtitle=f"v{result.crucible_version}",
            )
        )
        self.console.print()

        if result.is_dry_run:
            self.console.print(
                Panel(
                    "[bold yellow][!] DRY RUN MODE ENABLED[/bold yellow]\n"
                    "[dim]No actual requests were sent to the target agent.[/dim]",
                    border_style="yellow",
                    padding=(1, 2),
                )
            )
            self.console.print()

        info = Table(show_header=False, box=None, padding=(0, 2))
        info.add_column("Key", style="dim")
        info.add_column("Value", style="bold")
        info.add_row("Target", result.target.name)
        info.add_row("URL", str(result.target.url))
        info.add_row("Scan ID", result.id[:12])
        info.add_row("Duration", f"{result.duration_seconds:.1f}s")
        info.add_row("Status", result.status.value.upper())
        self.console.print(info)
        self.console.print()

    def _render_dry_run_summary(self, result: ScanResult) -> None:
        module_count = result.metadata.get("module_count", len(result.modules))
        module_names = result.metadata.get(
            "module_names", [module.module_name for module in result.modules]
        )
        payload_count = result.metadata.get(
            "payload_count", sum(module.total_attacks for module in result.modules)
        )
        request_rate = result.metadata.get("request_rate_per_second")
        duration = result.metadata.get("estimated_duration_seconds", 0.0)
        duration_label = f"{float(duration):.1f}s"
        if request_rate:
            duration_label = f"{duration_label} at {float(request_rate):g} req/sec"

        summary = Table(show_header=False, box=None, padding=(0, 2))
        summary.add_column("Key", style="dim")
        summary.add_column("Value", style="bold")
        summary.add_row("Target URL", str(result.target.url))
        summary.add_row("Modules", f"{module_count} ({', '.join(module_names)})")
        summary.add_row("Total attacks", str(payload_count))
        summary.add_row("Estimated duration", duration_label)
        summary.add_row(
            "Rate limit cost", f"{result.metadata.get('rate_limit_cost', payload_count)} requests"
        )
        summary.add_row("Network", "No requests sent")

        self.console.print(
            Panel(
                summary,
                title="[bold yellow]Dry Run Preview[/bold yellow]",
                border_style="yellow",
                padding=(1, 2),
            )
        )
        self.console.print()

        preview_payloads = result.metadata.get("preview_payloads", [])
        if preview_payloads:
            table = Table(
                title="First 3 Payloads",
                title_style="bold",
                border_style="cyan",
                show_lines=True,
            )
            table.add_column("Module", style="cyan", no_wrap=True)
            table.add_column("Attack", style="dim")
            table.add_column("Payload", overflow="fold")

            for item in preview_payloads[:3]:
                if isinstance(item, dict):
                    table.add_row(
                        escape(str(item.get("module", ""))),
                        escape(str(item.get("attack", ""))),
                        escape(str(item.get("payload", ""))),
                    )

            self.console.print(table)
            self.console.print()

        self.console.print(
            Panel(
                "[green]Dry run complete. No network requests were sent.[/green]",
                border_style="green",
            )
        )
        self.console.print()

    def _render_score_panel(self, result: ScanResult) -> None:
        grade_color = GRADE_COLORS.get(result.grade, "white")
        grade_label = GRADE_LABELS.get(result.grade, result.grade.value)

        score_text = Text()
        score_text.append("\n  Grade: ", style="bold")
        score_text.append(grade_label, style=grade_color)
        score_text.append("   Score: ", style="bold")
        score_text.append(f"{result.overall_score:.0f}", style=grade_color)
        score_text.append("/100\n", style="dim")

        bar_width = 40
        filled = int(result.overall_score / 100 * bar_width)
        bar = "#" * filled + "-" * (bar_width - filled)
        score_text.append(
            f"\n  [{bar}] {result.overall_score:.0f}%\n",
            style=grade_color,
        )

        border = grade_color.replace("bold ", "")
        self.console.print(
            Panel(
                score_text,
                title="[bold]Security Score[/bold]",
                border_style=border,
                padding=(0, 1),
            )
        )
        self.console.print()

    def _render_module_results(self, result: ScanResult) -> None:
        table = Table(
            title="Module Results",
            title_style="bold",
            border_style="blue",
            show_lines=True,
        )
        table.add_column("Module", style="cyan", no_wrap=True)
        table.add_column("Category", style="dim")
        table.add_column("Attacks", justify="right")
        table.add_column("Passed", justify="right", style="green")
        table.add_column("Failed", justify="right", style="red")
        table.add_column("Score", justify="right")
        table.add_column("Duration", justify="right", style="dim")

        for mod in result.modules:
            sc = (
                "green" if mod.score >= 80 else ("yellow" if mod.score >= 50 else "red")
            )
            table.add_row(
                mod.module_name,
                mod.category.value,
                str(mod.total_attacks),
                str(mod.passed),
                str(mod.failed),
                f"[{sc}]{mod.score:.0f}[/{sc}]",
                f"{mod.duration_seconds:.1f}s",
            )

        self.console.print(table)
        self.console.print()

    def _render_findings_table(self, result: ScanResult) -> None:
        failed = [f for m in result.modules for f in m.findings if not f.passed]

        if not failed:
            self.console.print(
                Panel(
                    "[green]No vulnerabilities detected![/green]",
                    border_style="green",
                )
            )
            self.console.print()
            return

        table = Table(
            title=f"Vulnerabilities ({len(failed)})",
            title_style="bold red",
            border_style="red",
            show_lines=True,
        )
        table.add_column("Attack", style="cyan", width=30)
        table.add_column("Severity", width=10)
        table.add_column("Status", width=8)
        table.add_column("Finding", width=40)

        for f in failed[:50]:
            sev_color = SEVERITY_COLORS.get(f.severity, "white")
            snippet = f.response_snippet[:80].replace("\n", " ")
            table.add_row(
                escape(f.title),
                f"[{sev_color}]{f.severity.value.upper()}[/{sev_color}]",
                "[red]FAILED[/red]",
                escape(snippet) or "[dim]---[/dim]",
            )

        self.console.print(table)
        self.console.print()

    def _render_summary(self, result: ScanResult) -> None:
        panels: list[Any] = [
            Panel(
                f"[bold red]{result.critical_count}[/bold red]",
                title="CRITICAL",
                border_style="red",
                width=14,
            ),
            Panel(
                f"[yellow]{result.high_count}[/yellow]",
                title="HIGH",
                border_style="yellow",
                width=14,
            ),
            Panel(
                f"[yellow]{result.medium_count}[/yellow]",
                title="MEDIUM",
                border_style="yellow",
                width=14,
            ),
            Panel(
                f"[blue]{result.low_count}[/blue]",
                title="LOW",
                border_style="blue",
                width=14,
            ),
        ]

        self.console.print(
            Panel(
                Columns(panels, equal=True, expand=True),
                title="[bold]Severity Breakdown[/bold]",
                border_style="blue",
            )
        )
        self.console.print()

    def _render_footer(self, result: ScanResult) -> None:
        grade = result.grade
        recommendations = self._get_recommendations(result)

        rec_text = "\n".join(f"  -> {r}" for r in recommendations)
        if not rec_text:
            rec_text = "  No critical recommendations."

        if grade == Grade.A:
            msg = f"[green]{rec_text}[/green]"
        elif grade == Grade.B:
            msg = f"[blue]{rec_text}[/blue]"
        elif grade == Grade.C:
            msg = f"[yellow]{rec_text}[/yellow]"
        else:
            msg = f"[red]{rec_text}[/red]"

        self.console.print(
            Panel(
                msg,
                title="[bold]Recommendations[/bold]",
                border_style="magenta",
            )
        )
        self.console.print(
            Text(
                "  Powered by Crucible" " -- github.com/crucible-security/crucible\n",
                style="dim",
            ),
        )
        self.console.print(
            Panel(
                Text.from_markup(
                    "  [bold]* Need persistent dashboards & compliance reports?[/bold]\n"
                    "  [dim cyan]-> https://crucible-cloud.vercel.app[/dim cyan]"
                ),
                border_style="dim",
                padding=(0, 1),
            )
        )

    def _get_recommendations(self, result: ScanResult) -> list[str]:
        recs: list[str] = []
        if result.critical_count > 0:
            recs.append("Fix prompt injection via input sanitization")
        if result.high_count > 0:
            recs.append("Add goal integrity checks to agent loop")
        if result.medium_count > 0:
            recs.append("Review and harden output filtering")
        if not recs:
            recs.append("Excellent posture! Continue monitoring.")
        return recs
