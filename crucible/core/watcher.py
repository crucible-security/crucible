"""crucible/core/watcher.py — The crucible watch daemon.

Runs behavioral drift scans on a schedule, compares against a stored baseline,
and fires alerts when thresholds are crossed.

Architecture:
  - asyncio event loop (consistent with the rest of the codebase)
  - Scheduler: asyncio.sleep() in a loop — no external dependency
  - SIGINT / SIGTERM → graceful shutdown: complete current cycle, print summary

On each tick:
  1. Run a full security scan (same as `crucible scan`)
  2. Compare against the stored baseline using compute_diff()
  3. Check drift_threshold (behavioral) and score_threshold (numeric)
  4. If either threshold is crossed → fire WatchAlert
  5. Append a WatchCheckResult entry to ~/.crucible/watch_log.jsonl
"""

from __future__ import annotations

import asyncio
import contextlib
import signal
import sys
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import httpx
from rich.console import Console

from crucible.core.differ import compute_diff
from crucible.core.runner import run_scan
from crucible.core.watch_store import WATCH_LOG, WatchStore, append_watch_log
from crucible.models import (
    AgentTarget,
    ScanResult,
    WatchAlert,
    WatchCheckResult,
    WatchConfig,
)

if TYPE_CHECKING:
    from pathlib import Path

console = Console()


class CrucibleWatcher:
    """The core watch daemon.

    Runs behavioral drift scans on a schedule, compares against a stored
    baseline, and fires alerts when thresholds are crossed.
    """

    def __init__(self, config: WatchConfig, log_path: Path | None = None) -> None:
        self.config = config
        self.store = WatchStore()
        self.log_path = log_path or WATCH_LOG
        self._shutdown_event = asyncio.Event()
        self._current_cycle_task: asyncio.Task | None = None  # type: ignore[type-arg]

        # Session counters
        self._check_count = 0
        self._alert_count = 0
        self._last_score: float | None = None
        self._started_at = datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    async def run_one_check(self) -> WatchCheckResult:
        """Run a single check cycle: scan → diff → alert if threshold crossed.

        This is also called by `crucible watch check` for a one-shot run.
        """
        self._check_count += 1
        now = datetime.now(timezone.utc).isoformat()

        # 1. Load baseline
        baseline = self.store.load_baseline(str(self.config.target.url))
        if baseline is None:
            console.print(
                "[red]✗ No baseline found for this target.[/red]\n"
                "  Run [bold]crucible watch set-baseline[/bold] first."
            )
            raise RuntimeError(
                f"No baseline stored for {self.config.target.url}. "
                "Run 'crucible watch set-baseline' first."
            )

        # 2. Run a fresh scan
        console.print(
            f"\n[bold cyan]⟳ Watch cycle #{self._check_count}[/bold cyan] "
            f"— {now[:19]}Z"
        )
        current_result = await run_scan(
            self.config.target,
            quiet=True,
            skip_preflight=self.config.skip_preflight,
        )
        self._last_score = current_result.overall_score

        # 3. Diff current vs baseline
        diff = compute_diff(
            baseline.scan_result,
            current_result,
        )

        score_delta = diff.score_delta
        baseline_score = diff.score_a
        current_score = diff.score_b

        # 4. Determine if alert should fire
        alert: WatchAlert | None = None
        alert_fired = False

        score_dropped = score_delta < -self.config.score_threshold
        has_regressions = diff.total_regressed > 0

        if score_dropped or has_regressions:
            alert_fired = True
            self._alert_count += 1

            if score_dropped and diff.total_regressed > 0:
                alert_type = "score_drop_and_regression"
                severity = "CRITICAL"
            elif score_dropped:
                alert_type = "score_drop"
                severity = "CRITICAL" if abs(score_delta) >= 20 else "WARNING"
            else:
                alert_type = "regression"
                severity = "WARNING"

            alert = WatchAlert(
                fired_at=now,
                alert_type=alert_type,
                score_before=baseline_score,
                score_after=current_score,
                score_delta=score_delta,
                diff_result=diff,
                severity=severity,
                target_url=str(self.config.target.url),
            )
            self._print_alert(alert, diff)

            if self.config.alert_slack_webhook:
                await self._send_slack_alert(alert, diff)

        else:
            # Print status update
            delta_str = f"{score_delta:+.1f}" if score_delta != 0 else "±0.0"
            color = "green" if score_delta >= 0 else "yellow"
            console.print(
                f"  Score: {baseline_score:.1f} → {current_score:.1f} "
                f"([{color}]{delta_str}[/{color}])  "
                f"Fixed: {diff.total_fixed}  Regressed: {diff.total_regressed}  "
                f"New: {diff.total_new}  "
                f"[green]✓ Within threshold[/green]"
            )

        # 5. Write JSONL log entry
        check_result = WatchCheckResult(
            checked_at=now,
            target_url=str(self.config.target.url),
            cycle_number=self._check_count,
            baseline_score=baseline_score,
            current_score=current_score,
            score_delta=score_delta,
            alert_fired=alert_fired,
            alert=alert,
            regressed_count=diff.total_regressed,
            fixed_count=diff.total_fixed,
            new_count=diff.total_new,
        )

        append_watch_log(check_result.model_dump(), log_path=self.log_path)

        return check_result

    async def start(self) -> None:
        """Start the daemon loop. Runs until SIGINT/SIGTERM or shutdown event."""
        interval_secs = self.config.interval.to_seconds()
        console.print(
            f"\n[bold green]▶ crucible watch started[/bold green]\n"
            f"  Target  : [cyan]{self.config.target.url}[/cyan]\n"
            f"  Interval: {self.config.interval.value}  "
            f"({interval_secs}s)\n"
            f"  Score threshold : -{self.config.score_threshold} pts\n"
            f"  Slack alerts    : "
            f"{'[green]enabled[/green]' if self.config.alert_slack_webhook else '[dim]disabled[/dim]'}\n"
            f"\n[dim]Press Ctrl+C to stop.[/dim]"
        )

        # Register SIGINT / SIGTERM handlers (Windows-safe)
        loop = asyncio.get_running_loop()

        def _request_shutdown() -> None:
            console.print(
                "\n[yellow]⚠ Shutdown signal received. "
                "Completing current cycle before stopping...[/yellow]"
            )
            self._shutdown_event.set()

        try:
            loop.add_signal_handler(signal.SIGINT, _request_shutdown)
            loop.add_signal_handler(signal.SIGTERM, _request_shutdown)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler on all event loops
            # Fall back to KeyboardInterrupt handling in the outer try/except
            pass

        alert_fired_ever = False
        try:
            while not self._shutdown_event.is_set():
                check_result = await self.run_one_check()
                if check_result.alert_fired:
                    alert_fired_ever = True

                if self._shutdown_event.is_set():
                    break

                # Sleep until next interval, waking early on shutdown signal
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(
                        self._shutdown_event.wait(),
                        timeout=float(interval_secs),
                    )

        except KeyboardInterrupt:
            # Windows fallback
            console.print(
                "\n[yellow]⚠ KeyboardInterrupt. "
                "Stopping after current cycle...[/yellow]"
            )

        self._print_shutdown_summary()

        if self.config.fail_on_alert and alert_fired_ever:
            sys.exit(1)

    # ------------------------------------------------------------------ #
    # Private helpers                                                      #
    # ------------------------------------------------------------------ #

    def _print_alert(self, alert: WatchAlert, diff: object) -> None:
        """Render a rich alert block to the terminal."""
        from crucible.models import DiffResult

        severity_color = "red" if alert.severity == "CRITICAL" else "yellow"
        console.print(
            f"\n[bold {severity_color}]🚨 ALERT [{alert.severity}]: "
            f"{alert.alert_type.replace('_', ' ').title()}[/bold {severity_color}]"
        )
        console.print(
            f"  Score : {alert.score_before:.1f} → {alert.score_after:.1f} "
            f"([{severity_color}]{alert.score_delta:+.1f}[/{severity_color}])"
        )
        if isinstance(diff, DiffResult):
            console.print(
                f"  Regressions : {diff.total_regressed}  "
                f"Fixed : {diff.total_fixed}  "
                f"New : {diff.total_new}"
            )
            # Print top regressions
            regressions = [
                fd
                for md in diff.modules
                for fd in md.findings
                if fd.status.value == "regressed"
            ]
            if regressions:
                console.print("  [bold]Top regressions:[/bold]")
                for fd in regressions[:5]:
                    console.print(
                        f"    • [{severity_color}]{fd.attack_id}[/{severity_color}] "
                        f"{fd.attack_name} ({fd.severity.value.upper()})"
                    )

    async def _send_slack_alert(self, alert: WatchAlert, diff: object) -> None:
        """POST a Block Kit alert to the configured Slack webhook."""
        from crucible.models import DiffResult

        regressions_text = ""
        if isinstance(diff, DiffResult):
            regressions = [
                fd
                for md in diff.modules
                for fd in md.findings
                if fd.status.value == "regressed"
            ]
            if regressions:
                lines = [
                    f"• {fd.attack_id} {fd.attack_name} ({fd.severity.value.upper()})"
                    for fd in regressions[:5]
                ]
                regressions_text = "\n".join(lines)

        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"🚨 Crucible Watch Alert [{alert.severity}]",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Target:*\n{alert.target_url}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Alert Type:*\n{alert.alert_type.replace('_', ' ').title()}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": (
                                f"*Score:*\n{alert.score_before:.1f} → "
                                f"{alert.score_after:.1f} ({alert.score_delta:+.1f})"
                            ),
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Checked At:*\n{alert.fired_at[:19]}Z",
                        },
                    ],
                },
            ]
        }

        if regressions_text:
            payload["blocks"].append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Top regressions:*\n{regressions_text}",
                    },
                }
            )

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    self.config.alert_slack_webhook,  # type: ignore[arg-type]
                    json=payload,
                )
                if resp.status_code != 200:
                    console.print(
                        f"[yellow]⚠ Slack alert failed: HTTP {resp.status_code}[/yellow]"
                    )
        except Exception as exc:
            console.print(f"[yellow]⚠ Slack alert error: {exc}[/yellow]")

    def _print_shutdown_summary(self) -> None:
        """Print a summary of the completed watch session."""
        console.print(
            f"\n[bold green]✓ crucible watch stopped.[/bold green]\n"
            f"  Session started : {self._started_at[:19]}Z\n"
            f"  Checks run      : {self._check_count}\n"
            f"  Alerts fired    : {self._alert_count}\n"
            f"  Final score     : "
            f"{self._last_score:.1f}"
            if self._last_score is not None
            else "  Final score     : N/A"
        )
        if self._alert_count > 0:
            console.print(
                f"  [red]⚠ {self._alert_count} alert(s) fired during this session.[/red]"
            )
        console.print(f"  Log             : [dim]{self.log_path}[/dim]")


# ---------------------------------------------------------------------------
# One-shot set-baseline helper (used by CLI)
# ---------------------------------------------------------------------------


async def set_baseline(target: AgentTarget, skip_preflight: bool = False) -> str:
    """Run a full scan and store the result as the baseline.

    Returns the path to the baseline file that was created.
    """
    console.print(
        f"\n[bold cyan]⟳ Running baseline scan against {target.url}...[/bold cyan]"
    )
    result: ScanResult = await run_scan(
        target, quiet=True, skip_preflight=skip_preflight
    )

    store = WatchStore()
    baseline = store.save_baseline(str(target.url), result)
    path = store.baseline_path_for(str(target.url))

    console.print(
        f"[bold green]✓ Baseline saved[/bold green]\n"
        f"  Score   : {result.overall_score:.1f}\n"
        f"  Grade   : {result.grade.value if result.grade else 'N/A'}\n"
        f"  Created : {baseline.created_at[:19]}Z\n"
        f"  File    : [dim]{path}[/dim]"
    )
    return str(path)
