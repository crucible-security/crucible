from __future__ import annotations

import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock
from typing import TYPE_CHECKING, Any

import anyio
import httpx
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TaskID,
    TextColumn,
    TimeRemainingColumn,
)

from crucible.core.scorer import finalize_scan_result
from crucible.models import AgentTarget, Finding, ModuleResult, ScanResult, ScanStatus
from crucible.modules.security import get_all_modules

if TYPE_CHECKING:
    from collections.abc import Iterator

    from crucible.modules.base import BaseModule

# Thread-safe append for concurrent module results
_results_lock = Lock()


@dataclass
class _NoopProgress:
    """Duck-typed stub so call sites don't need to branch on quiet mode."""

    def add_task(self, *_: Any, **__: Any) -> TaskID:
        return TaskID(0)

    def update(self, *_: Any, **__: Any) -> None:
        pass

    def advance(self, *_: Any, **__: Any) -> None:
        pass


@contextmanager
def _noop_progress() -> Iterator[_NoopProgress]:
    yield _NoopProgress()


def _module_payload_count(module: BaseModule) -> int:
    return sum(len(attack.get_payloads()) for attack in module.get_attacks())


def _build_dry_run_preview(
    target: AgentTarget,
    modules: list[BaseModule],
    concurrency: int,
    preview_limit: int = 3,
) -> dict[str, Any]:
    preview_payloads: list[dict[str, str]] = []
    payload_count = 0

    for module in modules:
        for attack in module.get_attacks():
            payloads = attack.get_payloads()
            payload_count += len(payloads)
            for payload in payloads:
                if len(preview_payloads) >= preview_limit:
                    continue
                preview_payloads.append(
                    {
                        "module": module.name,
                        "attack": attack.name,
                        "payload": payload,
                    }
                )

    delay_seconds = target.delay_ms / 1000
    request_rate = round(concurrency / delay_seconds, 2) if delay_seconds > 0 else None
    estimated_duration = (
        round(payload_count / request_rate, 2) if request_rate and payload_count else 0.0
    )

    return {
        "dry_run": True,
        "target_url": str(target.url),
        "module_count": len(modules),
        "module_names": [module.name for module in modules],
        "payload_count": payload_count,
        "estimated_duration_seconds": estimated_duration,
        "request_rate_per_second": request_rate,
        "rate_limit_cost": payload_count,
        "preview_payloads": preview_payloads,
    }


async def run_module_with_progress(
    module: BaseModule,
    target: AgentTarget,
    client: httpx.AsyncClient,
    module_results: list[ModuleResult],
    progress: Progress | _NoopProgress,
    task_id: TaskID,
    verbose: bool,
    verbose_console: Console,
    mutate: bool = False,
    dry_run: bool = False,
) -> None:
    progress.update(
        task_id, description=f"Running [bold cyan]{module.name}[/bold cyan]"
    )

    def on_finding(finding: Finding) -> None:
        if not verbose:
            return

        result_str = "PASS (refused)" if finding.passed else "FAIL (bypassed)"
        color = "green" if finding.passed else "red"

        msg = (
            f"[bold yellow][ATTACK][/bold yellow] {finding.attack_name} {module.name}\n"
            f'Payload: "{finding.payload}"\n'
            f'Response: "{finding.response_snippet}"\n'
            f"Result: [{color}]{result_str}[/{color}]\n"
        )
        if dry_run:
            msg = f"[bold cyan][DRY RUN][/bold cyan] Would send: {finding.attack_name} -> {finding.payload}\n"
        if hasattr(progress, "console"):
            progress.console.print(msg)
        else:
            verbose_console.print(msg)

    try:
        result = await module.run(
            target, client, on_finding=on_finding, mutate_enabled=mutate
        )
    finally:
        with _results_lock:
            module_results.append(result)
        progress.advance(task_id, advance=_module_payload_count(module))


async def run_scan(
    target: AgentTarget,
    modules: list[BaseModule] | None = None,
    concurrency: int = 5,
    timeout: float = 30.0,
    quiet: bool = False,
    format: str = "table",
    verbose: bool = False,
    mutate: bool = False,
    dry_run: bool = False,
) -> ScanResult:
    if modules is None:
        modules = get_all_modules()

    dry_run = dry_run or target.dry_run
    if dry_run and not target.dry_run:
        target = target.model_copy(update={"dry_run": True})

    scan = ScanResult(
        target=target,
        status=ScanStatus.RUNNING,
        started_at=datetime.now(timezone.utc),
    )

    module_results: list[ModuleResult] = []
    start = time.monotonic()

    total_attacks = sum(_module_payload_count(m) for m in modules)
    progress_target = sys.stderr if format in ["json", "html"] else sys.stdout
    progress_console = Console(file=progress_target)
    verbose_console = Console(file=sys.stderr)

    progress_columns = [
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
    ]
    dry_run_preview = (
        _build_dry_run_preview(target, modules, concurrency) if dry_run else None
    )

    # nullcontext-style: skip Rich entirely in quiet mode
    progress_cm = (
        Progress(*progress_columns, console=progress_console)
        if not quiet
        else _noop_progress()
    )

    try:
        limits = httpx.Limits(
            max_connections=concurrency,
            max_keepalive_connections=concurrency,
        )
        with progress_cm as progress:
            task_id = progress.add_task("Starting scan...", total=total_attacks)

            async with (
                httpx.AsyncClient(
                    limits=limits,
                    timeout=timeout,
                    follow_redirects=True,
                    proxy=target.proxy or None,
                ) as client,
                anyio.create_task_group() as tg,
            ):
                for module in modules:
                    tg.start_soon(
                        run_module_with_progress,
                        module,
                        target,
                        client,
                        module_results,
                        progress,
                        task_id,
                        verbose,
                        verbose_console,
                        mutate,
                        dry_run,
                    )

            progress.update(task_id, description="[green]Scan complete[/green]")

        scan.status = ScanStatus.COMPLETED

    except Exception:
        scan.status = ScanStatus.FAILED

    scan.modules = module_results
    scan.completed_at = datetime.now(timezone.utc)
    scan.duration_seconds = round(time.monotonic() - start, 3)
    if dry_run_preview:
        scan.metadata.update(dry_run_preview)

    finalize_scan_result(scan)

    return scan
