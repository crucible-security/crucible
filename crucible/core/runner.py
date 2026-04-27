from __future__ import annotations

import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock
from typing import TYPE_CHECKING

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
from crucible.models import AgentTarget, ModuleResult, ScanResult, ScanStatus
from crucible.modules.security import get_all_modules

if TYPE_CHECKING:
    from crucible.modules.base import BaseModule

# Thread-safe append for concurrent module results
_results_lock = Lock()


@dataclass
class _NoopProgress:
    """Duck-typed stub so call sites don't need to branch on quiet mode."""
    def add_task(self, *_: typing.Any, **__: typing.Any) -> TaskID:
        return TaskID(0)
    def update(self, *_: typing.Any, **__: typing.Any) -> None:
        pass
    def advance(self, *_: typing.Any, **__: typing.Any) -> None:
        pass


import typing

@contextmanager
def _noop_progress() -> typing.Iterator[_NoopProgress]:
    yield _NoopProgress()


def _module_payload_count(module: BaseModule) -> int:
    return sum(len(attack.get_payloads()) for attack in module.get_attacks())


async def run_module(
    module: BaseModule,
    target: AgentTarget,
    client: httpx.AsyncClient,
) -> ModuleResult:
    return await module.run(target, client)


async def run_module_with_progress(
    module: BaseModule,
    target: AgentTarget,
    client: httpx.AsyncClient,
    module_results: list[ModuleResult],
    progress: Progress | _NoopProgress,
    task_id: TaskID,
) -> None:
    progress.update(
        task_id, description=f"Running [bold cyan]{module.name}[/bold cyan]"
    )
    try:
        result = await run_module(module, target, client)
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
    output_format: str = "text",
) -> ScanResult:
    if modules is None:
        modules = get_all_modules()

    scan = ScanResult(
        target=target,
        status=ScanStatus.RUNNING,
        started_at=datetime.now(timezone.utc),
    )

    module_results: list[ModuleResult] = []
    start = time.monotonic()

    total_attacks = sum(_module_payload_count(m) for m in modules)
    progress_target = sys.stderr if output_format == "json" else sys.stdout

    progress_columns = [
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
    ]

    # nullcontext-style: skip Rich entirely in quiet mode
    progress_cm = (
        Progress(*progress_columns, console=Console(file=progress_target))
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
                    )

            progress.update(task_id, description="[green]Scan complete[/green]")

        scan.status = ScanStatus.COMPLETED

    except Exception:
        scan.status = ScanStatus.FAILED

    scan.modules = module_results
    scan.completed_at = datetime.now(timezone.utc)
    scan.duration_seconds = round(time.monotonic() - start, 3)

    finalize_scan_result(scan)

    return scan
