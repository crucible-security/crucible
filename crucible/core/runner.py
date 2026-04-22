from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import anyio
import httpx

from crucible.core.scorer import finalize_scan_result
from crucible.models import AgentTarget, ModuleResult, ScanResult, ScanStatus
from crucible.modules.security import get_all_modules

if TYPE_CHECKING:
    from crucible.modules.base import BaseModule


async def run_module(
    module: BaseModule,
    target: AgentTarget,
    client: httpx.AsyncClient,
    results: list[ModuleResult],
) -> None:
    result = await module.run(target, client)
    results.append(result)


async def run_scan(
    target: AgentTarget,
    modules: list[BaseModule] | None = None,
    concurrency: int = 5,
    timeout: float = 30.0,
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

    try:
        limits = httpx.Limits(
            max_connections=concurrency,
            max_keepalive_connections=concurrency,
        )
        async with (
            httpx.AsyncClient(
                limits=limits,
                timeout=timeout,
                follow_redirects=True,
            ) as client,
            anyio.create_task_group() as tg,
        ):
            for module in modules:
                tg.start_soon(run_module, module, target, client, module_results)

        scan.status = ScanStatus.COMPLETED

    except Exception:
        scan.status = ScanStatus.FAILED

    scan.modules = module_results
    scan.completed_at = datetime.now(timezone.utc)
    scan.duration_seconds = round(time.monotonic() - start, 3)

    finalize_scan_result(scan)

    return scan
