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
from crucible.models import (
    AgentTarget,
    Finding,
    ModuleResult,
    PreflightResult,
    ScanResult,
    ScanStatus,
)
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


def _module_payload_count(
    module: BaseModule, dynamic_payloads: bool = False, dynamic_count: int = 0
) -> int:
    static_count = sum(len(attack.get_payloads()) for attack in module.get_attacks())
    if dynamic_payloads:
        return static_count + (len(module.get_attacks()) * dynamic_count)
    return static_count


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
    confidence: bool = False,
    samples: int = 5,
    dynamic_payloads: bool = False,
    generator_endpoint: str | None = None,
    generator_model: str | None = None,
    generator_format_preset: str | None = None,
    dynamic_count: int = 10,
    dynamic_seed: int | None = None,
) -> None:
    progress.update(
        task_id, description=f"Running [bold cyan]{module.name}[/bold cyan]"
    )

    def on_finding(finding: Finding) -> None:
        if not verbose:
            return

        if getattr(finding, "execution_error", False):
            result_str = "ERROR (execution error)"
            color = "yellow"
        else:
            result_str = "PASS (refused)" if finding.passed else "FAIL (bypassed)"
            color = "green" if finding.passed else "red"

        msg = (
            f"[bold yellow][ATTACK][/bold yellow] {finding.attack_name} {module.name}\n"
            f'Payload: "{finding.payload}"\n'
            f'Response: "{finding.response_snippet}"\n'
            f"Result: [{color}]{result_str}[/{color}]\n"
        )
        if hasattr(progress, "console"):
            progress.console.print(msg)
        else:
            verbose_console.print(msg)

    try:
        result = await module.run(
            target,
            client,
            on_finding=on_finding,
            mutate_enabled=mutate,
            confidence=confidence,
            samples=samples,
            dynamic_payloads=dynamic_payloads,
            generator_endpoint=generator_endpoint,
            generator_model=generator_model,
            generator_format_preset=generator_format_preset,
            dynamic_count=dynamic_count,
            dynamic_seed=dynamic_seed,
        )
    finally:
        with _results_lock:
            module_results.append(result)
        progress.advance(
            task_id,
            advance=_module_payload_count(
                module, dynamic_payloads, dynamic_count
            ),
        )


class _PreflightError(Exception):
    """Raised inside run_scan() when preflight_check fails fatally."""

    def __init__(self, result: PreflightResult) -> None:
        self.result = result
        super().__init__(result.errors[0] if result.errors else "Preflight failed")


async def preflight_check(
    target: AgentTarget,
    client: httpx.AsyncClient,
) -> PreflightResult:
    """Send one minimal probe request to validate the target before scanning.

    Checks:
    1. Is the target reachable?
    2. Does it accept the configured HTTP method (405 = NO)?
    3. Does the response look like an LLM endpoint (JSON with message/content)?

    Returns a :class:`PreflightResult` describing the outcome.  The caller is
    responsible for deciding whether to abort the scan.
    """
    warnings: list[str] = []
    errors: list[str] = []

    # Build a minimal probe body using the target's body_template.
    probe_body = target.body_template.replace("{payload}", "Hello")

    try:
        response = await client.request(
            method=target.method,
            url=str(target.url),
            content=probe_body.encode(),
            headers={"Content-Type": "application/json", **target.headers},
        )
    except httpx.ConnectError as exc:
        errors.append(f"Connection error: {exc}")
        return PreflightResult(
            reachable=False,
            method_accepted=False,
            looks_like_llm_endpoint=False,
            status_code=0,
            warnings=warnings,
            errors=errors,
        )
    except Exception as exc:
        errors.append(f"Unexpected error during preflight: {exc}")
        return PreflightResult(
            reachable=False,
            method_accepted=False,
            looks_like_llm_endpoint=False,
            status_code=0,
            warnings=warnings,
            errors=errors,
        )

    status_code = response.status_code

    # 405 → method not accepted
    if status_code == 405:
        errors.append(
            f"Target returned 405 Method Not Allowed. "
            f"You specified --method {target.method} but this endpoint requires POST. "
            f"Re-run without --method {target.method} or use "
            f"--skip-preflight to bypass this check."
        )
        return PreflightResult(
            reachable=True,
            method_accepted=False,
            looks_like_llm_endpoint=False,
            status_code=status_code,
            warnings=warnings,
            errors=errors,
        )

    # Detect non-LLM responses: parse JSON and look for typical LLM response keys.
    looks_like_llm = False
    try:
        body = response.json()
        llm_keys = {
            "message",
            "choices",
            "content",
            "response",
            "output",
            "result",
            "text",
            "generated_text",
        }
        if isinstance(body, dict) and (
            llm_keys.intersection(body.keys()) or "message" in str(body).lower()
        ):
            looks_like_llm = True
    except Exception:
        pass

    if not looks_like_llm:
        warnings.append(
            "Target does not appear to return an LLM response format. "
            "Scan results may be unreliable."
        )

    return PreflightResult(
        reachable=True,
        method_accepted=True,
        looks_like_llm_endpoint=looks_like_llm,
        status_code=status_code,
        warnings=warnings,
        errors=errors,
    )


async def run_scan(
    target: AgentTarget,
    modules: list[BaseModule] | None = None,
    concurrency: int = 5,
    timeout: float = 30.0,
    quiet: bool = False,
    format: str = "table",
    verbose: bool = False,
    mutate: bool = False,
    skip_preflight: bool = False,
    confidence: bool = False,
    samples: int = 5,
    dynamic_payloads: bool = False,
    generator_endpoint: str | None = None,
    generator_model: str | None = None,
    generator_format_preset: str | None = None,
    dynamic_count: int = 10,
    dynamic_seed: int | None = None,
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

    total_attacks = sum(
        _module_payload_count(m, dynamic_payloads, dynamic_count)
        for m in modules
    )
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
            task_id = progress.add_task(
                "Starting scan...", total=total_attacks * (samples if confidence else 1)
            )

            # ── Confidence-mode warning ────────────────────────────────────────
            if confidence:
                warn_con = (
                    progress.console
                    if hasattr(progress, "console")
                    else Console(file=sys.stderr)
                )
                est_normal_s = max(1.0, (total_attacks * 0.5) / concurrency)
                est_conf_s = est_normal_s * samples
                normal_str = (
                    f"{est_normal_s / 60:.1f}m"
                    if est_normal_s >= 60
                    else f"{est_normal_s:.0f}s"
                )
                conf_str = (
                    f"{est_conf_s / 60:.1f}m"
                    if est_conf_s >= 60
                    else f"{est_conf_s:.0f}s"
                )
                warn_con.print(
                    f"[yellow]⚠ Confidence mode enabled: each attack runs {samples}x.\n"
                    f" Estimated scan time: ~{conf_str} (vs ~{normal_str} single-shot).\n"
                    f" Press Ctrl+C to abort.[/yellow]"
                )
            # ──────────────────────────────────────────────────────────────────

            # ── Preflight ─────────────────────────────────────────────────────
            preflight_client = httpx.AsyncClient(
                limits=limits,
                timeout=timeout,
                follow_redirects=True,
                proxy=target.proxy or None,
            )
            if not skip_preflight:
                async with preflight_client as pfc:
                    pf = await preflight_check(target, pfc)
                if not pf.reachable or not pf.method_accepted:
                    raise _PreflightError(pf)
                if not pf.looks_like_llm_endpoint and pf.warnings:
                    warn_console = (
                        progress.console
                        if hasattr(progress, "console")
                        else Console(file=sys.stderr)
                    )
                    warn_console.print(
                        f"[yellow]⚠ Preflight warning: {pf.warnings[0]}[/yellow]"
                    )
            # ─────────────────────────────────────────────────────────────────

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
                        confidence,
                        samples,
                        dynamic_payloads,
                        generator_endpoint,
                        generator_model,
                        generator_format_preset,
                        dynamic_count,
                        dynamic_seed,
                    )

            progress.update(task_id, description="[green]Scan complete[/green]")

        scan.status = ScanStatus.COMPLETED

    except _PreflightError:
        raise
    except Exception:
        scan.status = ScanStatus.FAILED

    scan.modules = module_results
    scan.completed_at = datetime.now(timezone.utc)
    scan.duration_seconds = round(time.monotonic() - start, 3)

    # Aggregate statistical findings from all modules into ScanResult
    if confidence:
        all_stat: list[Any] = []
        for mr in module_results:
            all_stat.extend(mr.statistical_findings)
        scan.statistical_findings = all_stat

    finalize_scan_result(scan)

    return scan
