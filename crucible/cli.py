from __future__ import annotations

import contextlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import anyio
import httpx
import typer
from rich.console import Console

from crucible import __version__
from crucible.core.behavioral_engine import BehavioralEngine
from crucible.core.cache import ScanCache
from crucible.core.compliance_engine import ComplianceEngine
from crucible.core.multi_turn_engine import MultiTurnEngine
from crucible.core.profiler import AgentProfiler
from crucible.core.runner import run_scan
from crucible.models import (
    PROVIDER_PRESETS,
    AgentTarget,
    Grade,
    ScanResult,
    ScanStatus,
    Severity,
)
from crucible.modules.security import get_all_modules
from crucible.reporters.compliance_reporter import ComplianceReporter
from crucible.reporters.html_reporter import HTMLReporter
from crucible.reporters.json_reporter import JSONReporter
from crucible.reporters.sarif_reporter import SARIFReporter
from crucible.reporters.slack import SlackReporter
from crucible.reporters.terminal import TerminalReporter

os.environ.setdefault("PYTHONIOENCODING", "utf-8")

if hasattr(sys.stdout, "reconfigure"):
    with contextlib.suppress(Exception):
        sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    with contextlib.suppress(Exception):
        sys.stderr.reconfigure(encoding="utf-8")

console = Console()

app = typer.Typer(
    name="crucible",
    help="pytest for AI agents -- test, score, and harden before production.",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)

_DEFAULT_BODY_TEMPLATE = '{"message": "{payload}"}'


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold magenta]Crucible[/bold magenta] v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    pass


@app.command()
def init(
    target: str = typer.Option(
        ...,
        "--target",
        "-t",
        help="Agent endpoint URL.",
    ),
    provider: str = typer.Option(
        "custom",
        "--provider",
        "-p",
        help="Provider: openai|anthropic|groq|custom.",
    ),
    key: str | None = typer.Option(
        None,
        "--key",
        "-k",
        help="API key (or reads from env).",
    ),
) -> None:
    config_path = Path(".crucible.json")
    if config_path.exists():
        console.print(
            "[yellow]Warning: .crucible.json already exists. Overwrite? [y/N][/yellow]"
        )
        confirm = input().strip().lower()
        if confirm != "y":
            console.print("[dim]Aborted.[/dim]")
            raise typer.Exit()

    config = {
        "target": {
            "name": "my-agent",
            "url": target,
            "provider": provider,
            "method": "POST",
            "headers": {},
            "body_template": '{"message": "{payload}"}',
            "timeout": 30,
        },
        "scan": {
            "modules": [
                "prompt_injection",
                "goal_hijacking",
                "jailbreaks",
            ],
            "timeout": 30,
        },
    }
    if key:
        config["target"]["headers"] = {"Authorization": f"Bearer {key}"}

    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    console.print("[green]Created .crucible.json[/green]")
    console.print("[dim]Edit the file and run: crucible scan[/dim]")


def load_scope_file(path: Path) -> list[str]:
    """Parse a basic YAML file looking for allowed_hosts list."""
    content = path.read_text(encoding="utf-8")
    allowed_hosts = []
    in_allowed_hosts = False
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("allowed_hosts:"):
            in_allowed_hosts = True
            continue
        if in_allowed_hosts and line.endswith(":") and not line.startswith("-"):
            in_allowed_hosts = False
            continue
        if in_allowed_hosts and line.startswith("-"):
            host = line[1:].strip()
            host = host.strip("'\"")
            if host:
                allowed_hosts.append(host)
    return allowed_hosts


@app.command()
def scan(
    target: str = typer.Option(
        ...,
        "--target",
        "-t",
        help="Target URL of the AI agent endpoint.",
    ),
    name: str = typer.Option(
        "target-agent",
        "--name",
        "-n",
        help="Human-readable name for the target.",
    ),
    method: str = typer.Option(
        "POST",
        "--method",
        "-m",
        help="HTTP method (GET, POST, PUT, etc.).",
    ),
    header: list[str] | None = typer.Option(
        None,
        "--header",
        "-H",
        help="Headers as 'Key: Value' (repeatable).",
    ),
    body_template: str = typer.Option(
        _DEFAULT_BODY_TEMPLATE,
        "--body",
        "-b",
        help="JSON body template with {payload} placeholder.",
    ),
    body_file: Path | None = typer.Option(
        None,
        "--body-file",
        "-B",
        help="Path to a file containing the JSON body template.",
    ),
    strategy: str = typer.Option(
        "single-shot",
        "--strategy",
        help="Attack strategy: single-shot | multi-turn | crescendo | context-confusion | token-theft",
    ),
    profile_file: Path | None = typer.Option(
        None,
        "--profile",
        help="JSON profile file generated by crucible profile.",
    ),
    format_preset: str = typer.Option(
        "",
        "--format-preset",
        help="Body format preset: openai | langchain | glean | raw | generic | ollama | lmstudio | huggingface-tgi.",
    ),
    model: str = typer.Option(
        "llama3",
        "--model",
        help="Model name for presets that require it (e.g. ollama).",
    ),
    response_path: str = typer.Option(
        "",
        "--response-path",
        help="JMESPath to extract response (e.g. 'choices[0].message.content').",
    ),
    timeout: float = typer.Option(
        30.0,
        "--timeout",
        help="Request timeout in seconds.",
    ),
    retry: int = typer.Option(
        2,
        "--retry",
        help="Number of retries on failure (default: 2).",
    ),
    delay: int = typer.Option(
        500,
        "--delay",
        help="Delay between requests in ms (default: 500).",
    ),
    rate_limit: float | None = typer.Option(
        None,
        "--rate-limit",
        help="Rate limit in requests per second. (Preferred over --delay)",
    ),
    proxy: str = typer.Option(
        "",
        "--proxy",
        help="HTTP proxy URL (e.g. http://localhost:8080 for Burp Suite).",
    ),
    concurrency: int = typer.Option(
        5,
        "--concurrency",
        "-c",
        help="Max concurrent requests.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "--output-file",
        "-o",
        help="Save report to file.",
    ),
    mutate: bool = typer.Option(
        False,
        "--mutate",
        help="Apply payload obfuscation mutations to bypass WAFs/guardrails.",
    ),
    generate_report: bool = typer.Option(
        False,
        "--generate-report",
        help="Auto-generate a Bugcrowd/HackerOne Markdown PoC report on findings.",
    ),
    format: str = typer.Option(
        "table",
        "--format",
        help="Output format: table | json | html | huntr | sarif.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show each attack result live.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress progress bar output.",
    ),
    cache: bool = typer.Option(
        False,
        "--cache",
        help="Cache the scan results to avoid duplicate runs.",
    ),
    cache_ttl: int = typer.Option(
        24,
        "--cache-ttl",
        help="Cache time-to-live in hours.",
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Force rescan, ignoring existing cache.",
    ),
    slack_webhook: str | None = typer.Option(
        None,
        "--slack-webhook",
        help="Slack Incoming Webhook URL to send results.",
    ),
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        help="Fail (exit non-zero) if findings match or exceed this severity (CRITICAL, HIGH, MEDIUM, LOW, INFO).",
    ),
    scope_file: Path | None = typer.Option(
        None,
        "--scope-file",
        help="Path to a YAML file defining the allowed target hosts.",
    ),
    turns: int | None = typer.Option(
        None,
        "--turns",
        help="Number of turns to execute for multi-turn strategies.",
    ),
    allow_incomplete: bool = typer.Option(
        False,
        "--allow-incomplete",
        help="Allow the scan to exit with code 0 even if the grade is INCOMPLETE.",
    ),
) -> None:
    parsed_headers = _parse_headers(header)

    if scope_file:
        if not scope_file.exists():
            console.print(f"[red]Error: Scope file not found: {scope_file}[/red]")
            raise typer.Exit(code=2)
        try:
            allowed_hosts = load_scope_file(scope_file)
        except Exception as e:
            console.print(f"[red]Error loading scope file: {e}[/red]")
            raise typer.Exit(code=2) from e

        from urllib.parse import urlparse

        parsed = urlparse(target)
        hostname = parsed.hostname
        if not hostname:
            hostname = urlparse("//" + target).hostname

        if not hostname or hostname not in allowed_hosts:
            allowed_list_str = ", ".join(allowed_hosts)
            console.print(
                f"[red]Error: Target {hostname or target} is not in scope file. Allowed: ({allowed_list_str})[/red]"
            )
            raise typer.Exit(code=2)

    # Resolve body template: explicit --body wins, then --body-file, then --format-preset, then default
    resolved_body = body_template
    resolved_response_path = response_path
    resolved_timeout = timeout

    if body_file:
        if not body_file.exists():
            console.print(f"[red]Body file not found: {body_file}[/red]")
            raise typer.Exit(code=1)
        resolved_body = body_file.read_text(encoding="utf-8")
    elif format_preset:
        if format_preset not in PROVIDER_PRESETS:
            console.print(
                f"[red]Unknown format preset: {format_preset}. "
                f"Available: {', '.join(PROVIDER_PRESETS.keys())}[/red]"
            )
            raise typer.Exit(code=1)
        preset = PROVIDER_PRESETS[format_preset]
        # Only apply preset if user didn't explicitly set --body
        if body_template == _DEFAULT_BODY_TEMPLATE:
            resolved_body = preset.body_template.replace("{model}", model)
        # Apply default response path if not explicitly set
        if not response_path:
            resolved_response_path = preset.response_path
        # Apply default timeout if not explicitly set
        if timeout == 30.0:
            resolved_timeout = preset.default_timeout
        # Merge extra headers from preset
        if preset.extra_headers:
            for k, v in preset.extra_headers.items():
                if k not in parsed_headers:
                    parsed_headers[k] = v
        # Append url_suffix if the target doesn't already end with it
        if preset.url_suffix and not target.rstrip("/").endswith(
            preset.url_suffix.rstrip("/")
        ):
            target = target.rstrip("/") + preset.url_suffix

    resolved_delay_ms = delay
    if rate_limit is not None:
        if rate_limit <= 0:
            console.print("[red]Error: --rate-limit must be greater than 0.[/red]")
            raise typer.Exit(code=1)
        resolved_delay_ms = int(1000.0 / rate_limit)

    agent_target = AgentTarget(
        name=name,
        url=target,  # type: ignore[arg-type]
        method=method,
        headers=parsed_headers,
        body_template=resolved_body,
        timeout=resolved_timeout,
        response_path=resolved_response_path,
        retry_count=retry,
        delay_ms=resolved_delay_ms,
        proxy=proxy,
    )

    if format not in ["json", "html"] and not quiet:
        _print_scan_header(name, target)

    modules = get_all_modules()
    scan_cache = ScanCache()
    cache_key = scan_cache.get_cache_key(agent_target, modules)
    result = None
    if cache and not no_cache:
        cached_result = scan_cache.get(cache_key)
        if cached_result:
            if format not in ["json", "html"] and not quiet:
                console.print(
                    f"[bold cyan]Cache hit for target (expires in {cache_ttl}h). Use --no-cache to force rescan.[/bold cyan]"
                )
            result = cached_result

    if result is None:
        if strategy in ["multi-turn", "crescendo", "context-confusion", "token-theft"]:
            if format not in ["json", "html"] and not quiet:
                console.print(
                    f"\n[bold magenta]Running MULTI-TURN Strategies ({strategy})[/bold magenta]"
                )

            async def run_multi_turn() -> ScanResult:
                from crucible.attacks.multi_turn_strategies import (
                    ContextConfusionStrategy,
                    CrescendoStrategy,
                    TokenTheftCrescendoStrategy,
                )

                strategies_to_run = []
                if strategy == "multi-turn":
                    strategies_to_run = [
                        CrescendoStrategy(),
                        ContextConfusionStrategy(),
                        TokenTheftCrescendoStrategy(),
                    ]
                elif strategy == "crescendo":
                    strategies_to_run = [CrescendoStrategy()]
                elif strategy == "context-confusion":
                    strategies_to_run = [ContextConfusionStrategy()]
                elif strategy == "token-theft":
                    strategies_to_run = [TokenTheftCrescendoStrategy()]

                results = []
                async with httpx.AsyncClient() as client:
                    engine = MultiTurnEngine(agent_target, client)
                    for strat in strategies_to_run:
                        res = await engine.run_strategy(strat, turns=turns)
                        results.append(res)

                return ScanResult(
                    target=agent_target,
                    modules=results,
                    status=ScanStatus.COMPLETED,
                )

            result = anyio.run(run_multi_turn)
            from crucible.core.scorer import finalize_scan_result

            finalize_scan_result(result)
        else:
            if profile_file and profile_file.exists():
                import json

                try:
                    profile_data = json.loads(profile_file.read_text(encoding="utf-8"))
                    rec_modules = profile_data.get("recommended_modules", [])
                    if rec_modules:
                        modules = [
                            m
                            for m in modules
                            if m.name.lower().replace(" ", "_") in rec_modules
                        ]
                        if format not in ["json", "html"] and not quiet:
                            console.print(
                                f"[bold cyan]Using profiled modules: {', '.join(m.name for m in modules)}[/bold cyan]"
                            )
                except Exception as e:
                    console.print(f"[yellow]Failed to load profile: {e}[/yellow]")

            result = anyio.run(
                run_scan,
                agent_target,
                modules,
                concurrency,
                resolved_timeout,
                quiet,
                format,
                verbose,
                mutate,
            )

        if cache:
            scan_cache.set(cache_key, result, ttl_hours=cache_ttl)

    _render_output(result, format, output)

    if generate_report:
        from crucible.core.reporter import BugBountyReportGenerator

        generator = BugBountyReportGenerator(output_dir=".")
        report_path = generator.generate(result)
        if report_path:
            console.print(
                f"\n[bold green]* Bug bounty report written to: {report_path}[/bold green]"
            )
        else:
            console.print(
                "\n[bold yellow]i No vulnerable findings - report not generated.[/bold yellow]"
            )

    if slack_webhook:
        reporter = SlackReporter()
        anyio.run(reporter.send, slack_webhook, result)

    if fail_on:
        try:
            severity_threshold = Severity[fail_on.upper()]
        except KeyError:
            console.print(f"[red]Invalid severity for --fail-on: {fail_on}[/red]")
            raise typer.Exit(code=1) from None

        counts = {
            Severity.CRITICAL: result.critical_count,
            Severity.HIGH: result.high_count,
            Severity.MEDIUM: result.medium_count,
            Severity.LOW: result.low_count,
            Severity.INFO: result.info_count,
        }

        severities = list(Severity)
        threshold_index = severities.index(severity_threshold)

        # Check all severities from CRITICAL down to the threshold
        should_fail = any(counts[sev] > 0 for sev in severities[: threshold_index + 1])

        if should_fail:
            if format not in ["json", "html"] and not quiet:
                console.print(
                    f"[bold red]Scan failed due to findings matching or exceeding {severity_threshold.value.upper()} severity.[/bold red]"
                )
            raise typer.Exit(code=1)

    if result.grade == Grade.INCOMPLETE and not allow_incomplete:
        if format not in ["json", "html"] and not quiet:
            console.print(
                "[bold red]Scan completed with INCOMPLETE status due to high execution failure rate (exceeded 20%).[/bold red]"
            )
        raise typer.Exit(code=1)


def _parse_headers(
    header: list[str] | None,
) -> dict[str, str]:
    parsed: dict[str, str] = {}
    if header:
        for h in header:
            if ":" not in h:
                console.print(f"[red]Invalid header format: {h}[/red]")
                raise typer.Exit(code=1)
            key, value = h.split(":", 1)
            parsed[key.strip()] = value.strip()
    return parsed


def _print_scan_header(name: str, target: str) -> None:
    console.print()
    console.print("[bold magenta]CRUCIBLE[/bold magenta] -- Starting security scan...")
    console.print(f"[dim]Target: {name} ({target})[/dim]")
    console.print()


def _render_output(
    result: ScanResult,
    format: str,
    output: Path | None,
) -> None:
    if format == "json":
        json_reporter = JSONReporter()
        sys.stdout.write(json_reporter.to_json(result) + "\n")
    elif format == "html":
        html_reporter = HTMLReporter()
        if not output:
            sys.stdout.write(html_reporter.to_html(result) + "\n")
    elif format == "sarif":
        sarif_reporter = SARIFReporter()
        if not output:
            sys.stdout.write(sarif_reporter.to_json(result) + "\n")
    elif format == "huntr":
        from crucible.reporters.huntr_reporter import HuntrReporter

        reporter = HuntrReporter()
        if output:
            reporter.write(result, output)
            console.print(f"[green]Huntr report saved to {output}[/green]")
            return  # Skip the default file writing below
        else:
            console.print(
                "[red]Error: --output is required when using --format huntr[/red]"
            )
            raise typer.Exit(code=1)
    else:
        terminal = TerminalReporter(console)
        terminal.render(result)

    if output:
        if format == "sarif" or output.suffix == ".sarif":
            s_reporter = SARIFReporter()
            saved = s_reporter.write(result, output)
        elif format == "html" or output.suffix == ".html":
            h_reporter = HTMLReporter()
            saved = h_reporter.write(result, output)
        else:
            j_reporter = JSONReporter()
            saved = j_reporter.write(result, output)

        if format not in ["json", "html", "sarif"]:
            console.print(f"[green]Report saved to {saved}[/green]")


@app.command()
def report(
    path: Path = typer.Argument(
        ...,
        help="Path to a Crucible JSON report file.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "--output-file",
        "-o",
        help="Save report to file.",
    ),
    format: str = typer.Option(
        "table",
        "--format",
        help="Output format: table | json | html | huntr.",
    ),
) -> None:
    if not path.exists():
        console.print(f"[red]File not found: {path}[/red]")
        raise typer.Exit(code=1)

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        result = ScanResult.model_validate(data)
    except (json.JSONDecodeError, ValueError) as exc:
        console.print(f"[red]Failed to parse report: {exc}[/red]")
        raise typer.Exit(code=1) from exc

    _render_output(result, format, output)


@app.command()
def behavioral_audit(
    target: str = typer.Option(..., "--target", "-t", help="Agent endpoint URL."),
    name: str = typer.Option("target-agent", "--name", "-n"),
    method: str = typer.Option("POST", "--method", "-m"),
    header: list[str] | None = typer.Option(None, "--header", "-H"),
    body_template: str = typer.Option(_DEFAULT_BODY_TEMPLATE, "--body", "-b"),
    baseline_turns: int = typer.Option(5, "--baseline-turns"),
    probe_turns: int = typer.Option(15, "--probe-turns"),
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    """Run a multi-turn behavioral drift and integrity audit."""
    parsed_headers = _parse_headers(header)
    agent_target = AgentTarget(
        name=name,
        url=target,  # type: ignore[arg-type]
        method=method,
        headers=parsed_headers,
        body_template=body_template,
    )

    console.print("\n[bold magenta]Crucible Behavioral Audit[/bold magenta]")
    console.print(f"Target: {name} ({target})\n")

    from crucible.models import ModuleResult

    async def _audit() -> ModuleResult:
        async with httpx.AsyncClient(timeout=30.0) as client:
            engine = BehavioralEngine(agent_target, client)
            return await engine.run_audit(baseline_turns, probe_turns)

    module_result = anyio.run(_audit)

    result = ScanResult(
        target=agent_target, modules=[module_result], status=ScanStatus.COMPLETED
    )
    from crucible.core.scorer import finalize_scan_result

    finalize_scan_result(result)

    _render_output(result, "table", output)


@app.command()
def profile(
    target: str = typer.Option(..., "--target", "-t", help="Agent endpoint URL."),
    name: str = typer.Option("target-agent", "--name", "-n"),
    method: str = typer.Option("POST", "--method", "-m"),
    header: list[str] | None = typer.Option(None, "--header", "-H"),
    body_template: str = typer.Option(_DEFAULT_BODY_TEMPLATE, "--body", "-b"),
    output: Path = typer.Option(Path("agent_profile.json"), "--output", "-o"),
) -> None:
    """Auto-profile an agent's capabilities to generate custom attacks."""
    parsed_headers = _parse_headers(header)
    agent_target = AgentTarget(
        name=name,
        url=target,  # type: ignore[arg-type]
        method=method,
        headers=parsed_headers,
        body_template=body_template,
    )

    console.print("\n[bold magenta]Crucible Agent Profiler[/bold magenta]")

    from crucible.models import AgentProfile

    async def _profile() -> AgentProfile:
        async with httpx.AsyncClient(timeout=30.0) as client:
            engine = AgentProfiler(agent_target, client)
            return await engine.run_profile()

    profile_result = anyio.run(_profile)

    output.write_text(profile_result.model_dump_json(indent=2), encoding="utf-8")
    console.print(f"[green]Profile generated: {output}[/green]")
    console.print(f"Detected Type: [bold]{profile_result.agent_type}[/bold]")
    console.print(
        f"Capabilities: {', '.join(c.value for c in profile_result.inferred_capabilities)}"
    )


@app.command()
def compliance_report(
    results: Path = typer.Option(
        ..., "--results", "-r", help="Path to scan results JSON."
    ),
    standard: str = typer.Option("eu-ai-act-2024", "--standard", "-s"),
    framework: str = typer.Option(
        "eu",
        "--framework",
        "-f",
        help="Compliance framework: eu | atlas | nist | all",
    ),
    output: Path = typer.Option(Path("compliance.md"), "--output", "-o"),
) -> None:
    """Generate a compliance report from scan results.

    Supports: EU AI Act (--framework eu), MITRE ATLAS (--framework atlas),
    NIST AI RMF (--framework nist), or all three (--framework all).
    """
    try:
        import json

        data = json.loads(results.read_text(encoding="utf-8"))
        scan_result = ScanResult.model_validate(data)
    except Exception as e:
        console.print(f"[red]Failed to load results: {e}[/red]")
        raise typer.Exit(code=1) from e

    framework = framework.lower().strip()

    if framework in ("eu", "eu-ai-act", "eu-ai-act-2024"):
        engine = ComplianceEngine(scan_result)
        report = engine.generate_report()
        reporter = ComplianceReporter()
        reporter.write(report, output)
        console.print(f"[green]EU AI Act compliance report generated at {output}[/green]")

    elif framework == "atlas":
        from crucible.reporters.atlas_reporter import ATLASReporter
        reporter_atlas = ATLASReporter()
        reporter_atlas.write(scan_result, output)
        console.print(f"[green]MITRE ATLAS report generated at {output}[/green]")

    elif framework == "nist":
        from crucible.reporters.nist_reporter import NISTReporter
        reporter_nist = NISTReporter()
        reporter_nist.write(scan_result, output)
        console.print(f"[green]NIST AI RMF report generated at {output}[/green]")

    elif framework == "all":
        from crucible.reporters.atlas_reporter import ATLASReporter
        from crucible.reporters.nist_reporter import NISTReporter

        stem = output.stem
        suffix = output.suffix or ".md"
        parent = output.parent

        # EU AI Act
        eu_out = parent / f"{stem}_eu{suffix}"
        engine = ComplianceEngine(scan_result)
        report = engine.generate_report()
        ComplianceReporter().write(report, eu_out)

        # ATLAS
        atlas_out = parent / f"{stem}_atlas{suffix}"
        ATLASReporter().write(scan_result, atlas_out)

        # NIST
        nist_out = parent / f"{stem}_nist{suffix}"
        NISTReporter().write(scan_result, nist_out)

        console.print("[green]All compliance reports generated:[/green]")
        console.print(f"  EU AI Act : {eu_out}")
        console.print(f"  MITRE ATLAS: {atlas_out}")
        console.print(f"  NIST AI RMF: {nist_out}")

    else:
        console.print(f"[red]Unknown framework: {framework!r}. Use: eu | atlas | nist | all[/red]")
        raise typer.Exit(code=1)


@app.command()
def diff(
    scan_a: Path = typer.Argument(..., help="Path to baseline scan results JSON."),
    scan_b: Path = typer.Argument(..., help="Path to current scan results JSON."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Save diff report to file."),
    format: str = typer.Option("terminal", "--format", "-f", help="Diff report format: terminal | json | html | markdown"),
    show_unchanged: bool = typer.Option(False, "--show-unchanged", help="Include UNCHANGED_PASS findings (default: hidden)."),
    module: str | None = typer.Option(None, "--module", "-m", help="Filter diff to a specific module."),
    severity: str | None = typer.Option(None, "--severity", "-s", help="Filter diff by severity: CRITICAL | HIGH | MEDIUM | LOW"),
) -> None:
    """Compare two scan results and show the difference in security posture (Fixed, Regressed, New)."""
    try:
        data_a = json.loads(scan_a.read_text(encoding="utf-8"))
        result_a = ScanResult.model_validate(data_a)
    except Exception as e:
        console.print(f"[red]Failed to load scan baseline {scan_a}: {e}[/red]")
        raise typer.Exit(code=1) from e

    try:
        data_b = json.loads(scan_b.read_text(encoding="utf-8"))
        result_b = ScanResult.model_validate(data_b)
    except Exception as e:
        console.print(f"[red]Failed to load scan current {scan_b}: {e}[/red]")
        raise typer.Exit(code=1) from e

    min_sev = None
    if severity:
        try:
            min_sev = Severity(severity.lower().strip())
        except ValueError:
            console.print(f"[red]Invalid severity: {severity}. Use: CRITICAL | HIGH | MEDIUM | LOW[/red]")
            raise typer.Exit(code=1) from None

    from crucible.core.differ import compute_diff
    diff_res = compute_diff(result_a, result_b)
    diff_res.scan_a_path = str(scan_a)
    diff_res.scan_b_path = str(scan_b)

    from crucible.reporters.diff_reporter import DiffReporter
    reporter = DiffReporter(
        show_unchanged=show_unchanged,
        module_filter=module,
        min_severity=min_sev,
    )

    if output:
        try:
            reporter.write(diff_res, output, format=format)
            console.print(f"[green]Diff report ({format}) saved to {output}[/green]")
        except Exception as e:
            console.print(f"[red]Failed to write diff report to {output}: {e}[/red]")
            raise typer.Exit(code=1) from e
    else:
        if format == "terminal":
            content = reporter.to_terminal(diff_res)
            console.print(content)
        elif format == "json":
            console.print(reporter.to_json(diff_res))
        elif format == "markdown":
            console.print(reporter.to_markdown(diff_res))
        elif format == "html":
            console.print(reporter.to_html(diff_res))
        else:
            console.print(f"[red]Unknown format: {format}. Use: terminal | json | html | markdown[/red]")
            raise typer.Exit(code=1)


@app.command()
def research(
    update: bool = typer.Option(
        False,
        "--update",
        help="Scrape all security feeds and update the local attack database.",
    ),
    query: str = typer.Option(
        "",
        "--query",
        "-q",
        help="Query the research store (e.g. 'SSRF', 'Prompt Injection', 'RCE').",
    ),
    severity: str = typer.Option(
        "",
        "--severity",
        "-s",
        help="Filter query by severity: CRITICAL | HIGH | MEDIUM | LOW.",
    ),
    provider: str = typer.Option(
        "gemini",
        "--provider",
        "-p",
        help="LLM provider for pattern extraction: gemini | openai | groq.",
    ),
    api_key: str = typer.Option(
        "",
        "--api-key",
        "-k",
        help="LLM API key (or set GEMINI_API_KEY / OPENAI_API_KEY / GROQ_API_KEY env var).",
    ),
    show_payloads: bool = typer.Option(
        False,
        "--show-payloads",
        help="Include extracted payloads in the output.",
    ),
    summary: bool = typer.Option(
        False,
        "--summary",
        help="Show a summary of the current research store.",
    ),
) -> None:
    """Deep research intelligence module — scrape, extract, and query security knowledge.

    Examples:

        # Update the local attack database from all security feeds
        crucible research --update

        # Query SSRF patterns from the store
        crucible research --query SSRF --show-payloads

        # Update with a specific LLM and show summary
        crucible research --update --provider gemini --api-key $GEMINI_API_KEY --summary
    """
    from crucible.attacks.dynamic_generator import DynamicAttackGenerator

    gen = DynamicAttackGenerator(
        provider=provider,
        api_key=api_key or None,
    )

    if update:
        console.print("\n[bold magenta]Crucible Deep Research Engine[/bold magenta]")
        console.print("[dim]Scraping security feeds...[/dim]\n")
        new_count = gen.refresh(verbose=True)
        console.print(
            f"\n[bold green]✓ Research database updated — {new_count} new attack templates added.[/bold green]"
        )

    if query:
        console.print(f"\n[bold cyan]Research Store Query: {query}[/bold cyan]")
        attacks = gen.get_attacks(
            vulnerability_class=query,
            severity=severity or None,
            limit=50,
        )

        if not attacks:
            console.print(
                "[yellow]No matching templates found. Run --update first.[/yellow]"
            )
        else:
            from rich.table import Table

            table = Table(title=f"Attack Templates — {query}", show_lines=True)
            table.add_column("ID", style="dim", width=10)
            table.add_column("Severity", width=10)
            table.add_column("Title", width=50)
            table.add_column("Source", width=20)

            for atk in attacks:
                sev_color = {
                    "CRITICAL": "bold red",
                    "HIGH": "red",
                    "MEDIUM": "yellow",
                    "LOW": "green",
                }.get(atk.severity.value.upper(), "white")

                table.add_row(
                    atk.name,
                    f"[{sev_color}]{atk.severity.value.upper()}[/{sev_color}]",
                    atk.title[:50],
                    atk.references[0][:30] if atk.references else "",
                )

            console.print(table)

            if show_payloads:
                payloads = gen.get_ssrf_payloads() if "ssrf" in query.lower() else []
                if payloads:
                    console.print("\n[bold]Extracted Payloads:[/bold]")
                    for p in payloads[:20]:
                        console.print(f"  [dim]•[/dim] {p}")

    if summary or (not update and not query):
        s = gen.summary()
        console.print("\n[bold]Research Store Summary[/bold]")
        console.print(f"  Total Templates : [cyan]{s['total_templates']}[/cyan]")
        console.print(f"  Store Path      : [dim]{s['store_path']}[/dim]")

        if s["by_vulnerability_class"]:
            console.print("\n  [bold]By Vulnerability Class:[/bold]")
            for cls, count in sorted(
                s["by_vulnerability_class"].items(), key=lambda x: -x[1]
            ):
                console.print(f"    {cls:<30} {count}")

        if s["by_severity"]:
            console.print("\n  [bold]By Severity:[/bold]")
            for sev, count in sorted(s["by_severity"].items()):
                console.print(f"    {sev:<15} {count}")


@app.command()
def fingerprint(
    target: str = typer.Option(
        ...,
        "--target",
        "-t",
        help="Target agent URL.",
    ),
    method: str = typer.Option(
        "POST",
        "--method",
        "-m",
        help="HTTP method (GET, POST, etc.).",
    ),
    header: list[str] | None = typer.Option(
        None,
        "--header",
        "-H",
        help="Headers as 'Key: Value' (repeatable).",
    ),
    body_template: str = typer.Option(
        '{"message": "{payload}"}',
        "--body",
        "-b",
        help="JSON body template with {payload} placeholder.",
    ),
    timeout: float = typer.Option(
        30.0,
        "--timeout",
        help="Request timeout in seconds.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show live probe details.",
    ),
) -> None:
    """[v0.5] Profile an AI agent's psychological and technical refusal boundaries."""
    from crucible.core.adaptive_fingerprinter import AdaptiveBehavioralFingerprinter

    # Needs to match how scan handles headers
    parsed_headers = {}
    if header:
        for h in header:
            if ":" in h:
                k, v = h.split(":", 1)
                parsed_headers[k.strip()] = v.strip()

    agent_target = AgentTarget(
        name="target",
        url=target,  # type: ignore[arg-type]
        method=method,
        headers=parsed_headers,
        body_template=body_template,
        timeout=timeout,
    )

    async def run_fingerprint() -> None:
        async with httpx.AsyncClient() as client:
            fingerprinter = AdaptiveBehavioralFingerprinter(
                target=agent_target, client=client, verbose=verbose
            )
            fp = await fingerprinter.run_profiling()

            console.print("\n[bold cyan]=== Behavioral Fingerprint ===[/bold cyan]")
            console.print(
                f"Refusal Threshold: [yellow]{fp.refusal_threshold:.2f}[/yellow]"
            )
            console.print(
                f"Persona Stability: [yellow]{fp.persona_stability:.2f}[/yellow]"
            )

            if sensitivities := fp.topic_sensitivities:
                console.print("\n[bold]Topic Sensitivities (Refusal Rates):[/bold]")
                for topic, rate in sensitivities.items():
                    console.print(f"  - {topic}: {rate:.2%}")

            if fp.vulnerable_topics:
                console.print(
                    "\n[bold red]Vulnerable Topics (Failed expected refusal):[/bold red]"
                )
                for topic in fp.vulnerable_topics:
                    console.print(f"  - {topic}")
            else:
                console.print(
                    "\n[bold green]No critical boundary failures detected.[/bold green]"
                )

    anyio.run(run_fingerprint)


@app.command()
def patch(
    report: Path = typer.Option(
        ...,
        "--report",
        "-r",
        help="Path to the JSON scan report.",
    ),
    repo: Path = typer.Option(
        Path("."),
        "--repo",
        help="Path to the repository to patch.",
    ),
    github_token: str | None = typer.Option(
        None,
        "--github-token",
        envvar="GITHUB_TOKEN",
        help="GitHub token for opening PRs.",
    ),
) -> None:
    """[v0.7] Auto-remediate vulnerabilities by patching the source code."""
    from crucible.core.patcher import AutoRemediationEngine, GitIntegrator

    if not report.exists():
        console.print(f"[red]Error: Report file {report} not found.[/red]")
        raise typer.Exit(1)

    try:
        with open(report, encoding="utf-8") as f:
            data = json.load(f)
            scan_result = ScanResult(**data)
    except Exception as e:
        console.print(f"[red]Error parsing report: {e}[/red]")
        raise typer.Exit(1) from None

    patcher = AutoRemediationEngine(repo_path=str(repo), github_token=github_token)
    integrator = GitIntegrator(repo_path=str(repo), github_token=github_token)

    console.print(
        f"[*] Analyzing {len(scan_result.get_failed_findings())} failed findings for remediation..."
    )

    patches_applied = 0
    for finding in scan_result.get_failed_findings():
        success = patcher.generate_patch(finding)
        if success:
            patches_applied += 1
            console.print(f"  [green][+][/green] Applied patch for: {finding.title}")

    if patches_applied > 0:
        branch = f"crucible-fix-{scan_result.id[:8]}"
        integrator.create_pr(
            branch_name=branch,
            title=f"Security: Auto-remediation for Crucible scan {scan_result.id[:8]}",
            body="This PR was automatically generated by Crucible to fix identified security vulnerabilities.",
        )
        console.print(
            f"\n[bold green]Success: Applied {patches_applied} patches and pushed branch {branch}.[/bold green]"
        )
    else:
        console.print(
            "\n[yellow]No patches could be automatically generated for the current findings.[/yellow]"
        )


@app.command()
def canary(
    type: str = typer.Option(
        "aws",
        "--type",
        "-t",
        help="Canary type: aws | dns | generic.",
    ),
    topic: str = typer.Option(
        "internal_config",
        "--topic",
        help="Topic for generic poison pills.",
    ),
) -> None:
    """[v0.7] Generate active deception canaries to detect data exfiltration."""
    from crucible.core.canary import CanaryGenerator

    gen = CanaryGenerator()
    token = None

    if type == "aws":
        token = gen.generate_aws_canary()
    elif type == "dns":
        token = gen.generate_dns_canary()
    else:
        token = gen.generate_poison_pill(topic)

    console.print(
        f"\n[bold cyan]=== Crucible Canary Generated [{token.id}] ===[/bold cyan]"
    )
    console.print(f"Type: [yellow]{token.type}[/yellow]")
    console.print(f"Created: {token.created_at}")
    console.print("\n[bold]Content to inject into Agent context:[/bold]")
    console.print(f"[magenta]{token.content}[/magenta]")
    console.print(
        "\n[dim]Note: Monitor for this token to detect exfiltration attempts.[/dim]"
    )


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", help="Host to bind the API to."),
    port: int = typer.Option(8000, help="Port to bind the API to."),
) -> None:
    """[v0.7] Launch the Crucible Sovereign API for the SaaS dashboard."""
    import uvicorn

    from crucible.core.api import app as fastapi_app

    console.print(
        f"[*] Launching Crucible Sovereign API on [cyan]{host}:{port}[/cyan]..."
    )
    uvicorn.run(fastapi_app, host=host, port=port)


@app.command(name="mcp-scan")
def mcp_scan(
    server: str = typer.Option(
        ...,
        "--server",
        "-s",
        help="URL of the MCP server to audit (e.g. https://my-mcp.example.com).",
    ),
    header: list[str] | None = typer.Option(
        None,
        "--header",
        "-H",
        help="Headers as 'Key: Value' (repeatable). Useful for auth tokens.",
    ),
    timeout: float = typer.Option(
        10.0,
        "--timeout",
        help="HTTP request timeout in seconds.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Save JSON results to this path.",
    ),
) -> None:
    """[v0.4] Audit an MCP server for tool poisoning, command injection, and excessive OAuth scopes.

    Maps every finding to the OWASP MCP Top 10.

    \\b
    Tests run (10 total):
      MCP-T01  Tool poisoning — hidden instructions in descriptions
      MCP-T02  Tool poisoning — hidden instructions in tool names
      MCP-T03  Command injection — shell sequences in descriptions
      MCP-T04  Command injection — shell sequences in parameter schemas
      MCP-T05  Excessive OAuth — wildcard file/db scopes (files:*, db:*)
      MCP-T06  Excessive OAuth — admin/full-access scopes (admin:*)
      MCP-T07  Excessive agency — dangerous tool names (exec, shell, sudo…)
      MCP-T08  Sensitive data exposure in tool descriptions
      MCP-T09  Unrestricted tool parameter schemas (no type/enum/pattern)
      MCP-T10  Tools registered without descriptions

    Examples:

        crucible mcp-scan --server https://my-mcp.example.com

        crucible mcp-scan --server http://localhost:3000 --header "Authorization: Bearer sk-xxx"
    """
    from crucible.core.mcp_scanner import McpScanner

    parsed_headers = _parse_headers(header)

    console.print()
    console.print("[bold magenta]CRUCIBLE[/bold magenta] — MCP Server Security Scan")
    console.print(f"[dim]Target: {server}[/dim]")
    console.print()

    # --- Fetch the MCP manifest ------------------------------------------------
    manifest: dict[str, Any] = {}
    try:
        from crucible.core.mcp_scanner import load_manifest

        manifest = load_manifest(server, headers=parsed_headers, timeout=timeout)
    except httpx.HTTPStatusError as exc:
        console.print(
            f"[bold red]Error: MCP server returned HTTP {exc.response.status_code}.[/bold red]"
        )
        raise typer.Exit(code=2) from None
    except httpx.RequestError as exc:
        console.print(
            f"[bold red]Error: Could not reach MCP server ({exc}).[/bold red]"
        )
        raise typer.Exit(code=2) from None
    except Exception as exc:
        console.print(
            f"[bold red]Error: Failed to parse MCP manifest ({exc}).[/bold red]"
        )
        raise typer.Exit(code=2) from None

    # --- Run scanner -----------------------------------------------------------
    scanner = McpScanner(server_url=server, manifest=manifest)
    result = scanner.run()

    # --- Render results --------------------------------------------------------
    from rich.table import Table

    table = Table(
        title="MCP Security Scan Results",
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("ID", style="dim", width=10)
    table.add_column("Severity", width=10)
    table.add_column("Status", width=8)
    table.add_column("Title", width=52)
    table.add_column("OWASP Ref", width=40)
    table.add_column("Evidence", width=30)

    _sev_styles = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
    }
    for f in result.findings:
        status_str = "[green]PASS[/green]" if f.passed else "[bold red]FAIL[/bold red]"
        sev_style = _sev_styles.get(f.severity, "white")
        table.add_row(
            f.test_id,
            f"[{sev_style}]{f.severity}[/{sev_style}]",
            status_str,
            f.title,
            f.owasp_ref,
            f.evidence[:28] + "…" if len(f.evidence) > 28 else f.evidence,
        )

    console.print(table)

    # Score / grade summary
    grade_color = {
        "A": "bold green",
        "B": "green",
        "C": "yellow",
        "D": "red",
        "F": "bold red",
    }.get(result.grade, "white")

    console.print()
    console.print(
        f"Score: [bold]{result.score:.0f}/100[/bold]  "
        f"Grade: [{grade_color}]{result.grade}[/{grade_color}]  "
        f"Passed: [green]{result.passed}[/green]  "
        f"Failed: [red]{result.failed}[/red]  "
        f"Total: {result.total_tests}"
    )

    # Remediation hints for failures
    failures = [f for f in result.findings if not f.passed]
    if failures:
        console.print()
        console.print("[bold]Remediation Guidance:[/bold]")
        for f in failures:
            console.print(
                f"  [{_sev_styles.get(f.severity, 'white')}]{f.test_id}[/] — {f.remediation}"
            )

    # Optional JSON output
    if output:
        import json as _json

        data = {
            "server": result.server_url,
            "score": result.score,
            "grade": result.grade,
            "total_tests": result.total_tests,
            "passed": result.passed,
            "failed": result.failed,
            "findings": [
                {
                    "test_id": f.test_id,
                    "title": f.title,
                    "severity": f.severity,
                    "owasp_ref": f.owasp_ref,
                    "passed": f.passed,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                }
                for f in result.findings
            ],
        }
        output.write_text(_json.dumps(data, indent=2), encoding="utf-8")
        console.print(f"\n[green]JSON report saved to {output}[/green]")


if __name__ == "__main__":
    app()
