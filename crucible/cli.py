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
    skip_preflight: bool = typer.Option(
        False,
        "--skip-preflight",
        help="Skip preflight endpoint check (useful for rate-limited or non-standard targets).",
    ),
    confidence: bool = typer.Option(
        False,
        "--confidence",
        help="Run each attack N times and compute bootstrap confidence intervals.",
    ),
    samples: int = typer.Option(
        5,
        "--samples",
        min=1,
        max=20,
        help="Number of times each attack is run in --confidence mode (default: 5, max: 20).",
    ),
    dynamic_payloads: bool = typer.Option(
        False,
        "--dynamic-payloads",
        help="Generate novel attack variants dynamically using an LLM.",
    ),
    generator_endpoint: str | None = typer.Option(
        None,
        "--generator-endpoint",
        help="HTTP endpoint of the generator LLM (e.g. http://localhost:11434).",
    ),
    generator_model: str | None = typer.Option(
        None,
        "--generator-model",
        help="Model name for the generator LLM.",
    ),
    generator_format_preset: str | None = typer.Option(
        None,
        "--generator-format-preset",
        help="Body format preset for the generator (e.g. ollama, openai).",
    ),
    dynamic_count: int = typer.Option(
        10,
        "--dynamic-count",
        help="Number of dynamic payloads to generate per attack.",
    ),
    dynamic_seed: int | None = typer.Option(
        None,
        "--dynamic-seed",
        help="Random seed for deterministic dynamic generation.",
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

            if dynamic_payloads:
                if format not in ["json", "html"] and not quiet:
                    console.print(
                        f"[yellow]⚠ Dynamic payload generation enabled: generating {dynamic_count} novel\n"
                        f" variants per module using {generator_model or 'generator'}. This will increase scan time.\n"
                        f" Static payloads run first for deterministic baseline coverage.[/yellow]\n"
                    )

            from crucible.core.runner import _PreflightError

            try:
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
                    skip_preflight,
                    confidence,
                    samples,
                    dynamic_payloads,
                    generator_endpoint,
                    generator_model,
                    generator_format_preset,
                    dynamic_count,
                    dynamic_seed,
                )
            except _PreflightError as exc:
                pf = exc.result
                msg = pf.errors[0] if pf.errors else "Preflight check failed."
                console.print(f"[bold red]\u2717 Preflight failed: {msg}[/bold red]")
                console.print(
                    "[dim]Tip: Use --skip-preflight to bypass this check.[/dim]"
                )
                raise typer.Exit(code=2) from exc

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
        console.print(
            f"[green]EU AI Act compliance report generated at {output}[/green]"
        )

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
        console.print(
            f"[red]Unknown framework: {framework!r}. Use: eu | atlas | nist | all[/red]"
        )
        raise typer.Exit(code=1)


@app.command()
def diff(
    scan_a: Path = typer.Argument(..., help="Path to baseline scan results JSON."),
    scan_b: Path = typer.Argument(..., help="Path to current scan results JSON."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Save diff report to file."
    ),
    format: str = typer.Option(
        "terminal",
        "--format",
        "-f",
        help="Diff report format: terminal | json | html | markdown",
    ),
    show_unchanged: bool = typer.Option(
        False,
        "--show-unchanged",
        help="Include UNCHANGED_PASS findings (default: hidden).",
    ),
    module: str | None = typer.Option(
        None, "--module", "-m", help="Filter diff to a specific module."
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        "-s",
        help="Filter diff by severity: CRITICAL | HIGH | MEDIUM | LOW",
    ),
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
            console.print(
                f"[red]Invalid severity: {severity}. Use: CRITICAL | HIGH | MEDIUM | LOW[/red]"
            )
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
            console.print(
                f"[red]Unknown format: {format}. Use: terminal | json | html | markdown[/red]"
            )
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


# ---------------------------------------------------------------------------
# crucible watch sub-app (Phase 4)
# ---------------------------------------------------------------------------

watch_app = typer.Typer(
    name="watch",
    help="Monitor an AI agent for behavioral drift over time.",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)
app.add_typer(watch_app, name="watch")


def _build_agent_target_for_watch(
    target: str,
    name: str,
    method: str,
    header: list[str] | None,
    body_template: str,
    format_preset: str,
    model: str,
    response_path: str,
    timeout: float,
    proxy: str,
) -> AgentTarget:
    """Build an AgentTarget from the common watch CLI options."""
    parsed_headers = _parse_headers(header)
    resolved_body = body_template
    resolved_response_path = response_path
    resolved_timeout = timeout

    if format_preset:
        if format_preset not in PROVIDER_PRESETS:
            console.print(
                f"[red]Unknown format preset: {format_preset}. "
                f"Available: {', '.join(PROVIDER_PRESETS.keys())}[/red]"
            )
            raise typer.Exit(code=1)
        preset = PROVIDER_PRESETS[format_preset]
        if body_template == _DEFAULT_BODY_TEMPLATE:
            resolved_body = preset.body_template.replace("{model}", model)
        if not response_path:
            resolved_response_path = preset.response_path
        if timeout == 30.0:
            resolved_timeout = preset.default_timeout
        if preset.extra_headers:
            for k, v in preset.extra_headers.items():
                if k not in parsed_headers:
                    parsed_headers[k] = v
        if preset.url_suffix and not target.rstrip("/").endswith(
            preset.url_suffix.rstrip("/")
        ):
            target = target.rstrip("/") + preset.url_suffix

    return AgentTarget(
        name=name,
        url=target,  # type: ignore[arg-type]
        method=method,
        headers=parsed_headers,
        body_template=resolved_body,
        timeout=resolved_timeout,
        response_path=resolved_response_path,
        proxy=proxy,
    )


_WATCH_TARGET_OPT = typer.Option(
    ..., "--target", "-t", help="Target URL of the AI agent endpoint."
)
_WATCH_NAME_OPT = typer.Option(
    "target-agent", "--name", "-n", help="Human-readable name."
)
_WATCH_METHOD_OPT = typer.Option("POST", "--method", "-m", help="HTTP method.")
_WATCH_HEADER_OPT = typer.Option(
    None, "--header", "-H", help="Headers as 'Key: Value' (repeatable)."
)
_WATCH_BODY_OPT = typer.Option(
    _DEFAULT_BODY_TEMPLATE, "--body", "-b", help="JSON body template."
)
_WATCH_PRESET_OPT = typer.Option(
    "", "--format-preset", help="Body format preset (openai, ollama, etc.)."
)
_WATCH_MODEL_OPT = typer.Option(
    "llama3", "--model", help="Model name for presets that require it."
)
_WATCH_RPATH_OPT = typer.Option(
    "", "--response-path", help="JMESPath to extract LLM response."
)
_WATCH_TIMEOUT_OPT = typer.Option(30.0, "--timeout", help="Request timeout in seconds.")
_WATCH_PROXY_OPT = typer.Option("", "--proxy", help="HTTP proxy URL.")
_WATCH_SKIP_PF_OPT = typer.Option(
    False, "--skip-preflight", help="Skip preflight endpoint check."
)


@watch_app.command("set-baseline")
def watch_set_baseline(
    target: str = _WATCH_TARGET_OPT,
    name: str = _WATCH_NAME_OPT,
    method: str = _WATCH_METHOD_OPT,
    header: list[str] | None = _WATCH_HEADER_OPT,
    body_template: str = _WATCH_BODY_OPT,
    format_preset: str = _WATCH_PRESET_OPT,
    model: str = _WATCH_MODEL_OPT,
    response_path: str = _WATCH_RPATH_OPT,
    timeout: float = _WATCH_TIMEOUT_OPT,
    proxy: str = _WATCH_PROXY_OPT,
    skip_preflight: bool = _WATCH_SKIP_PF_OPT,
) -> None:
    """Run a full scan and store the result as the behavioral baseline."""
    agent_target = _build_agent_target_for_watch(
        target,
        name,
        method,
        header,
        body_template,
        format_preset,
        model,
        response_path,
        timeout,
        proxy,
    )
    from crucible.core.watcher import set_baseline

    anyio.run(set_baseline, agent_target, skip_preflight)


@watch_app.command("check")
def watch_check(
    target: str = _WATCH_TARGET_OPT,
    name: str = _WATCH_NAME_OPT,
    method: str = _WATCH_METHOD_OPT,
    header: list[str] | None = _WATCH_HEADER_OPT,
    body_template: str = _WATCH_BODY_OPT,
    format_preset: str = _WATCH_PRESET_OPT,
    model: str = _WATCH_MODEL_OPT,
    response_path: str = _WATCH_RPATH_OPT,
    timeout: float = _WATCH_TIMEOUT_OPT,
    proxy: str = _WATCH_PROXY_OPT,
    drift_threshold: float = typer.Option(
        0.15, "--drift-threshold", help="Behavioral drift alert threshold (0–1)."
    ),
    score_threshold: float = typer.Option(
        10.0, "--score-threshold", help="Score-drop alert threshold (points)."
    ),
    slack_webhook: str | None = typer.Option(
        None, "--slack-webhook", help="Slack webhook URL for alerts."
    ),
    fail_on_alert: bool = typer.Option(
        False, "--fail-on-alert", help="Exit code 1 if an alert fires."
    ),
    skip_preflight: bool = _WATCH_SKIP_PF_OPT,
) -> None:
    """Run a single watch check and compare against the stored baseline."""
    from crucible.core.watcher import CrucibleWatcher
    from crucible.models import WatchConfig, WatchInterval

    agent_target = _build_agent_target_for_watch(
        target,
        name,
        method,
        header,
        body_template,
        format_preset,
        model,
        response_path,
        timeout,
        proxy,
    )
    config = WatchConfig(
        target=agent_target,
        interval=WatchInterval.ONE_HOUR,
        drift_threshold=drift_threshold,
        score_threshold=score_threshold,
        alert_slack_webhook=slack_webhook,
        fail_on_alert=fail_on_alert,
        skip_preflight=skip_preflight,
    )
    watcher = CrucibleWatcher(config)

    async def _run() -> None:
        try:
            result = await watcher.run_one_check()
            if result.alert_fired and fail_on_alert:
                raise typer.Exit(code=1)
        except RuntimeError as exc:
            console.print(f"[red]✗ {exc}[/red]")
            raise typer.Exit(code=2) from exc

    anyio.run(_run)


@watch_app.command("start")
def watch_start(
    target: str = _WATCH_TARGET_OPT,
    name: str = _WATCH_NAME_OPT,
    method: str = _WATCH_METHOD_OPT,
    header: list[str] | None = _WATCH_HEADER_OPT,
    body_template: str = _WATCH_BODY_OPT,
    format_preset: str = _WATCH_PRESET_OPT,
    model: str = _WATCH_MODEL_OPT,
    response_path: str = _WATCH_RPATH_OPT,
    timeout: float = _WATCH_TIMEOUT_OPT,
    proxy: str = _WATCH_PROXY_OPT,
    interval: str = typer.Option(
        "1h", "--interval", help="Check interval: 5m|15m|1h|6h|12h|24h."
    ),
    drift_threshold: float = typer.Option(
        0.15, "--drift-threshold", help="Behavioral drift alert threshold (0–1)."
    ),
    score_threshold: float = typer.Option(
        10.0, "--score-threshold", help="Score-drop alert threshold (points)."
    ),
    slack_webhook: str | None = typer.Option(
        None, "--slack-webhook", help="Slack webhook URL for alerts."
    ),
    fail_on_alert: bool = typer.Option(
        False, "--fail-on-alert", help="Exit code 1 if an alert fires."
    ),
    skip_preflight: bool = _WATCH_SKIP_PF_OPT,
) -> None:
    """Start the watch daemon. Runs continuously until Ctrl+C."""
    from crucible.core.watcher import CrucibleWatcher
    from crucible.models import WatchConfig, WatchInterval

    try:
        watch_interval = WatchInterval(interval)
    except ValueError as err:
        console.print(
            f"[red]Invalid interval: {interval}. "
            f"Choose from: {', '.join(i.value for i in WatchInterval)}[/red]"
        )
        raise typer.Exit(code=1) from err

    agent_target = _build_agent_target_for_watch(
        target,
        name,
        method,
        header,
        body_template,
        format_preset,
        model,
        response_path,
        timeout,
        proxy,
    )
    config = WatchConfig(
        target=agent_target,
        interval=watch_interval,
        drift_threshold=drift_threshold,
        score_threshold=score_threshold,
        alert_slack_webhook=slack_webhook,
        fail_on_alert=fail_on_alert,
        skip_preflight=skip_preflight,
    )
    watcher = CrucibleWatcher(config)
    anyio.run(watcher.start)


@watch_app.command("status")
def watch_status() -> None:
    """Show the status of recent watch sessions by reading the watch log."""
    import json as _json

    from crucible.core.watch_store import WATCH_LOG

    if not WATCH_LOG.exists():
        console.print("[yellow]No watch log found at[/yellow] " + str(WATCH_LOG))
        console.print("Run [bold]crucible watch start[/bold] to begin watching.")
        return

    entries = []
    with WATCH_LOG.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                with contextlib.suppress(_json.JSONDecodeError):
                    entries.append(_json.loads(line))

    if not entries:
        console.print("[yellow]Watch log is empty.[/yellow]")
        return

    last = entries[-1]
    total_checks = len(entries)
    total_alerts = sum(1 for e in entries if e.get("alert_fired"))
    last_check = last.get("checked_at", "unknown")[:19] + "Z"
    last_score = last.get("current_score")
    baseline_score = last.get("baseline_score")

    console.print("\n[bold cyan]Crucible Watch Status[/bold cyan]")
    console.print(f"  Log file       : [dim]{WATCH_LOG}[/dim]")
    console.print(f"  Total checks   : {total_checks}")
    console.print(
        f"  Total alerts   : {'[red]' if total_alerts else ''}{total_alerts}{'[/red]' if total_alerts else ''}"
    )
    console.print(f"  Last check     : {last_check}")
    if last_score is not None:
        console.print(f"  Last score     : {last_score:.1f}")
    if baseline_score is not None:
        console.print(f"  Baseline score : {baseline_score:.1f}")

    # Show last 5 entries
    console.print("\n[bold]Recent checks:[/bold]")
    for entry in entries[-5:]:
        ts = entry.get("checked_at", "")[:19] + "Z"
        score = entry.get("current_score", 0.0)
        delta = entry.get("score_delta", 0.0)
        fired = entry.get("alert_fired", False)
        delta_str = f"{delta:+.1f}"
        color = "red" if fired else ("yellow" if delta < 0 else "green")
        alert_tag = " [red][ALERT][/red]" if fired else ""
        console.print(
            f"  {ts}  score={score:.1f} " f"([{color}]{delta_str}[/{color}]){alert_tag}"
        )


@watch_app.command("list-baselines")
def watch_list_baselines() -> None:
    """List all stored baselines."""
    from crucible.core.watch_store import WatchStore

    store = WatchStore()
    baselines = store.list_baselines()

    if not baselines:
        console.print("[yellow]No baselines stored.[/yellow]")
        console.print(
            "Run [bold]crucible watch set-baseline --target <URL>[/bold] to create one."
        )
        return

    console.print(f"\n[bold cyan]Stored Baselines ({len(baselines)})[/bold cyan]\n")
    for bl in baselines:
        grade = bl.scan_result.grade.value if bl.scan_result.grade else "N/A"
        score = bl.scan_result.overall_score
        console.print(
            f"  [cyan]{bl.target_url}[/cyan]\n"
            f"    Created : {bl.created_at[:19]}Z\n"
            f"    Score   : {score:.1f}  Grade: {grade}\n"
            f"    Version : {bl.version}\n"
        )


@watch_app.command("delete-baseline")
def watch_delete_baseline(
    target: str = _WATCH_TARGET_OPT,
) -> None:
    """Delete the stored baseline for a target."""
    from crucible.core.watch_store import WatchStore

    store = WatchStore()
    deleted = store.delete_baseline(target)
    if deleted:
        console.print(f"[green]✓ Baseline deleted for {target}[/green]")
    else:
        console.print(f"[yellow]No baseline found for {target}[/yellow]")


# =============================================================================
# crucible trace — MCP tool-call interception proxy (v0.7.0)
# =============================================================================

trace_app = typer.Typer(
    name="trace",
    help="Intercept and audit MCP tool calls in transit.",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)
app.add_typer(trace_app, name="trace")


@trace_app.command("validate-policy")
def trace_validate_policy(
    policy: Path = typer.Option(
        ...,
        "--policy",
        "-p",
        help="Path to the policy YAML file to validate.",
        exists=False,  # we validate existence ourselves for a friendlier error
    ),
) -> None:
    """Validate a trace policy YAML file.

    Exits 0 if the policy is valid, 1 if there are any errors.
    Regex patterns are compiled at validation time so bad patterns are caught.
    """
    from crucible.trace.policy import PolicyError, load_policy

    try:
        loaded = load_policy(policy)
        console.print(
            f"[green]✓ Policy OK[/green] — {len(loaded.rules)} rule(s), "
            f"default action: [bold]{loaded.default_action.value}[/bold]"
        )
        for rule in loaded.rules:
            action_colour = {
                "allow": "green",
                "deny": "red",
                "alert": "yellow",
            }.get(rule.action.value, "white")
            parts = [f"[{action_colour}]{rule.action.value.upper()}[/{action_colour}]"]
            if rule.tool_name:
                parts.append(f"tool={rule.tool_name!r}")
            if rule.parameter_pattern:
                parts.append(f"pattern={rule.parameter_pattern!r}")
            console.print(f"  • {rule.name}: {' '.join(parts)}")
    except PolicyError as exc:
        console.print(f"[red]✗ Policy invalid:[/red] {exc}")
        raise typer.Exit(code=1) from exc


@trace_app.command("report")
def trace_report(
    log: Path = typer.Option(
        Path("crucible_trace.jsonl"),
        "--log",
        "-l",
        help="Path to the JSONL audit log file.",
    ),
) -> None:
    """Display a formatted report of the trace audit log.

    Reads the JSONL file and renders a Rich table:
      Time | Tool | Caller IP | Action | Rule Matched | Latency (ms)

    Exits 1 if the log file does not exist.
    """
    from rich.table import Table

    from crucible.trace.audit_log import AuditLog
    from crucible.trace.models import PolicyAction

    if not log.exists():
        console.print(f"[red]✗ Log file not found:[/red] {log}")
        raise typer.Exit(code=1)

    audit = AuditLog(log)
    entries = audit.read_all()

    if not entries:
        console.print("[yellow]Log file is empty — no entries to display.[/yellow]")
        return

    table = Table(
        title=f"Crucible Trace Report — {log}",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("Time (UTC)", style="dim", min_width=19)
    table.add_column("Tool", min_width=12)
    table.add_column("Caller IP", min_width=12)
    table.add_column("Action", min_width=7)
    table.add_column("Rule Matched", min_width=16)
    table.add_column("Latency (ms)", min_width=12, justify="right")

    _action_style = {
        PolicyAction.ALLOW: "green",
        PolicyAction.DENY: "bold red",
        PolicyAction.ALERT: "yellow",
    }

    total = len(entries)
    tool_calls = sum(1 for e in entries if e.tool_name is not None)
    denied = sum(1 for e in entries if e.policy_action == PolicyAction.DENY)
    alerts = sum(1 for e in entries if e.policy_action == PolicyAction.ALERT)

    for entry in entries:
        ts = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        tool = entry.tool_name or "[dim]—[/dim]"
        action_style = _action_style.get(entry.policy_action, "white")
        action_text = (
            f"[{action_style}]{entry.policy_action.value.upper()}[/{action_style}]"
        )
        rule = entry.policy_rule_matched or "[dim]default[/dim]"
        latency = (
            f"{entry.upstream_latency_ms:.1f}"
            if entry.upstream_latency_ms is not None
            else "[dim]—[/dim]"
        )
        table.add_row(ts, tool, entry.caller_ip, action_text, rule, latency)

    console.print(table)
    console.print(
        f"\n[bold]Summary:[/bold] {total} request(s) | "
        f"{tool_calls} tool call(s) | "
        f"[red]{denied} denied[/red] | "
        f"[yellow]{alerts} alert(s)[/yellow]"
    )


@trace_app.command("start")
def trace_start(
    upstream: str = typer.Option(
        ...,
        "--upstream",
        "-u",
        help="URL of the upstream MCP server to proxy to (e.g. http://localhost:3000).",
    ),
    listen_port: int = typer.Option(
        8080,
        "--listen",
        "-l",
        help="TCP port to listen on.",
    ),
    listen_host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Interface to bind (use 0.0.0.0 for all interfaces).",
    ),
    policy: Path | None = typer.Option(
        None,
        "--policy",
        "-p",
        help="Path to the YAML policy file.  If omitted, all traffic is forwarded (allow-all mode).",
    ),
    log: Path = typer.Option(
        Path("crucible_trace.jsonl"),
        "--log",
        help="Path to the JSONL audit log file (append-only).",
    ),
    tls: bool = typer.Option(
        False,
        "--tls/--no-tls",
        help="Enable TLS on the listening socket (agent \u2192 proxy hop).",
    ),
    tls_cert: Path | None = typer.Option(
        None,
        "--tls-cert",
        help="Path to a PEM certificate file.  Required when --tls is set unless --tls-self-signed is used.",
    ),
    tls_key: Path | None = typer.Option(
        None,
        "--tls-key",
        help="Path to a PEM private key file.  Required when --tls is set unless --tls-self-signed is used.",
    ),
    tls_self_signed: bool = typer.Option(
        False,
        "--tls-self-signed",
        help="Auto-generate a self-signed RSA 2048 certificate for development/testing.  Implies --tls.",
    ),
    tls_handshake_timeout: float = typer.Option(
        30.0,
        "--tls-handshake-timeout",
        help="Seconds to wait for the TLS handshake before dropping the connection (default: 30).",
    ),
) -> None:
    """Start the crucible trace proxy.

    Listens for MCP JSON-RPC traffic on --listen, evaluates tools/call
    requests against --policy, and writes every decision to --log.

    \b
    TLS (v0.8.x):
      --tls --tls-cert cert.pem --tls-key key.pem   load an existing cert
      --tls --tls-self-signed                        auto-generate a dev cert

    Press Ctrl+C to stop.  A summary is printed on exit.
    """
    import tempfile

    from crucible.trace.audit_log import AuditLog
    from crucible.trace.policy import PolicyError, load_policy
    from crucible.trace.proxy import TraceProxy

    # --- Resolve TLS settings ---
    _tls_active = tls or tls_self_signed
    _tls_cert: Path | None = tls_cert
    _tls_key: Path | None = tls_key

    if _tls_active:
        if tls_self_signed:
            from crucible.trace.tls_utils import generate_self_signed

            _tmp_tls_dir = Path(tempfile.mkdtemp(prefix="crucible_tls_"))
            _tls_cert, _tls_key = generate_self_signed(_tmp_tls_dir)
            console.print(
                f"[green]\u2713 Self-signed cert generated:[/green] {_tls_cert}"
            )
        elif _tls_cert is None or _tls_key is None:
            console.print(
                "[red]\u2717 TLS error:[/red] --tls requires either "
                "--tls-cert + --tls-key, or --tls-self-signed."
            )
            raise typer.Exit(code=1)

    # --- Load policy ---
    loaded_policy = None
    if policy is not None:
        try:
            loaded_policy = load_policy(policy)
            console.print(
                f"[green]✓ Policy loaded:[/green] {policy} "
                f"({len(loaded_policy.rules)} rule(s))"
            )
        except PolicyError as exc:
            console.print(f"[red]✗ Policy error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
    else:
        console.print(
            "[yellow]⚠  No policy file specified — running in allow-all mode.[/yellow]"
        )

    # --- Startup banner ---
    scheme = "https" if _tls_active else "http"
    tls_label = (
        "[green]\u2713 TLS enabled (self-signed)[/green]"
        if tls_self_signed
        else (
            "[green]\u2713 TLS enabled[/green]"
            if _tls_active
            else "[dim]plain HTTP[/dim]"
        )
    )
    console.print(
        f"\n[bold cyan]crucible trace[/bold cyan] v{__version__} starting\n"
        f"  [dim]upstream :[/dim] {upstream}\n"
        f"  [dim]listen   :[/dim] {scheme}://{listen_host}:{listen_port}\n"
        f"  [dim]TLS      :[/dim] {tls_label}\n"
        f"  [dim]log      :[/dim] {log}\n"
        f"  [dim]policy   :[/dim] {policy or 'allow-all'}\n"
    )
    console.print("Press [bold]Ctrl+C[/bold] to stop.\n")

    # --- Run proxy ---
    audit_log = AuditLog(log)
    proxy = TraceProxy(
        upstream=upstream,
        policy=loaded_policy,
        audit_log=audit_log,
        listen_host=listen_host,
        listen_port=listen_port,
        tls_cert=_tls_cert,
        tls_key=_tls_key,
        tls_handshake_timeout=tls_handshake_timeout,
    )

    with contextlib.suppress(KeyboardInterrupt):
        anyio.run(proxy.serve, backend="asyncio")

    counters = proxy.counters
    console.print(
        f"\n[bold]crucible trace stopped.[/bold]  "
        f"{counters['total']} request(s) proxied | "
        f"[red]{counters['denied']} denied[/red] | "
        f"[yellow]{counters['alerts']} alert(s)[/yellow] | "
        f"[green]{counters['allowed']} allowed[/green]"
    )


# =============================================================================
# crucible poison-test — Memory and RAG poisoning evaluation (v0.8.0)
# =============================================================================

poison_app = typer.Typer(
    name="poison-test",
    help="Evaluate autonomous agents for memory and RAG poisoning vulnerabilities.",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)
app.add_typer(poison_app, name="poison-test")


@poison_app.command("plant")
def poison_plant(
    target: str = typer.Option(
        ...,
        "--target",
        "-t",
        help="Target URL of the agent system.",
    ),
    memory_type: str = typer.Option(
        "rag",
        "--memory-type",
        "-m",
        help="Target memory type: rag | episodic | semantic | unknown",
    ),
    topic: str = typer.Option(
        ...,
        "--topic",
        help="The business topic/subject of the poisoning.",
    ),
    technique: int = typer.Option(
        1,
        "--technique",
        help="The document generation technique (1 to 4).",
    ),
    trigger: str = typer.Option(
        ...,
        "--trigger",
        help="The query/trigger that should activate the poison.",
    ),
    session_id: str | None = typer.Option(
        None,
        "--session-id",
        help="Custom session ID (auto-generated if omitted).",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Optional path to save the plant record JSON.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite session record if session-id already exists.",
    ),
) -> None:
    """Generate a poisoned document and plant/store it.

    Creates a session record containing the generated document, unique
    activation signal, and triggers, and registers it in the local session store.
    """
    import uuid
    from datetime import datetime, timezone

    from crucible.models import MemoryType, PoisonPlantRecord
    from crucible.poison.document_generator import DocumentGenerator
    from crucible.poison.session_store import PoisonSessionStore

    # Validate memory type
    try:
        m_type = MemoryType(memory_type.lower())
    except ValueError:
        console.print(
            f"[red]✗ Invalid memory type: {memory_type}. Must be rag, episodic, semantic, or unknown.[/red]"
        )
        raise typer.Exit(code=1) from None

    # Validate technique
    if technique not in (1, 2, 3, 4):
        console.print("[red]✗ Technique must be 1, 2, 3, or 4.[/red]")
        raise typer.Exit(code=1)

    resolved_session_id = session_id or str(uuid.uuid4())

    store = PoisonSessionStore()
    existing = store.load(resolved_session_id)
    if existing is not None and not force:
        console.print(
            f"[red]✗ Session ID '{resolved_session_id}' already exists.[/red]\n"
            f"Use [bold]--force[/bold] to overwrite this record."
        )
        raise typer.Exit(code=1)

    # Generate document and signal
    generator = DocumentGenerator()
    document_text, activation_signal = generator.generate(technique, topic)

    record = PoisonPlantRecord(
        session_id=resolved_session_id,
        memory_type=m_type,
        topic=topic,
        technique=technique,
        trigger=trigger,
        activation_signal=activation_signal,
        document_text=document_text,
        planted_at=datetime.now(timezone.utc).isoformat(),
        target_url=target,
    )

    store.save(record)

    console.print(
        f"[green]✓ Planted session [bold]{resolved_session_id}[/bold][/green]"
    )
    console.print(f"  • Memory Type : {m_type.value}")
    console.print(f"  • Topic       : {topic}")
    console.print(f"  • Signal      : [bold cyan]{activation_signal}[/bold cyan]")
    console.print(f"  • Trigger     : {trigger}")

    if output is not None:
        try:
            output.write_text(record.model_dump_json(indent=2), encoding="utf-8")
            console.print(f"[green]✓ Plant record saved to {output}[/green]")
        except Exception as exc:
            console.print(f"[red]✗ Failed to write output file: {exc}[/red]")

    # Print document snippet
    console.print("\n[bold]Generated Document Text Snippet:[/bold]")
    console.print("---")
    console.print(record.document_text)
    console.print("---")


@poison_app.command("verify")
def poison_verify(
    session_id: str | None = typer.Option(
        None,
        "--session-id",
        help="The session ID to verify from the store.",
    ),
    plant_record: Path | None = typer.Option(
        None,
        "--plant-record",
        help="Path to a plant record JSON file to verify.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Path to save the test report JSON.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Allow verification even if already marked VERIFIED_ACTIVE.",
    ),
) -> None:
    """Verify if a planted poison has been activated.

    Sends the trigger query to the target agent and checks for the presence of
    the activation signal in the response.
    """
    from datetime import datetime, timezone

    import httpx

    from crucible.models import PoisonPlantRecord, PoisonStatus, PoisonTestResult
    from crucible.poison.session_store import PoisonSessionStore

    record: PoisonPlantRecord | None = None
    store = PoisonSessionStore()

    if plant_record is not None:
        if not plant_record.exists():
            console.print(f"[red]✗ Plant record file not found: {plant_record}[/red]")
            raise typer.Exit(code=1)
        try:
            record = PoisonPlantRecord.model_validate_json(
                plant_record.read_text(encoding="utf-8")
            )
        except Exception as exc:
            console.print(f"[red]✗ Failed to parse plant record: {exc}[/red]")
            raise typer.Exit(code=1) from None
    elif session_id is not None:
        record = store.load(session_id)
        if record is None:
            console.print(f"[red]✗ Session '{session_id}' not found in store.[/red]")
            raise typer.Exit(code=1)
    else:
        console.print(
            "[red]✗ Must specify either --session-id or --plant-record.[/red]"
        )
        raise typer.Exit(code=1)

    # Check status
    if record.status == PoisonStatus.VERIFIED_ACTIVE and not force:
        console.print(
            f"[yellow]⚠  Session '{record.session_id}' is already marked VERIFIED_ACTIVE.[/yellow]\n"
            f"Use [bold]--force[/bold] to re-verify."
        )
        raise typer.Exit(code=0)

    console.print(f"[cyan]Verifying session [bold]{record.session_id}[/bold]...[/cyan]")
    console.print(f"  • Target URL: {record.target_url}")
    console.print(f"  • Trigger   : {record.trigger}")
    console.print(f"  • Signal    : {record.activation_signal}")

    # Send trigger to agent target
    # We use a POST request to standard Ollama /api/chat or OpenAI-compatible format
    # Check if Ollama preset style can be built, otherwise default to generic POST
    payload = {
        "model": "llama3.2",
        "messages": [{"role": "user", "content": record.trigger}],
        "stream": False,
    }

    headers = {"Content-Type": "application/json"}
    agent_response = ""
    error_msg = None
    status = PoisonStatus.VERIFIED_INACTIVE

    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(record.target_url, json=payload, headers=headers)
        if resp.status_code == 200:
            try:
                # Try parsing Ollama chat format: message.content
                body = resp.json()
                agent_response = body.get("message", {}).get("content", "")
                if not agent_response:
                    # Try raw string or generic JSON
                    agent_response = body.get("response", str(body))
            except Exception:
                agent_response = resp.text
        else:
            error_msg = f"Target returned status code {resp.status_code}"
            status = PoisonStatus.VERIFICATION_ERROR
    except Exception as exc:
        error_msg = f"Failed to connect or communicate with target: {exc}"
        status = PoisonStatus.VERIFICATION_ERROR

    is_active = False
    if error_msg is None:
        if record.activation_signal in agent_response:
            is_active = True
            status = PoisonStatus.VERIFIED_ACTIVE
        else:
            status = PoisonStatus.VERIFIED_INACTIVE

    # Update store if session exists in store
    if store.load(record.session_id) is not None:
        store.update_status(
            session_id=record.session_id,
            status=status,
            verified_at=datetime.now(timezone.utc).isoformat(),
            activation_response=agent_response if is_active else None,
        )

    # Print results
    if status == PoisonStatus.VERIFIED_ACTIVE:
        console.print(
            f"[bold green]✔ POISON ACTIVE[/bold green] — Activation signal [bold]{record.activation_signal}[/bold] found in response!"
        )
    elif status == PoisonStatus.VERIFIED_INACTIVE:
        console.print(
            "[bold yellow]✘ POISON INACTIVE[/bold yellow] — Activation signal not found."
        )
    else:
        console.print(f"[bold red]✗ VERIFICATION ERROR[/bold red] — {error_msg}")

    test_result = PoisonTestResult(
        session_id=record.session_id,
        status=status,
        verified_at=datetime.now(timezone.utc).isoformat(),
        activation_signal=record.activation_signal,
        trigger=record.trigger,
        response_snippet=agent_response[:200] if agent_response else "",
        is_active=is_active,
        error_message=error_msg,
    )

    if output is not None:
        try:
            output.write_text(test_result.model_dump_json(indent=2), encoding="utf-8")
            console.print(f"[green]✓ Test report saved to {output}[/green]")
        except Exception as exc:
            console.print(f"[red]✗ Failed to write report file: {exc}[/red]")


@poison_app.command("rag")
def poison_rag(
    ingest_endpoint: str = typer.Option(
        ...,
        "--ingest-endpoint",
        help="Endpoint where poison document should be POSTed/ingested.",
    ),
    query_endpoint: str = typer.Option(
        ...,
        "--query-endpoint",
        help="Endpoint to query with the trigger phrase.",
    ),
    trigger: str = typer.Option(
        ...,
        "--trigger",
        help="The query/trigger phrase.",
    ),
    topic: str = typer.Option(
        ...,
        "--topic",
        help="The topic of the RAG document.",
    ),
    session_id: str | None = typer.Option(
        None,
        "--session-id",
        help="Custom session ID.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Path to save the test report JSON.",
    ),
) -> None:
    """Run an automated RAG plant-and-verify lifecycle.

    Generates a document using Technique 4 (RAG-specific), ingests it into
    the ingest endpoint, waits, queries the query endpoint, and returns status.
    """
    import time
    import uuid
    from datetime import datetime, timezone

    import httpx

    from crucible.models import (
        MemoryType,
        PoisonPlantRecord,
        PoisonStatus,
        PoisonTestResult,
    )
    from crucible.poison.document_generator import DocumentGenerator
    from crucible.poison.session_store import PoisonSessionStore

    resolved_session_id = session_id or str(uuid.uuid4())
    store = PoisonSessionStore()

    generator = DocumentGenerator()
    document_text, activation_signal = generator.generate(4, topic)

    record = PoisonPlantRecord(
        session_id=resolved_session_id,
        memory_type=MemoryType.RAG,
        topic=topic,
        technique=4,
        trigger=trigger,
        activation_signal=activation_signal,
        document_text=document_text,
        planted_at=datetime.now(timezone.utc).isoformat(),
        target_url=query_endpoint,
    )

    # Ingest document
    console.print("[cyan]Ingesting poisoned document into RAG database...[/cyan]")
    console.print(f"  • Ingest URL: {ingest_endpoint}")

    ingest_payload = {"document": document_text}
    headers = {"Content-Type": "application/json"}
    ingested_ok = False
    ingest_error = ""

    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(ingest_endpoint, json=ingest_payload, headers=headers)
        if resp.status_code in (200, 201):
            ingested_ok = True
            console.print("[green]✓ Document ingested successfully.[/green]")
        else:
            ingest_error = (
                f"Ingestion returned HTTP status code {resp.status_code}: {resp.text}"
            )
    except Exception as exc:
        ingest_error = f"Ingestion connection failed: {exc}"

    if not ingested_ok:
        console.print(f"[red]✗ Ingestion failed: {ingest_error}[/red]")
        # Save session as PLANTED (not verification error)
        record.status = PoisonStatus.PLANTED
        store.save(record)
        raise typer.Exit(code=1)

    # Save initial record
    store.save(record)

    # Wait for RAG indexing
    console.print("Waiting 1 second for indexing...")
    time.sleep(1.0)

    # Query endpoint
    console.print("[cyan]Querying RAG system to verify activation...[/cyan]")
    console.print(f"  • Query URL: {query_endpoint}")
    console.print(f"  • Trigger  : {trigger}")

    query_payload = {"query": trigger}
    query_response = ""
    error_msg = None
    status = PoisonStatus.VERIFIED_INACTIVE

    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(query_endpoint, json=query_payload, headers=headers)
        if resp.status_code == 200:
            query_response = resp.text
            # Try JSON extraction
            try:
                body = resp.json()
                query_response = body.get(
                    "response", body.get("message", {}).get("content", resp.text)
                )
            except Exception:
                pass
        else:
            error_msg = f"Query returned status code {resp.status_code}"
            status = PoisonStatus.VERIFICATION_ERROR
    except Exception as exc:
        error_msg = f"Query connection failed: {exc}"
        status = PoisonStatus.VERIFICATION_ERROR

    is_active = False
    if error_msg is None:
        if activation_signal in query_response:
            is_active = True
            status = PoisonStatus.VERIFIED_ACTIVE
        else:
            status = PoisonStatus.VERIFIED_INACTIVE

    store.update_status(
        session_id=resolved_session_id,
        status=status,
        verified_at=datetime.now(timezone.utc).isoformat(),
        activation_response=query_response if is_active else None,
    )

    if status == PoisonStatus.VERIFIED_ACTIVE:
        console.print(
            f"[bold green]✔ POISON ACTIVE[/bold green] — Activation signal [bold]{activation_signal}[/bold] found in response!"
        )
    elif status == PoisonStatus.VERIFIED_INACTIVE:
        console.print(
            "[bold yellow]✘ POISON INACTIVE[/bold yellow] — Activation signal not found."
        )
    else:
        console.print(f"[bold red]✗ VERIFICATION ERROR[/bold red] — {error_msg}")

    test_result = PoisonTestResult(
        session_id=resolved_session_id,
        status=status,
        verified_at=datetime.now(timezone.utc).isoformat(),
        activation_signal=activation_signal,
        trigger=trigger,
        response_snippet=query_response[:200] if query_response else "",
        is_active=is_active,
        error_message=error_msg,
    )

    if output is not None:
        try:
            output.write_text(test_result.model_dump_json(indent=2), encoding="utf-8")
            console.print(f"[green]✓ Test report saved to {output}[/green]")
        except Exception as exc:
            console.print(f"[red]✗ Failed to write report file: {exc}[/red]")


@poison_app.command("list")
def poison_list() -> None:
    """List all memory poisoning evaluation sessions in the store."""
    from rich.table import Table

    from crucible.poison.session_store import PoisonSessionStore

    store = PoisonSessionStore()
    records = store.list_all()

    if not records:
        console.print("[yellow]No memory poisoning sessions found in store.[/yellow]")
        return

    table = Table(
        title="Planted Memory Poisoning Sessions",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("Session ID", style="bold")
    table.add_column("Type")
    table.add_column("Topic")
    table.add_column("Tech")
    table.add_column("Signal", style="dim")
    table.add_column("Status")
    table.add_column("Planted At", style="dim")

    for r in records:
        status_colour = {
            "planted": "white",
            "verified_active": "green",
            "verified_inactive": "yellow",
            "verification_error": "red",
            "expired": "dim",
        }.get(r.status.value, "white")
        status_text = f"[{status_colour}]{r.status.value.upper()}[/{status_colour}]"

        table.add_row(
            r.session_id,
            r.memory_type.value,
            r.topic,
            str(r.technique),
            r.activation_signal,
            status_text,
            r.planted_at[:16],
        )

    console.print(table)


@poison_app.command("status")
def poison_status(
    session_id: str = typer.Option(
        ...,
        "--session-id",
        "-s",
        help="The session ID to display.",
    ),
) -> None:
    """Display the detailed status of a single poisoning session."""
    from crucible.poison.session_store import PoisonSessionStore

    store = PoisonSessionStore()
    record = store.load(session_id)

    if record is None:
        console.print(f"[red]✗ Session '{session_id}' not found in store.[/red]")
        raise typer.Exit(code=1)

    console.print(f"\n[bold cyan]Poison Session Status: {session_id}[/bold cyan]")
    console.print(
        f"  • Status             : [bold]{record.status.value.upper()}[/bold]"
    )
    console.print(f"  • Memory Type        : {record.memory_type.value}")
    console.print(f"  • Topic              : {record.topic}")
    console.print(f"  • Technique          : {record.technique}")
    console.print(f"  • Trigger            : {record.trigger}")
    console.print(f"  • Activation Signal  : {record.activation_signal}")
    console.print(f"  • Planted At         : {record.planted_at}")
    console.print(f"  • Last Verified At   : {record.verified_at or 'Never'}")
    console.print(f"  • Target URL         : {record.target_url}")
    if record.activation_response:
        console.print("\n[bold]Last Activation Response Output Snippet:[/bold]")
        console.print("---")
        console.print(record.activation_response[:500])
        console.print("---")




if __name__ == "__main__":
    app()


# ---------------------------------------------------------------------------
# Step 9.7 — crucible identity subapp
# ---------------------------------------------------------------------------

identity_app = typer.Typer(
    name="identity",
    help="Audit, baseline, and compare named AI agent behaviour over time.",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)
app.add_typer(identity_app, name="identity")


@identity_app.command("audit")
def identity_audit(
    agent_id: str = typer.Argument(..., help="Agent ID to audit."),
    hours: int = typer.Option(24, "--hours", "-h", help="Analysis window in hours."),
    policy: str = typer.Option(
        None,
        "--policy",
        "-p",
        help="Path to policy.yaml (v2) for allowlist comparison.",
    ),
    log_dir: str = typer.Option(
        None,
        "--log-dir",
        help="Override the identity-log directory (default: ~/.crucible/identity-logs).",
    ),
) -> None:
    """Analyse a named agent's tool-call behaviour and report anomalies.

    Reads the agent's behavioral log and produces a rich risk summary including:
    call counts, tool distribution, allowlist violations, rate-limit status,
    and a 0.0–1.0 risk score.
    """
    from pathlib import Path as _Path

    from rich.panel import Panel
    from rich.table import Table

    from crucible.trace.identity_store import IdentityStore

    store = IdentityStore(log_dir=_Path(log_dir) if log_dir else None)

    # Optionally load identity definition from v2 policy
    identity_obj = None
    if policy:
        try:
            from crucible.trace.policy import load_policy as _lp

            loaded = _lp(_Path(policy))
            identity_obj = loaded.agents.get(agent_id)
            if identity_obj is None:
                console.print(
                    f"[yellow]⚠  Agent '{agent_id}' not found in policy — "
                    "running audit without allowlist comparison.[/yellow]"
                )
        except Exception as exc:
            console.print(f"[red]Failed to load policy: {exc}[/red]")
            raise typer.Exit(1) from exc

    summary = store.generate_summary(agent_id, hours=hours, identity=identity_obj)

    if summary.total_calls == 0:
        console.print(
            f"[yellow]No calls recorded for agent '{agent_id}' "
            f"in the last {hours}h.[/yellow]\n"
            "Use [bold]crucible trace[/bold] with [bold]--identity-log[/bold] "
            "enabled to start recording."
        )
        raise typer.Exit(0)

    # Risk badge
    risk_pct = summary.risk_score * 100
    if summary.risk_score >= 0.7:
        risk_badge = f"[bold red]{risk_pct:.1f}% HIGH[/bold red]"
    elif summary.risk_score >= 0.4:
        risk_badge = f"[bold yellow]{risk_pct:.1f}% MEDIUM[/bold yellow]"
    else:
        risk_badge = f"[bold green]{risk_pct:.1f}% LOW[/bold green]"

    console.print(
        Panel.fit(
            f"[bold cyan]crucible identity audit[/bold cyan] — Agent: [bold]{agent_id}[/bold]\n"
            f"Window: {summary.window_start[:19]}Z → {summary.window_end[:19]}Z ({hours}h)\n"
            f"Risk Score: {risk_badge}",
            border_style="cyan",
        )
    )

    # Call summary table
    tbl = Table(title="Tool Call Summary", show_header=True, header_style="bold magenta")
    tbl.add_column("Tool", style="cyan", no_wrap=True)
    tbl.add_column("Calls", justify="right")
    tbl.add_column("In Allowlist?", justify="center")

    allowed = identity_obj.allowed_tools if identity_obj else []
    for tool, count in sorted(summary.calls_per_tool.items(), key=lambda x: -x[1]):
        in_list = (
            "[green]✓[/green]"
            if not allowed or tool in allowed
            else "[red]✗ OUTSIDE[/red]"
        )
        tbl.add_row(tool, str(count), in_list)

    console.print(tbl)
    console.print(
        f"\n  Total calls : [bold]{summary.total_calls}[/bold]   "
        f"Denied : [bold red]{summary.calls_denied}[/bold red]   "
        f"Alerted : [bold yellow]{summary.calls_alerted}[/bold yellow]"
    )

    if summary.violations:
        console.print("\n[bold red]⚠  Violations detected:[/bold red]")
        for v in summary.violations:
            console.print(f"  • [{v.severity.value.upper()}] {v.description}")
    else:
        console.print("\n[green]✓  No violations detected.[/green]")

    if summary.findings:
        console.print("\n[bold]Findings:[/bold]")
        for f in summary.findings:
            console.print(f"  → {f}")


@identity_app.command("baseline")
def identity_baseline(
    agent_id: str = typer.Argument(..., help="Agent ID to baseline."),
    hours: int = typer.Option(
        24, "--hours", "-h", help="Hours of history to include in baseline."
    ),
    output: str = typer.Option(
        None,
        "--output",
        "-o",
        help="Output path for the baseline JSON (default: ~/.crucible/identity-baselines/{agent_id}.json).",
    ),
    log_dir: str = typer.Option(
        None, "--log-dir", help="Override identity-log directory."
    ),
) -> None:
    """Save a behaviour baseline snapshot for a named agent.

    The baseline captures current tool-call distribution so that future
    [bold]crucible identity diff[/bold] commands can detect anomalies.
    """
    import json as _json
    from pathlib import Path as _Path

    from crucible.trace.identity_store import IdentityStore

    store = IdentityStore(log_dir=_Path(log_dir) if log_dir else None)
    summary = store.generate_summary(agent_id, hours=hours)

    if summary.total_calls == 0:
        console.print(
            f"[yellow]No calls found for agent '{agent_id}' in the last {hours}h. "
            "Baseline not saved.[/yellow]"
        )
        raise typer.Exit(1)

    out_path = (
        _Path(output)
        if output
        else _Path.home() / ".crucible" / "identity-baselines" / f"{agent_id}.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(summary.model_dump_json(indent=2), encoding="utf-8")

    console.print(
        f"[green]✓  Baseline saved[/green] for [bold]{agent_id}[/bold] "
        f"({summary.total_calls} calls over {hours}h)\n"
        f"   → {out_path}"
    )


@identity_app.command("diff")
def identity_diff(
    agent_id: str = typer.Argument(..., help="Agent ID to compare."),
    hours: int = typer.Option(
        24, "--hours", "-h", help="Analysis window for current behaviour."
    ),
    baseline_path: str = typer.Option(
        None,
        "--baseline",
        "-b",
        help="Path to baseline JSON (default: ~/.crucible/identity-baselines/{agent_id}.json).",
    ),
    log_dir: str = typer.Option(
        None, "--log-dir", help="Override identity-log directory."
    ),
) -> None:
    """Compare current agent behaviour against a saved baseline.

    Highlights new tools, disappeared tools, and call-volume changes.
    Exit code 1 if significant drift is detected (risk delta ≥ 0.2).
    """
    import json as _json
    from pathlib import Path as _Path

    from rich.table import Table

    from crucible.models import IdentityBehaviorSummary
    from crucible.trace.identity_store import IdentityStore

    base_path = (
        _Path(baseline_path)
        if baseline_path
        else _Path.home() / ".crucible" / "identity-baselines" / f"{agent_id}.json"
    )
    if not base_path.exists():
        console.print(
            f"[red]No baseline found at {base_path}.[/red]\n"
            "Run [bold]crucible identity baseline[/bold] first."
        )
        raise typer.Exit(1)

    baseline = IdentityBehaviorSummary.model_validate_json(
        base_path.read_text(encoding="utf-8")
    )
    store = IdentityStore(log_dir=_Path(log_dir) if log_dir else None)
    current = store.generate_summary(agent_id, hours=hours)

    if current.total_calls == 0:
        console.print(
            f"[yellow]No current data for agent '{agent_id}'.[/yellow]"
        )
        raise typer.Exit(0)

    # Compute diff
    new_tools = set(current.unique_tools_used) - set(baseline.unique_tools_used)
    gone_tools = set(baseline.unique_tools_used) - set(current.unique_tools_used)
    risk_delta = current.risk_score - baseline.risk_score

    console.print(
        f"\n[bold cyan]crucible identity diff[/bold cyan] — Agent: [bold]{agent_id}[/bold]"
    )
    console.print(
        f"  Baseline : {baseline.window_start[:10]}  "
        f"({baseline.total_calls} calls, risk {baseline.risk_score:.2f})"
    )
    console.print(
        f"  Current  : {current.window_start[:10]}  "
        f"({current.total_calls} calls, risk {current.risk_score:.2f})"
    )

    delta_colour = "red" if risk_delta > 0.1 else ("yellow" if risk_delta > 0 else "green")
    console.print(
        f"  Risk Δ   : [{delta_colour}]{risk_delta:+.4f}[/{delta_colour}]"
    )

    if new_tools:
        console.print(f"\n[bold yellow]🆕 New tools (not in baseline):[/bold yellow]")
        for t in sorted(new_tools):
            console.print(f"  + {t}")

    if gone_tools:
        console.print(f"\n[bold blue]⬇ Tools no longer active:[/bold blue]")
        for t in sorted(gone_tools):
            console.print(f"  - {t}")

    if not new_tools and not gone_tools and abs(risk_delta) < 0.05:
        console.print("\n[green]✓  Behaviour is consistent with baseline.[/green]")

    if risk_delta >= 0.2:
        console.print(
            "\n[bold red]⚠  Significant behaviour drift detected "
            f"(Δ {risk_delta:+.4f}).[/bold red]"
        )
        raise typer.Exit(1)


@identity_app.command("list")
def identity_list(
    log_dir: str = typer.Option(
        None, "--log-dir", help="Override identity-log directory."
    ),
) -> None:
    """List all agents that have recorded behavioural logs."""
    from pathlib import Path as _Path

    from rich.table import Table

    from crucible.trace.identity_store import IdentityStore

    store = IdentityStore(log_dir=_Path(log_dir) if log_dir else None)
    agents = store.list_agents()

    if not agents:
        console.print("[yellow]No agent logs found.[/yellow]")
        raise typer.Exit(0)

    tbl = Table(
        title="Recorded Agent Identities",
        show_header=True,
        header_style="bold magenta",
    )
    tbl.add_column("Agent ID", style="cyan")
    tbl.add_column("Log File", style="dim")

    log_dir_path = _Path(log_dir) if log_dir else None
    temp_store = IdentityStore(log_dir=log_dir_path)
    for agent in sorted(agents):
        log_file = temp_store._agent_path(agent)
        tbl.add_row(agent, str(log_file))

    console.print(tbl)
    console.print(f"\n  [dim]{len(agents)} agent{'s' if len(agents) != 1 else ''} found.[/dim]")


@identity_app.command("clear")
def identity_clear(
    agent_id: str = typer.Argument(..., help="Agent ID whose log to delete."),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip confirmation prompt."
    ),
    log_dir: str = typer.Option(
        None, "--log-dir", help="Override identity-log directory."
    ),
) -> None:
    """Delete the behavioural log for a named agent.

    [bold red]Warning:[/bold red] This is irreversible.
    """
    from pathlib import Path as _Path

    from crucible.trace.identity_store import IdentityStore

    if not yes:
        confirmed = typer.confirm(
            f"Delete all behavioural log data for agent '{agent_id}'?",
            default=False,
        )
        if not confirmed:
            console.print("[yellow]Cancelled.[/yellow]")
            raise typer.Exit(0)

    store = IdentityStore(log_dir=_Path(log_dir) if log_dir else None)
    deleted = store.clear_agent_log(agent_id)

    if deleted:
        console.print(
            f"[green]✓  Log cleared[/green] for agent [bold]{agent_id}[/bold]."
        )
    else:
        console.print(
            f"[yellow]No log found for agent '{agent_id}'.[/yellow]"
        )
        raise typer.Exit(1)
