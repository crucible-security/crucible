from __future__ import annotations

import json
import os
import profile
import sys
from pathlib import Path

import anyio
import typer
from rich.console import Console

from crucible import __version__
from crucible.core.cache import ScanCache
from crucible.core.runner import run_scan
from crucible.models import AgentTarget, ScanResult, Severity
from crucible.modules.security import get_all_modules
from crucible.reporters.html_reporter import HTMLReporter
from crucible.reporters.json_reporter import JSONReporter
from crucible.reporters.slack import SlackReporter
from crucible.reporters.terminal import TerminalReporter

os.environ.setdefault("PYTHONIOENCODING", "utf-8")

console = Console()

app = typer.Typer(
    name="crucible",
    help="pytest for AI agents -- test, score, and harden before production.",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)


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
    format: str = typer.Option(
        "table",
        "--format",
        help="Output format: table | json | html.",
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
        help="Fail (exit non-zero) if findings match or exceed this severity...",
    ),
    profile: Path | None = typer.Option(  # noqa: F811
        None,
        "--profile",
        "-p",
        help="Path to agent_profile.json to filter relevant attack modules.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ), 
 ) -> None:

    parsed_headers = _parse_headers(header)

    agent_target = AgentTarget(
        name=name,
        url=target,  # type: ignore[arg-type]
        method=method,
        headers=parsed_headers,
        body_template=body_template,
        timeout=timeout,
    )

    if format not in ["json", "html"] and not quiet:
        _print_scan_header(name, target)

    modules = get_all_modules()

    if profile:
        profile_data = json.loads(profile.read_text())
        agent_type = profile_data.get("agent_type")
        if not quiet:
            console.print(f"[cyan]Target profile loaded: {agent_type}[/cyan]")

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
        result = anyio.run(
            run_scan,
            agent_target,
            modules,
            concurrency,
            timeout,
            quiet,
            format,
            verbose,
        )
        if cache:
            scan_cache.set(cache_key, result, ttl_hours=cache_ttl)

    _render_output(result, format, output)

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
    else:
        terminal = TerminalReporter(console)
        terminal.render(result)

    if output:
        if format == "html" or output.suffix == ".html":
            h_reporter = HTMLReporter()
            saved = h_reporter.write(result, output)
        else:
            j_reporter = JSONReporter()
            saved = j_reporter.write(result, output)

        if format not in ["json", "html"]:
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
        help="Output format: table | json | html.",
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


if __name__ == "__main__":
    app()
