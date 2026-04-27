from __future__ import annotations

import json
import os
from pathlib import Path

import anyio
import typer
from rich.console import Console

from crucible import __version__
from crucible.core.cache import ScanCache
from crucible.core.runner import run_scan
from crucible.models import AgentTarget, ScanResult
from crucible.modules.security import get_all_modules
from crucible.reporters.json_reporter import JSONReporter
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
            "[yellow]Warning: .crucible.json already exists."
            " Overwrite? [y/N][/yellow]"
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
    output_file: Path | None = typer.Option(
        None,
        "--output-file",
        "-o",
        help="Save JSON report to file.",
    ),
    output: str = typer.Option(
        "terminal",
        "--output",
        help="Output format: terminal | json.",
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

    if output != "json" and not quiet:
        _print_scan_header(name, target)

    modules = get_all_modules()
    scan_cache = ScanCache()
    cache_key = scan_cache.get_cache_key(agent_target, modules)

    result = None
    if cache and not no_cache:
        cached_result = scan_cache.get(cache_key)
        if cached_result:
            if output != "json" and not quiet:
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
            output,
        )
        if cache:
            scan_cache.set(cache_key, result, ttl_hours=cache_ttl)

    _render_output(result, output, output_file)


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
    console.print(
        "[bold magenta]CRUCIBLE[/bold magenta]" " -- Starting security scan..."
    )
    console.print(f"[dim]Target: {name} ({target})[/dim]")
    console.print()


def _render_output(
    result: ScanResult,
    output: str,
    output_file: Path | None,
) -> None:
    if output == "json":
        reporter = JSONReporter()
        console.print(reporter.to_json(result))
    else:
        terminal = TerminalReporter(console)
        terminal.render(result)

    if output_file:
        reporter = JSONReporter()
        saved = reporter.write(result, output_file)
        if output != "json":
            console.print(f"[green]Report saved to {saved}[/green]")


@app.command()
def report(
    path: Path = typer.Argument(
        ...,
        help="Path to a Crucible JSON report file.",
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

    terminal = TerminalReporter(console)
    terminal.render(result)


if __name__ == "__main__":
    app()
