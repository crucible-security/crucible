"""
Example: Scanning an OpenAI Assistants API Agent

The OpenAI Assistants API is stateful and requires multiple asynchronous steps
(create thread, add message, create run, poll for completion, fetch messages).
Crucible scans single HTTP endpoints synchronously. Therefore, to scan an Assistant,
you typically point Crucible at your application's API endpoint that wraps the
Assistant logic.

In this example, we:
1. Define a target pointing to a hypothetical local wrapper (http://localhost:8000/api/assistant/chat).
2. Use `respx` to mock this endpoint so the example passes CI without needing a real API key.
3. Run the scan and interpret the results.
"""

from __future__ import annotations

import anyio
import httpx
import respx
from rich.console import Console

from crucible.core.runner import run_scan
from crucible.models import AgentTarget
from crucible.reporters.terminal import TerminalReporter


@respx.mock
async def main() -> None:
    console = Console()
    console.print("[bold blue]Setting up OpenAI Assistant Mock Target...[/bold blue]")

    # Mocking the wrapper endpoint that normally communicates with the OpenAI Assistants API.
    # In a real scenario, this would be your application's API endpoint, and you wouldn't use respx.
    respx.post("http://localhost:8000/api/assistant/chat").mock(
        return_value=httpx.Response(
            200, text="I am a helpful assistant, I cannot help with that."
        )
    )

    # 1. Setting up the target
    target = AgentTarget(
        name="openai-assistant-wrapper",
        url="http://localhost:8000/api/assistant/chat",
        provider="custom",
        method="POST",
        headers={"Content-Type": "application/json"},
        body_template='{"message": "{payload}"}',
        timeout=30.0,
        description="Local wrapper for OpenAI Assistants API",
    )

    console.print(f"Target configured: [green]{target.name}[/green] at {target.url}")
    console.print("[bold yellow]Running Crucible scan...[/bold yellow]")

    # 2. Running the scan
    # In a real run, you can increase concurrency. Here we keep it small.
    result = await run_scan(target, concurrency=2)

    # 3. Interpreting the output
    console.print("\n[bold cyan]Scan Complete. Rendering Report:[/bold cyan]")
    reporter = TerminalReporter()
    reporter.render(result)

    if result.grade.value in ("D", "F"):
        console.print(
            f"\n[bold red]Final Grade: {result.grade.value} - The Assistant needs hardening![/bold red]"
        )
    else:
        console.print(
            f"\n[bold green]Final Grade: {result.grade.value} - The Assistant is secure![/bold green]"
        )


if __name__ == "__main__":
    anyio.run(main)
