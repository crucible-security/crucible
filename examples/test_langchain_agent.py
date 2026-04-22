from __future__ import annotations

import anyio

from crucible.core.runner import run_scan
from crucible.models import AgentTarget
from crucible.reporters.terminal import TerminalReporter


async def main() -> None:
    target = AgentTarget(
        name="langchain-react-agent",
        url="http://localhost:8000/api/chat",
        provider="custom",
        method="POST",
        headers={"Content-Type": "application/json"},
        body_template='{"input": "{payload}"}',
        timeout=30,
        description="LangChain ReAct agent for testing",
    )

    result = await run_scan(
        target,
        concurrency=3,
        timeout=30.0,
    )

    reporter = TerminalReporter()
    reporter.render(result)

    from rich.console import Console

    console = Console()
    if result.grade.value in ("D", "F"):
        console.print(
            f"\n[red]Grade: {result.grade.value}" " -- agent needs hardening![/red]"
        )
    else:
        console.print(
            f"\n[green]Grade: {result.grade.value}" " -- looking good![/green]"
        )


if __name__ == "__main__":
    anyio.run(main)
