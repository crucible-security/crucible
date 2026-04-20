
from __future__ import annotations

import os

import anyio

from crucible.core.runner import run_scan
from crucible.models import AgentTarget
from crucible.reporters.terminal import TerminalReporter

async def main() -> None:
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        from rich.console import Console

        Console().print(
            "[red]Set OPENAI_API_KEY environment variable.[/red]"
        )
        return

    target = AgentTarget(
        name="openai-chatgpt",
        url="https://api.openai.com/v1/chat/completions",
        provider="openai",
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        body_template=(
            '{"model": "gpt-4o-mini",'
            ' "messages": [{"role": "user",'
            ' "content": "{payload}"}]}'
        ),
        timeout=30,
    )

    result = await run_scan(target, concurrency=5)

    reporter = TerminalReporter()
    reporter.render(result)

if __name__ == "__main__":
    anyio.run(main)

