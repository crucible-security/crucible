"""
Example: Scanning a LangChain Agent

LangChain agents (whether built with AgentExecutor or an LCEL chain) are typically
served behind an HTTP endpoint (e.g. via LangServe or a custom FastAPI wrapper).
Crucible scans that HTTP endpoint directly — no LangChain SDK required at scan time.

This example demonstrates:
1. Setting up a Crucible target pointing at a hypothetical LangChain agent API.
2. Using `respx` to mock HTTP responses so the script runs in CI without a live server.
3. Interpreting OWASP LLM Top 10 findings in the final report.

OWASP LLM Top 10 Mapping (most relevant for LangChain agents):
  - LLM01: Prompt Injection    — Crucible's PromptInjection module
  - LLM02: Insecure Output Handling — Crucible's OutputHandling module
  - LLM06: Sensitive Information Disclosure — Crucible's DataLeakage module
  - LLM08: Excessive Agency    — Crucible's ExcessiveAgency module
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
    console.print("[bold blue]Setting up LangChain Agent Mock Target...[/bold blue]")

    # Mock the LangChain agent endpoint.
    # In production this would be a real LangServe endpoint or a FastAPI wrapper.
    # The mock returns a safe, benign response to all payloads.
    respx.post("http://localhost:8000/api/langchain/chat").mock(
        return_value=httpx.Response(
            200,
            json={"output": "I'm sorry, I cannot help with that request."},
        )
    )

    # 1. Define the target
    # This mirrors a typical LangServe /invoke endpoint or a custom FastAPI wrapper.
    target = AgentTarget(
        name="langchain-react-agent",
        url="http://localhost:8000/api/langchain/chat",  # type: ignore[arg-type]
        provider="custom",
        method="POST",
        headers={"Content-Type": "application/json"},
        # LangServe expects {"input": {"input": "<payload>"}} but simple wrappers
        # often accept {"input": "<payload>"} or {"message": "<payload>"}.
        body_template='{"input": "{payload}"}',
        timeout=30.0,
        description="LangChain ReAct agent served via LangServe / FastAPI",
    )

    console.print(f"Target: [green]{target.name}[/green] at {target.url}")
    console.print("[bold yellow]Running Crucible scan (mocked for CI)...[/bold yellow]")

    # 2. Run the scan
    result = await run_scan(target, concurrency=2)

    # 3. Render the full terminal report
    console.print("\n[bold cyan]Scan Complete — Rendering Report:[/bold cyan]")
    reporter = TerminalReporter()
    reporter.render(result)

    # 4. Interpret OWASP findings
    console.print("\n[bold]OWASP LLM Top 10 Findings Summary:[/bold]")
    owasp_map = {
        "PromptInjection": "LLM01 — Prompt Injection",
        "OutputHandling": "LLM02 — Insecure Output Handling",
        "DataLeakage": "LLM06 — Sensitive Information Disclosure",
        "ExcessiveAgency": "LLM08 — Excessive Agency",
    }
    for module_result in result.modules:
        owasp_label = owasp_map.get(
            module_result.module_name, module_result.module_name
        )
        status = (
            "[green]PASS[/green]" if module_result.failed == 0 else "[red]FAIL[/red]"
        )
        console.print(
            f"  {status} {owasp_label}: "
            f"{module_result.passed}/{module_result.total_attacks} attacks passed "
            f"(score: {module_result.score:.1f})"
        )

    # 5. Final grade verdict
    if result.grade.value in ("D", "F"):
        console.print(
            f"\n[bold red]Final Grade: {result.grade.value} — "
            "The LangChain agent needs hardening! "
            "Review findings above and add input/output guardrails.[/bold red]"
        )
    else:
        console.print(
            f"\n[bold green]Final Grade: {result.grade.value} — "
            "The LangChain agent passed Crucible's security checks![/bold green]"
        )


if __name__ == "__main__":
    anyio.run(main)
