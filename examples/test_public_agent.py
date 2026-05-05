"""Run Crucible against a live public endpoint to verify it works end-to-end."""

import asyncio

from crucible.core.runner import run_scan
from crucible.models import AgentTarget

target = AgentTarget(name="httpbin-echo", url="https://httpbin.org/post")
result = asyncio.run(run_scan(target))
print(
    f"Grade: {result.grade.value} | Findings: {result.total_findings} | Score: {result.overall_score}"
)
