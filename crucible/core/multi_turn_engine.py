from __future__ import annotations

import time
from typing import TYPE_CHECKING

import httpx

from crucible.core.response_extractor import extract_response
from crucible.models import (
    AgentTarget,
    ConversationHistory,
    ConversationTurn,
    Finding,
    ModuleResult,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from crucible.attacks.base import BaseAttack


class MultiTurnEngine:
    def __init__(self, target: AgentTarget, client: httpx.AsyncClient) -> None:
        self.target = target
        self.client = client
        self.history = ConversationHistory()

    async def _send_message(self, message: str) -> str:
        # In a real engine, we'd need to construct the full context.
        # Since we're dealing with generic API endpoints, we assume the API
        # might be stateful (e.g. cookie based) or we append history to the prompt.
        # For simplicity, we just send the message.

        self.history.turns.append(ConversationTurn(role="user", content=message))

        # Append history to prompt if we want to simulate state for stateless APIs
        # context = "\n".join(f"{t.role}: {t.content}" for t in self.history.turns)

        body = self.target.build_payload_body(message)
        headers = {"Content-Type": "application/json", **self.target.headers}

        try:
            response = await self.client.request(
                method=self.target.method,
                url=str(self.target.url),
                content=body,
                headers=headers,
                timeout=self.target.timeout,
            )
            resp_text = extract_response(
                response.text[:2000], self.target.response_path
            )
        except Exception as e:
            resp_text = f"[ERROR] {e}"

        self.history.turns.append(ConversationTurn(role="assistant", content=resp_text))
        return resp_text

    async def run_strategy(
        self,
        strategy: BaseAttack,
        on_finding: Callable[[Finding], None] | None = None,
    ) -> ModuleResult:
        start_time = time.monotonic()
        findings: list[Finding] = []
        payloads = strategy.get_payloads()

        final_response = ""
        for i, payload in enumerate(payloads):
            final_response = await self._send_message(payload)
            if i < len(payloads) - 1:
                # Give a small delay between turns
                import anyio
                await anyio.sleep(self.target.delay_ms / 1000.0)

        # Evaluate only the final turn for success
        final_payload = payloads[-1]
        passed = strategy.evaluate_response(final_payload, final_response)

        finding = Finding(
            attack_name=strategy.name,
            category=strategy.category,
            severity=strategy.severity,
            title=strategy.title,
            description=strategy.description,
            payload=final_payload,
            response_snippet=final_response[:500],
            passed=passed,
            remediation=strategy.remediation,
            references=strategy.references,
            owasp_ref=strategy.owasp_ref,
        )
        findings.append(finding)
        if on_finding:
            on_finding(finding)

        duration = time.monotonic() - start_time

        return ModuleResult(
            module_name=strategy.name,
            module_description=strategy.description,
            category=strategy.category,
            total_attacks=1,  # It's one sequence
            passed=1 if passed else 0,
            failed=0 if passed else 1,
            errors=0,
            findings=findings,
            score=100.0 if passed else 0.0,
            duration_seconds=duration,
            metadata={"turns_taken": len(payloads)},
        )
