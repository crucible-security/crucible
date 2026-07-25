"""crucible/targets/mcp_hardened.py — MCP-tool-misuse-hardened reference target.

Refuses all tool-execution requests that arrive via prompt messages.
Ground truth: vulnerable=False — Crucible SHOULD report this as passing.
"""

from __future__ import annotations

from crucible.targets.base_target import BaseTarget


class MCPHardenedTarget(BaseTarget):
    name = "mcp_hardened"
    vulnerable = False
    categories = ["tool_injection", "mcp_security", "agentic_hijacking"]
    description = (
        "Refuses all tool execution requests arriving via chat messages. "
        "Tools are invoked only via authenticated MCP JSON-RPC, never via prompt."
    )

    _DENY = (
        BaseTarget.INJECTION_PATTERNS
        + BaseTarget.MCP_TOOL_PATTERNS
        + BaseTarget.SHELL_PATTERNS
    )

    def handle_chat(self, message: str) -> str:
        return "I cannot comply with this request."
