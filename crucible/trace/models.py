"""Data models for the crucible trace proxy subsystem."""

from __future__ import annotations

import datetime  # noqa: TC003
import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class PolicyAction(str, Enum):
    """Actions a policy rule can apply to an intercepted tool call."""

    ALLOW = "allow"
    DENY = "deny"
    ALERT = "alert"


class PolicyRule(BaseModel):
    """A single policy rule.  First matching rule wins."""

    name: str = Field(description="Human-readable rule identifier.")
    tool_name: str | None = Field(
        default=None,
        description="Exact tool name to match.  None means any tool.",
    )
    parameter_pattern: str | None = Field(
        default=None,
        description="Regex applied to the JSON-serialised arguments string.",
    )
    action: PolicyAction = Field(description="What to do when this rule matches.")
    # --- Phase 9 additions (v2 policy fields) ---
    agent_id: str | None = Field(
        default=None,
        description="Only apply this rule if the request agent_id matches. None = any agent.",
    )
    tool_name_not_in_allowlist: bool = Field(
        default=False,
        description="If True, match when tool_name is not in the agent's allowed_tools list.",
    )

    # Compiled regex — populated by PolicyLoader, not from YAML directly.
    _compiled: re.Pattern[str] | None = None

    def compile_pattern(self) -> None:
        """Compile parameter_pattern into _compiled.  Raises ValueError on bad regex."""
        if self.parameter_pattern is not None:
            self._compiled = re.compile(self.parameter_pattern, re.DOTALL)

    def matches(
        self,
        tool_name: str | None,
        arguments_json: str,
        agent_id: str = "unknown",
        agent_allowed_tools: list[str] | None = None,
    ) -> bool:
        """Return True if this rule matches the given tool call.

        Args:
            tool_name:           The MCP tool name.
            arguments_json:      JSON-serialised arguments.
            agent_id:            The agent making the call (default 'unknown').
            agent_allowed_tools: The agent's allowed_tools list, for
                                 tool_name_not_in_allowlist evaluation.
        """
        # Agent-scoped rule: only match if agent_id matches
        if self.agent_id is not None and self.agent_id != agent_id:
            return False
        # tool_name_not_in_allowlist: match when tool is NOT in agent's allowlist
        if self.tool_name_not_in_allowlist:
            if agent_allowed_tools is None:
                return False  # no allowlist defined — can't evaluate
            if tool_name in agent_allowed_tools:
                return False  # tool IS in allowlist — no match
            # tool is outside allowlist → rule matches
            return True
        # Tool name check (None in rule = wildcard)
        if self.tool_name is not None and self.tool_name != tool_name:
            return False
        # Pattern check
        if self._compiled is not None:
            return bool(self._compiled.search(arguments_json))
        # If we had a tool_name match (or wildcard) and no pattern, it's a match
        return True


class Policy(BaseModel):
    """The full policy loaded from a YAML file (v1 and v2 compatible)."""

    rules: list[PolicyRule] = Field(default_factory=list)
    default_action: PolicyAction = Field(
        default=PolicyAction.ALLOW,
        description="Action applied when no rule matches.",
    )
    # Phase 9 — v2 policy: agent identity definitions keyed by agent_id.
    # Always present (empty dict for v1 policies) for consistent access.
    agents: dict[str, Any] = Field(
        default_factory=dict,
        description="AgentIdentity objects keyed by agent_id (v2 policies only).",
    )


class TraceEntry(BaseModel):
    """One row in the JSONL audit log."""

    timestamp: datetime.datetime = Field(description="UTC time of the request.")
    request_id: str = Field(description="UUID4 unique to this request.")
    tool_name: str | None = Field(
        default=None,
        description="Tool name if this was a tools/call, else None.",
    )
    parameters: dict[str, Any] | None = Field(
        default=None,
        description="The 'arguments' dict from the tools/call params, else None.",
    )
    policy_action: PolicyAction = Field(description="Policy decision applied.")
    policy_rule_matched: str | None = Field(
        default=None,
        description="Name of the matching rule, or None if default was used.",
    )
    upstream_status_code: int | None = Field(
        default=None,
        description="HTTP status from upstream, or None if request was denied locally.",
    )
    upstream_latency_ms: float | None = Field(
        default=None,
        description="Round-trip latency to upstream in ms, or None if denied.",
    )
    request_size_bytes: int = Field(description="Size of the incoming request body.")
    caller_ip: str = Field(description="IP address of the MCP client.")
    # Phase 9 — identity layer: which named agent made this call.
    # Populated from X-Crucible-Agent-Id header or agent_id JSON body field.
    # Defaults to 'unknown' for backward compatibility with existing log files.
    agent_id: str = Field(
        default="unknown",
        description="Named agent identity from X-Crucible-Agent-Id header or body field.",
    )


TraceEntry.model_rebuild()
