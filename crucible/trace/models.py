"""Data models for the crucible trace proxy subsystem."""

from __future__ import annotations

import re
from enum import Enum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from datetime import datetime


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

    # Compiled regex — populated by PolicyLoader, not from YAML directly.
    _compiled: re.Pattern[str] | None = None

    def compile_pattern(self) -> None:
        """Compile parameter_pattern into _compiled.  Raises ValueError on bad regex."""
        if self.parameter_pattern is not None:
            self._compiled = re.compile(self.parameter_pattern, re.DOTALL)

    def matches(self, tool_name: str | None, arguments_json: str) -> bool:
        """Return True if this rule matches the given tool call."""
        # Tool name check (None in rule = wildcard)
        if self.tool_name is not None and self.tool_name != tool_name:
            return False
        # Pattern check
        if self._compiled is not None:
            return bool(self._compiled.search(arguments_json))
        # If we had a tool_name match (or wildcard) and no pattern, it's a match
        return True


class Policy(BaseModel):
    """The full policy loaded from a YAML file."""

    rules: list[PolicyRule] = Field(default_factory=list)
    default_action: PolicyAction = Field(
        default=PolicyAction.ALLOW,
        description="Action applied when no rule matches.",
    )


class TraceEntry(BaseModel):
    """One row in the JSONL audit log."""

    timestamp: datetime = Field(description="UTC time of the request.")
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
