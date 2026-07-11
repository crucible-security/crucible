"""YAML policy loader and evaluator for the crucible trace proxy.

v1 policies (no ``version:`` field, no ``agents:`` section) are 100%
backward-compatible — they load identically to v0.8.x and produce a
:class:`Policy` with an empty ``agents`` dict.

v2 policies (``version: "2"``, optional ``agents:`` section) support
named agent identity definitions alongside the existing rules.  New rule
fields (``agent_id``, ``tool_name_not_in_allowlist``) are also v2-only and
gracefully ignored / unavailable in v1 parse paths.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

import yaml  # type: ignore[import-untyped]

from crucible.trace.models import Policy, PolicyAction, PolicyRule

if TYPE_CHECKING:
    from pathlib import Path


class PolicyError(Exception):
    """Raised when a policy file cannot be loaded or is invalid."""


# ---------------------------------------------------------------------------
# Allowed key sets — updated for v2
# ---------------------------------------------------------------------------

_ALLOWED_RULE_KEYS_V1 = frozenset({"name", "tool_name", "parameter_pattern", "action"})
_ALLOWED_RULE_KEYS_V2 = _ALLOWED_RULE_KEYS_V1 | frozenset(
    {"agent_id", "tool_name_not_in_allowlist"}
)
_ALLOWED_TOP_KEYS_V1 = frozenset({"rules", "default_action"})
_ALLOWED_TOP_KEYS_V2 = _ALLOWED_TOP_KEYS_V1 | frozenset({"version", "agents"})

_VALID_ACTIONS = {a.value for a in PolicyAction}

_ALLOWED_AGENT_KEYS = frozenset(
    {
        "id",
        "description",
        "allowed_tools",
        "denied_tools",
        "max_calls_per_session",
        "max_calls_per_hour",
        "max_unique_tools_per_session",
        "allowed_hours_utc",
    }
)


# ---------------------------------------------------------------------------
# Helper: parse a list of rules (shared by v1 and v2)
# ---------------------------------------------------------------------------


def _parse_rules(
    raw_rules: list[Any],
    allowed_keys: frozenset[str],
    is_v2: bool,
) -> list[PolicyRule]:
    compiled_rules: list[PolicyRule] = []
    for idx, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, dict):
            raise PolicyError(
                f"Rule #{idx} must be a YAML mapping, got: {type(raw_rule).__name__}"
            )

        unknown = set(raw_rule.keys()) - allowed_keys
        if unknown:
            rule_name = raw_rule.get("name", f"#{idx}")
            raise PolicyError(
                f"Rule '{rule_name}' has unknown keys: {sorted(unknown)}. "
                f"Allowed: {sorted(allowed_keys)}"
            )

        if "name" not in raw_rule:
            raise PolicyError(f"Rule #{idx} is missing the required 'name' field.")

        action_str = raw_rule.get("action")
        if action_str not in _VALID_ACTIONS:
            raise PolicyError(
                f"Rule '{raw_rule['name']}' has invalid action '{action_str}'. "
                f"Must be one of: {sorted(_VALID_ACTIONS)}"
            )

        rule_kwargs: dict[str, Any] = {
            "name": raw_rule["name"],
            "tool_name": raw_rule.get("tool_name"),
            "parameter_pattern": raw_rule.get("parameter_pattern"),
            "action": PolicyAction(action_str),
        }

        if is_v2:
            rule_kwargs["agent_id"] = raw_rule.get("agent_id")
            rule_kwargs["tool_name_not_in_allowlist"] = bool(
                raw_rule.get("tool_name_not_in_allowlist", False)
            )

        rule = PolicyRule(**rule_kwargs)

        # Compile regex at load time — fail fast on bad patterns
        try:
            rule.compile_pattern()
        except re.error as exc:
            raise PolicyError(
                f"Rule '{rule.name}' has an invalid regex in parameter_pattern: {exc}"
            ) from exc

        compiled_rules.append(rule)
    return compiled_rules


# ---------------------------------------------------------------------------
# Helper: parse an agents: section (v2 only)
# ---------------------------------------------------------------------------


def _parse_agents(raw_agents: list[Any]) -> dict[str, Any]:
    """Parse the v2 ``agents:`` list into a dict keyed by agent_id.

    Returns an ``AgentIdentity``-compatible dict.  We avoid importing
    ``AgentIdentity`` here to prevent circular imports (``crucible.models``
    imports from ``crucible.trace.models`` transitively).  The proxy layer
    imports ``AgentIdentity`` directly when needed.
    """
    from crucible.models import AgentIdentity  # deferred to avoid circularity

    if not isinstance(raw_agents, list):
        raise PolicyError("'agents' must be a YAML list of agent definitions.")

    result: dict[str, Any] = {}
    for idx, raw_agent in enumerate(raw_agents):
        if not isinstance(raw_agent, dict):
            raise PolicyError(
                f"Agent #{idx} must be a YAML mapping, got: {type(raw_agent).__name__}"
            )
        unknown = set(raw_agent.keys()) - _ALLOWED_AGENT_KEYS
        if unknown:
            agent_name = raw_agent.get("id", f"#{idx}")
            raise PolicyError(
                f"Agent '{agent_name}' has unknown keys: {sorted(unknown)}. "
                f"Allowed: {sorted(_ALLOWED_AGENT_KEYS)}"
            )
        if "id" not in raw_agent:
            raise PolicyError(f"Agent #{idx} is missing the required 'id' field.")

        identity = AgentIdentity(
            agent_id=raw_agent["id"],
            description=raw_agent.get("description", ""),
            allowed_tools=raw_agent.get("allowed_tools", []),
            denied_tools=raw_agent.get("denied_tools", []),
            max_calls_per_session=raw_agent.get("max_calls_per_session"),
            max_calls_per_hour=raw_agent.get("max_calls_per_hour"),
            max_unique_tools_per_session=raw_agent.get("max_unique_tools_per_session"),
            allowed_hours_utc=raw_agent.get("allowed_hours_utc"),
        )
        result[identity.agent_id] = identity
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_policy(path: Path) -> Policy:
    """Load and validate a YAML policy file (v1 and v2 compatible).

    v1 (no ``version:`` / no ``agents:``):
        Parses identically to v0.8.x.  Returns ``Policy`` with ``agents={}``.

    v2 (``version: "2"``):
        Parses the optional ``agents:`` list into ``AgentIdentity`` objects
        stored in ``Policy.agents`` keyed by ``agent_id``.  New rule fields
        (``agent_id``, ``tool_name_not_in_allowlist``) are available in rules.

    Rules are compiled at load time — any invalid regex raises *PolicyError*
    immediately, before the proxy starts accepting connections.

    Args:
        path: Path to the policy YAML file.

    Returns:
        A validated :class:`Policy` instance with all patterns pre-compiled.

    Raises:
        PolicyError: If the file is missing, invalid YAML, has unknown keys,
                     or contains a bad regex pattern.
    """
    if not path.exists():
        raise PolicyError(f"Policy file not found: {path}")

    try:
        raw: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"Invalid YAML in policy file: {exc}") from exc

    if not isinstance(raw, dict):
        raise PolicyError("Policy file must be a YAML mapping at the top level.")

    # Detect version
    version_str: str = str(raw.get("version", "1"))
    is_v2 = version_str == "2"
    allowed_top = _ALLOWED_TOP_KEYS_V2 if is_v2 else _ALLOWED_TOP_KEYS_V1

    unknown_top = set(raw.keys()) - allowed_top
    if unknown_top:
        raise PolicyError(
            f"Unknown top-level keys in policy: {sorted(unknown_top)}. "
            f"Allowed: {sorted(allowed_top)}"
        )

    # Parse default_action
    default_str: str = raw.get("default_action", "allow")
    if default_str not in _VALID_ACTIONS:
        raise PolicyError(
            f"Invalid default_action '{default_str}'. "
            f"Must be one of: {sorted(_VALID_ACTIONS)}"
        )
    default_action = PolicyAction(default_str)

    # Parse rules
    raw_rules: list[Any] = raw.get("rules", [])
    if not isinstance(raw_rules, list):
        raise PolicyError("'rules' must be a YAML list.")

    allowed_rule_keys = _ALLOWED_RULE_KEYS_V2 if is_v2 else _ALLOWED_RULE_KEYS_V1
    compiled_rules = _parse_rules(raw_rules, allowed_rule_keys, is_v2)

    # Parse agents (v2 only)
    agents: dict[str, Any] = {}
    if is_v2 and "agents" in raw:
        agents = _parse_agents(raw["agents"])

    return Policy(rules=compiled_rules, default_action=default_action, agents=agents)


def evaluate_policy(
    policy: Policy,
    tool_name: str | None,
    arguments: dict[str, Any] | None,
    agent_id: str = "unknown",
    agent_allowed_tools: list[str] | None = None,
) -> tuple[PolicyAction, str | None]:
    """Evaluate the policy for a given tool call.

    Args:
        policy:              The loaded policy object.
        tool_name:           The MCP tool name (may be None for malformed calls).
        arguments:           The tool arguments dict (may be None).
        agent_id:            The identity of the calling agent (Phase 9).
        agent_allowed_tools: The agent's allowed_tools list for
                             ``tool_name_not_in_allowlist`` evaluation (Phase 9).

    Returns:
        ``(action, matched_rule_name)`` — *matched_rule_name* is None if the
        default action was used.
    """
    arguments_json = json.dumps(arguments or {})

    for rule in policy.rules:
        if rule.matches(
            tool_name,
            arguments_json,
            agent_id=agent_id,
            agent_allowed_tools=agent_allowed_tools,
        ):
            return rule.action, rule.name

    return policy.default_action, None
