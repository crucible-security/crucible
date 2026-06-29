"""YAML policy loader and evaluator for the crucible trace proxy."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from crucible.trace.models import Policy, PolicyAction, PolicyRule


class PolicyError(Exception):
    """Raised when a policy file cannot be loaded or is invalid."""


_ALLOWED_RULE_KEYS = frozenset({"name", "tool_name", "parameter_pattern", "action"})
_ALLOWED_TOP_KEYS = frozenset({"rules", "default_action"})
_VALID_ACTIONS = {a.value for a in PolicyAction}


def load_policy(path: Path) -> Policy:
    """Load and validate a YAML policy file.

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

    unknown_top = set(raw.keys()) - _ALLOWED_TOP_KEYS
    if unknown_top:
        raise PolicyError(
            f"Unknown top-level keys in policy: {sorted(unknown_top)}. "
            f"Allowed: {sorted(_ALLOWED_TOP_KEYS)}"
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

    compiled_rules: list[PolicyRule] = []
    for idx, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, dict):
            raise PolicyError(
                f"Rule #{idx} must be a YAML mapping, got: {type(raw_rule).__name__}"
            )

        unknown = set(raw_rule.keys()) - _ALLOWED_RULE_KEYS
        if unknown:
            rule_name = raw_rule.get("name", f"#{idx}")
            raise PolicyError(
                f"Rule '{rule_name}' has unknown keys: {sorted(unknown)}. "
                f"Allowed: {sorted(_ALLOWED_RULE_KEYS)}"
            )

        if "name" not in raw_rule:
            raise PolicyError(f"Rule #{idx} is missing the required 'name' field.")

        action_str = raw_rule.get("action")
        if action_str not in _VALID_ACTIONS:
            raise PolicyError(
                f"Rule '{raw_rule['name']}' has invalid action '{action_str}'. "
                f"Must be one of: {sorted(_VALID_ACTIONS)}"
            )

        rule = PolicyRule(
            name=raw_rule["name"],
            tool_name=raw_rule.get("tool_name"),
            parameter_pattern=raw_rule.get("parameter_pattern"),
            action=PolicyAction(action_str),
        )

        # Compile regex at load time — fail fast on bad patterns
        try:
            rule.compile_pattern()
        except re.error as exc:
            raise PolicyError(
                f"Rule '{rule.name}' has an invalid regex in parameter_pattern: {exc}"
            ) from exc

        compiled_rules.append(rule)

    return Policy(rules=compiled_rules, default_action=default_action)


def evaluate_policy(
    policy: Policy,
    tool_name: str | None,
    arguments: dict[str, Any] | None,
) -> tuple[PolicyAction, str | None]:
    """Evaluate the policy for a given tool call.

    Args:
        policy:    The loaded policy object.
        tool_name: The MCP tool name (may be None for malformed calls).
        arguments: The tool arguments dict (may be None).

    Returns:
        ``(action, matched_rule_name)`` — *matched_rule_name* is None if the
        default action was used.
    """
    arguments_json = json.dumps(arguments or {})

    for rule in policy.rules:
        if rule.matches(tool_name, arguments_json):
            return rule.action, rule.name

    return policy.default_action, None
