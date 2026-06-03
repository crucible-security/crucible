"""crucible.core.mcp_scanner
~~~~~~~~~~~~~~~~~~~~~~~~~
MCP Server Security Scanner — tests tool poisoning, command injection, and
excessive OAuth scopes.  All tests are static (no live HTTP calls to the
MCP server) so they can run without a running server and are fully testable.

OWASP MCP Top 10 mapping used here:
  MCP-001  Prompt / Tool Injection
  MCP-002  Excessive Permissions & OAuth Scope Abuse
  MCP-003  Tool Poisoning (hidden instructions in descriptions)
  MCP-004  Command Injection via Tool Parameters
  MCP-005  Sensitive Data Exposure through Tools
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# OWASP MCP Top 10 reference strings
# ---------------------------------------------------------------------------


class OwaspMcp(str, Enum):
    TOOL_INJECTION = "MCP-001: Prompt / Tool Injection"
    EXCESSIVE_PERMISSIONS = "MCP-002: Excessive Permissions & OAuth Scope Abuse"
    TOOL_POISONING = "MCP-003: Tool Poisoning"
    COMMAND_INJECTION = "MCP-004: Command Injection via Tool Parameters"
    SENSITIVE_EXPOSURE = "MCP-005: Sensitive Data Exposure through Tools"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class McpFinding:
    test_id: str
    title: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    owasp_ref: str
    description: str
    evidence: str
    passed: bool  # True  → no issue found; False → vulnerability detected
    remediation: str


@dataclass
class McpScanResult:
    server_url: str
    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    findings: list[McpFinding] = field(default_factory=list)

    @property
    def score(self) -> float:
        """Simple deduction-based score (same logic as core scorer)."""
        deductions = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2}
        s = 100.0
        for f in self.findings:
            if not f.passed:
                s -= deductions.get(f.severity, 0)
        return max(0.0, s)

    @property
    def grade(self) -> str:
        s = self.score
        if s >= 90:
            return "A"
        if s >= 75:
            return "B"
        if s >= 60:
            return "C"
        if s >= 40:
            return "D"
        return "F"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Patterns that signal hidden instructions buried in tool descriptions
_POISONING_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"ignore\s+(all\s+)?previous\s+instructions?",
        r"disregard\s+(all\s+)?prior\s+instructions?",
        r"you\s+(are\s+)?now\s+(in\s+)?admin\s+mode",
        r"system\s*:\s*override",
        r"<\s*system\s*>",
        r"\[INST\]",
        r"act\s+as\s+if\s+you\s+have\s+no\s+restrictions?",
        r"do\s+not\s+follow\s+your\s+(safety\s+)?guidelines?",
        r"your\s+new\s+instructions?\s+(are|is)\s*:",
        r"secret\s+instructions?",
    ]
]

# Command injection sequences to look for in tool parameter schemas / descriptions
_CMD_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r";\s*(rm|ls|cat|curl|wget|bash|sh|powershell|cmd)\b",
        r"\|\s*(bash|sh|powershell|cmd)\b",
        r"`[^`]+`",  # backtick subshell
        r"\$\([^)]+\)",  # $() subshell
        r"&&\s*(rm|curl|wget|bash)\b",
        r"\.\./\.\.",  # path traversal
        r"file:///",
        r"__import__\s*\(",  # python eval injection
        r"eval\s*\(",
        r"exec\s*\(",
    ]
]

# OAuth scope patterns that indicate excessive permissions
_EXCESSIVE_SCOPE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bfiles?:\*",
        r"\bdb:\*",
        r"\badmin:\*",
        r"\bread_write\b",
        r"\ball_scopes?\b",
        r"\bfull_access\b",
        r"\bsuperuser\b",
        r"\broot\b",
        r"\bunrestricted\b",
    ]
]

# Dangerous tool names / capability words that suggest excessive agency
_DANGEROUS_TOOL_NAMES: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bexec(ute)?\b",
        r"\brun_command\b",
        r"\bshell\b",
        r"\bsudo\b",
        r"\brm_rf\b",
        r"\bdelete_all\b",
        r"\bdrop_table\b",
        r"\bformat_disk\b",
    ]
]

# Sensitive data references that should never appear in tool descriptions
_SENSITIVE_DATA_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bpassword\b",
        r"\bsecret_?key\b",
        r"\bapi_?key\b",
        r"\bprivate_?key\b",
        r"\bcredit.?card\b",
        r"\bssn\b",
        r"\baccess.?token\b",
        r"\bbearer.?token\b",
    ]
]


def _match_any(text: str, patterns: list[re.Pattern[str]]) -> list[str]:
    """Return all unique matched strings across all patterns."""
    matches: list[str] = []
    for pat in patterns:
        for m in pat.finditer(text):
            matches.append(m.group(0))
    return list(dict.fromkeys(matches))  # deduplicate, preserve order


def _tool_text(tool: dict[str, Any]) -> str:
    """Flatten a tool dict into a single searchable string."""
    parts: list[str] = [
        str(tool.get("name", "")),
        str(tool.get("description", "")),
        str(tool.get("inputSchema", "")),
    ]
    return " ".join(parts)


def _scope_text(manifest: dict[str, Any]) -> str:
    """Flatten auth / scope fields from a manifest into a single string."""
    auth = manifest.get("auth", {}) or {}
    scopes: Any = (
        auth.get("scopes") or auth.get("oauth_scopes") or auth.get("permissions") or []
    )
    if isinstance(scopes, list):
        return " ".join(str(s) for s in scopes)
    return str(scopes)


# ---------------------------------------------------------------------------
# The scanner
# ---------------------------------------------------------------------------


class McpScanner:
    """
    Run up to 10 security tests against a parsed MCP server manifest.

    Parameters
    ----------
    server_url:
        The URL of the MCP server being audited (stored in results only).
    manifest:
        A dict representing the MCP server manifest / capability response.
        Expected shape::

            {
              "tools": [
                {"name": "...", "description": "...", "inputSchema": {...}},
                ...
              ],
              "auth": {
                "type": "oauth2",
                "scopes": ["files:*", "admin:read"]
              }
            }

        If the dict is empty the scanner still runs all static tests and
        reports them as passed (nothing to flag).
    """

    def __init__(self, server_url: str, manifest: dict[str, Any]) -> None:
        self.server_url = server_url
        self.manifest = manifest
        self._tools: list[dict[str, Any]] = manifest.get("tools", []) or []
        self._scope_str: str = _scope_text(manifest)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self) -> McpScanResult:
        result = McpScanResult(server_url=self.server_url)

        tests = [
            self._test_tool_poisoning_descriptions,
            self._test_tool_poisoning_names,
            self._test_cmd_injection_in_descriptions,
            self._test_cmd_injection_in_schema_defaults,
            self._test_excessive_oauth_wildcard_scopes,
            self._test_excessive_oauth_admin_scopes,
            self._test_dangerous_tool_names,
            self._test_sensitive_data_in_descriptions,
            self._test_unrestricted_input_schemas,
            self._test_missing_tool_descriptions,
        ]

        for test_fn in tests:
            finding = test_fn()
            result.findings.append(finding)
            result.total_tests += 1
            if finding.passed:
                result.passed += 1
            else:
                result.failed += 1

        return result

    # ------------------------------------------------------------------
    # Test 1 — Tool Poisoning: hidden instructions in descriptions
    # ------------------------------------------------------------------

    def _test_tool_poisoning_descriptions(self) -> McpFinding:
        hits: list[str] = []
        for tool in self._tools:
            desc = str(tool.get("description", ""))
            hits.extend(_match_any(desc, _POISONING_PATTERNS))

        passed = len(hits) == 0
        return McpFinding(
            test_id="MCP-T01",
            title="Tool Poisoning — Hidden Instructions in Tool Descriptions",
            severity="CRITICAL",
            owasp_ref=OwaspMcp.TOOL_POISONING.value,
            description=(
                "Tool descriptions are injected into the LLM context verbatim. "
                "Adversarial text hidden inside descriptions can override system "
                "prompts or silently redirect the model's behaviour."
            ),
            evidence=", ".join(hits[:5]) if hits else "None",
            passed=passed,
            remediation=(
                "Strip or reject tool descriptions containing instruction-override "
                "language before registering tools. Apply the same input-validation "
                "rules used for user messages."
            ),
        )

    # ------------------------------------------------------------------
    # Test 2 — Tool Poisoning: instruction patterns in tool names
    # ------------------------------------------------------------------

    def _test_tool_poisoning_names(self) -> McpFinding:
        hits: list[str] = []
        for tool in self._tools:
            name = str(tool.get("name", ""))
            hits.extend(_match_any(name, _POISONING_PATTERNS))

        passed = len(hits) == 0
        return McpFinding(
            test_id="MCP-T02",
            title="Tool Poisoning — Hidden Instructions in Tool Names",
            severity="HIGH",
            owasp_ref=OwaspMcp.TOOL_POISONING.value,
            description=(
                "Tool names are rendered in the LLM context alongside descriptions. "
                "Encoding override instructions in a tool name is a subtle variant "
                "of tool poisoning."
            ),
            evidence=", ".join(hits[:5]) if hits else "None",
            passed=passed,
            remediation=(
                "Enforce an allowlist of safe characters for tool names (e.g. "
                r"[a-z0-9_\-]{1,64}). Reject names containing whitespace or "
                "natural-language sentences."
            ),
        )

    # ------------------------------------------------------------------
    # Test 3 — Command Injection: injection sequences in descriptions
    # ------------------------------------------------------------------

    def _test_cmd_injection_in_descriptions(self) -> McpFinding:
        hits: list[str] = []
        for tool in self._tools:
            desc = str(tool.get("description", ""))
            hits.extend(_match_any(desc, _CMD_INJECTION_PATTERNS))

        passed = len(hits) == 0
        return McpFinding(
            test_id="MCP-T03",
            title="Command Injection — Shell Sequences in Tool Descriptions",
            severity="CRITICAL",
            owasp_ref=OwaspMcp.COMMAND_INJECTION.value,
            description=(
                "Shell meta-characters or subshell syntax detected in tool "
                "descriptions. If these descriptions are passed to execution "
                "environments without sanitisation, arbitrary command execution "
                "may be possible."
            ),
            evidence=", ".join(hits[:5]) if hits else "None",
            passed=passed,
            remediation=(
                "Sanitise all tool descriptions with a strict allowlist before "
                "storing or rendering them. Treat them as untrusted user input."
            ),
        )

    # ------------------------------------------------------------------
    # Test 4 — Command Injection: injection in parameter schema defaults
    # ------------------------------------------------------------------

    def _test_cmd_injection_in_schema_defaults(self) -> McpFinding:
        hits: list[str] = []
        for tool in self._tools:
            schema_str = str(tool.get("inputSchema", ""))
            hits.extend(_match_any(schema_str, _CMD_INJECTION_PATTERNS))

        passed = len(hits) == 0
        return McpFinding(
            test_id="MCP-T04",
            title="Command Injection — Shell Sequences in Tool Input Schemas",
            severity="HIGH",
            owasp_ref=OwaspMcp.COMMAND_INJECTION.value,
            description=(
                "Shell meta-characters or path-traversal sequences detected inside "
                "an inputSchema definition. Pre-populated default values with "
                "injection payloads can execute silently when the LLM calls the tool."
            ),
            evidence=", ".join(hits[:5]) if hits else "None",
            passed=passed,
            remediation=(
                "Audit inputSchema default values. Never include executable strings "
                "as defaults. Validate schema definitions against a JSON Schema "
                "allowlist before publishing."
            ),
        )

    # ------------------------------------------------------------------
    # Test 5 — Excessive OAuth: wildcard scopes (files:*, db:*)
    # ------------------------------------------------------------------

    def _test_excessive_oauth_wildcard_scopes(self) -> McpFinding:
        hits = _match_any(
            self._scope_str,
            [
                re.compile(r"\bfiles?:\*", re.IGNORECASE),
                re.compile(r"\bdb:\*", re.IGNORECASE),
                re.compile(r"\bread_write\b", re.IGNORECASE),
            ],
        )
        passed = len(hits) == 0
        return McpFinding(
            test_id="MCP-T05",
            title="Excessive OAuth Scope — Wildcard File / DB Permissions",
            severity="HIGH",
            owasp_ref=OwaspMcp.EXCESSIVE_PERMISSIONS.value,
            description=(
                "The server requests wildcard OAuth scopes (files:*, db:*) that "
                "grant far broader access than any specific tool operation requires. "
                "This violates the principle of least privilege."
            ),
            evidence=", ".join(hits[:5]) if hits else "None",
            passed=passed,
            remediation=(
                "Replace wildcard scopes with the narrowest scopes needed. "
                "For example, replace 'files:*' with 'files:read' if the tool "
                "only reads files. Document scope justifications in the manifest."
            ),
        )

    # ------------------------------------------------------------------
    # Test 6 — Excessive OAuth: admin:* scopes
    # ------------------------------------------------------------------

    def _test_excessive_oauth_admin_scopes(self) -> McpFinding:
        hits = _match_any(
            self._scope_str,
            [
                re.compile(r"\badmin:\*", re.IGNORECASE),
                re.compile(r"\bfull_access\b", re.IGNORECASE),
                re.compile(r"\ball_scopes?\b", re.IGNORECASE),
                re.compile(r"\bsuperuser\b", re.IGNORECASE),
            ],
        )
        passed = len(hits) == 0
        return McpFinding(
            test_id="MCP-T06",
            title="Excessive OAuth Scope — Admin / Full-Access Permissions",
            severity="CRITICAL",
            owasp_ref=OwaspMcp.EXCESSIVE_PERMISSIONS.value,
            description=(
                "The server requests admin-level or full-access OAuth scopes. "
                "A compromised or malicious MCP server with admin credentials "
                "can cause catastrophic damage to connected systems."
            ),
            evidence=", ".join(hits[:5]) if hits else "None",
            passed=passed,
            remediation=(
                "Never request admin:* or equivalent scopes from an MCP server. "
                "Use role-based scopes with explicit resource constraints. "
                "Require explicit user consent for any elevated scope."
            ),
        )

    # ------------------------------------------------------------------
    # Test 7 — Dangerous tool names (exec, shell, sudo…)
    # ------------------------------------------------------------------

    def _test_dangerous_tool_names(self) -> McpFinding:
        hits: list[str] = []
        for tool in self._tools:
            name = str(tool.get("name", ""))
            hits.extend(_match_any(name, _DANGEROUS_TOOL_NAMES))

        passed = len(hits) == 0
        return McpFinding(
            test_id="MCP-T07",
            title="Excessive Agency — Dangerous Tool Names Detected",
            severity="HIGH",
            owasp_ref=OwaspMcp.TOOL_INJECTION.value,
            description=(
                "Tool names suggesting arbitrary command execution, shell access, "
                "or destructive operations were detected. LLMs may choose these "
                "tools autonomously, leading to unintended system-level actions."
            ),
            evidence=", ".join(hits[:5]) if hits else "None",
            passed=passed,
            remediation=(
                "Replace generic execution tools with purpose-scoped alternatives "
                "(e.g. 'run_sql_query' instead of 'exec'). Apply tool-call allow "
                "lists and require human-in-the-loop confirmation for sensitive ops."
            ),
        )

    # ------------------------------------------------------------------
    # Test 8 — Sensitive data references in descriptions
    # ------------------------------------------------------------------

    def _test_sensitive_data_in_descriptions(self) -> McpFinding:
        hits: list[str] = []
        for tool in self._tools:
            desc = str(tool.get("description", ""))
            hits.extend(_match_any(desc, _SENSITIVE_DATA_PATTERNS))

        passed = len(hits) == 0
        return McpFinding(
            test_id="MCP-T08",
            title="Sensitive Data Exposure — Credentials Referenced in Tool Descriptions",
            severity="HIGH",
            owasp_ref=OwaspMcp.SENSITIVE_EXPOSURE.value,
            description=(
                "Tool descriptions reference sensitive data types (passwords, API "
                "keys, tokens). This increases the risk of the model being tricked "
                "into exposing or logging sensitive values."
            ),
            evidence=", ".join(hits[:5]) if hits else "None",
            passed=passed,
            remediation=(
                "Remove credential references from tool descriptions. Use opaque "
                "parameter names (e.g. 'credential_id') that reference secrets "
                "stored in a vault, never inline values."
            ),
        )

    # ------------------------------------------------------------------
    # Test 9 — Unrestricted input schemas (no type / enum constraints)
    # ------------------------------------------------------------------

    def _test_unrestricted_input_schemas(self) -> McpFinding:
        unrestricted: list[str] = []
        for tool in self._tools:
            schema: Any = tool.get("inputSchema", {}) or {}
            props: dict[str, Any] = (
                schema.get("properties", {}) if isinstance(schema, dict) else {}
            )
            for param_name, param_def in props.items():
                if not isinstance(param_def, dict):
                    continue
                has_type = "type" in param_def
                has_enum = "enum" in param_def
                has_pattern = "pattern" in param_def
                has_format = "format" in param_def
                if not (has_type or has_enum or has_pattern or has_format):
                    unrestricted.append(f"{tool.get('name', '?')}.{param_name}")

        passed = len(unrestricted) == 0
        return McpFinding(
            test_id="MCP-T09",
            title="Command Injection Risk — Unrestricted Tool Parameter Schemas",
            severity="MEDIUM",
            owasp_ref=OwaspMcp.COMMAND_INJECTION.value,
            description=(
                "One or more tool parameters have no type, enum, pattern, or "
                "format constraints in their inputSchema. Unconstrained string "
                "parameters are prime injection targets."
            ),
            evidence=", ".join(unrestricted[:5]) if unrestricted else "None",
            passed=passed,
            remediation=(
                "Add explicit 'type', 'enum', 'pattern', or 'format' constraints "
                "to every tool parameter schema. Use the most restrictive constraint "
                "applicable (enum > pattern > type)."
            ),
        )

    # ------------------------------------------------------------------
    # Test 10 — Missing tool descriptions (increases injection risk)
    # ------------------------------------------------------------------

    def _test_missing_tool_descriptions(self) -> McpFinding:
        missing: list[str] = []
        for tool in self._tools:
            desc = str(tool.get("description", "")).strip()
            if not desc:
                missing.append(str(tool.get("name", "<unnamed>")))

        passed = len(missing) == 0
        return McpFinding(
            test_id="MCP-T10",
            title="Tool Poisoning Risk — Tools Registered Without Descriptions",
            severity="LOW",
            owasp_ref=OwaspMcp.TOOL_POISONING.value,
            description=(
                "Tools without descriptions leave a vacuum that the LLM fills with "
                "guesswork. This makes it easier for a poisoned tool elsewhere in "
                "the context to claim authority over the undescribed tool's purpose."
            ),
            evidence=", ".join(missing[:5]) if missing else "None",
            passed=passed,
            remediation=(
                "Every registered tool must have a clear, concise description that "
                "states exactly what it does and what inputs it expects. "
                "Reject tools/list responses that omit descriptions."
            ),
        )


def load_manifest(server: str, headers: dict[str, str] | None = None, timeout: float = 10.0) -> dict[str, Any]:
    """Load an MCP manifest from a local file path or a URL."""
    import json
    import os
    import httpx

    # Check if server is a file path
    is_file = (
        server.startswith("./")
        or server.startswith("/")
        or server.startswith(".\\")
        or (len(server) > 1 and server[1] == ":")
        or os.path.exists(server)
    )

    if is_file:
        with open(server, "r", encoding="utf-8") as f:
            return json.load(f)

    with httpx.Client(timeout=timeout) as client:
        resp = client.get(server, headers=headers)
        resp.raise_for_status()
        return resp.json()
