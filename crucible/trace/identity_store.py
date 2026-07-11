"""Per-agent behavioral log store for the crucible trace identity layer.

Storage layout
--------------
    ~/.crucible/identity-logs/{sanitised_agent_id}.jsonl

One :class:`~crucible.models.IdentityCallRecord` JSON line per call.
Files are appended atomically using a tmp→replace pattern that is
safe on both Windows (NTFS) and POSIX.

Thread / async safety
---------------------
``record_call`` is a coroutine that writes to disk via
``anyio.to_thread.run_sync`` so it never blocks the proxy event loop.
All file I/O failures are caught, logged, and swallowed — a write error
must never cause the proxy to drop or delay a request.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import anyio

if TYPE_CHECKING:
    from crucible.models import AgentIdentity, IdentityBehaviorSummary, IdentityCallRecord

logger = logging.getLogger(__name__)

# Default root directory for identity behavioral logs
IDENTITY_LOG_DIR = Path.home() / ".crucible" / "identity-logs"

# Characters that are illegal in Windows filenames (and Linux basenames)
_UNSAFE_FILENAME_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def _sanitise_agent_id(agent_id: str) -> str:
    """Return a filename-safe version of *agent_id*.

    Replaces any character that is illegal in Windows or Linux filenames
    with ``_``.  Leading/trailing dots and spaces are also stripped.
    """
    safe = _UNSAFE_FILENAME_RE.sub("_", agent_id).strip(". ")
    return safe or "unknown"


class IdentityStore:
    """Records and queries per-agent behavioral call logs.

    Args:
        log_dir: Root directory for identity logs.
                 Defaults to ``~/.crucible/identity-logs``.
    """

    def __init__(self, log_dir: Path | None = None) -> None:
        self._log_dir = log_dir or IDENTITY_LOG_DIR
        self._log_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _agent_path(self, agent_id: str) -> Path:
        return self._log_dir / f"{_sanitise_agent_id(agent_id)}.jsonl"

    def _read_records(self, agent_id: str) -> list[dict[str, Any]]:
        """Read all raw record dicts for *agent_id* from disk (sync)."""
        path = self._agent_path(agent_id)
        if not path.exists():
            return []
        records: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    logger.warning("Skipping malformed line in %s", path)
        return records

    def _append_record(self, agent_id: str, record_json: str) -> None:
        """Atomically append *record_json* + newline to the agent log (sync).

        Uses tmp-file + replace() for atomicity on Windows and POSIX.
        If any error occurs it is logged and swallowed — never propagated.
        """
        try:
            path = self._agent_path(agent_id)
            path.parent.mkdir(parents=True, exist_ok=True)

            # Read existing content, append new line, write atomically
            existing = path.read_text(encoding="utf-8") if path.exists() else ""
            new_content = existing + record_json + "\n"

            tmp = path.with_suffix(".tmp")
            tmp.write_text(new_content, encoding="utf-8")
            tmp.replace(path)
        except Exception:
            logger.exception(
                "IdentityStore: failed to write call record for agent '%s' — "
                "continuing without recording.",
                agent_id,
            )

    # ------------------------------------------------------------------
    # Public async API
    # ------------------------------------------------------------------

    async def record_call(self, record: IdentityCallRecord) -> None:
        """Append *record* to the agent's JSONL log (non-blocking).

        Runs disk I/O in a thread-pool worker via ``anyio.to_thread.run_sync``
        so the proxy event loop is never blocked.  Failures are silently logged.
        """
        record_json = record.model_dump_json()
        await anyio.to_thread.run_sync(
            self._append_record, record.agent_id, record_json
        )

    # ------------------------------------------------------------------
    # Query API (synchronous — used by CLI and tests)
    # ------------------------------------------------------------------

    def get_session_calls(
        self, agent_id: str, session_marker: str | None = None
    ) -> list[dict[str, Any]]:
        """Return call records for *agent_id* filtered by *session_marker*.

        If *session_marker* is None, returns the last 100 records.
        """
        records = self._read_records(agent_id)
        if session_marker is not None:
            records = [r for r in records if r.get("session_marker") == session_marker]
        return records[-100:]

    def get_hourly_call_count(self, agent_id: str) -> int:
        """Return the number of calls made by *agent_id* in the last 60 minutes."""
        cutoff = (datetime.now(tz=timezone.utc) - timedelta(hours=1)).isoformat()
        records = self._read_records(agent_id)
        return sum(1 for r in records if r.get("timestamp", "") >= cutoff)

    def get_unique_tools_this_session(
        self, agent_id: str, session_marker: str | None = None
    ) -> list[str]:
        """Return distinct tool names used in *session_marker* (or last 100 calls)."""
        records = self.get_session_calls(agent_id, session_marker)
        return list({r["tool_name"] for r in records if "tool_name" in r})

    def check_limits(
        self,
        agent_id: str,
        identity: AgentIdentity,
        session_marker: str | None = None,
    ) -> str | None:
        """Check whether *agent_id* has exceeded any of its configured limits.

        Returns a human-readable violation description string if any limit is
        exceeded, or ``None`` if all limits are within bounds.

        Checked (in order):
          1. allowed_hours_utc — is the current UTC time inside the window?
          2. denied_tools — is the requested tool on the explicit denylist?
             (Note: individual tool denials are checked per-call in the proxy.)
          3. max_calls_per_session
          4. max_calls_per_hour
          5. max_unique_tools_per_session
        """
        now_utc = datetime.now(tz=timezone.utc)

        # 1. Hour window
        if identity.allowed_hours_utc:
            try:
                start_str, end_str = identity.allowed_hours_utc.split("-")
                sh, sm = (int(x) for x in start_str.strip().split(":"))
                eh, em = (int(x) for x in end_str.strip().split(":"))
                current_minutes = now_utc.hour * 60 + now_utc.minute
                start_minutes = sh * 60 + sm
                end_minutes = eh * 60 + em
                if not (start_minutes <= current_minutes < end_minutes):
                    return (
                        f"Agent '{agent_id}' called outside allowed UTC hours "
                        f"{identity.allowed_hours_utc} "
                        f"(current UTC {now_utc.strftime('%H:%M')})"
                    )
            except (ValueError, AttributeError):
                logger.warning(
                    "Could not parse allowed_hours_utc '%s' for agent '%s'",
                    identity.allowed_hours_utc,
                    agent_id,
                )

        # 2. Session call limit
        if identity.max_calls_per_session is not None:
            session_calls = len(self.get_session_calls(agent_id, session_marker))
            limit = identity.max_calls_per_session
            if session_calls >= limit:
                return (
                    f"Agent '{agent_id}' has exceeded max_calls_per_session "
                    f"({session_calls}/{limit})"
                )
            # Approaching-limit warnings (checked in proxy, not here)

        # 3. Hourly call limit
        if identity.max_calls_per_hour is not None:
            hourly = self.get_hourly_call_count(agent_id)
            limit = identity.max_calls_per_hour
            if hourly >= limit:
                return (
                    f"Agent '{agent_id}' has exceeded max_calls_per_hour "
                    f"({hourly}/{limit})"
                )

        # 4. Unique tools per session
        if identity.max_unique_tools_per_session is not None:
            unique_tools = self.get_unique_tools_this_session(agent_id, session_marker)
            limit = identity.max_unique_tools_per_session
            if len(unique_tools) >= limit:
                return (
                    f"Agent '{agent_id}' has exceeded max_unique_tools_per_session "
                    f"({len(unique_tools)}/{limit}): {unique_tools}"
                )

        return None

    def approaching_limit_warnings(
        self,
        agent_id: str,
        identity: AgentIdentity,
        session_marker: str | None = None,
    ) -> list[str]:
        """Return warning strings when an agent is approaching (80%/90%) its limits.

        Empty list = no warnings.
        """
        warnings: list[str] = []

        if identity.max_calls_per_session is not None:
            session_calls = len(self.get_session_calls(agent_id, session_marker))
            limit = identity.max_calls_per_session
            pct = session_calls / limit if limit else 0
            if pct >= 0.90:
                warnings.append(
                    f"⚠  Agent '{agent_id}' at {pct:.0%} of session call limit "
                    f"({session_calls}/{limit}) — approaching deny threshold"
                )
            elif pct >= 0.80:
                warnings.append(
                    f"⚠  Agent '{agent_id}' at {pct:.0%} of session call limit "
                    f"({session_calls}/{limit})"
                )

        if identity.max_calls_per_hour is not None:
            hourly = self.get_hourly_call_count(agent_id)
            limit = identity.max_calls_per_hour
            pct = hourly / limit if limit else 0
            if pct >= 0.90:
                warnings.append(
                    f"⚠  Agent '{agent_id}' at {pct:.0%} of hourly call limit "
                    f"({hourly}/{limit}) — approaching deny threshold"
                )
            elif pct >= 0.80:
                warnings.append(
                    f"⚠  Agent '{agent_id}' at {pct:.0%} of hourly call limit "
                    f"({hourly}/{limit})"
                )

        return warnings

    def generate_summary(
        self, agent_id: str, hours: int = 24, identity: AgentIdentity | None = None
    ) -> IdentityBehaviorSummary:
        """Build an :class:`~crucible.models.IdentityBehaviorSummary` for *agent_id*.

        Args:
            agent_id:  The agent to summarise.
            hours:     How many hours back to analyse (default 24).
            identity:  The agent's :class:`~crucible.models.AgentIdentity`
                       definition (for allowlist comparison).  If None, no
                       allowlist violations are computed.
        """
        from crucible.models import (
            IdentityBehaviorSummary,
            IdentityViolation,
            Severity,
        )
        from crucible.trace.models import PolicyAction

        now = datetime.now(tz=timezone.utc)
        cutoff = (now - timedelta(hours=hours)).isoformat()
        window_start = cutoff
        window_end = now.isoformat()

        all_records = self._read_records(agent_id)
        records = [r for r in all_records if r.get("timestamp", "") >= cutoff]

        calls_per_tool: dict[str, int] = {}
        for r in records:
            tool = r.get("tool_name", "unknown")
            calls_per_tool[tool] = calls_per_tool.get(tool, 0) + 1

        unique_tools = list(calls_per_tool.keys())
        calls_denied = sum(
            1 for r in records if r.get("policy_action") == PolicyAction.DENY.value
        )
        calls_alerted = sum(
            1 for r in records if r.get("policy_action") == PolicyAction.ALERT.value
        )

        # Compute tools outside allowlist
        tools_outside: list[str] = []
        violations: list[IdentityViolation] = []
        findings: list[str] = []

        allowed_tools = identity.allowed_tools if identity else []
        denied_tools = identity.denied_tools if identity else []

        if allowed_tools:
            tools_outside = [t for t in unique_tools if t not in allowed_tools]
            for tool in tools_outside:
                count = calls_per_tool.get(tool, 0)
                v = IdentityViolation(
                    violation_type="tool_outside_allowlist",
                    severity=Severity.HIGH,
                    agent_id=agent_id,
                    tool_name=tool,
                    description=(
                        f"Tool '{tool}' is not in {agent_id}'s allowed_tools "
                        f"({count} call{'s' if count != 1 else ''})"
                    ),
                    detected_at=now.isoformat(),
                    evidence={"call_count": count, "allowed_tools": allowed_tools},
                )
                violations.append(v)
                findings.append(v.description)

        if denied_tools:
            for tool in unique_tools:
                if tool in denied_tools:
                    count = calls_per_tool.get(tool, 0)
                    v = IdentityViolation(
                        violation_type="denied_tool",
                        severity=Severity.CRITICAL,
                        agent_id=agent_id,
                        tool_name=tool,
                        description=(
                            f"Tool '{tool}' is on {agent_id}'s explicit denylist "
                            f"({count} call{'s' if count != 1 else ''})"
                        ),
                        detected_at=now.isoformat(),
                        evidence={"call_count": count, "denied_tools": denied_tools},
                    )
                    violations.append(v)
                    findings.append(v.description)

        # Risk score: weighted combination of violation indicators
        total = len(records)
        if total == 0:
            risk_score = 0.0
        else:
            denied_ratio = calls_denied / total
            alerted_ratio = calls_alerted / total
            outside_ratio = len(tools_outside) / max(len(unique_tools), 1)
            risk_score = min(
                1.0,
                (denied_ratio * 0.5) + (alerted_ratio * 0.3) + (outside_ratio * 0.2),
            )

        return IdentityBehaviorSummary(
            agent_id=agent_id,
            window_start=window_start,
            window_end=window_end,
            total_calls=total,
            unique_tools_used=unique_tools,
            tools_outside_allowlist=tools_outside,
            calls_per_tool=calls_per_tool,
            calls_denied=calls_denied,
            calls_alerted=calls_alerted,
            risk_score=round(risk_score, 4),
            violations=violations,
            findings=findings,
        )

    # ------------------------------------------------------------------
    # Management API
    # ------------------------------------------------------------------

    def list_agents(self) -> list[str]:
        """Return all agent_ids that have log files in the store."""
        return [p.stem for p in self._log_dir.glob("*.jsonl")]

    def clear_agent_log(self, agent_id: str) -> bool:
        """Delete *agent_id*'s log file.

        Returns:
            True if the file existed and was deleted; False if not found.
        """
        path = self._agent_path(agent_id)
        if path.exists():
            path.unlink()
            return True
        return False
