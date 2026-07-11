"""Tests for Phase 9 — Identity & Privilege Layer (ASI03).

Test index (18 total):
  9.2  Data models (3 tests)
  9.3  Policy YAML v2 (4 tests: v1 compat + 3 v2 scenarios)
  9.4  Agent ID extraction (3 tests)
  9.5  IdentityStore (4 tests)
  9.6  Identity-aware policy evaluation (2 tests)
  9.7  CLI smoke-tests (2 tests)

pytest target: ≥ 409 passed, 0 failed (391 baseline + 18 new).
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest
import anyio

# ---------------------------------------------------------------------------
# Step 9.2 — Data model import and field validation
# ---------------------------------------------------------------------------


def test_agent_identity_fields() -> None:
    """AgentIdentity has all required fields with correct defaults."""
    from crucible.models import AgentIdentity

    identity = AgentIdentity(agent_id="test-bot")
    assert identity.agent_id == "test-bot"
    assert identity.description == ""
    assert identity.allowed_tools == []
    assert identity.denied_tools == []
    assert identity.max_calls_per_session is None
    assert identity.max_calls_per_hour is None
    assert identity.max_unique_tools_per_session is None
    assert identity.allowed_hours_utc is None


def test_identity_call_record_round_trip() -> None:
    """IdentityCallRecord serialises and deserialises cleanly."""
    from crucible.models import IdentityCallRecord
    from crucible.trace.models import PolicyAction

    record = IdentityCallRecord(
        timestamp="2026-07-11T06:00:00Z",
        agent_id="customer-support-bot",
        tool_name="read_file",
        parameters={"path": "/etc/passwd"},
        policy_action=PolicyAction.DENY,
        request_id="deadbeef-0000-0000-0000-000000000001",
    )
    assert record.policy_action == PolicyAction.DENY

    dumped = record.model_dump_json()
    restored = IdentityCallRecord.model_validate_json(dumped)
    assert restored.agent_id == "customer-support-bot"
    assert restored.tool_name == "read_file"
    assert restored.policy_action == PolicyAction.DENY
    assert restored.session_marker is None


def test_identity_behavior_summary_fields() -> None:
    """IdentityBehaviorSummary has all required fields, risk_score bounded 0-1."""
    from crucible.models import IdentityBehaviorSummary

    fields = list(IdentityBehaviorSummary.model_fields.keys())
    for required in [
        "agent_id",
        "window_start",
        "window_end",
        "total_calls",
        "unique_tools_used",
        "tools_outside_allowlist",
        "calls_per_tool",
        "calls_denied",
        "calls_alerted",
        "risk_score",
        "violations",
        "findings",
    ]:
        assert required in fields, f"Missing field: {required}"

    summary = IdentityBehaviorSummary(
        agent_id="bot",
        window_start="2026-07-11T00:00:00Z",
        window_end="2026-07-11T06:00:00Z",
        total_calls=10,
        unique_tools_used=["bash", "read_file"],
        tools_outside_allowlist=["bash"],
        calls_per_tool={"bash": 8, "read_file": 2},
        calls_denied=3,
        calls_alerted=1,
        risk_score=0.75,
    )
    assert 0.0 <= summary.risk_score <= 1.0


# ---------------------------------------------------------------------------
# Step 9.3 — Policy YAML v2: backward-compat FIRST, then v2 scenarios
# ---------------------------------------------------------------------------


def test_v1_policy_backward_compatible(tmp_path: Path) -> None:
    """v1 policy.yaml with no agents: section loads exactly as before."""
    from crucible.trace.policy import load_policy

    policy_yaml = textwrap.dedent("""\
        default_action: allow
        rules:
          - name: block-bash
            tool_name: bash
            action: deny
    """)
    p = tmp_path / "v1_policy.yaml"
    p.write_text(policy_yaml, encoding="utf-8")

    policy = load_policy(p)

    assert policy.default_action.value == "allow"
    assert len(policy.rules) == 1
    assert policy.rules[0].name == "block-bash"
    assert policy.rules[0].action.value == "deny"
    assert hasattr(policy, "agents")
    assert policy.agents == {}


def test_v2_policy_loads_agents(tmp_path: Path) -> None:
    """v2 policy.yaml with agents: section loads AgentIdentity objects."""
    from crucible.trace.policy import load_policy

    policy_yaml = textwrap.dedent("""\
        version: "2"
        default_action: allow
        agents:
          - id: research-bot
            description: Research assistant
            allowed_tools:
              - web_search
              - read_file
            max_calls_per_session: 50
            max_calls_per_hour: 200
        rules:
          - name: block-bash-globally
            tool_name: bash
            action: deny
    """)
    p = tmp_path / "v2_policy.yaml"
    p.write_text(policy_yaml, encoding="utf-8")

    policy = load_policy(p)

    assert "research-bot" in policy.agents
    bot = policy.agents["research-bot"]
    assert bot.allowed_tools == ["web_search", "read_file"]
    assert bot.max_calls_per_session == 50
    assert bot.max_calls_per_hour == 200
    assert len(policy.rules) == 1


def test_v2_policy_agent_scoped_rule(tmp_path: Path) -> None:
    """v2 agent-scoped rule only matches the specified agent."""
    from crucible.trace.policy import evaluate_policy, load_policy

    policy_yaml = textwrap.dedent("""\
        version: "2"
        default_action: allow
        agents:
          - id: restricted-agent
            allowed_tools:
              - read_file
        rules:
          - name: restricted-agent-deny-bash
            agent_id: restricted-agent
            tool_name: bash
            action: deny
    """)
    p = tmp_path / "v2_scoped.yaml"
    p.write_text(policy_yaml, encoding="utf-8")
    policy = load_policy(p)

    # restricted-agent calling bash → DENY
    action, rule = evaluate_policy(
        policy, "bash", {}, agent_id="restricted-agent"
    )
    assert action.value == "deny"
    assert rule == "restricted-agent-deny-bash"

    # other-agent calling bash → ALLOW (rule doesn't match different agent)
    action2, rule2 = evaluate_policy(
        policy, "bash", {}, agent_id="other-agent"
    )
    assert action2.value == "allow"
    assert rule2 is None


def test_v2_policy_tool_name_not_in_allowlist(tmp_path: Path) -> None:
    """tool_name_not_in_allowlist rule denies tools outside the agent's allowlist."""
    from crucible.trace.policy import evaluate_policy, load_policy

    policy_yaml = textwrap.dedent("""\
        version: "2"
        default_action: allow
        agents:
          - id: narrow-agent
            allowed_tools:
              - read_file
        rules:
          - name: deny-outside-allowlist
            agent_id: narrow-agent
            tool_name_not_in_allowlist: true
            action: deny
    """)
    p = tmp_path / "v2_allowlist.yaml"
    p.write_text(policy_yaml, encoding="utf-8")
    policy = load_policy(p)

    allowed_tools = policy.agents["narrow-agent"].allowed_tools

    # read_file is in allowlist → ALLOW
    action, rule = evaluate_policy(
        policy, "read_file", {}, agent_id="narrow-agent",
        agent_allowed_tools=allowed_tools,
    )
    assert action.value == "allow"

    # bash is NOT in allowlist → DENY
    action2, rule2 = evaluate_policy(
        policy, "bash", {}, agent_id="narrow-agent",
        agent_allowed_tools=allowed_tools,
    )
    assert action2.value == "deny"
    assert rule2 == "deny-outside-allowlist"


# ---------------------------------------------------------------------------
# Step 9.4 — Agent ID extraction
# ---------------------------------------------------------------------------


def test_extract_agent_id_from_header() -> None:
    """extract_agent_id reads X-Crucible-Agent-Id header (case-insensitive key)."""
    from crucible.trace.proxy import extract_agent_id

    headers = {"x-crucible-agent-id": "my-agent"}
    result = extract_agent_id(headers, None)
    assert result == "my-agent"


def test_extract_agent_id_from_body_field() -> None:
    """extract_agent_id falls back to body agent_id field when header absent."""
    from crucible.trace.proxy import extract_agent_id

    body = {"method": "tools/call", "agent_id": "body-agent"}
    result = extract_agent_id({}, body)
    assert result == "body-agent"


def test_extract_agent_id_fallback_unknown() -> None:
    """extract_agent_id returns 'unknown' when neither header nor body has agent_id."""
    import crucible.trace.proxy as proxy_mod
    from crucible.trace.proxy import extract_agent_id

    # Reset the global warning flag so this test exercises the warning path
    original = proxy_mod._WARN_UNKNOWN_AGENT
    proxy_mod._WARN_UNKNOWN_AGENT = True
    try:
        result = extract_agent_id({}, {"method": "tools/call"})
        assert result == "unknown"
        # Warning flag is now False (consumed)
        assert proxy_mod._WARN_UNKNOWN_AGENT is False
    finally:
        proxy_mod._WARN_UNKNOWN_AGENT = original


# ---------------------------------------------------------------------------
# Step 9.5 — IdentityStore
# ---------------------------------------------------------------------------


def test_identity_store_record_and_read(tmp_path: Path) -> None:
    """record_call() writes a record; get_session_calls() reads it back."""
    from crucible.models import IdentityCallRecord
    from crucible.trace.identity_store import IdentityStore
    from crucible.trace.models import PolicyAction

    store = IdentityStore(log_dir=tmp_path)

    record = IdentityCallRecord(
        timestamp="2026-07-11T06:00:00Z",
        agent_id="test-bot",
        tool_name="read_file",
        policy_action=PolicyAction.ALLOW,
        request_id="aabbccdd-0000-0000-0000-000000000001",
    )

    anyio.from_thread.run_sync = None  # not needed — use sync directly
    # Use sync internal method to avoid spinning up an event loop in this test
    store._append_record(record.agent_id, record.model_dump_json())

    records = store.get_session_calls("test-bot")
    assert len(records) == 1
    assert records[0]["tool_name"] == "read_file"
    assert records[0]["agent_id"] == "test-bot"


def test_identity_store_sanitises_agent_id(tmp_path: Path) -> None:
    """Agent IDs with path-unsafe characters are sanitised to prevent traversal."""
    from crucible.trace.identity_store import IdentityStore, _sanitise_agent_id

    # Windows-unsafe characters must be replaced
    assert _sanitise_agent_id("agent/with/slashes") == "agent_with_slashes"
    assert _sanitise_agent_id("agent:colon") == "agent_colon"
    assert _sanitise_agent_id("agent<>pipe") == "agent__pipe"
    assert _sanitise_agent_id("") == "unknown"
    assert _sanitise_agent_id("normal-agent-id") == "normal-agent-id"


def test_identity_store_list_and_clear(tmp_path: Path) -> None:
    """list_agents() returns all agents; clear_agent_log() deletes one."""
    from crucible.models import IdentityCallRecord
    from crucible.trace.identity_store import IdentityStore
    from crucible.trace.models import PolicyAction

    store = IdentityStore(log_dir=tmp_path)

    for agent in ["alpha-bot", "beta-bot"]:
        record = IdentityCallRecord(
            timestamp="2026-07-11T06:00:00Z",
            agent_id=agent,
            tool_name="ping",
            policy_action=PolicyAction.ALLOW,
            request_id=f"00000000-0000-0000-0000-00000000000{agent[0]}",
        )
        store._append_record(agent, record.model_dump_json())

    agents = store.list_agents()
    assert set(agents) == {"alpha-bot", "beta-bot"}

    deleted = store.clear_agent_log("alpha-bot")
    assert deleted is True
    assert store.list_agents() == ["beta-bot"]

    # Clearing non-existent agent returns False
    assert store.clear_agent_log("ghost-bot") is False


def test_identity_store_check_limits_session(tmp_path: Path) -> None:
    """check_limits() triggers when session call count hits max_calls_per_session."""
    from crucible.models import AgentIdentity, IdentityCallRecord
    from crucible.trace.identity_store import IdentityStore
    from crucible.trace.models import PolicyAction

    store = IdentityStore(log_dir=tmp_path)
    identity = AgentIdentity(agent_id="limited-bot", max_calls_per_session=3)

    # Write exactly 3 records (at limit)
    for i in range(3):
        record = IdentityCallRecord(
            timestamp="2026-07-11T06:00:00Z",
            agent_id="limited-bot",
            tool_name=f"tool_{i}",
            policy_action=PolicyAction.ALLOW,
            request_id=f"00000000-0000-0000-0000-00000000000{i}",
        )
        store._append_record("limited-bot", record.model_dump_json())

    violation = store.check_limits("limited-bot", identity)
    assert violation is not None
    assert "max_calls_per_session" in violation
    assert "3/3" in violation


# ---------------------------------------------------------------------------
# Step 9.6 — Identity-aware policy evaluation integration
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_proxy_records_agent_id_in_trace_entry(tmp_path: Path) -> None:
    """TraceEntry.agent_id is populated from X-Crucible-Agent-Id header."""
    import datetime as _dt

    from crucible.trace.audit_log import AuditLog
    from crucible.trace.models import Policy
    from crucible.trace.proxy import TraceProxy

    log_path = tmp_path / "audit.jsonl"
    audit = AuditLog(log_path)
    proxy = TraceProxy(
        upstream="http://localhost:19999",  # won't actually connect
        policy=Policy(),
        audit_log=audit,
    )

    # Build a minimal HTTP POST with the agent_id header
    body = json.dumps({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 1,
        "params": {"name": "bash", "arguments": {"cmd": "ls"}},
    }).encode()
    headers = (
        b"POST /api/chat HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/json\r\n"
        b"X-Crucible-Agent-Id: proxy-test-agent\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )

    # _process is the internal pipeline; call directly to avoid real network
    _response, _status = await proxy._process(headers, "127.0.0.1")

    entries = audit.read_all()
    assert len(entries) == 1
    assert entries[0].agent_id == "proxy-test-agent"
    assert entries[0].tool_name == "bash"


@pytest.mark.anyio
async def test_proxy_identity_limit_denies_over_session_cap(tmp_path: Path) -> None:
    """Proxy denies requests when agent exceeds max_calls_per_session."""
    from crucible.models import AgentIdentity, IdentityCallRecord
    from crucible.trace.audit_log import AuditLog
    from crucible.trace.identity_store import IdentityStore
    from crucible.trace.models import Policy, PolicyAction
    from crucible.trace.proxy import TraceProxy

    log_path = tmp_path / "audit.jsonl"
    audit = AuditLog(log_path)
    id_log_dir = tmp_path / "id-logs"

    # Create an identity with limit=2, write 2 existing records
    store = IdentityStore(log_dir=id_log_dir)
    identity = AgentIdentity(agent_id="capped-bot", max_calls_per_session=2)

    for i in range(2):
        r = IdentityCallRecord(
            timestamp="2026-07-11T06:00:00Z",
            agent_id="capped-bot",
            tool_name="read_file",
            policy_action=PolicyAction.ALLOW,
            request_id=f"00000000-0000-0000-0000-00000000000{i}",
        )
        store._append_record("capped-bot", r.model_dump_json())

    # Build policy with the identity registered
    policy = Policy(agents={"capped-bot": identity})
    proxy = TraceProxy(
        upstream="http://localhost:19999",
        policy=policy,
        audit_log=audit,
        identity_store=store,
    )

    body = json.dumps({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 42,
        "params": {"name": "read_file", "arguments": {}},
    }).encode()
    request = (
        b"POST /api/chat HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/json\r\n"
        b"X-Crucible-Agent-Id: capped-bot\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )

    response_bytes, _status = await proxy._process(request, "127.0.0.1")

    response_body = response_bytes.split(b"\r\n\r\n", 1)[1]
    resp = json.loads(response_body)
    assert "error" in resp
    assert resp["error"]["message"] == "blocked_by_policy"
    assert resp["error"]["data"]["action"] == "deny"


# ---------------------------------------------------------------------------
# Step 9.7 — CLI smoke-tests
# ---------------------------------------------------------------------------


def test_cli_identity_list_empty(tmp_path: Path) -> None:
    """crucible identity list prints a message when no agents are logged."""
    from typer.testing import CliRunner

    from crucible.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["identity", "list", "--log-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "No agent logs found" in result.output


def test_cli_identity_audit_no_data(tmp_path: Path) -> None:
    """crucible identity audit exits 0 and prints a helpful message when no logs exist."""
    from typer.testing import CliRunner

    from crucible.cli import app

    runner = CliRunner()
    result = runner.invoke(
        app, ["identity", "audit", "ghost-agent", "--log-dir", str(tmp_path)]
    )
    assert result.exit_code == 0
    assert "No calls recorded" in result.output
