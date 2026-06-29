"""Tests for the crucible trace proxy subsystem (Phase 6 / v0.7.0).

Coverage
--------
  1.  load_policy — valid file
  2.  load_policy — invalid regex raises PolicyError
  3.  evaluate_policy — deny by exact tool name
  4.  evaluate_policy — deny by parameter pattern
  5.  evaluate_policy — alert action
  6.  evaluate_policy — allow action
  7.  evaluate_policy — default allow (no matching rule)
  8.  is_tool_call — True for tools/call body
  9.  is_tool_call — False for other methods
  10. is_tool_call — False for non-JSON body
  11. AuditLog — append then read back, verify all fields
  12. Integration — deny: proxy returns JSON-RPC error (HTTP 200)
  13. Integration — allow: proxy forwards to mock MCP server
  14. CLI validate-policy — exits 0 for valid policy
  15. CLI validate-policy — exits 1 for invalid policy (bad regex)
"""

from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path

import anyio
import httpx
import pytest
from typer.testing import CliRunner

from crucible.cli import app
from crucible.trace.audit_log import AuditLog
from crucible.trace.models import PolicyAction, TraceEntry
from crucible.trace.policy import PolicyError, evaluate_policy, load_policy
from crucible.trace.proxy import TraceProxy, is_tool_call
from tests.fixtures.mock_mcp_server import MockMCPServer

# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------
_FIXTURES = Path(__file__).parent / "fixtures"
_VALID_POLICY = _FIXTURES / "test_policy.yaml"


# ---------------------------------------------------------------------------
# Helper: find a free port
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for_port(port: int, timeout: float = 5.0) -> bool:
    start_time = time.monotonic()
    while time.monotonic() - start_time < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return True
        except (socket.error, ConnectionRefusedError):
            time.sleep(0.05)
    return False


# ---------------------------------------------------------------------------


class _ProxyThread:
    """Runs a TraceProxy in a daemon thread for the duration of the test.

    Shutdown is signalled via a ``threading.Event`` which the async loop
    polls, avoiding the need to call ``CancelScope.cancel()`` across threads
    (which requires a running event loop and breaks outside asyncio).
    """

    def __init__(self, proxy: TraceProxy) -> None:
        self._proxy = proxy
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        def _run() -> None:
            async def _main() -> None:
                async with anyio.create_task_group() as tg:
                    tg.start_soon(self._proxy.serve)

                    async def _watcher() -> None:
                        # Poll the threading.Event and cancel the group when set
                        while not self._stop_event.is_set():
                            await anyio.sleep(0.05)
                        tg.cancel_scope.cancel()

                    tg.start_soon(_watcher)

            anyio.run(_main, backend="asyncio")

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()
        # Wait for the server to bind
        if not _wait_for_port(self._proxy.listen_port):
            raise RuntimeError(
                f"Proxy failed to start on port {self._proxy.listen_port}"
            )

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)


# ===========================================================================
# 1. load_policy — valid file
# ===========================================================================


def test_load_policy_valid() -> None:
    policy = load_policy(_VALID_POLICY)
    assert len(policy.rules) == 4
    assert policy.default_action == PolicyAction.ALLOW
    rule_names = [r.name for r in policy.rules]
    assert "block-bash" in rule_names
    assert "block-dangerous-rm" in rule_names
    assert "alert-execute-code" in rule_names
    assert "allow-read-file" in rule_names


# ===========================================================================
# 2. load_policy — invalid regex raises PolicyError
# ===========================================================================


def test_load_policy_invalid_regex(tmp_path: Path) -> None:
    bad_policy = tmp_path / "bad.yaml"
    bad_policy.write_text(
        "default_action: allow\n"
        "rules:\n"
        "  - name: bad-rule\n"
        "    parameter_pattern: 'rm\\s+[rf'\n"  # unclosed character class
        "    action: deny\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="invalid regex"):
        load_policy(bad_policy)


# ===========================================================================
# 3. evaluate_policy — deny by exact tool name (bash)
# ===========================================================================


def test_evaluate_policy_deny_by_name() -> None:
    policy = load_policy(_VALID_POLICY)
    action, rule = evaluate_policy(policy, "bash", {})
    assert action == PolicyAction.DENY
    assert rule == "block-bash"


# ===========================================================================
# 4. evaluate_policy — deny by parameter pattern ("rm -rf")
# ===========================================================================


def test_evaluate_policy_deny_by_pattern() -> None:
    policy = load_policy(_VALID_POLICY)
    # tool_name doesn't match block-bash; pattern should catch the args
    action, rule = evaluate_policy(policy, "shell", {"command": "rm -rf /"})
    assert action == PolicyAction.DENY
    assert rule == "block-dangerous-rm"


# ===========================================================================
# 5. evaluate_policy — alert action
# ===========================================================================


def test_evaluate_policy_alert() -> None:
    policy = load_policy(_VALID_POLICY)
    action, rule = evaluate_policy(policy, "execute_code", {"code": "print('hi')"})
    assert action == PolicyAction.ALERT
    assert rule == "alert-execute-code"


# ===========================================================================
# 6. evaluate_policy — allow action (explicit rule)
# ===========================================================================


def test_evaluate_policy_allow() -> None:
    policy = load_policy(_VALID_POLICY)
    action, rule = evaluate_policy(policy, "read_file", {"path": "/etc/hosts"})
    assert action == PolicyAction.ALLOW
    assert rule == "allow-read-file"


# ===========================================================================
# 7. evaluate_policy — default allow (no matching rule)
# ===========================================================================


def test_evaluate_policy_default_allow() -> None:
    policy = load_policy(_VALID_POLICY)
    action, rule = evaluate_policy(policy, "list_directory", {"path": "/tmp"})
    assert action == PolicyAction.ALLOW
    assert rule is None  # default, no rule matched


# ===========================================================================
# 8. is_tool_call — True for tools/call body
# ===========================================================================


def test_is_tool_call_true() -> None:
    body = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": "bash", "arguments": {"command": "whoami"}},
        "id": 1,
    }
    result, name = is_tool_call(body)
    assert result is True
    assert name == "bash"


# ===========================================================================
# 9. is_tool_call — False for other method (tools/list)
# ===========================================================================


def test_is_tool_call_false_other_method() -> None:
    body = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
    result, name = is_tool_call(body)
    assert result is False
    assert name is None


# ===========================================================================
# 10. is_tool_call — False for non-JSON body
# ===========================================================================


def test_is_tool_call_false_non_json() -> None:
    result, name = is_tool_call("not a dict")  # type: ignore[arg-type]
    assert result is False
    assert name is None


# ===========================================================================
# 11. AuditLog — append then read back, verify all fields
# ===========================================================================


def test_audit_log_append_and_read(tmp_path: Path) -> None:
    from datetime import datetime, timezone

    log_path = tmp_path / "trace.jsonl"
    log = AuditLog(log_path)

    entry = TraceEntry(
        timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        request_id="test-uuid-1234",
        tool_name="bash",
        parameters={"command": "whoami"},
        policy_action=PolicyAction.DENY,
        policy_rule_matched="block-bash",
        upstream_status_code=None,
        upstream_latency_ms=None,
        request_size_bytes=128,
        caller_ip="127.0.0.1",
    )
    log.append(entry)

    # Verify file exists and has one line
    assert log_path.exists()
    lines = [
        line
        for line in log_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(lines) == 1

    # Deserialise and verify fields
    parsed = json.loads(lines[0])
    assert parsed["tool_name"] == "bash"
    assert parsed["policy_action"] == "deny"
    assert parsed["policy_rule_matched"] == "block-bash"
    assert parsed["upstream_status_code"] is None
    assert parsed["request_size_bytes"] == 128
    assert parsed["caller_ip"] == "127.0.0.1"

    # read_all() round-trip
    all_entries = log.read_all()
    assert len(all_entries) == 1
    assert all_entries[0].tool_name == "bash"
    assert all_entries[0].policy_action == PolicyAction.DENY


# ===========================================================================
# 12. Integration — deny: proxy returns JSON-RPC error (HTTP 200)
# ===========================================================================


def test_proxy_deny_returns_json_rpc_error(tmp_path: Path) -> None:
    """Full integration: proxy denies bash call, returns JSON-RPC error body."""
    log_path = tmp_path / "trace.jsonl"
    audit_log = AuditLog(log_path)
    policy = load_policy(_VALID_POLICY)
    port = _free_port()

    proxy = TraceProxy(
        upstream="http://127.0.0.1:1",  # unreachable — should never be hit for deny
        policy=policy,
        audit_log=audit_log,
        listen_host="127.0.0.1",
        listen_port=port,
    )
    pt = _ProxyThread(proxy)
    pt.start()
    try:
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "bash", "arguments": {"command": "whoami"}},
                "id": 1,
            }
        ).encode()

        with httpx.Client(timeout=10.0) as client:
            resp = client.post(
                f"http://127.0.0.1:{port}",
                content=payload,
                headers={"Content-Type": "application/json"},
            )

        assert resp.status_code == 200
        body = resp.json()
        assert "error" in body
        assert body["error"]["message"] == "blocked_by_policy"
        assert body["error"]["data"]["action"] == "deny"
        assert body["error"]["data"]["tool"] == "bash"
        assert body["error"]["data"]["rule"] == "block-bash"

        # Audit log must have one deny entry
        entries = audit_log.read_all()
        assert len(entries) == 1
        assert entries[0].policy_action == PolicyAction.DENY
        assert entries[0].tool_name == "bash"
        assert entries[0].upstream_status_code is None
    finally:
        pt.stop()


# ===========================================================================
# 13. Integration — allow: proxy forwards to mock MCP server
# ===========================================================================


def test_proxy_allow_forwards_to_upstream(tmp_path: Path) -> None:
    """Full integration: proxy forwards read_file call to mock MCP server."""
    log_path = tmp_path / "trace.jsonl"
    audit_log = AuditLog(log_path)
    policy = load_policy(_VALID_POLICY)
    port = _free_port()

    with MockMCPServer() as mock:
        proxy = TraceProxy(
            upstream=mock.url,
            policy=policy,
            audit_log=audit_log,
            listen_host="127.0.0.1",
            listen_port=port,
        )
        pt = _ProxyThread(proxy)
        pt.start()
        try:
            payload = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "name": "read_file",
                        "arguments": {"path": "/etc/hosts"},
                    },
                    "id": 2,
                }
            ).encode()

            with httpx.Client(timeout=10.0) as client:
                resp = client.post(
                    f"http://127.0.0.1:{port}",
                    content=payload,
                    headers={"Content-Type": "application/json"},
                )

            assert resp.status_code == 200
            body = resp.json()
            assert "result" in body
            assert body["result"]["isError"] is False
            # Mock server echoes the tool name
            assert "read_file" in body["result"]["content"][0]["text"]

            # Audit log must have one allow entry with upstream status
            entries = audit_log.read_all()
            assert len(entries) == 1
            assert entries[0].policy_action == PolicyAction.ALLOW
            assert entries[0].tool_name == "read_file"
            assert entries[0].upstream_status_code == 200
            assert entries[0].upstream_latency_ms is not None
            assert entries[0].upstream_latency_ms >= 0
        finally:
            pt.stop()


# ===========================================================================
# 14. CLI validate-policy — exits 0 for valid policy
# ===========================================================================


def test_validate_policy_cli_ok() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app, ["trace", "validate-policy", "--policy", str(_VALID_POLICY)]
    )
    assert result.exit_code == 0, result.output
    assert "OK" in result.output or "valid" in result.output.lower()


# ===========================================================================
# 15. CLI validate-policy — exits 1 for bad regex
# ===========================================================================


def test_validate_policy_cli_bad_regex(tmp_path: Path) -> None:
    bad_policy = tmp_path / "bad.yaml"
    bad_policy.write_text(
        "default_action: allow\n"
        "rules:\n"
        "  - name: bad-regex-rule\n"
        "    parameter_pattern: 'rm\\s+[rf'\n"
        "    action: deny\n",
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(
        app, ["trace", "validate-policy", "--policy", str(bad_policy)]
    )
    assert result.exit_code == 1
    assert "invalid" in result.output.lower() or "error" in result.output.lower()
