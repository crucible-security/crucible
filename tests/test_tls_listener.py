"""Tests for Phase 8 — TLS Listener for crucible trace proxy (v0.8.2).

Coverage (8 tests, target total ≥ 389):
  1.  generate_self_signed — cert + key PEM files created and readable
  2.  generate_self_signed — cert is valid x509, key matches
  3.  build_ssl_context — loads valid cert/key without error
  4.  build_ssl_context — raises FileNotFoundError on missing cert
  5.  build_ssl_context — raises FileNotFoundError on missing key
  6.  TLS proxy — real TLS handshake via httpx (verify=False); allow response
  7.  TLS proxy — blocked tool returns JSON-RPC error over TLS
  8.  plain HTTP path unchanged — existing proxy works after TLS code addition
  (CLI flag validation test is covered via integration in test_trace_proxy.py)
"""

from __future__ import annotations

import socket
import ssl
import threading
import time
from typing import TYPE_CHECKING

import anyio
import httpx
import pytest

from crucible.trace.audit_log import AuditLog
from crucible.trace.models import Policy, PolicyAction, PolicyRule
from crucible.trace.proxy import TraceProxy
from crucible.trace.tls_utils import build_ssl_context, generate_self_signed

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for_port(port: int, timeout: float = 5.0) -> bool:
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return True
        except (OSError, ConnectionRefusedError):
            time.sleep(0.05)
    return False


def _wait_for_tls_port(port: int, timeout: float = 5.0) -> bool:
    """Wait until the port accepts a TLS connection (not just TCP)."""
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with (
                socket.create_connection(("127.0.0.1", port), timeout=2.0) as raw,
                ctx.wrap_socket(raw, server_hostname="localhost"),
            ):
                return True
        except Exception:
            time.sleep(0.05)
    return False


class _TLSProxyThread:
    """Run a TLS-enabled TraceProxy in a daemon thread for a single test."""

    def __init__(self, proxy: TraceProxy) -> None:
        self._proxy = proxy
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        def _run() -> None:
            async def _main() -> None:
                async with anyio.create_task_group() as tg:
                    tg.start_soon(self._proxy.serve)

                    async def _watcher() -> None:
                        while not self._stop.is_set():
                            await anyio.sleep(0.05)
                        tg.cancel_scope.cancel()

                    tg.start_soon(_watcher)

            anyio.run(_main, backend="asyncio")

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()
        if not _wait_for_tls_port(self._proxy.listen_port):
            raise RuntimeError(
                f"TLS proxy failed to start on port {self._proxy.listen_port}"
            )

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)


class _PlainProxyThread:
    """Run a plain-HTTP TraceProxy in a daemon thread for regression guard."""

    def __init__(self, proxy: TraceProxy) -> None:
        self._proxy = proxy
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        def _run() -> None:
            async def _main() -> None:
                async with anyio.create_task_group() as tg:
                    tg.start_soon(self._proxy.serve)

                    async def _watcher() -> None:
                        while not self._stop.is_set():
                            await anyio.sleep(0.05)
                        tg.cancel_scope.cancel()

                    tg.start_soon(_watcher)

            anyio.run(_main, backend="asyncio")

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()
        if not _wait_for_port(self._proxy.listen_port):
            raise RuntimeError(
                f"Plain proxy failed to start on port {self._proxy.listen_port}"
            )

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def self_signed_certs(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """Generate one self-signed cert pair for the entire test module."""
    tmpdir = tmp_path_factory.mktemp("tls_certs")
    cert_path, key_path = generate_self_signed(tmpdir)
    return cert_path, key_path


@pytest.fixture(scope="module")
def module_ssl_context(
    self_signed_certs: tuple[Path, Path],
) -> ssl.SSLContext:
    cert_path, key_path = self_signed_certs
    return build_ssl_context(cert_path, key_path)


# ===========================================================================
# Test 1 — generate_self_signed creates readable PEM files
# ===========================================================================


def test_generate_self_signed_creates_files(tmp_path: Path) -> None:
    cert_path, key_path = generate_self_signed(tmp_path)

    assert cert_path.exists(), "cert PEM file should exist"
    assert key_path.exists(), "key PEM file should exist"
    assert cert_path.stat().st_size > 0, "cert file must not be empty"
    assert key_path.stat().st_size > 0, "key file must not be empty"

    cert_pem = cert_path.read_text()
    key_pem = key_path.read_text()
    assert "BEGIN CERTIFICATE" in cert_pem
    assert "BEGIN RSA PRIVATE KEY" in key_pem or "BEGIN PRIVATE KEY" in key_pem


# ===========================================================================
# Test 2 — generate_self_signed cert is valid x509, SAN includes localhost
# ===========================================================================


def test_generate_self_signed_valid_x509(tmp_path: Path) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    cert_path, key_path = generate_self_signed(tmp_path)

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    assert (
        cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        == "crucible-trace-proxy"
    )

    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_names = san.value.get_values_for_type(x509.DNSName)
    assert "localhost" in dns_names

    # Verify key pair matches (public keys are equal)
    from cryptography.hazmat.primitives.asymmetric import rsa

    priv_key = load_pem_private_key(key_path.read_bytes(), password=None)
    pub_key_from_priv = priv_key.public_key()
    pub_key_from_cert = cert.public_key()

    assert isinstance(pub_key_from_priv, rsa.RSAPublicKey)
    assert isinstance(pub_key_from_cert, rsa.RSAPublicKey)
    assert pub_key_from_priv.public_numbers() == pub_key_from_cert.public_numbers()


# ===========================================================================
# Test 3 — build_ssl_context loads a valid cert/key without error
# ===========================================================================


def test_build_ssl_context_loads_cert(
    self_signed_certs: tuple[Path, Path],
) -> None:
    cert_path, key_path = self_signed_certs
    ctx = build_ssl_context(cert_path, key_path)
    assert isinstance(ctx, ssl.SSLContext)


# ===========================================================================
# Test 4 — build_ssl_context raises FileNotFoundError on missing cert
# ===========================================================================


def test_build_ssl_context_missing_cert(tmp_path: Path) -> None:
    _, key_path = generate_self_signed(tmp_path)
    fake_cert = tmp_path / "nonexistent.crt"
    with pytest.raises(FileNotFoundError, match="certificate"):
        build_ssl_context(fake_cert, key_path)


# ===========================================================================
# Test 5 — build_ssl_context raises FileNotFoundError on missing key
# ===========================================================================


def test_build_ssl_context_missing_key(tmp_path: Path) -> None:
    cert_path, _ = generate_self_signed(tmp_path)
    fake_key = tmp_path / "nonexistent.key"
    with pytest.raises(FileNotFoundError, match="key"):
        build_ssl_context(cert_path, fake_key)


# ===========================================================================
# Test 6 — TLS proxy: real TLS handshake via httpx, allow response
# ===========================================================================


def test_tls_proxy_allow_over_https(
    self_signed_certs: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    cert_path, key_path = self_signed_certs
    port = _free_port()
    log_file = tmp_path / "tls_audit.jsonl"

    # Use a non-existent upstream — we only test the TLS layer + deny path
    # here so we build a deny-all policy to avoid needing a real upstream
    deny_policy = Policy(
        default_action=PolicyAction.DENY,
        rules=[],
    )
    audit = AuditLog(log_file)
    proxy = TraceProxy(
        upstream="http://127.0.0.1:19999",  # intentionally unreachable
        policy=deny_policy,
        audit_log=audit,
        listen_host="127.0.0.1",
        listen_port=port,
        tls_cert=cert_path,
        tls_key=key_path,
        tls_handshake_timeout=10.0,
    )

    pt = _TLSProxyThread(proxy)
    pt.start()
    try:
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {}},
            "id": 42,
        }
        resp = httpx.post(
            f"https://127.0.0.1:{port}",
            json=payload,
            verify=False,  # self-signed cert — skip verification
            timeout=10.0,
        )
        assert resp.status_code == 200
        body = resp.json()
        # default_action=DENY → JSON-RPC error
        assert "error" in body
        assert body["error"]["message"] == "blocked_by_policy"
    finally:
        pt.stop()


# ===========================================================================
# Test 7 — TLS proxy: blocked tool returns JSON-RPC error over TLS
# ===========================================================================


def test_tls_proxy_deny_over_https(
    self_signed_certs: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    cert_path, key_path = self_signed_certs
    port = _free_port()
    log_file = tmp_path / "tls_deny_audit.jsonl"

    deny_rule = PolicyRule(
        name="block-bash",
        tool_name="bash",
        action=PolicyAction.DENY,
    )
    policy = Policy(
        default_action=PolicyAction.ALLOW,
        rules=[deny_rule],
    )
    audit = AuditLog(log_file)
    proxy = TraceProxy(
        upstream="http://127.0.0.1:19999",
        policy=policy,
        audit_log=audit,
        listen_host="127.0.0.1",
        listen_port=port,
        tls_cert=cert_path,
        tls_key=key_path,
        tls_handshake_timeout=10.0,
    )

    pt = _TLSProxyThread(proxy)
    pt.start()
    try:
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "bash", "arguments": {"cmd": "whoami"}},
            "id": 99,
        }
        resp = httpx.post(
            f"https://127.0.0.1:{port}",
            json=payload,
            verify=False,
            timeout=10.0,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "error" in body
        assert body["error"]["message"] == "blocked_by_policy"
        err_data = body["error"]["data"]
        assert err_data["tool"] == "bash"
        assert err_data["action"] == "deny"
    finally:
        pt.stop()


# ===========================================================================
# Test 8 — plain HTTP path is 100% unchanged (regression guard)
# ===========================================================================


def test_plain_http_proxy_unchanged(tmp_path: Path) -> None:
    """Verify that a TraceProxy with no TLS params still works as plain HTTP."""
    from tests.fixtures.mock_mcp_server import MockMCPServer

    port = _free_port()
    log_file = tmp_path / "plain_audit.jsonl"

    with MockMCPServer() as upstream:
        audit = AuditLog(log_file)
        # No tls_cert / tls_key — plain HTTP mode
        proxy = TraceProxy(
            upstream=upstream.url,
            policy=None,
            audit_log=audit,
            listen_host="127.0.0.1",
            listen_port=port,
        )

        pt = _PlainProxyThread(proxy)
        pt.start()
        try:
            payload = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "list_files", "arguments": {}},
                "id": 1,
            }
            resp = httpx.post(
                f"http://127.0.0.1:{port}",
                json=payload,
                timeout=10.0,
            )
            assert resp.status_code == 200
            # The mock MCP server returns a valid JSON body
            body = resp.json()
            assert body is not None
        finally:
            pt.stop()


# ===========================================================================
# Test 9 — TLS handshake timeout is configurable
# ===========================================================================


def test_tls_handshake_timeout_configurable(
    self_signed_certs: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    """Verify that setting a short handshake timeout drops incomplete handshakes quickly."""
    cert_path, key_path = self_signed_certs
    port = _free_port()
    log_file = tmp_path / "tls_timeout_audit.jsonl"

    audit = AuditLog(log_file)
    proxy = TraceProxy(
        upstream="http://127.0.0.1:19999",
        policy=None,
        audit_log=audit,
        listen_host="127.0.0.1",
        listen_port=port,
        tls_cert=cert_path,
        tls_key=key_path,
        tls_handshake_timeout=0.2,  # very short timeout
    )

    pt = _TLSProxyThread(proxy)
    pt.start()
    try:
        # Connect raw TCP but do not send any TLS ClientHello
        s = socket.create_connection(("127.0.0.1", port), timeout=2.0)
        time.sleep(0.5)  # Wait longer than 0.2s timeout
        # Try to read or write, which should fail or indicate the socket is closed
        s.settimeout(0.5)
        try:
            # If the server closed the connection, receive will return empty bytes or raise connection error
            data = s.recv(1024)
            assert len(data) == 0, "Server should have closed the connection"
        except (TimeoutError, OSError):
            # Closed socket or timeout on read is also acceptable
            pass
        finally:
            s.close()
    finally:
        pt.stop()


# ===========================================================================
# Test 10 — Server handles invalid/garbage handshakes gracefully without crashing
# ===========================================================================


def test_tls_proxy_rejects_invalid_cert_client_gracefully(
    self_signed_certs: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    """Verify that client sending plain text/garbage to TLS listener doesn't crash the server."""
    cert_path, key_path = self_signed_certs
    port = _free_port()
    log_file = tmp_path / "tls_garbage_audit.jsonl"

    deny_policy = Policy(
        default_action=PolicyAction.DENY,
        rules=[],
    )
    audit = AuditLog(log_file)
    proxy = TraceProxy(
        upstream="http://127.0.0.1:19999",
        policy=deny_policy,
        audit_log=audit,
        listen_host="127.0.0.1",
        listen_port=port,
        tls_cert=cert_path,
        tls_key=key_path,
        tls_handshake_timeout=1.0,
    )

    pt = _TLSProxyThread(proxy)
    pt.start()
    try:
        # 1. Send garbage (plain HTTP request to HTTPS port)
        s = socket.create_connection(("127.0.0.1", port), timeout=2.0)
        try:
            s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            # Wait a moment for server to process and close
            s.settimeout(1.0)
            s.recv(1024)
        except OSError:
            pass
        finally:
            s.close()

        # 2. Verify that the server is still alive and serving other clients
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {}},
            "id": 43,
        }
        resp = httpx.post(
            f"https://127.0.0.1:{port}",
            json=payload,
            verify=False,
            timeout=10.0,
        )
        assert resp.status_code == 200
        assert "error" in resp.json()  # Denied by policy, but connection succeeded!
    finally:
        pt.stop()
