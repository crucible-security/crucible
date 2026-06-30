"""Async HTTP reverse proxy for MCP tool-call interception.

Architecture
------------
The proxy is a raw TCP server built on anyio + h11 (a pure-Python HTTP/1.1
implementation that ships as a transitive dependency of httpx).  It listens
on a configurable port, parses each incoming HTTP/1.1 request, inspects the
body for MCP JSON-RPC ``tools/call`` payloads, evaluates the loaded policy,
and either:

  * **deny**  — returns HTTP 200 with a JSON-RPC error body (code -32600)
                without touching the upstream server, and writes an audit entry.
  * **alert** — forwards the request to upstream, prints a console warning,
                and writes an audit entry.
  * **allow** — forwards the request to upstream transparently and writes an
                audit entry.

Why HTTP 200 for denied calls?
-------------------------------
# JSON-RPC spec requires 200 OK even for application-level errors.
# Returning 403 would break MCP clients that only handle 200 responses.

TLS support (v0.8.2)
---------------------
When *tls_cert* and *tls_key* are provided to :class:`TraceProxy`, the TCP
listener is wrapped with ``anyio.streams.tls.TLSListener`` to terminate TLS on
the first hop (agent → proxy).  The proxy → upstream connection remains plain
HTTP unless the upstream URL itself uses HTTPS.

When **no** TLS parameters are supplied the code path is 100% identical to
pre-v0.8.2 — the plain-HTTP branch is never touched.

  * ``standard_compatible=True`` (default): performs the RFC-compliant TLS
    closing handshake and forcefully closes the socket on handshake errors so
    plain-HTTP clients connecting to a TLS port receive a clean RST, not a hang.
  * ``handshake_timeout`` is configurable (CLI flag ``--tls-handshake-timeout``,
    default 30 s) — no magic numbers in security-critical paths.

Windows note
------------
anyio.run() is called with ``backend="asyncio"`` everywhere, which is the
only backend tested to work reliably on Windows 11.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import anyio
import anyio.abc
import h11
import httpx
from anyio.streams.tls import TLSListener

from crucible.trace.models import Policy, PolicyAction, TraceEntry
from crucible.trace.policy import evaluate_policy

if TYPE_CHECKING:
    import ssl
    from pathlib import Path

    from crucible.trace.audit_log import AuditLog


def is_tool_call(body: dict[str, Any]) -> tuple[bool, str | None]:
    """Detect whether *body* is an MCP ``tools/call`` JSON-RPC request.

    Args:
        body: Parsed JSON object from the incoming HTTP body.

    Returns:
        ``(is_tool_call, tool_name)`` — *tool_name* may be None for malformed
        payloads that have ``method == "tools/call"`` but no ``params.name``.
    """
    if not isinstance(body, dict):
        return False, None
    if body.get("method") != "tools/call":
        return False, None
    name: str | None = body.get("params", {}).get("name")
    return True, name


def _build_deny_response(
    request_id: Any, tool_name: str | None, rule_name: str | None
) -> bytes:
    """Build an HTTP 200 response carrying a JSON-RPC error body for denied calls."""
    error_body = json.dumps(
        {
            "jsonrpc": "2.0",
            "error": {
                "code": -32600,
                "message": "blocked_by_policy",
                "data": {
                    "rule": rule_name,
                    "tool": tool_name,
                    "action": "deny",
                },
            },
            "id": request_id,
        }
    ).encode()

    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Connection: close\r\n"
        b"Content-Length: " + str(len(error_body)).encode() + b"\r\n"
        b"\r\n" + error_body
    )
    return response


class TraceProxy:
    """Async HTTP reverse proxy with policy enforcement and audit logging.

    Args:
        upstream:              Base URL of the upstream MCP server (e.g.
                               ``http://localhost:3000``).
        policy:                Loaded :class:`Policy` to evaluate; ``None``
                               means allow-all.
        audit_log:             :class:`AuditLog` instance to append entries to.
        listen_host:           Interface to bind (default ``127.0.0.1``).
        listen_port:           TCP port to listen on (default ``8080``).
        tls_cert:              Path to a PEM certificate file.  When provided
                               together with *tls_key*, TLS is enabled on the
                               listening socket.
        tls_key:               Path to a PEM private key file matching *tls_cert*.
        tls_handshake_timeout: Seconds to wait for the TLS handshake before
                               aborting the connection (default ``30``).
    """

    def __init__(
        self,
        upstream: str,
        policy: Policy | None,
        audit_log: AuditLog,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8080,
        tls_cert: Path | None = None,
        tls_key: Path | None = None,
        tls_handshake_timeout: float = 30.0,
    ) -> None:
        self.upstream = upstream.rstrip("/")
        self.policy = policy
        self.audit_log = audit_log
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        self.tls_handshake_timeout = tls_handshake_timeout
        # Counters updated under anyio — single-threaded so no lock needed
        self._total = 0
        self._denied = 0
        self._alerts = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def handle_connection(
        self, stream: anyio.abc.ByteStream, caller_ip: str
    ) -> None:
        """Handle one TCP connection end-to-end."""
        raw = await self._read_all(stream)
        response_bytes, _ = await self._process(raw, caller_ip)
        await stream.send(response_bytes)

    async def _read_all(self, stream: anyio.abc.ByteStream) -> bytes:
        """Read until the stream closes or we have a complete HTTP request."""
        chunks: list[bytes] = []
        conn = h11.Connection(h11.SERVER)

        with anyio.move_on_after(30):  # 30-second read timeout
            while True:
                data = await stream.receive(65536)
                if not data:
                    break
                chunks.append(data)
                conn.receive_data(data)
                # Check if h11 has parsed a complete request
                while True:
                    event = conn.next_event()
                    if event is h11.NEED_DATA:
                        break
                    if isinstance(event, h11.EndOfMessage):
                        return b"".join(chunks)
                    if isinstance(event, h11.Request):
                        # Keep accumulating until EndOfMessage
                        pass

        return b"".join(chunks)

    async def _process(self, raw: bytes, caller_ip: str) -> tuple[bytes, int]:
        """Core request processing pipeline.

        Returns:
            ``(response_bytes, http_status_code)``
        """
        self._total += 1
        request_id = str(uuid.uuid4())
        request_size = len(raw)

        # --- Parse HTTP to extract body ---
        body_bytes = self._extract_body(raw)
        body_dict: dict[str, Any] | None = None
        rpc_id: Any = None

        try:
            body_dict = json.loads(body_bytes) if body_bytes else None
            if isinstance(body_dict, dict):
                rpc_id = body_dict.get("id")
        except (json.JSONDecodeError, ValueError):
            body_dict = None

        # --- Detect tool call ---
        tool_call = False
        tool_name: str | None = None
        arguments: dict[str, Any] | None = None

        if body_dict is not None:
            tool_call, tool_name = is_tool_call(body_dict)
            if tool_call:
                raw_args = body_dict.get("params", {}).get("arguments")
                arguments = raw_args if isinstance(raw_args, dict) else None

        # --- Evaluate policy ---
        action = PolicyAction.ALLOW
        rule_matched: str | None = None

        if tool_call and self.policy is not None:
            action, rule_matched = evaluate_policy(self.policy, tool_name, arguments)
        elif not tool_call:
            action = PolicyAction.ALLOW  # non-tool traffic always forwarded

        # --- Execute decision ---
        upstream_status: int | None = None
        upstream_latency: float | None = None
        response_bytes: bytes

        if action == PolicyAction.DENY:
            self._denied += 1
            response_bytes = _build_deny_response(rpc_id, tool_name, rule_matched)
            upstream_status = None
            upstream_latency = None
        else:
            if action == PolicyAction.ALERT:
                self._alerts += 1
                print(
                    f"[crucible trace] ALERT — tool '{tool_name}' matched rule "
                    f"'{rule_matched}' (forwarding anyway)",
                    flush=True,
                )
            # Forward to upstream
            response_bytes, upstream_status, upstream_latency = await self._forward(raw)

        # --- Write audit log ---
        entry = TraceEntry(
            timestamp=datetime.now(tz=timezone.utc),
            request_id=request_id,
            tool_name=tool_name if tool_call else None,
            parameters=arguments if tool_call else None,
            policy_action=action,
            policy_rule_matched=rule_matched,
            upstream_status_code=upstream_status,
            upstream_latency_ms=upstream_latency,
            request_size_bytes=request_size,
            caller_ip=caller_ip,
        )
        self.audit_log.append(entry)

        return response_bytes, upstream_status or 200

    def _extract_body(self, raw: bytes) -> bytes:
        """Extract the HTTP body from raw HTTP/1.1 bytes using h11."""
        conn = h11.Connection(h11.SERVER)
        conn.receive_data(raw)
        body_parts: list[bytes] = []
        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA or isinstance(event, h11.EndOfMessage):
                break
            if isinstance(event, h11.Data):
                body_parts.append(event.data)
        return b"".join(body_parts)

    async def _forward(self, raw: bytes) -> tuple[bytes, int, float]:
        """Forward raw HTTP bytes to upstream; return (response_bytes, status, latency_ms)."""
        # Parse the incoming request with h11 to extract method, path, headers
        conn = h11.Connection(h11.SERVER)
        conn.receive_data(raw)

        method = b"POST"
        path = b"/"
        headers: dict[str, str] = {}
        body_parts: list[bytes] = []

        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA:
                break
            if isinstance(event, h11.Request):
                method = event.method
                path = event.target
                for name, value in event.headers:
                    hname = name.decode("latin-1").lower()
                    # Skip hop-by-hop headers
                    if hname not in ("host", "connection", "transfer-encoding"):
                        headers[hname] = value.decode("latin-1")
            elif isinstance(event, h11.Data):
                body_parts.append(event.data)
            elif isinstance(event, h11.EndOfMessage):
                break

        body = b"".join(body_parts)
        url = self.upstream + path.decode("latin-1")

        import time  # local import to avoid circular top-level

        t0 = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.request(
                    method=method.decode(),
                    url=url,
                    headers=headers,
                    content=body,
                )
            latency_ms = (time.perf_counter() - t0) * 1000.0
            # Re-serialise as raw HTTP/1.1 response bytes
            status_line = (
                f"HTTP/1.1 {resp.status_code} {resp.reason_phrase}\r\n".encode()
            )
            resp_headers = b"".join(
                f"{k}: {v}\r\n".encode()
                for k, v in resp.headers.items()
                if k.lower() not in ("transfer-encoding",)
            )
            resp_headers += b"Connection: close\r\n"
            response_bytes = status_line + resp_headers + b"\r\n" + resp.content
            return response_bytes, resp.status_code, latency_ms
        except Exception as exc:
            latency_ms = (time.perf_counter() - t0) * 1000.0
            error_body = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32603, "message": str(exc)},
                    "id": None,
                }
            ).encode()
            response_bytes = (
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\n"
                b"Connection: close\r\nContent-Length: "
                + str(len(error_body)).encode()
                + b"\r\n\r\n"
                + error_body
            )
            return response_bytes, 502, latency_ms

    # ------------------------------------------------------------------
    # Server lifecycle
    # ------------------------------------------------------------------

    async def serve(self) -> None:
        """Start the anyio TCP listener.  Blocks until cancelled (Ctrl+C).

        When *tls_cert* and *tls_key* were supplied at construction time, wraps
        the raw TCP listener with :class:`anyio.streams.tls.TLSListener` so
        that TLS is terminated on the first hop.  The plain-HTTP code path is
        100% unchanged when no TLS parameters are provided.
        """
        tcp_listener = await anyio.create_tcp_listener(
            local_host=self.listen_host,
            local_port=self.listen_port,
        )

        # --- TLS wrapping (additive, plain-HTTP path unchanged) ---
        if self.tls_cert is not None and self.tls_key is not None:
            from crucible.trace.tls_utils import build_ssl_context

            ssl_ctx: ssl.SSLContext = build_ssl_context(self.tls_cert, self.tls_key)
            listener: anyio.abc.Listener[anyio.abc.ByteStream] = TLSListener(
                listener=tcp_listener,
                ssl_context=ssl_ctx,
                standard_compatible=True,
                handshake_timeout=self.tls_handshake_timeout,
            )
        else:
            listener = tcp_listener

        async with listener, anyio.create_task_group() as tg:

            async def _serve_one(stream: anyio.abc.ByteStream) -> None:
                caller_ip = "unknown"
                try:
                    # anyio SocketStream exposes .extra() for peer info
                    import anyio.abc

                    if hasattr(stream, "extra"):
                        try:
                            peer = stream.extra(
                                anyio.abc.SocketAttribute.remote_address
                            )
                            caller_ip = str(peer[0]) if peer else "unknown"
                        except Exception:
                            pass
                    async with stream:
                        await self.handle_connection(stream, caller_ip)
                except Exception:
                    pass

            await listener.serve(_serve_one, task_group=tg)

    @property
    def counters(self) -> dict[str, int]:
        """Return current request counters."""
        return {
            "total": self._total,
            "denied": self._denied,
            "alerts": self._alerts,
            "allowed": self._total - self._denied - self._alerts,
        }
