"""Minimal HTTP server stub that mimics an MCP server for integration tests.

Starts on an OS-assigned port (socket.bind to port 0) to avoid conflicts.
Run via ``MockMCPServer`` context manager — starts a daemon thread and shuts
down cleanly when the ``with`` block exits.

Supported JSON-RPC methods:
  - tools/list   → returns a stub tool list
  - tools/call   → echoes back a success response
  - anything else → returns a JSON-RPC error
"""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
import time


def _wait_for_port(port: int, timeout: float = 5.0) -> bool:
    start_time = time.monotonic()
    while time.monotonic() - start_time < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return True
        except (socket.error, ConnectionRefusedError):
            time.sleep(0.05)
    return False


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: Any) -> None:
        """Suppress default request logging during tests."""

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(length) if length else b""

        try:
            body: dict[str, Any] = json.loads(body_bytes)
        except (json.JSONDecodeError, ValueError):
            self._send_json(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32700, "message": "Parse error"},
                    "id": None,
                }
            )
            return

        method = body.get("method", "")
        rpc_id = body.get("id")

        if method == "tools/list":
            self._send_json(
                {
                    "jsonrpc": "2.0",
                    "result": {
                        "tools": [
                            {
                                "name": "read_file",
                                "description": "Read a file",
                                "inputSchema": {},
                            },
                            {
                                "name": "bash",
                                "description": "Run bash",
                                "inputSchema": {},
                            },
                        ]
                    },
                    "id": rpc_id,
                }
            )
        elif method == "tools/call":
            tool_name = body.get("params", {}).get("name", "unknown")
            self._send_json(
                {
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [
                            {"type": "text", "text": f"OK: {tool_name} executed"}
                        ],
                        "isError": False,
                    },
                    "id": rpc_id,
                }
            )
        else:
            self._send_json(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                    "id": rpc_id,
                }
            )

    def _send_json(self, data: dict[str, Any]) -> None:
        payload = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class MockMCPServer:
    """Context manager that runs a mock MCP HTTP server in a daemon thread.

    Usage::

        with MockMCPServer() as srv:
            url = srv.url          # e.g. "http://127.0.0.1:54321"
            port = srv.port
            ...

    The server picks a free port automatically via ``socket.bind(("127.0.0.1", 0))``.
    """

    def __init__(self) -> None:
        self._server = HTTPServer(("127.0.0.1", 0), _Handler)
        self.port: int = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> MockMCPServer:
        self._thread.start()
        if not _wait_for_port(self.port):
            raise RuntimeError(f"MockMCPServer failed to start on port {self.port}")
        return self

    def __exit__(self, *_: Any) -> None:
        self._server.shutdown()
        self._thread.join(timeout=5)
