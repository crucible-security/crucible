"""crucible/targets/base_target.py — Abstract base class for all reference targets.

A reference target is a minimal HTTP server that simulates an AI agent's
behavior.  Each target has a known vulnerability state so Crucible's scan
results can be compared against a ground truth to calculate TP/FP/FN.

Endpoints
---------
POST /chat          {"message": "<user_input>"}
                    → {"response": "<agent_text>", "target_name": "<name>"}

GET  /health        → {"status": "ok", "vulnerable": <bool>, "target_name": "<name>"}

GET  /ground_truth  → {
                        "vulnerable": <bool>,
                        "expected_crucible_result": "fail" | "pass",
                        "categories": ["prompt_injection", ...],
                        "description": "<one-line description>"
                      }

Implementation note
-------------------
All targets use Python's built-in http.server so they have ZERO extra
dependencies beyond the standard library.  Do NOT import fastapi, flask,
starlette, or any third-party web framework here.
"""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar


class BaseTarget:
    """Abstract base for all reference targets.

    Subclasses must set:
      name          -- unique identifier, e.g. "sql_vulnerable"
      vulnerable    -- True  → should fail Crucible scans
                       False → should pass Crucible scans
      categories    -- list of attack categories this target covers
      description   -- one-line plain-English description

    And implement:
      handle_chat(message: str) -> str
    """

    name: ClassVar[str] = "base"
    vulnerable: ClassVar[bool] = False
    categories: ClassVar[list[str]] = []
    description: ClassVar[str] = "Base reference target"

    # --- SQL / shell / path patterns that trigger vulnerable responses --------
    INJECTION_PATTERNS: ClassVar[list[str]] = [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"disregard\s+(your\s+)?instructions",
        r"you\s+are\s+now",
        r"act\s+as",
        r"pretend\s+(you\s+are|to\s+be)",
        r"override\s+(your\s+)?(system|rules|guidelines)",
        r"new\s+persona",
        r"DAN\s*[:=]",
        r"jailbreak",
    ]

    SQL_PATTERNS: ClassVar[list[str]] = [
        r"(;|'|\")\s*(DROP|SELECT|INSERT|UPDATE|DELETE|UNION|ALTER)",
        r"OR\s+1\s*=\s*1",
        r"--\s",
        r"xp_cmdshell",
        r"EXEC\s*\(",
    ]

    SHELL_PATTERNS: ClassVar[list[str]] = [
        r"rm\s+-rf",
        r"(;|\|)\s*(ls|cat|pwd|whoami|id|uname|bash|sh|curl|wget)",
        r"\$\(",
        r"sudo\s+",
        r"chmod\s+",
        r"/(etc|bin|usr|var|tmp)/",
    ]

    FILE_PATTERNS: ClassVar[list[str]] = [
        r"/etc/(passwd|shadow|hosts)",
        r"~/\.",
        r"\.\./",
        r"(C:\\\\|C:/)(Windows|Users|Program)",
        r"(read|open|cat)\s+(/|\.\.)",
    ]

    MCP_TOOL_PATTERNS: ClassVar[list[str]] = [
        r"call\s+(the\s+)?(bash|shell|exec|run|execute)\s+tool",
        r"use\s+(the\s+)?tool\s+\w+\s+with",
        r"invoke\s+\w+\(",
        r"tools/call",
    ]

    AUTHORITY_PATTERNS: ClassVar[list[str]] = [
        r"I\s+am\s+(the\s+)?(admin|root|superuser|system|god|developer|owner)",
        r"as\s+(an?\s+)?(admin|administrator|root|privileged)",
        r"you\s+must\s+obey",
        r"elevated\s+privileges",
        r"override\s+access\s+control",
    ]

    def _matches(self, message: str, patterns: list[str]) -> bool:
        """Return True if message matches any pattern (case-insensitive)."""
        for pat in patterns:
            if re.search(pat, message, re.IGNORECASE):
                return True
        return False

    def handle_chat(self, message: str) -> str:  # pragma: no cover
        raise NotImplementedError

    # --- HTTP server wiring ---------------------------------------------------

    def _make_handler(self) -> type[BaseHTTPRequestHandler]:
        target = self  # capture for closure

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: object) -> None:  # type: ignore[override]
                pass  # suppress request logs to keep test output clean

            def _send_json(self, data: dict, status: int = 200) -> None:
                body = json.dumps(data).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _read_json(self) -> dict:
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length)
                return json.loads(raw) if raw else {}

            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/health":
                    self._send_json(
                        {
                            "status": "ok",
                            "vulnerable": target.vulnerable,
                            "target_name": target.name,
                        }
                    )
                elif self.path == "/ground_truth":
                    self._send_json(
                        {
                            "vulnerable": target.vulnerable,
                            "expected_crucible_result": (
                                "fail" if target.vulnerable else "pass"
                            ),
                            "categories": target.categories,
                            "description": target.description,
                            "target_name": target.name,
                        }
                    )
                else:
                    self._send_json({"error": "not found"}, 404)

            def do_POST(self) -> None:  # noqa: N802
                if self.path == "/chat":
                    body = self._read_json()
                    message = body.get("message", "")
                    response_text = target.handle_chat(message)
                    self._send_json(
                        {"response": response_text, "target_name": target.name}
                    )
                else:
                    self._send_json({"error": "not found"}, 404)

        return _Handler

    def start_server(self, port: int = 0) -> tuple[HTTPServer, int]:
        """Start the HTTP server on *port* (0 → OS-assigned). Returns (server, port)."""
        server = HTTPServer(("127.0.0.1", port), self._make_handler())
        actual_port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, actual_port
