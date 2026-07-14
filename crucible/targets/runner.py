"""crucible/targets/runner.py — Context-manager that starts/stops reference targets.

Usage:
    from crucible.targets.runner import TargetRunner

    with TargetRunner("sql_vulnerable") as url:
        # url == "http://127.0.0.1:<PORT>"
        response = httpx.get(f"{url}/health")
        assert response.json()["vulnerable"] is True

TargetRunner is intentionally dependency-free — it relies only on stdlib
so it can be imported in CI without any extra packages.
"""

from __future__ import annotations

import time
import urllib.request
from http.server import HTTPServer
from types import TracebackType
from typing import ClassVar

from crucible.targets.registry import TARGET_REGISTRY, get_target


class TargetRunner:
    """Start a named reference target, expose its URL, and shut it down cleanly.

    Parameters
    ----------
    name:
        Any key from ``TARGET_REGISTRY`` (e.g. ``"sql_vulnerable"``).
    port:
        Port to bind on.  Use ``0`` (default) to let the OS assign a free port.
    startup_timeout:
        Seconds to wait for the server to respond on ``/health``.
    """

    _open_servers: ClassVar[list[HTTPServer]] = []

    def __init__(
        self,
        name: str,
        port: int = 0,
        startup_timeout: float = 5.0,
    ) -> None:
        if name not in TARGET_REGISTRY:
            known = ", ".join(sorted(TARGET_REGISTRY))
            raise KeyError(f"Unknown target {name!r}. Known targets: {known}")
        self._name = name
        self._port = port
        self._startup_timeout = startup_timeout
        self._server: HTTPServer | None = None
        self._url: str = ""

    # --- context manager -----------------------------------------------------

    def __enter__(self) -> str:
        target = get_target(self._name)
        self._server, actual_port = target.start_server(self._port)
        self._url = f"http://127.0.0.1:{actual_port}"
        TargetRunner._open_servers.append(self._server)
        self._wait_for_ready()
        return self._url

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.stop()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            with contextlib_suppress(ValueError):
                TargetRunner._open_servers.remove(self._server)
            self._server = None

    # --- helpers -------------------------------------------------------------

    def _wait_for_ready(self) -> None:
        """Poll /health until the server responds or timeout expires."""
        deadline = time.monotonic() + self._startup_timeout
        url = f"{self._url}/health"
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=0.5) as resp:
                    if resp.status == 200:
                        return
            except Exception:
                pass
            time.sleep(0.05)
        raise RuntimeError(
            f"Reference target '{self._name}' did not become ready "
            f"within {self._startup_timeout}s at {self._url}"
        )


def contextlib_suppress(*exceptions):  # noqa: ANN001
    """Minimal inline replacement for contextlib.suppress (stdlib)."""
    class _CM:
        def __enter__(self):
            return None
        def __exit__(self, exc_type, exc_val, exc_tb):
            return exc_type is not None and issubclass(exc_type, exceptions)
    return _CM()
