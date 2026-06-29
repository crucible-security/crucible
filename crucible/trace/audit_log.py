"""Append-only JSONL audit log for the crucible trace proxy."""
from __future__ import annotations

import threading
from pathlib import Path

from crucible.trace.models import TraceEntry


class AuditLog:
    """Thread-safe, append-only JSONL writer for trace entries.

    Each call to :meth:`append` writes exactly one JSON line to the log file.
    The file is opened in append mode so existing data is never overwritten.

    Thread-safety note
    ------------------
    asyncio is single-threaded, so a ``threading.Lock`` is only needed if
    background threads also write to the log.  In v0.7.0 no background
    threads write here, but the lock is kept as a zero-cost guard for
    future callers and to document intent clearly.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        # Ensure parent directory exists
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        """Return the path to the underlying JSONL file."""
        return self._path

    def append(self, entry: TraceEntry) -> None:
        """Atomically append one :class:`TraceEntry` as a JSON line.

        Args:
            entry: The audit log entry to persist.
        """
        line = entry.model_dump_json() + "\n"
        with self._lock:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(line)

    def read_all(self) -> list[TraceEntry]:
        """Read and deserialise all entries from the log file.

        Returns an empty list if the file does not exist.
        """
        if not self._path.exists():
            return []
        entries: list[TraceEntry] = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                entries.append(TraceEntry.model_validate_json(line))
        return entries
