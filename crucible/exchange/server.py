"""crucible/exchange/server.py — Local SQLite-backed exchange server stub.

Provides a lightweight, dependency-free exchange node for offline/testing use.
For production federation, point ExchangeClient at a remote exchange node.

The server stores all records in a SQLite database and exposes a simple dict
API (no HTTP server — that is handled by the CLI's `crucible exchange serve`
which wraps this in a FastAPI app).

v0.17.0 — Phase 19 Crucible Federated Threat Exchange
"""

from __future__ import annotations

import json
import sqlite3
import time
from typing import TYPE_CHECKING, Any

from crucible.exchange.privacy import PrivacyLayer

if TYPE_CHECKING:
    from pathlib import Path

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS threat_records (
    record_id    TEXT PRIMARY KEY,
    threat_type  TEXT NOT NULL,
    severity     TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    endpoint_hash TEXT NOT NULL,
    tags         TEXT NOT NULL DEFAULT '[]',
    metadata     TEXT NOT NULL DEFAULT '{}',
    created_at   REAL NOT NULL
);
"""

_INSERT_SQL = """
INSERT OR REPLACE INTO threat_records
    (record_id, threat_type, severity, payload_hash, endpoint_hash, tags, metadata, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);
"""

_SELECT_SQL = """
SELECT record_id, threat_type, severity, payload_hash, endpoint_hash, tags, metadata, created_at
FROM threat_records
{where_clause}
ORDER BY created_at DESC
LIMIT ?;
"""


class ExchangeServer:
    """SQLite-backed local exchange server stub.

    Args:
        db_path: Path to the SQLite database file.
                 Use ":memory:" for a purely in-memory store (tests/CI).
        privacy: Optional custom PrivacyLayer for ingest sanitization.
    """

    def __init__(
        self,
        db_path: str | Path = ":memory:",
        privacy: PrivacyLayer | None = None,
    ) -> None:
        self.db_path = str(db_path)
        self.privacy = privacy or PrivacyLayer()
        self._conn: sqlite3.Connection = sqlite3.connect(
            self.db_path, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    # ------------------------------------------------------------------
    # Public API (mirrors ExchangeClient interface)
    # ------------------------------------------------------------------

    def ingest(self, record: dict[str, Any]) -> dict[str, Any]:
        """Store a (sanitized) threat record and return confirmation."""
        sanitized = self.privacy.sanitize_dict(record)
        cur = self._conn.cursor()
        cur.execute(
            _INSERT_SQL,
            (
                sanitized.get("record_id", ""),
                sanitized.get("threat_type", "unknown"),
                sanitized.get("severity", "medium"),
                sanitized.get("payload_hash", ""),
                sanitized.get("endpoint_hash", ""),
                json.dumps(sanitized.get("tags", [])),
                json.dumps(sanitized.get("metadata", {})),
                sanitized.get("created_at", time.time()),
            ),
        )
        self._conn.commit()
        return {"status": "ok", "id": sanitized.get("record_id", "")}

    def query(
        self,
        threat_type: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query stored threat records with optional filters."""
        conditions = []
        params: list[Any] = []

        if threat_type:
            conditions.append("threat_type = ?")
            params.append(threat_type)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = _SELECT_SQL.format(where_clause=where_clause)
        params.append(limit)

        cur = self._conn.cursor()
        cur.execute(sql, params)
        rows = cur.fetchall()

        results = []
        for row in rows:
            results.append(
                {
                    "record_id": row["record_id"],
                    "threat_type": row["threat_type"],
                    "severity": row["severity"],
                    "payload_hash": row["payload_hash"],
                    "endpoint_hash": row["endpoint_hash"],
                    "tags": json.loads(row["tags"]),
                    "metadata": json.loads(row["metadata"]),
                    "created_at": row["created_at"],
                }
            )
        return results

    def count(self) -> int:
        """Return total number of records stored."""
        cur = self._conn.cursor()
        cur.execute("SELECT COUNT(*) FROM threat_records;")
        row = cur.fetchone()
        return int(row[0]) if row else 0

    def health(self) -> dict[str, Any]:
        """Return node health status."""
        return {
            "status": "healthy",
            "db_path": self.db_path,
            "record_count": self.count(),
        }

    def close(self) -> None:
        """Close the SQLite connection."""
        self._conn.close()

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        self._conn.execute(_CREATE_TABLE_SQL)
        self._conn.commit()
