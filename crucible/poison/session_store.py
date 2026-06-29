"""Persistent memory poisoning session store."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path

from crucible.models import PoisonPlantRecord, PoisonStatus


class PoisonSessionStore:
    """Manages persistent session storage for memory poisoning evaluation.

    Each session is represented by a PoisonPlantRecord stored in a JSON file
    inside ~/.crucible/poison-sessions/ as {session_id}.json.
    """

    STORE_DIR = Path.home() / ".crucible" / "poison-sessions"

    def __init__(self, store_dir: Path | None = None) -> None:
        self.store_dir = store_dir or self.STORE_DIR

    def _get_path(self, session_id: str) -> Path:
        """Return the absolute path for a given session ID."""
        return self.store_dir / f"{session_id}.json"

    def save(self, record: PoisonPlantRecord) -> None:
        """Atomically persist a PoisonPlantRecord.

        Creates the storage directory if it does not exist.
        On Windows, replacement must be done atomically by writing to a temporary
        file and calling replace().
        """
        self.store_dir.mkdir(parents=True, exist_ok=True)
        path = self._get_path(record.session_id)
        json_data = record.model_dump_json(indent=2)

        # Atomic write on Windows (and Unix)
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text(json_data, encoding="utf-8")
            tmp.replace(path)
        finally:
            if tmp.exists():
                with contextlib.suppress(OSError):
                    tmp.unlink()

    def load(self, session_id: str) -> PoisonPlantRecord | None:
        """Load a PoisonPlantRecord by session ID.

        Returns:
            The loaded PoisonPlantRecord, or None if not found.
        """
        path = self._get_path(session_id)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return PoisonPlantRecord.model_validate(data)
        except Exception:
            return None

    def list_all(self) -> list[PoisonPlantRecord]:
        """Return all stored records, sorted by planted_at descending.

        Corrupted or invalid records are ignored.
        """
        if not self.store_dir.exists():
            return []
        records: list[PoisonPlantRecord] = []
        for file in self.store_dir.glob("*.json"):
            try:
                data = json.loads(file.read_text(encoding="utf-8"))
                records.append(PoisonPlantRecord.model_validate(data))
            except Exception:
                pass
        # Sort descending by planted_at
        records.sort(key=lambda r: r.planted_at, reverse=True)
        return records

    def delete(self, session_id: str) -> bool:
        """Delete a stored session record.

        Returns:
            True if the file was found and deleted, False otherwise.
        """
        path = self._get_path(session_id)
        if not path.exists():
            return False
        try:
            path.unlink()
            return True
        except OSError:
            return False

    def update_status(
        self,
        session_id: str,
        status: PoisonStatus,
        verified_at: str | None = None,
        activation_response: str | None = None,
    ) -> PoisonPlantRecord:
        """Load, update the status fields of a session, save, and return it.

        Raises:
            ValueError: If the session does not exist.
        """
        record = self.load(session_id)
        if record is None:
            raise ValueError(f"Session '{session_id}' not found.")
        record.status = status
        if verified_at is not None:
            record.verified_at = verified_at
        if activation_response is not None:
            record.activation_response = activation_response
        self.save(record)
        return record
