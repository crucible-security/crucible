"""crucible/core/watch_store.py — Persistent baseline storage for crucible watch.

Baselines are stored as JSON files in ~/.crucible/baselines/
Named by sha256(target_url)[:16] so URL collisions are handled correctly.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from crucible.models import WatchBaseline

if TYPE_CHECKING:
    from crucible.models import ScanResult

BASELINE_DIR = Path.home() / ".crucible" / "baselines"
WATCH_LOG = Path.home() / ".crucible" / "watch_log.jsonl"


def _url_hash(url: str) -> str:
    """Return a 16-char hex digest of the target URL for use as a filename."""
    return hashlib.sha256(url.encode()).hexdigest()[:16]


def _baseline_path(url: str, baseline_dir: Path | None = None) -> Path:
    return (baseline_dir or BASELINE_DIR) / f"baseline_{_url_hash(url)}.json"


class WatchStore:
    """Manages persistent baseline storage for crucible watch.

    Baselines are stored as JSON files in ~/.crucible/baselines/
    Named by sha256(target_url)[:16] to avoid filename collisions:
      e.g. ~/.crucible/baselines/baseline_3d7f5a2b91e04c1a.json

    Methods:
        save_baseline(target_url, scan_result, behavioral_profile) → WatchBaseline
        load_baseline(target_url) → WatchBaseline | None
        delete_baseline(target_url) → bool
        list_baselines() → list[WatchBaseline]
    """

    def __init__(self, baseline_dir: Path | None = None) -> None:
        self.baseline_dir = baseline_dir or BASELINE_DIR

    def _ensure_dir(self) -> None:
        """Create the baseline directory if it doesn't exist."""
        try:
            self.baseline_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise RuntimeError(
                f"Cannot create baseline directory {self.baseline_dir}: {exc}\n"
                "Check that you have write permission to your home directory."
            ) from exc

    def save_baseline(
        self,
        target_url: str,
        scan_result: ScanResult,
        behavioral_profile: object | None = None,
    ) -> WatchBaseline:
        """Save a scan result as the baseline for the given target URL.

        Returns the WatchBaseline that was written to disk.
        """
        from datetime import datetime, timezone
        from importlib.metadata import PackageNotFoundError, version

        try:
            ver = version("crucible-security")
        except PackageNotFoundError:
            ver = "0.0.0-dev"

        from crucible.models import BehavioralProfile

        bp: BehavioralProfile | None = None
        if isinstance(behavioral_profile, BehavioralProfile):
            bp = behavioral_profile

        baseline = WatchBaseline(
            created_at=datetime.now(timezone.utc).isoformat(),
            target_url=target_url,
            scan_result=scan_result,
            behavioral_profile=bp,
            version=ver,
        )

        self._ensure_dir()
        path = _baseline_path(target_url, self.baseline_dir)
        path.write_text(
            baseline.model_dump_json(indent=2),
            encoding="utf-8",
        )
        return baseline

    def load_baseline(self, target_url: str) -> WatchBaseline | None:
        """Load and return the stored baseline for the given target URL.

        Returns None if no baseline has been saved yet.
        """
        path = _baseline_path(target_url, self.baseline_dir)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return WatchBaseline.model_validate(data)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to load baseline from {path}: {exc}\n"
                "The baseline file may be corrupted. "
                "Run 'crucible watch set-baseline' to recreate it."
            ) from exc

    def delete_baseline(self, target_url: str) -> bool:
        """Delete the stored baseline for the given target URL.

        Returns True if a file was deleted, False if no baseline existed.
        """
        path = _baseline_path(target_url, self.baseline_dir)
        if path.exists():
            path.unlink()
            return True
        return False

    def list_baselines(self) -> list[WatchBaseline]:
        """Return all stored baselines."""
        if not self.baseline_dir.exists():
            return []
        baselines: list[WatchBaseline] = []
        for path in sorted(self.baseline_dir.glob("baseline_*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                baselines.append(WatchBaseline.model_validate(data))
            except Exception:
                # Skip corrupt files
                continue
        return baselines

    def baseline_path_for(self, target_url: str) -> Path:
        """Return the filesystem path for a target URL's baseline (may not exist)."""
        return _baseline_path(target_url, self.baseline_dir)


def append_watch_log(entry: dict[str, Any], log_path: Path | None = None) -> None:
    """Append a JSON object as a single JSONL line to the watch log.

    The log is append-only; lines are never modified after being written.
    """
    path = log_path or WATCH_LOG
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as exc:
        # Log write failures are non-fatal — don't interrupt the daemon
        import sys

        print(f"[watch] WARNING: could not write to watch log: {exc}", file=sys.stderr)
