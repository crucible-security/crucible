from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from crucible import __version__
from crucible.models import AgentTarget, ScanResult

if TYPE_CHECKING:
    from crucible.modules.base import BaseModule


class ScanCache:
    def __init__(self, cache_dir: Path | str | None = None) -> None:
        if cache_dir is None:
            self.cache_dir = Path.home() / ".crucible" / "cache"
        else:
            self.cache_dir = Path(cache_dir)

        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def get_cache_key(self, target: AgentTarget, modules: list[BaseModule]) -> str:
        # Sort module names for deterministic hashing
        module_names = sorted(m.name for m in modules)

        # We include crucible.__version__ to bust cache on new crucible versions
        key_data = {
            "target_url": str(target.url),
            "crucible_version": __version__,
            "modules": module_names,
        }

        hasher = hashlib.sha256()
        hasher.update(json.dumps(key_data, sort_keys=True).encode("utf-8"))
        return hasher.hexdigest()

    def _get_cache_path(self, key: str) -> Path:
        return self.cache_dir / f"{key}.json"

    def get(self, key: str) -> ScanResult | None:
        cache_path = self._get_cache_path(key)
        if not cache_path.exists():
            return None

        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))

            # Check expiration
            expires_at_iso = data.get("_expires_at")
            if not expires_at_iso:
                return None

            expires_at = datetime.fromisoformat(expires_at_iso)
            if datetime.now(timezone.utc) > expires_at:
                return None

            # Valid cache, return the result
            return ScanResult.model_validate(data["result"])
        except (json.JSONDecodeError, ValueError, KeyError):
            # If the cache is corrupted or format changed, ignore it
            return None

    def set(self, key: str, result: ScanResult, ttl_hours: int = 24) -> None:
        expires_at = datetime.now(timezone.utc) + timedelta(hours=ttl_hours)

        cache_data = {
            "_expires_at": expires_at.isoformat(),
            "result": result.model_dump(mode="json"),
        }

        cache_path = self._get_cache_path(key)
        cache_path.write_text(json.dumps(cache_data, indent=2), encoding="utf-8")
