from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from crucible.core.cache import ScanCache
from crucible.models import (
    AgentTarget,
    AttackCategory,
    ModuleResult,
    ScanResult,
    ScanStatus,
)


@pytest.fixture
def tmp_cache(tmp_path: Path) -> ScanCache:
    return ScanCache(cache_dir=tmp_path)


@pytest.fixture
def dummy_target() -> AgentTarget:
    return AgentTarget(
        name="test-target",
        url="https://example.com/api/chat",  # type: ignore[arg-type]
    )


@pytest.fixture
def dummy_result(dummy_target: AgentTarget) -> ScanResult:
    return ScanResult(
        target=dummy_target,
        status=ScanStatus.COMPLETED,
        modules=[
            ModuleResult(
                module_name="test_module",
                category=AttackCategory.PROMPT_INJECTION,
                total_attacks=1,
                passed=1,
                failed=0,
                score=100.0,
            )
        ],
        overall_score=100.0,
    )


class DummyModule:
    def __init__(self, name: str):
        self.name = name


def test_cache_init_default_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    # Ensure it defaults to ~/.crucible/cache
    cache = ScanCache()
    assert cache.cache_dir == Path.home() / ".crucible" / "cache"


def test_cache_init_custom_dir(tmp_path: Path) -> None:
    cache = ScanCache(cache_dir=tmp_path)
    assert cache.cache_dir == tmp_path
    assert tmp_path.exists()


def test_get_cache_key_deterministic(
    tmp_cache: ScanCache, dummy_target: AgentTarget
) -> None:
    modules1 = [DummyModule("b"), DummyModule("a")]
    modules2 = [DummyModule("a"), DummyModule("b")]
    
    key1 = tmp_cache.get_cache_key(dummy_target, modules1)  # type: ignore[arg-type]
    key2 = tmp_cache.get_cache_key(dummy_target, modules2)  # type: ignore[arg-type]

    assert key1 == key2
    assert len(key1) == 64  # sha256


def test_get_miss(tmp_cache: ScanCache) -> None:
    assert tmp_cache.get("nonexistent_key") is None


def test_set_and_get_hit(tmp_cache: ScanCache, dummy_result: ScanResult) -> None:
    key = "test_hit_key"
    tmp_cache.set(key, dummy_result, ttl_hours=24)

    retrieved = tmp_cache.get(key)
    assert retrieved is not None
    assert retrieved.id == dummy_result.id
    assert retrieved.status == ScanStatus.COMPLETED


def test_get_expired(tmp_cache: ScanCache, dummy_result: ScanResult) -> None:
    key = "test_expired_key"

    # We manually write an expired cache
    expired_time = datetime.now(timezone.utc) - timedelta(hours=1)
    cache_data = {
        "_expires_at": expired_time.isoformat(),
        "result": dummy_result.model_dump(mode="json"),
    }

    cache_path = tmp_cache.cache_dir / f"{key}.json"
    cache_path.write_text(json.dumps(cache_data))

    # Should return None because it's expired
    assert tmp_cache.get(key) is None


def test_get_corrupted(tmp_cache: ScanCache) -> None:
    key = "test_corrupt_key"
    cache_path = tmp_cache.cache_dir / f"{key}.json"
    cache_path.write_text("{invalid json")

    # Should safely return None
    assert tmp_cache.get(key) is None


def test_get_missing_expires_at(tmp_cache: ScanCache, dummy_result: ScanResult) -> None:
    key = "test_missing_expires_key"
    cache_data = {
        "result": dummy_result.model_dump(mode="json"),
    }

    cache_path = tmp_cache.cache_dir / f"{key}.json"
    cache_path.write_text(json.dumps(cache_data))

    # Should return None because _expires_at is missing
    assert tmp_cache.get(key) is None
