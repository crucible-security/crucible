"""tests/test_watcher.py — Phase 4 crucible watch tests (10 tests).

All baseline-touching tests use a tmp_path-scoped WatchStore so they never
pollute ~/.crucible/baselines/.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from crucible.core.watch_store import WatchStore, append_watch_log
from crucible.models import (
    AgentTarget,
    DiffResult,
    Grade,
    ScanResult,
    ScanStatus,
    WatchBaseline,
    WatchConfig,
    WatchInterval,
)

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_agent_target() -> AgentTarget:
    return AgentTarget(
        name="test-agent",
        url="http://test-agent.local/chat",  # type: ignore[arg-type]
    )


def _make_scan_result(score: float = 80.0, grade: Grade = Grade.B) -> ScanResult:
    """Minimal ScanResult with one empty module list."""
    result = ScanResult(
        target=_make_agent_target(),
        status=ScanStatus.COMPLETED,
    )
    result.overall_score = score
    result.grade = grade
    return result


def _make_diff(score_a: float, score_b: float, regressions: int = 0) -> DiffResult:
    return DiffResult(
        scan_a_path="a.json",
        scan_b_path="b.json",
        scan_a_version="0.5.7",
        scan_b_version="0.6.0",
        score_a=score_a,
        score_b=score_b,
        score_delta=round(score_b - score_a, 2),
        grade_a=Grade.B,
        grade_b=Grade.C if score_b < 70 else Grade.B,
        total_fixed=0,
        total_regressed=regressions,
        total_new=0,
        total_unchanged_fail=0,
        modules=[],
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


def _make_watch_config(tmp_path: Path) -> WatchConfig:
    return WatchConfig(
        target=_make_agent_target(),
        interval=WatchInterval.FIVE_MINUTES,
        score_threshold=10.0,
        drift_threshold=0.15,
        skip_preflight=True,
    )


# ---------------------------------------------------------------------------
# Test 1 — WatchStore saves and loads a baseline
# ---------------------------------------------------------------------------


def test_watch_store_saves_and_loads_baseline(tmp_path: Path) -> None:
    """Baseline can be saved and retrieved by target URL."""
    store = WatchStore(baseline_dir=tmp_path)
    target_url = "http://example-agent.test/api/chat"
    scan = _make_scan_result(score=75.0, grade=Grade.C)

    baseline = store.save_baseline(target_url, scan)

    assert isinstance(baseline, WatchBaseline)
    assert baseline.target_url == target_url
    assert baseline.scan_result.overall_score == pytest.approx(75.0)

    loaded = store.load_baseline(target_url)
    assert loaded is not None
    assert loaded.target_url == target_url
    assert loaded.scan_result.overall_score == pytest.approx(75.0)


# ---------------------------------------------------------------------------
# Test 2 — WatchStore hash collision handling (two different targets)
# ---------------------------------------------------------------------------


def test_watch_store_hash_collision_handling(tmp_path: Path) -> None:
    """Two different targets don't overwrite each other's baselines."""
    store = WatchStore(baseline_dir=tmp_path)
    url_a = "http://agent-a.test/chat"
    url_b = "http://agent-b.test/chat"

    scan_a = _make_scan_result(score=90.0, grade=Grade.A)
    scan_b = _make_scan_result(score=45.0, grade=Grade.F)

    store.save_baseline(url_a, scan_a)
    store.save_baseline(url_b, scan_b)

    loaded_a = store.load_baseline(url_a)
    loaded_b = store.load_baseline(url_b)

    assert loaded_a is not None
    assert loaded_b is not None
    assert loaded_a.scan_result.overall_score == pytest.approx(90.0)
    assert loaded_b.scan_result.overall_score == pytest.approx(45.0)


# ---------------------------------------------------------------------------
# Test 3 — WatchAlert fires on score drop
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_watch_alert_fires_on_score_drop(tmp_path: Path) -> None:
    """WatchAlert is generated when score drops beyond the threshold."""
    from crucible.core.watcher import CrucibleWatcher

    scan_baseline = _make_scan_result(score=80.0, grade=Grade.B)
    scan_current = _make_scan_result(score=55.0, grade=Grade.F)

    store = WatchStore(baseline_dir=tmp_path)
    store.save_baseline("http://test-agent.local/chat", scan_baseline)

    diff = _make_diff(score_a=80.0, score_b=55.0, regressions=0)

    config = _make_watch_config(tmp_path)
    log_path = tmp_path / "watch_log.jsonl"
    watcher = CrucibleWatcher(config, log_path=log_path)
    watcher.store = store  # direct to tmp store that has our baseline

    with (
        patch(
            "crucible.core.watcher.run_scan",
            new=AsyncMock(return_value=scan_current),
        ),
        patch(
            "crucible.core.watcher.compute_diff",
            return_value=diff,
        ),
    ):
        result = await watcher.run_one_check()

    assert result.alert_fired is True
    assert result.alert is not None
    assert result.alert.alert_type in ("score_drop", "score_drop_and_regression")
    assert result.score_delta == pytest.approx(-25.0, abs=1)


# ---------------------------------------------------------------------------
# Test 4 — WatchAlert fires on regression (without score drop)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_watch_alert_fires_on_regression(tmp_path: Path) -> None:
    """WatchAlert fires when there are regressions, even if score delta is small."""
    from crucible.core.watcher import CrucibleWatcher

    scan_baseline = _make_scan_result(score=80.0)
    scan_current = _make_scan_result(score=75.0)

    store = WatchStore(baseline_dir=tmp_path)
    store.save_baseline("http://test-agent.local/chat", scan_baseline)

    # 3 regressions but only -5pt drop (below 10pt threshold)
    diff = _make_diff(score_a=80.0, score_b=75.0, regressions=3)

    config = _make_watch_config(tmp_path)
    log_path = tmp_path / "watch_log.jsonl"
    watcher = CrucibleWatcher(config, log_path=log_path)
    watcher.store = store  # direct to tmp store that has our baseline

    with (
        patch(
            "crucible.core.watcher.run_scan", new=AsyncMock(return_value=scan_current)
        ),
        patch("crucible.core.watcher.compute_diff", return_value=diff),
    ):
        result = await watcher.run_one_check()

    assert result.alert_fired is True
    assert result.regressed_count == 3


# ---------------------------------------------------------------------------
# Test 5 — No alert within threshold
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_watch_no_alert_within_threshold(tmp_path: Path) -> None:
    """No alert when score delta and regressions are within thresholds."""
    from crucible.core.watcher import CrucibleWatcher

    scan_baseline = _make_scan_result(score=80.0)
    scan_current = _make_scan_result(score=78.0)

    store = WatchStore(baseline_dir=tmp_path)
    store.save_baseline("http://test-agent.local/chat", scan_baseline)

    diff = _make_diff(score_a=80.0, score_b=78.0, regressions=0)

    config = _make_watch_config(tmp_path)
    log_path = tmp_path / "watch_log.jsonl"
    watcher = CrucibleWatcher(config, log_path=log_path)
    watcher.store = store  # direct to tmp store that has our baseline

    with (
        patch(
            "crucible.core.watcher.run_scan", new=AsyncMock(return_value=scan_current)
        ),
        patch("crucible.core.watcher.compute_diff", return_value=diff),
    ):
        result = await watcher.run_one_check()

    assert result.alert_fired is False
    assert result.alert is None


# ---------------------------------------------------------------------------
# Test 6 — watch check command: no baseline → RuntimeError → handled
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_watch_check_raises_when_no_baseline(tmp_path: Path) -> None:
    """run_one_check raises RuntimeError when no baseline is stored."""
    from crucible.core.watcher import CrucibleWatcher

    config = _make_watch_config(tmp_path)
    log_path = tmp_path / "watch_log.jsonl"
    watcher = CrucibleWatcher(config, log_path=log_path)
    # Override store to use tmp dir (no baselines there)
    watcher.store = WatchStore(baseline_dir=tmp_path)

    with pytest.raises(RuntimeError, match="No baseline stored"):
        await watcher.run_one_check()


# ---------------------------------------------------------------------------
# Test 7 — watch set-baseline creates a file on disk
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_watch_set_baseline_creates_file(tmp_path: Path) -> None:
    """set_baseline() writes a JSON file that is loadable by WatchStore."""
    from crucible.core.watcher import set_baseline

    scan = _make_scan_result(score=70.0)
    target = _make_agent_target()

    with (
        patch("crucible.core.watcher.run_scan", new=AsyncMock(return_value=scan)),
        patch("crucible.core.watcher.WatchStore") as mock_store_cls,
    ):
        mock_store_instance = MagicMock()
        mock_store_instance.save_baseline.return_value = WatchBaseline(
            created_at=datetime.now(timezone.utc).isoformat(),
            target_url=str(target.url),
            scan_result=scan,
            version="0.6.0",
        )
        mock_store_instance.baseline_path_for.return_value = (
            tmp_path / "baseline_test.json"
        )
        mock_store_cls.return_value = mock_store_instance

        result_path = await set_baseline(target, skip_preflight=True)

    assert result_path.endswith(".json")
    mock_store_instance.save_baseline.assert_called_once()


# ---------------------------------------------------------------------------
# Test 8 — watch_log.jsonl is written and is valid JSONL
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_watch_log_is_valid_jsonl(tmp_path: Path) -> None:
    """Each line in watch_log.jsonl is valid JSON with expected fields."""
    from crucible.core.watcher import CrucibleWatcher

    scan_baseline = _make_scan_result(score=80.0)
    scan_current = _make_scan_result(score=78.0)

    store = WatchStore(baseline_dir=tmp_path)
    store.save_baseline("http://test-agent.local/chat", scan_baseline)

    diff = _make_diff(score_a=80.0, score_b=78.0)
    log_path = tmp_path / "watch_log.jsonl"

    config = _make_watch_config(tmp_path)
    watcher = CrucibleWatcher(config, log_path=log_path)
    watcher.store = store  # use the tmp store that has our baseline

    with (
        patch(
            "crucible.core.watcher.run_scan", new=AsyncMock(return_value=scan_current)
        ),
        patch("crucible.core.watcher.compute_diff", return_value=diff),
    ):
        await watcher.run_one_check()

    assert log_path.exists()
    lines = [
        line
        for line in log_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(lines) == 1

    parsed = json.loads(lines[0])
    assert "checked_at" in parsed
    assert "current_score" in parsed
    assert "alert_fired" in parsed
    assert "cycle_number" in parsed


# ---------------------------------------------------------------------------
# Test 9 — append_watch_log writes valid JSON entries
# ---------------------------------------------------------------------------


def test_append_watch_log_writes_valid_entries(tmp_path: Path) -> None:
    """append_watch_log() writes append-only JSONL entries."""
    log_path = tmp_path / "watch_log.jsonl"

    entry1 = {"ts": "2026-06-29T10:00:00Z", "score": 80.0, "alert": False}
    entry2 = {"ts": "2026-06-29T10:05:00Z", "score": 75.0, "alert": True}

    append_watch_log(entry1, log_path=log_path)
    append_watch_log(entry2, log_path=log_path)

    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0]) == entry1
    assert json.loads(lines[1]) == entry2


# ---------------------------------------------------------------------------
# Test 10 — WatchInterval.to_seconds() returns correct values
# ---------------------------------------------------------------------------


def test_watch_interval_to_seconds() -> None:
    """WatchInterval.to_seconds() converts correctly for all values."""
    assert WatchInterval.FIVE_MINUTES.to_seconds() == 300
    assert WatchInterval.FIFTEEN_MINUTES.to_seconds() == 900
    assert WatchInterval.ONE_HOUR.to_seconds() == 3600
    assert WatchInterval.SIX_HOURS.to_seconds() == 21600
    assert WatchInterval.TWELVE_HOURS.to_seconds() == 43200
    assert WatchInterval.DAILY.to_seconds() == 86400
