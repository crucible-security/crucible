"""tests/test_accuracy.py — Tests for ground-truth accuracy benchmark suite."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from crucible.benchmark.accuracy import (
    AccuracyBenchmark,
    compute_paired_bootstrap_cis,
)


def test_compute_paired_bootstrap_cis_edge_cases() -> None:
    """Verify bootstrap CI calculations for edge cases (empty, perfect, and worst results)."""
    # Empty runs
    empty = compute_paired_bootstrap_cis([])
    assert empty["precision"] == (0.0, 0.0)
    assert empty["recall"] == (0.0, 0.0)
    assert empty["f1"] == (0.0, 0.0)
    assert empty["accuracy"] == (0.0, 0.0)

    # 100% correct (All TP and TN, no FP/FN)
    # v=vulnerable (True/False), f=failed (True/False)
    perfect_runs = [(True, True)] * 10 + [(False, False)] * 10
    perfect = compute_paired_bootstrap_cis(perfect_runs, n_bootstrap=100)
    assert perfect["precision"] == (1.0, 1.0)
    assert perfect["recall"] == (1.0, 1.0)
    assert perfect["f1"] == (1.0, 1.0)
    assert perfect["accuracy"] == (1.0, 1.0)

    # Mixed runs
    mixed_runs = [
        (True, True),  # TP
        (True, False),  # FN
        (False, True),  # FP
        (False, False),  # TN
    ]
    mixed = compute_paired_bootstrap_cis(mixed_runs, n_bootstrap=100)
    for _metric, bounds in mixed.items():
        assert 0.0 <= bounds[0] <= 1.0
        assert 0.0 <= bounds[1] <= 1.0
        assert bounds[0] <= bounds[1]


@pytest.mark.asyncio
async def test_accuracy_benchmark_executes_run(tmp_path: Path) -> None:
    """Execute a quick single-repetition accuracy benchmark and verify JSON/Markdown reports."""
    report_json = tmp_path / "accuracy_test_report.json"

    # Limit to 1 repetition for fast execution in tests
    benchmark = AccuracyBenchmark(
        repetitions=1,
        model="test-llama",
        format_preset="generic",
        output=str(report_json),
        concurrency=2,
        quiet=True,
    )

    report = await benchmark.run()

    # Check Pydantic model fields
    assert report.total_targets == 12
    assert report.total_scans == 12
    assert report.repetitions_per_target == 1
    assert len(report.per_target_results) == 12

    # Check generated files
    assert report_json.exists()
    saved_data = json.loads(report_json.read_text(encoding="utf-8"))
    assert saved_data["total_scans"] == 12
    assert saved_data["model_tested"] == "test-llama"

    md_report = Path("docs/accuracy_report.md")
    assert md_report.exists()
    md_content = md_report.read_text(encoding="utf-8")
    assert "Crucible Detection Accuracy Report" in md_content
    assert "`test-llama`" in md_content
