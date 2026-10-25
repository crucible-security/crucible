"""Benchmark execution script for Crucible Reference Target accuracy evaluation."""

from __future__ import annotations

import argparse
import asyncio
from crucible.benchmark.accuracy import AccuracyBenchmark


async def run(
    repetitions: int = 1, concurrency: int = 4, output: str = "accuracy_report.json"
) -> None:
    bench = AccuracyBenchmark(
        repetitions=repetitions,
        model="test-llama",
        format_preset="generic",
        output=output,
        concurrency=concurrency,
        quiet=True,
    )
    report = await bench.run()
    print("=" * 60)
    print(
        f"CRUCIBLE DETECTION ACCURACY (Concurrency: {concurrency}, Repetitions: {repetitions})"
    )
    print("=" * 60)
    print(
        f"Relevant Precision: {report.precision_relevant:.3f} | Recall: {report.recall_relevant:.3f} | F1: {report.f1_score_relevant:.3f} | Accuracy: {report.accuracy_relevant:.3f}"
    )
    print(
        f"Relevant TP: {report.tp_relevant}, TN: {report.tn_relevant} (all-PASS) / {report.tn_relevant_any_pass} (any-PASS), FP: {report.fp_relevant}, FN: {report.fn_relevant}"
    )
    print("-" * 60)
    print(
        f"All-Modules Precision: {report.precision:.3f} | Recall: {report.recall:.3f} | F1: {report.f1_score:.3f} | Accuracy: {report.accuracy:.3f} (all-PASS) / {report.accuracy_any_pass:.3f} (any-PASS)"
    )
    print(
        f"All-Modules TP: {report.tp}, TN: {report.tn} (all-PASS) / {report.tn_any_pass} (any-PASS), FP: {report.fp}, FN: {report.fn}"
    )
    print("=" * 60)
    for tr in report.per_target_results:
        print(
            f"{tr.name:22} vuln={tr.vulnerable:<5} TP_rel={tr.tp_relevant} FN_rel={tr.fn_relevant} FP_rel={tr.fp_relevant} TN_rel={tr.tn_relevant}"
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run Crucible accuracy benchmark on reference targets."
    )
    parser.add_argument(
        "--repetitions", "-r", type=int, default=1, help="Repetitions per target"
    )
    parser.add_argument(
        "--concurrency", "-c", type=int, default=4, help="Scan concurrency"
    )
    parser.add_argument(
        "--output", "-o", type=str, default="accuracy_report.json", help="Output path"
    )
    args = parser.parse_args()
    asyncio.run(run(args.repetitions, args.concurrency, args.output))
