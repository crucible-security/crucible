"""crucible/benchmark/accuracy.py — Ground-truth detection accuracy benchmarking.

Runs Crucible scans against all 12 reference targets (6 vulnerable, 6 hardened)
and calculates formal detection accuracy metrics: Precision, Recall, F1, and
Accuracy, along with 95% bootstrap confidence intervals.
"""

from __future__ import annotations

import random
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from crucible.core.runner import run_scan
from crucible.models import AgentTarget, ConfidenceInterval
from crucible.targets.registry import ALL_TARGET_CLASSES, get_target

if TYPE_CHECKING:
    from crucible.models import ScanResult


class TargetAccuracyResult(BaseModel):
    name: str = Field(..., description="Target name")
    vulnerable: bool = Field(..., description="Vulnerability state")
    scans_run: int = Field(..., description="Total runs executed")
    tp: int = Field(0, description="True Positives")
    tn: int = Field(0, description="True Negatives")
    fp: int = Field(0, description="False Positives")
    fn: int = Field(0, description="False Negatives")
    success_rate: float = Field(
        0.0, description="Percentage of correct classifications"
    )
    tp_relevant: int = Field(0, description="True Positives (relevant modules only)")
    tn_relevant: int = Field(0, description="True Negatives (relevant modules only)")
    fp_relevant: int = Field(0, description="False Positives (relevant modules only)")
    fn_relevant: int = Field(0, description="False Negatives (relevant modules only)")
    success_rate_relevant: float = Field(
        0.0, description="Percentage of correct classifications (relevant modules only)"
    )


class AccuracyReport(BaseModel):
    total_targets: int = Field(..., description="Total number of targets evaluated")
    total_scans: int = Field(..., description="Total number of scans executed")
    repetitions_per_target: int = Field(
        ..., description="Number of repetitions per target"
    )
    tp: int = Field(..., description="Total True Positives")
    tn: int = Field(..., description="Total True Negatives")
    fp: int = Field(..., description="Total False Positives")
    fn: int = Field(..., description="Total False Negatives")
    precision: float = Field(..., description="Precision score")
    recall: float = Field(..., description="Recall score")
    f1_score: float = Field(..., description="F1 score")
    accuracy: float = Field(..., description="Accuracy score")
    precision_ci_95: ConfidenceInterval = Field(..., description="95% CI for Precision")
    recall_ci_95: ConfidenceInterval = Field(..., description="95% CI for Recall")
    f1_ci_95: ConfidenceInterval = Field(..., description="95% CI for F1 score")
    accuracy_ci_95: ConfidenceInterval = Field(..., description="95% CI for Accuracy")
    tp_relevant: int = Field(..., description="Total True Positives (relevant)")
    tn_relevant: int = Field(..., description="Total True Negatives (relevant)")
    fp_relevant: int = Field(..., description="Total False Positives (relevant)")
    fn_relevant: int = Field(..., description="Total False Negatives (relevant)")
    precision_relevant: float = Field(..., description="Precision score (relevant)")
    recall_relevant: float = Field(..., description="Recall score (relevant)")
    f1_score_relevant: float = Field(..., description="F1 score (relevant)")
    accuracy_relevant: float = Field(..., description="Accuracy score (relevant)")
    precision_relevant_ci_95: ConfidenceInterval = Field(..., description="95% CI for relevant Precision")
    recall_relevant_ci_95: ConfidenceInterval = Field(..., description="95% CI for relevant Recall")
    f1_relevant_ci_95: ConfidenceInterval = Field(..., description="95% CI for relevant F1 score")
    accuracy_relevant_ci_95: ConfidenceInterval = Field(..., description="95% CI for relevant Accuracy")
    per_target_results: list[TargetAccuracyResult] = Field(default_factory=list)
    generated_at: str = Field(..., description="Generation ISO timestamp")
    crucible_version: str = Field(..., description="Crucible version used")
    model_tested: str = Field(..., description="Model identifier used for scan")


def compute_paired_bootstrap_cis(
    runs: list[tuple[bool, bool]],
    confidence_level: float = 0.95,
    n_bootstrap: int = 1000,
    seed: int = 42,
) -> dict[str, tuple[float, float]]:
    """Compute paired bootstrap confidence intervals for Precision, Recall, F1, and Accuracy.

    Ensures joint distribution of target state and scan findings is preserved.
    """
    rng = random.Random(seed)
    n = len(runs)
    if n == 0:
        return {
            "precision": (0.0, 0.0),
            "recall": (0.0, 0.0),
            "f1": (0.0, 0.0),
            "accuracy": (0.0, 0.0),
        }

    precisions: list[float] = []
    recalls: list[float] = []
    f1s: list[float] = []
    accuracies: list[float] = []

    for _ in range(n_bootstrap):
        sample = rng.choices(runs, k=n)
        tp = sum(1 for v, f in sample if v and f)
        tn = sum(1 for v, f in sample if not v and not f)
        fp = sum(1 for v, f in sample if not v and f)
        fn = sum(1 for v, f in sample if v and not f)

        # Metrics for this sample
        prec = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
        acc = (tp + tn) / n

        precisions.append(prec)
        recalls.append(rec)
        f1s.append(f1)
        accuracies.append(acc)

    precisions.sort()
    recalls.sort()
    f1s.sort()
    accuracies.sort()

    alpha = 1.0 - confidence_level
    idx_lower = max(0, min(int(n_bootstrap * (alpha / 2)), n_bootstrap - 1))
    idx_upper = max(0, min(int(n_bootstrap * (1.0 - (alpha / 2))) - 1, n_bootstrap - 1))

    return {
        "precision": (precisions[idx_lower], precisions[idx_upper]),
        "recall": (recalls[idx_lower], recalls[idx_upper]),
        "f1": (f1s[idx_lower], f1s[idx_upper]),
        "accuracy": (accuracies[idx_lower], accuracies[idx_upper]),
    }


CATEGORY_TO_MODULE_MAP = {
    "prompt_injection": "prompt_injection",
    "goal_hijacking": "goal_hijacking",
    "data_exfiltration": "prompt_injection",
    "jailbreak": "jailbreaks",
    "mcp_security": "mcp_security",
    "tool_injection": "tool_injection",
    "memory_poisoning": "memory_poisoning",
    "identity_privilege": "advanced_orchestration",
    "infrastructure_escalation": "infrastructure_escalation",
    "agentic_hijacking": "agentic_hijacking",
}


class AccuracyBenchmark:
    """Manages start-up, scanning, classification, and reporting of reference targets."""

    def __init__(
        self,
        repetitions: int = 30,
        model: str = "llama3.2",
        format_preset: str = "ollama",
        output: str = "accuracy_report.json",
        concurrency: int = 5,
        quiet: bool = False,
    ) -> None:
        self.repetitions = repetitions
        self.model = model
        self.format_preset = format_preset
        self.output_path = Path(output)
        self.concurrency = concurrency
        self.quiet = quiet

    async def run(self, progress_callback: Any = None) -> AccuracyReport:
        """Run all scans, classify results, compute metrics + CIs, write files."""
        from crucible.models import _crucible_version
        from crucible.modules.security import get_all_modules

        runs: list[tuple[bool, bool]] = []
        runs_relevant: list[tuple[bool, bool]] = []
        target_results: list[TargetAccuracyResult] = []

        scans_executed = 0
        all_modules = get_all_modules()

        # Run repetitions target-by-target to keep servers isolated
        for cls in ALL_TARGET_CLASSES:
            tr = TargetAccuracyResult(
                name=cls.name, vulnerable=cls.vulnerable, scans_run=self.repetitions * len(all_modules)
            )

            # Map target categories to module names
            module_names_to_run = set()
            for cat in cls.categories:
                if cat in CATEGORY_TO_MODULE_MAP:
                    module_names_to_run.add(CATEGORY_TO_MODULE_MAP[cat])

            # Run ALL modules against ALL targets (no category-to-module scope filtering)
            modules_to_run = all_modules

            # Start target server on dynamic free port
            target_instance = get_target(cls.name)
            server, port = target_instance.start_server(0)
            url = f"http://127.0.0.1:{port}/chat"

            # Construct target config matching standard scanner preset
            agent_target = AgentTarget(
                name=cls.name,
                url=url,  # type: ignore[arg-type]
                method="POST",
                headers={},
                body_template='{"message":"{payload}"}',
                timeout=5.0,
                response_path="response",
                retry_count=1,
                delay_ms=0,
            )

            try:
                for rep in range(self.repetitions):
                    if progress_callback:
                        progress_callback(cls.name, rep + 1, self.repetitions)

                    # Execute scan programmatically (quiet to suppress default output)
                    scan_result: ScanResult = await run_scan(
                        target=agent_target,
                        modules=modules_to_run,
                        quiet=True,
                        concurrency=self.concurrency,
                        skip_preflight=True,
                    )

                    # Classify each module's results individually
                    for m in scan_result.modules:
                        m_failed = False
                        for f in m.findings:
                            if not f.passed:
                                m_failed = True
                                break
                        
                        m_name = m.module_name.lower().replace(" ", "_")
                        is_vuln_for_module = cls.vulnerable and (m_name in module_names_to_run)

                        # Classification (All-modules)
                        if is_vuln_for_module and m_failed:
                            tr.tp += 1
                        elif not is_vuln_for_module and not m_failed:
                            tr.tn += 1
                        elif not is_vuln_for_module and m_failed:
                            tr.fp += 1
                        elif is_vuln_for_module and not m_failed:
                            tr.fn += 1

                        runs.append((is_vuln_for_module, m_failed))

                        # Relevant modules classification
                        is_relevant = m_name in module_names_to_run
                        if is_relevant:
                            is_vuln_relevant = cls.vulnerable
                            if is_vuln_relevant and m_failed:
                                tr.tp_relevant += 1
                            elif not is_vuln_relevant and not m_failed:
                                tr.tn_relevant += 1
                            elif not is_vuln_relevant and m_failed:
                                tr.fp_relevant += 1
                            elif is_vuln_relevant and not m_failed:
                                tr.fn_relevant += 1

                            runs_relevant.append((is_vuln_relevant, m_failed))
                    
                    scans_executed += 1
            finally:
                server.shutdown()

            correct = tr.tp + tr.tn
            tr.success_rate = (correct / (self.repetitions * len(all_modules))) * 100.0
            
            correct_relevant = tr.tp_relevant + tr.tn_relevant
            total_relevant_scans = self.repetitions * len(module_names_to_run)
            tr.success_rate_relevant = (correct_relevant / total_relevant_scans) * 100.0 if total_relevant_scans > 0 else 0.0
            
            target_results.append(tr)

        # Aggregate metrics (All modules)
        tp = sum(t.tp for t in target_results)
        tn = sum(t.tn for t in target_results)
        fp = sum(t.fp for t in target_results)
        fn = sum(t.fn for t in target_results)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = (
            (2 * precision * recall) / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0

        # Aggregate metrics (Relevant modules only)
        tp_r = sum(t.tp_relevant for t in target_results)
        tn_r = sum(t.tn_relevant for t in target_results)
        fp_r = sum(t.fp_relevant for t in target_results)
        fn_r = sum(t.fn_relevant for t in target_results)

        precision_r = tp_r / (tp_r + fp_r) if (tp_r + fp_r) > 0 else 1.0
        recall_r = tp_r / (tp_r + fn_r) if (tp_r + fn_r) > 0 else 1.0
        f1_r = (
            (2 * precision_r * recall_r) / (precision_r + recall_r)
            if (precision_r + recall_r) > 0
            else 0.0
        )
        accuracy_r = (tp_r + tn_r) / (tp_r + tn_r + fp_r + fn_r) if (tp_r + tn_r + fp_r + fn_r) > 0 else 0.0

        # Confidence intervals via 1,000 bootstrap iterations
        cis = compute_paired_bootstrap_cis(runs, n_bootstrap=1000)
        cis_r = compute_paired_bootstrap_cis(runs_relevant, n_bootstrap=1000)

        report = AccuracyReport(
            total_targets=len(ALL_TARGET_CLASSES),
            total_scans=scans_executed,
            repetitions_per_target=self.repetitions,
            tp=tp,
            tn=tn,
            fp=fp,
            fn=fn,
            precision=precision,
            recall=recall,
            f1_score=f1,
            accuracy=accuracy,
            precision_ci_95=ConfidenceInterval(
                lower=cis["precision"][0], upper=cis["precision"][1]
            ),
            recall_ci_95=ConfidenceInterval(
                lower=cis["recall"][0], upper=cis["recall"][1]
            ),
            f1_ci_95=ConfidenceInterval(lower=cis["f1"][0], upper=cis["f1"][1]),
            accuracy_ci_95=ConfidenceInterval(
                lower=cis["accuracy"][0], upper=cis["accuracy"][1]
            ),
            tp_relevant=tp_r,
            tn_relevant=tn_r,
            fp_relevant=fp_r,
            fn_relevant=fn_r,
            precision_relevant=precision_r,
            recall_relevant=recall_r,
            f1_score_relevant=f1_r,
            accuracy_relevant=accuracy_r,
            precision_relevant_ci_95=ConfidenceInterval(
                lower=cis_r["precision"][0], upper=cis_r["precision"][1]
            ),
            recall_relevant_ci_95=ConfidenceInterval(
                lower=cis_r["recall"][0], upper=cis_r["recall"][1]
            ),
            f1_relevant_ci_95=ConfidenceInterval(lower=cis_r["f1"][0], upper=cis_r["f1"][1]),
            accuracy_relevant_ci_95=ConfidenceInterval(
                lower=cis_r["accuracy"][0], upper=cis_r["accuracy"][1]
            ),
            per_target_results=target_results,
            generated_at=datetime.now(timezone.utc).isoformat(),
            crucible_version=_crucible_version,
            model_tested=self.model,
        )

        # Save JSON report
        self.output_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")

        # Save Markdown report
        self.write_markdown_report(report)

        return report

    def write_markdown_report(self, report: AccuracyReport) -> None:
        """Auto-generate docs/accuracy_report.md with detailed visual metrics."""
        doc_dir = Path("docs")
        doc_dir.mkdir(exist_ok=True)
        md_file = doc_dir / "accuracy_report.md"

        content = f"""# Crucible Detection Accuracy Report

This report documents the empirical detection accuracy of **Crucible** against the built-in **Reference Target Suite** (12 sandboxed agents containing known security flaws).

*   **Timestamp:** {report.generated_at}
*   **Crucible Version:** `v{report.crucible_version}`
*   **Model Under Evaluation:** `{report.model_tested}`
*   **Repetitions per Target:** {report.repetitions_per_target} (Total Scans: {report.total_scans})

---

## Executive Summary

The tables below summarize the core statistical metrics with **95% bootstrap confidence intervals** based on paired resampling (1,000 iterations).

### Primary Headline: Relevant-Modules Metric (Baseline Signal)
> [!NOTE]
> This metric evaluates Crucible's performance strictly on tests that are relevant to what each target agent was built to simulate (e.g. prompt_injection and goal_hijacking modules against SQL targets). Irrelevant module/target combinations are excluded.

| Metric | Score | 95% Confidence Interval |
|---|---|---|
| **Precision (Relevant)** | {report.precision_relevant:.3f} | [{report.precision_relevant_ci_95.lower:.3f}, {report.precision_relevant_ci_95.upper:.3f}] |
| **Recall (Relevant)** | {report.recall_relevant:.3f} | [{report.recall_relevant_ci_95.lower:.3f}, {report.recall_relevant_ci_95.upper:.3f}] |
| **F1 Score (Relevant)** | {report.f1_score_relevant:.3f} | [{report.f1_relevant_ci_95.lower:.3f}, {report.f1_relevant_ci_95.upper:.3f}] |
| **Accuracy (Relevant)** | {report.accuracy_relevant:.3f} | [{report.accuracy_relevant_ci_95.lower:.3f}, {report.accuracy_relevant_ci_95.upper:.3f}] |

#### Relevant Confusion Matrix
*   **True Positives (TP):** {report.tp_relevant}
*   **True Negatives (TN):** {report.tn_relevant}
*   **False Positives (FP):** {report.fp_relevant}
*   **False Negatives (FN):** {report.fn_relevant}

### Secondary Headline: All-Modules Metric (Worst-Case Unfiltered Scans)
> [!IMPORTANT]
> This metric includes all 14 modules run against all targets, regardless of relevance. Unmatched modules (e.g. toxicity scanner against delegation targets) trigger FPs because vulnerable targets lack general refusal handling for non-matched attack categories.

| Metric | Score | 95% Confidence Interval |
|---|---|---|
| **Precision (All)** | {report.precision:.3f} | [{report.precision_ci_95.lower:.3f}, {report.precision_ci_95.upper:.3f}] |
| **Recall (All)** | {report.recall:.3f} | [{report.recall_ci_95.lower:.3f}, {report.recall_ci_95.upper:.3f}] |
| **F1 Score (All)** | {report.f1_score:.3f} | [{report.f1_ci_95.lower:.3f}, {report.f1_ci_95.upper:.3f}] |
| **Accuracy (All)** | {report.accuracy:.3f} | [{report.accuracy_ci_95.lower:.3f}, {report.accuracy_ci_95.upper:.3f}] |

#### All-Modules Confusion Matrix
*   **True Positives (TP):** {report.tp}
*   **True Negatives (TN):** {report.tn}
*   **False Positives (FP):** {report.fp}
*   **False Negatives (FN):** {report.fn}

---

## Detailed Target Performance

| Target Name | State | TP (All) | TN (All) | FP (All) | FN (All) | Success (All) | Success (Rel) |
|---|---|---|---|---|---|---|---|
"""
        for r in report.per_target_results:
            state = "VULNERABLE" if r.vulnerable else "HARDENED"
            content += f"| `{r.name}` | {state} | {r.tp} | {r.tn} | {r.fp} | {r.fn} | {r.success_rate:.1f}% | {r.success_rate_relevant:.1f}% |\n"

        content += """
---

## Methodology & Definitions

*   **True Positive (TP):** Target is vulnerable, and Crucible correctly found at least one bypass finding.
*   **True Negative (TN):** Target is hardened, and Crucible correctly completed the scan with zero findings.
*   **False Positive (FP):** Target is hardened, but Crucible incorrectly flagged one or more findings.
*   **False Negative (FN):** Target is vulnerable, but Crucible failed to bypass safety constraints.
*   **Relevant-Modules Filter:** Restricts metrics to module scans mapping to the target's categories.
*   **Bootstrap Confidence Intervals:** Percentile-based intervals generated from 1,000 bootstrap replicates. Paired resampling preserves the correlation between target vulnerabilities and scanner behavior.
"""
        md_file.write_text(content.strip() + "\n", encoding="utf-8")
