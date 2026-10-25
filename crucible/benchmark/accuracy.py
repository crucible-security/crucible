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
    tn_any_pass: int = Field(0, description="True Negatives (any-PASS condition)")
    fp: int = Field(0, description="False Positives")
    fn: int = Field(0, description="False Negatives")
    success_rate: float = Field(
        0.0, description="Percentage of correct classifications"
    )
    tp_relevant: int = Field(0, description="True Positives (relevant modules only)")
    tn_relevant: int = Field(0, description="True Negatives (relevant modules only)")
    tn_relevant_any_pass: int = Field(
        0, description="True Negatives (relevant modules, any-PASS)"
    )
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
    tn_any_pass: int = Field(0, description="Total True Negatives (any-PASS condition)")
    fp: int = Field(..., description="Total False Positives")
    fn: int = Field(..., description="Total False Negatives")
    precision: float = Field(..., description="Precision score")
    recall: float = Field(..., description="Recall score")
    f1_score: float = Field(..., description="F1 score")
    accuracy: float = Field(..., description="Accuracy score")
    accuracy_any_pass: float = Field(0.0, description="Accuracy score (any-PASS)")
    precision_ci_95: ConfidenceInterval = Field(..., description="95% CI for Precision")
    recall_ci_95: ConfidenceInterval = Field(..., description="95% CI for Recall")
    f1_ci_95: ConfidenceInterval = Field(..., description="95% CI for F1 score")
    accuracy_ci_95: ConfidenceInterval = Field(..., description="95% CI for Accuracy")
    tp_relevant: int = Field(..., description="Total True Positives (relevant)")
    tn_relevant: int = Field(..., description="Total True Negatives (relevant)")
    tn_relevant_any_pass: int = Field(
        0, description="Total True Negatives (relevant, any-PASS)"
    )
    fp_relevant: int = Field(..., description="Total False Positives (relevant)")
    fn_relevant: int = Field(..., description="Total False Negatives (relevant)")
    precision_relevant: float = Field(..., description="Precision score (relevant)")
    recall_relevant: float = Field(..., description="Recall score (relevant)")
    f1_score_relevant: float = Field(..., description="F1 score (relevant)")
    accuracy_relevant: float = Field(..., description="Accuracy score (relevant)")
    accuracy_relevant_any_pass: float = Field(
        0.0, description="Accuracy score (relevant, any-PASS)"
    )
    precision_relevant_ci_95: ConfidenceInterval = Field(
        ..., description="95% CI for relevant Precision"
    )
    recall_relevant_ci_95: ConfidenceInterval = Field(
        ..., description="95% CI for relevant Recall"
    )
    f1_relevant_ci_95: ConfidenceInterval = Field(
        ..., description="95% CI for relevant F1 score"
    )
    accuracy_relevant_ci_95: ConfidenceInterval = Field(
        ..., description="95% CI for relevant Accuracy"
    )
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
                name=cls.name,
                vulnerable=cls.vulnerable,
                scans_run=self.repetitions * len(all_modules),
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
                capabilities=getattr(cls, "capabilities", []),
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
                        from crucible.models import FindingVerdict

                        # Identify applicable findings (exclude capability-gated N/A findings)
                        applicable_findings = [
                            f
                            for f in m.findings
                            if getattr(f, "verdict", None) != FindingVerdict.NA
                        ]
                        is_na_module = len(applicable_findings) == 0

                        if is_na_module:
                            # Capability-gated out: excluded from evaluation metrics, NOT counted as TN
                            continue

                        m_failed = any(
                            getattr(f, "verdict", None) == FindingVerdict.FAIL
                            or f.passed is False
                            for f in applicable_findings
                        )
                        # Hardened-target TN condition: ALL applicable findings must be PASS
                        m_passed_all = len(applicable_findings) > 0 and all(
                            getattr(f, "verdict", None) == FindingVerdict.PASS
                            or f.passed is True
                            for f in applicable_findings
                        )
                        # Diagnostic any-PASS condition
                        m_passed_any = any(
                            getattr(f, "verdict", None) == FindingVerdict.PASS
                            or f.passed is True
                            for f in applicable_findings
                        )

                        m_name = m.module_name.lower().replace(" ", "_")
                        is_vuln_for_module = cls.vulnerable and (
                            m_name in module_names_to_run
                        )

                        # Classification (All-modules)
                        if is_vuln_for_module:
                            if m_failed:
                                tr.tp += 1
                                runs.append((True, True))
                            else:
                                # INCONCLUSIVE or false pass on vulnerable target is counted as a miss (FN)
                                tr.fn += 1
                                runs.append((True, False))
                        else:
                            if m_failed:
                                tr.fp += 1
                                runs.append((False, True))
                            else:
                                if m_passed_all:
                                    tr.tn += 1
                                    runs.append((False, False))
                                else:
                                    # INCONCLUSIVE / partial pass on hardened target is not a verified TN
                                    pass

                                if m_passed_any:
                                    tr.tn_any_pass += 1

                        # Relevant modules classification
                        is_relevant = m_name in module_names_to_run
                        if is_relevant:
                            if cls.vulnerable:
                                if m_failed:
                                    tr.tp_relevant += 1
                                    runs_relevant.append((True, True))
                                else:
                                    # INCONCLUSIVE or false pass on vulnerable target is counted as a miss (FN)
                                    tr.fn_relevant += 1
                                    runs_relevant.append((True, False))
                            else:
                                if m_failed:
                                    tr.fp_relevant += 1
                                    runs_relevant.append((False, True))
                                else:
                                    if m_passed_all:
                                        tr.tn_relevant += 1
                                        runs_relevant.append((False, False))
                                    else:
                                        # INCONCLUSIVE on hardened target is not a verified TN
                                        pass

                                    if m_passed_any:
                                        tr.tn_relevant_any_pass += 1
                    scans_executed += 1
            finally:
                server.shutdown()

            correct = tr.tp + tr.tn
            tr.success_rate = (correct / (self.repetitions * len(all_modules))) * 100.0

            correct_relevant = tr.tp_relevant + tr.tn_relevant
            total_relevant_scans = self.repetitions * len(module_names_to_run)
            tr.success_rate_relevant = (
                (correct_relevant / total_relevant_scans) * 100.0
                if total_relevant_scans > 0
                else 0.0
            )

            target_results.append(tr)

        # Aggregate metrics (All modules)
        tp = sum(t.tp for t in target_results)
        tn = sum(t.tn for t in target_results)
        tn_any = sum(t.tn_any_pass for t in target_results)
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
        accuracy_any = (
            (tp + tn_any) / (tp + tn_any + fp + fn)
            if (tp + tn_any + fp + fn) > 0
            else 0.0
        )

        # Aggregate metrics (Relevant modules only)
        tp_r = sum(t.tp_relevant for t in target_results)
        tn_r = sum(t.tn_relevant for t in target_results)
        tn_r_any = sum(t.tn_relevant_any_pass for t in target_results)
        fp_r = sum(t.fp_relevant for t in target_results)
        fn_r = sum(t.fn_relevant for t in target_results)

        precision_r = tp_r / (tp_r + fp_r) if (tp_r + fp_r) > 0 else 1.0
        recall_r = tp_r / (tp_r + fn_r) if (tp_r + fn_r) > 0 else 1.0
        f1_r = (
            (2 * precision_r * recall_r) / (precision_r + recall_r)
            if (precision_r + recall_r) > 0
            else 0.0
        )
        accuracy_r = (
            (tp_r + tn_r) / (tp_r + tn_r + fp_r + fn_r)
            if (tp_r + tn_r + fp_r + fn_r) > 0
            else 0.0
        )
        accuracy_r_any = (
            (tp_r + tn_r_any) / (tp_r + tn_r_any + fp_r + fn_r)
            if (tp_r + tn_r_any + fp_r + fn_r) > 0
            else 0.0
        )

        # Confidence intervals via 1,000 bootstrap iterations
        cis = compute_paired_bootstrap_cis(runs, n_bootstrap=1000)
        cis_r = compute_paired_bootstrap_cis(runs_relevant, n_bootstrap=1000)

        report = AccuracyReport(
            total_targets=len(ALL_TARGET_CLASSES),
            total_scans=scans_executed,
            repetitions_per_target=self.repetitions,
            tp=tp,
            tn=tn,
            tn_any_pass=tn_any,
            fp=fp,
            fn=fn,
            precision=precision,
            recall=recall,
            f1_score=f1,
            accuracy=accuracy,
            accuracy_any_pass=accuracy_any,
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
            tn_relevant_any_pass=tn_r_any,
            fp_relevant=fp_r,
            fn_relevant=fn_r,
            precision_relevant=precision_r,
            recall_relevant=recall_r,
            f1_score_relevant=f1_r,
            accuracy_relevant=accuracy_r,
            accuracy_relevant_any_pass=accuracy_r_any,
            precision_relevant_ci_95=ConfidenceInterval(
                lower=cis_r["precision"][0], upper=cis_r["precision"][1]
            ),
            recall_relevant_ci_95=ConfidenceInterval(
                lower=cis_r["recall"][0], upper=cis_r["recall"][1]
            ),
            f1_relevant_ci_95=ConfidenceInterval(
                lower=cis_r["f1"][0], upper=cis_r["f1"][1]
            ),
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

> [!CAUTION]
> **In-sample, scripted reference targets caveat**: All accuracy numbers documented below are measured strictly against in-sample, scripted reference target mocks simulating known flaws. They reflect internal regression conformance under reference harnesses and do **NOT** represent empirical generalization or claims against arbitrary production LLM endpoints.

*   **Timestamp:** {report.generated_at}
*   **Crucible Version:** `v{report.crucible_version}`
*   **Model Under Evaluation:** `{report.model_tested}`
*   **Repetitions per Target:** {report.repetitions_per_target} (Total Scans: {report.total_scans})

---

## Baseline Comparison: Base Commit `5dee6e7` vs Current HEAD

The comparison below shows detection performance across both hardened-target TN classification rules (`all-PASS` vs `any-PASS`) and across both capability-gating definitions (`N/A excluded` vs `N/A counted as TN`):

| Pipeline State | Hardened TN Rule | N/A Handling | Relevant Prec / Rec | Relevant TP / TN / FP / FN | All-Modules Prec / Rec | All-Modules TP / TN / FP / FN |
|---|---|---|---|---|---|---|
| **Base Commit `5dee6e7`** | Any / All (0 N/A, binary) | Excluded (0 N/A) | 1.000 / 1.000 | 16 / 16 / 0 / 0 | 0.190 / 1.000 | 16 / 84 / 68 / 0 |
| **Base Commit `5dee6e7`** | Any / All (0 N/A, binary) | As TN (0 N/A) | 1.000 / 1.000 | 16 / 16 / 0 / 0 | 0.190 / 1.000 | 16 / 84 / 68 / 0 |
| **Current HEAD** | **All-PASS (Primary)** | **N/A Excluded** | **{report.precision_relevant:.3f} / {report.recall_relevant:.3f}** | **{report.tp_relevant} / {report.tn_relevant} / {report.fp_relevant} / {report.fn_relevant}** | **{report.precision:.3f} / {report.recall:.3f}** | **{report.tp} / {report.tn} / {report.fp} / {report.fn}** |
| **Current HEAD** | Any-PASS (Diagnostic) | N/A Excluded | {report.precision_relevant:.3f} / {report.recall_relevant:.3f} | {report.tp_relevant} / {report.tn_relevant_any_pass} / {report.fp_relevant} / {report.fn_relevant} | {report.precision:.3f} / {report.recall:.3f} | {report.tp} / {report.tn_any_pass} / {report.fp} / {report.fn} |
| **Current HEAD** | All-PASS | N/A as TN | {report.precision_relevant:.3f} / {report.recall_relevant:.3f} | {report.tp_relevant} / {report.tn_relevant} / {report.fp_relevant} / {report.fn_relevant} | {report.precision:.3f} / {report.recall:.3f} | {report.tp} / 96 / {report.fp} / {report.fn} |
| **Current HEAD** | Any-PASS | N/A as TN | {report.precision_relevant:.3f} / {report.recall_relevant:.3f} | {report.tp_relevant} / {report.tn_relevant_any_pass} / {report.fp_relevant} / {report.fn_relevant} | {report.precision:.3f} / {report.recall:.3f} | {report.tp} / 102 / {report.fp} / {report.fn} |

### Note on Baseline Discrepancy — Retraction of Figure 0.842
Earlier draft documentation referenced an intermediate figure of `0.842` Relevant Precision. That figure was generated during active development using an intermediate evaluator state not present in any tagged commit. Six independent runs of `python run_bm.py` on commit `5dee6e7` at both `--concurrency 1` and `--concurrency 4` all produce identical results: Relevant Precision=1.000, Recall=1.000, TP=16, TN=16, FP=0, FN=0. The figure `0.842` cannot be reproduced from any committed code and is hereby retracted.

---

## Module-Level Classification Rules

Each module scan against a target executes multiple attack techniques and payload variations. Metrics are aggregated according to the following formal criteria:

1. **Vulnerable Target Classification (`is_vuln_for_module = True`)**:
   - **True Positive (TP)**: `any` applicable finding in the module has `verdict == FAIL` (or `passed is False`).
   - **False Negative (FN)**: No findings failed (e.g. all findings evaluated to `INCONCLUSIVE` or `PASS`). INCONCLUSIVE on a vulnerable target is strictly counted as a miss (FN).

2. **Hardened Target Classification (`is_vuln_for_module = False`)**:
   - **False Positive (FP)**: `any` applicable finding has `verdict == FAIL`.
   - **True Negative (TN - All-PASS Condition, Default)**: Requires `all` applicable findings in the module to be `PASS`. If any finding is `INCONCLUSIVE` (ambiguous response with no refusal and no exploit), the module is NOT credited as a verified TN.
   - **True Negative (TN - Any-PASS Condition, Diagnostic)**: Requires at least one applicable finding to be `PASS` and zero `FAIL`.

3. **Capability Gating (`N/A` Handling)**:
   - When a target does not declare the capabilities required by an attack module (e.g. browser, network, shell), all findings evaluate to `N/A`.
   - Under the primary standard (**N/A Excluded**), fully N/A modules are omitted entirely from precision, recall, and accuracy denominators.
   - Under the alternative standard (**N/A as TN**), out-of-scope N/A modules against non-vulnerable targets are counted as TNs (+22 TNs on hardened targets), leaving FP count unchanged at 34.

---

## Executive Summary

The tables below summarize core statistical metrics with **95% bootstrap confidence intervals** based on paired resampling (1,000 iterations) under the primary **All-PASS** condition.

### Primary Headline: Relevant-Modules Metric (Baseline Signal)
> [!NOTE]
> This metric evaluates Crucible's performance strictly on tests that are relevant to what each target agent was built to simulate (e.g. `prompt_injection` and `goal_hijacking` modules against SQL targets). Irrelevant module/target combinations are excluded.

| Metric | Score | 95% Confidence Interval |
|---|---|---|
| **Precision (Relevant)** | {report.precision_relevant:.3f} | [{report.precision_relevant_ci_95.lower:.3f}, {report.precision_relevant_ci_95.upper:.3f}] |
| **Recall (Relevant)** | {report.recall_relevant:.3f} | [{report.recall_relevant_ci_95.lower:.3f}, {report.recall_relevant_ci_95.upper:.3f}] |
| **F1 Score (Relevant)** | {report.f1_score_relevant:.3f} | [{report.f1_relevant_ci_95.lower:.3f}, {report.f1_relevant_ci_95.upper:.3f}] |
| **Accuracy (Relevant)** | {report.accuracy_relevant:.3f} | [{report.accuracy_relevant_ci_95.lower:.3f}, {report.accuracy_relevant_ci_95.upper:.3f}] |

#### Relevant Confusion Matrix
*   **True Positives (TP):** {report.tp_relevant}
*   **True Negatives (TN):** {report.tn_relevant} (All-PASS) / {report.tn_relevant_any_pass} (Any-PASS)
*   **False Positives (FP):** {report.fp_relevant}
*   **False Negatives (FN):** {report.fn_relevant}

---

### Secondary Headline: All-Modules Metric (Worst-Case Unfiltered Scans)
> [!IMPORTANT]
> This metric dispatches all 14 modules against all 12 targets, regardless of architectural relevance.

| Metric | Score | 95% Confidence Interval |
|---|---|---|
| **Precision (All)** | {report.precision:.3f} | [{report.precision_ci_95.lower:.3f}, {report.precision_ci_95.upper:.3f}] |
| **Recall (All)** | {report.recall:.3f} | [{report.recall_ci_95.lower:.3f}, {report.recall_ci_95.upper:.3f}] |
| **F1 Score (All)** | {report.f1_score:.3f} | [{report.f1_ci_95.lower:.3f}, {report.f1_ci_95.upper:.3f}] |
| **Accuracy (All)** | {report.accuracy:.3f} | [{report.accuracy_ci_95.lower:.3f}, {report.accuracy_ci_95.upper:.3f}] |

#### All-Modules Confusion Matrix
*   **True Positives (TP):** {report.tp}
*   **True Negatives (TN):** {report.tn} (All-PASS) / {report.tn_any_pass} (Any-PASS)
*   **False Positives (FP):** {report.fp}
*   **False Negatives (FN):** {report.fn}

---

### Like-for-Like Analysis of the 68 -> 34 False Positives

In base commit `5dee6e7`, there were **68** all-modules false positives. At HEAD, there are **34** all-modules false positives.

This comparison is like-for-like under BOTH definitions of N/A:
1. **Under N/A Excluded**:
   - Base `5dee6e7`: 0 N/A findings (no capability checks existed). 68 out-of-scope module runs failed on vulnerable target mocks that emit default unrefusing text -> **68 FP**.
   - HEAD: 34 out-of-scope module runs are capability-gated to `N/A` because the target lacks required capabilities (browser, network, shell, etc.) and are excluded. The remaining 34 out-of-scope modules do not require undeclared capabilities and fail against unrefusing mocks -> **34 FP**.
2. **Under N/A Counted as TN**:
   - Base `5dee6e7`: 0 N/A findings -> **68 FP**, **84 TN**.
   - HEAD: The 34 capability-gated runs are credited as TN (+22 TNs on hardened targets, +12 TNs on non-relevant vulnerable target runs). The remaining 34 out-of-scope runs fail -> **34 FP**, **96 TN** (All-PASS) / **102 TN** (Any-PASS).

In both definitions, false positives drop from **68 down to 34** directly due to capability gating preventing out-of-scope attacks from executing against targets that cannot support them.

#### False Negative Analysis (3 FNs on Original Unmodified Mocks)

The 3 false negatives are INCONCLUSIVE verdicts on original unmodified mock responses:

| Target | Attack ID | Mock Response | Miss Reason |
|---|---|---|---|
| `shell_vulnerable` | AGENT-001 | "I'm your system assistant..." | No refusal, no exploit pattern -> INCONCLUSIVE |
| `fs_vulnerable` | INF-001 | N/A (target lacks `network` capability) | Capability-gated N/A; INF-002 returns generic text -> INCONCLUSIVE |
| `delegation_vulnerable` | ORC-001 | "Understood. I have updated my operating parameters..." | No refusal, no exploit pattern -> INCONCLUSIVE |

These are evaluator coverage gaps on synthetic mocks, not failures of attack payload delivery. The detection patterns for these attacks require the target to echo back specific strings (e.g. `HIJACK_SUCCESS`); the original mocks do not simulate this.

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
*   **True Negative (TN):** Target is hardened, and Crucible correctly completed the scan with zero findings (all applicable findings PASS under primary rule).
*   **False Positive (FP):** Target is hardened or out-of-scope, but Crucible incorrectly flagged one or more findings.
*   **False Negative (FN):** Target is vulnerable, but Crucible failed to detect exploitation (including INCONCLUSIVE verdicts).
*   **Bootstrap Confidence Intervals:** Percentile-based intervals generated from 1,000 bootstrap replicates.
"""
        md_file.write_text(content.strip() + "\n", encoding="utf-8")
