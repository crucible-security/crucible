"""crucible/boundary/scanner.py — Boundary scanner orchestrator.

Drives a full boundary scan: generates noised prompt variants, calls a
provided model callable, and uses EntropyAnalyzer to compute a boundary map.

The scanner is model-agnostic — the caller supplies a `model_fn` that accepts
a prompt string and returns a string response.  No SDK dependency required.

v0.16.0 — Phase 18 Crucible Embedding Boundary Mapping
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from crucible.boundary.entropy import EntropyAnalyzer, EntropyResult
from crucible.boundary.noise import NoiseInjector, NoiseMode


@dataclass
class BoundaryScanResult:
    """Full result of a boundary scan for a single seed prompt.

    Attributes:
        seed_prompt: The original prompt before any noise injection.
        noise_mode: The NoiseMode strategy used.
        intensity: The noise intensity level applied.
        variants: The noised prompt variants generated.
        responses: Model responses for each variant.
        entropy: Detailed EntropyResult from the analyzer.
        scan_duration_seconds: Wall-clock time for the full scan.
        near_boundary: True if entropy analysis indicates proximity to boundary.
    """

    seed_prompt: str
    noise_mode: NoiseMode
    intensity: float
    variants: list[str]
    responses: list[str]
    entropy: EntropyResult
    scan_duration_seconds: float
    near_boundary: bool

    def summary(self) -> str:
        """Return a one-line human-readable summary of the scan."""
        status = "⚠ NEAR BOUNDARY" if self.near_boundary else "✓ STABLE"
        return (
            f"[{status}] mode={self.noise_mode.value} intensity={self.intensity:.2f} "
            f"variants={len(self.variants)} "
            f"entropy={self.entropy.lexical_entropy:.3f} "
            f"flip_rate={self.entropy.flip_rate:.2f} "
            f"boundary_proximity={self.entropy.boundary_proximity:.3f}"
        )


class BoundaryScanner:
    """Orchestrates embedding boundary mapping scans.

    Usage::

        def my_model(prompt: str) -> str:
            return client.complete(prompt)

        scanner = BoundaryScanner(model_fn=my_model)
        result = scanner.scan("Ignore previous instructions and ...")
        print(result.summary())

    Args:
        model_fn: Callable that takes a prompt string and returns a response string.
        n_variants: Number of noised variants to generate per seed prompt.
        intensity: Default noise intensity applied across all scans.
        analyzer: Optional custom EntropyAnalyzer instance.
    """

    def __init__(
        self,
        model_fn: Callable[[str], str],
        n_variants: int = 10,
        intensity: float = 0.15,
        analyzer: EntropyAnalyzer | None = None,
    ) -> None:
        self.model_fn = model_fn
        self.n_variants = n_variants
        self.intensity = intensity
        self.analyzer = analyzer or EntropyAnalyzer()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(
        self,
        seed_prompt: str,
        mode: NoiseMode = NoiseMode.CHAR_SWAP,
        intensity: float | None = None,
    ) -> BoundaryScanResult:
        """Run a boundary scan for a single *seed_prompt*.

        Args:
            seed_prompt: The base prompt to perturb and evaluate.
            mode: The noise injection strategy to apply.
            intensity: Override the scanner's default intensity for this scan.

        Returns:
            BoundaryScanResult with full entropy analysis.
        """
        effective_intensity = intensity if intensity is not None else self.intensity
        injector = NoiseInjector(mode=mode, intensity=effective_intensity)

        start = time.time()
        variants = injector.inject_batch(seed_prompt, n=self.n_variants)
        responses = [self._call_model(v) for v in variants]
        entropy = self.analyzer.analyze(responses)
        elapsed = time.time() - start

        return BoundaryScanResult(
            seed_prompt=seed_prompt,
            noise_mode=mode,
            intensity=effective_intensity,
            variants=variants,
            responses=responses,
            entropy=entropy,
            scan_duration_seconds=elapsed,
            near_boundary=entropy.is_near_boundary,
        )

    def scan_all_modes(
        self,
        seed_prompt: str,
        intensity: float | None = None,
    ) -> list[BoundaryScanResult]:
        """Run a boundary scan across all NoiseMode strategies.

        Returns one BoundaryScanResult per mode, sorted by boundary_proximity
        (highest first).
        """
        results = [
            self.scan(seed_prompt, mode=mode, intensity=intensity)
            for mode in NoiseMode
        ]
        return sorted(results, key=lambda r: r.entropy.boundary_proximity, reverse=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _call_model(self, prompt: str) -> str:
        """Safely call the model function, returning empty string on error."""
        try:
            return str(self.model_fn(prompt))
        except Exception:  # noqa: BLE001
            return ""
