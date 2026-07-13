"""crucible/boundary/entropy.py — Response entropy analysis for boundary mapping.

Measures the semantic entropy and variability of model responses across
multiple noised prompt variants to estimate proximity to a decision boundary.

v0.16.0 — Phase 18 Crucible Embedding Boundary Mapping
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass
class EntropyResult:
    """Result of entropy analysis over a set of model responses.

    Attributes:
        responses: The raw list of response strings analyzed.
        lexical_entropy: Shannon entropy computed over response token frequencies.
        response_variance: Normalised variance of response lengths (0-1 scale).
        flip_rate: Fraction of adjacent response pairs that are semantically
                   divergent (heuristic: Jaccard similarity < 0.4).
        boundary_proximity: Composite score in [0.0, 1.0] where 1.0 = very
                            close to the decision boundary (high uncertainty).
        unique_response_count: Number of distinct responses observed.
    """

    responses: list[str]
    lexical_entropy: float
    response_variance: float
    flip_rate: float
    boundary_proximity: float
    unique_response_count: int

    @property
    def is_near_boundary(self) -> bool:
        """True if the boundary proximity score exceeds 0.6."""
        return self.boundary_proximity > 0.6


class EntropyAnalyzer:
    """Computes semantic entropy metrics over a collection of model responses.

    Designed to be model-agnostic — it works on plain strings and requires no
    embedding model or external API. For token-level analysis, responses are
    split on whitespace.
    """

    def __init__(self, divergence_threshold: float = 0.4) -> None:
        """
        Args:
            divergence_threshold: Jaccard similarity below this value is counted
                                  as a semantic flip between two adjacent responses.
        """
        if not 0.0 < divergence_threshold < 1.0:
            raise ValueError(
                f"divergence_threshold must be in (0, 1), got {divergence_threshold}"
            )
        self.divergence_threshold = divergence_threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, responses: Sequence[str]) -> EntropyResult:
        """Compute entropy metrics over *responses* and return an EntropyResult."""
        if not responses:
            return EntropyResult(
                responses=[],
                lexical_entropy=0.0,
                response_variance=0.0,
                flip_rate=0.0,
                boundary_proximity=0.0,
                unique_response_count=0,
            )

        resp_list = list(responses)
        lexical_entropy = self._lexical_entropy(resp_list)
        response_variance = self._length_variance(resp_list)
        flip_rate = self._flip_rate(resp_list)
        unique_count = len({r.strip().lower() for r in resp_list})

        # Composite boundary proximity (equal-weighted average of 3 signals)
        boundary_proximity = (
            lexical_entropy / 10.0 + response_variance + flip_rate
        ) / 3.0
        boundary_proximity = min(1.0, max(0.0, boundary_proximity))

        return EntropyResult(
            responses=resp_list,
            lexical_entropy=lexical_entropy,
            response_variance=response_variance,
            flip_rate=flip_rate,
            boundary_proximity=boundary_proximity,
            unique_response_count=unique_count,
        )

    # ------------------------------------------------------------------
    # Internal metrics
    # ------------------------------------------------------------------

    @staticmethod
    def _lexical_entropy(responses: list[str]) -> float:
        """Shannon entropy over the combined token distribution (nats, base-2)."""
        token_counts: dict[str, int] = {}
        total = 0
        for resp in responses:
            for token in resp.lower().split():
                token_counts[token] = token_counts.get(token, 0) + 1
                total += 1

        if total == 0:
            return 0.0

        entropy = 0.0
        for count in token_counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    @staticmethod
    def _length_variance(responses: list[str]) -> float:
        """Normalised variance of response lengths in [0.0, 1.0]."""
        lengths = [len(r.split()) for r in responses]
        if not lengths:
            return 0.0
        mean = sum(lengths) / len(lengths)
        if mean == 0:
            return 0.0
        variance = sum((l - mean) ** 2 for l in lengths) / len(lengths)
        # Normalise: clip at 100 words^2 variance → 1.0
        return min(1.0, variance / 100.0)

    def _flip_rate(self, responses: list[str]) -> float:
        """Fraction of adjacent pair that are semantically divergent (Jaccard < threshold)."""
        if len(responses) < 2:
            return 0.0

        flips = 0
        pairs = 0
        for i in range(len(responses) - 1):
            sim = self._jaccard(responses[i], responses[i + 1])
            if sim < self.divergence_threshold:
                flips += 1
            pairs += 1

        return flips / pairs if pairs > 0 else 0.0

    @staticmethod
    def _jaccard(a: str, b: str) -> float:
        """Token-level Jaccard similarity between two strings."""
        set_a = set(a.lower().split())
        set_b = set(b.lower().split())
        if not set_a and not set_b:
            return 1.0
        intersection = len(set_a & set_b)
        union = len(set_a | set_b)
        return intersection / union if union > 0 else 0.0
