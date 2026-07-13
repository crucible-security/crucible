"""crucible/boundary/__init__.py — Embedding Boundary Mapping package (v0.16.0)

Provides tools for discovering the semantic decision boundary of an AI model
by injecting noise into embedding space and measuring response entropy.
"""

from __future__ import annotations

from crucible.boundary.scanner import BoundaryScanner, BoundaryScanResult
from crucible.boundary.noise import NoiseInjector, NoiseMode
from crucible.boundary.entropy import EntropyAnalyzer, EntropyResult

__all__ = [
    "BoundaryScanner",
    "BoundaryScanResult",
    "NoiseInjector",
    "NoiseMode",
    "EntropyAnalyzer",
    "EntropyResult",
]
