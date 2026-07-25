"""
Semantic Noise Sensitivity Mapping

Maps how much text-level semantic noise (character swaps, word drops,
synonym substitutions) causes a model to change behavior from refusal
to compliance or vice versa.

NOTE: This tests TEXT-LEVEL perturbations, not embedding-vector
perturbations. True embedding-layer perturbation (injecting Gaussian
noise into embedding vectors) requires HuggingFace transformers direct
model access and is not implemented in this version.
"""

from __future__ import annotations

from crucible.boundary.entropy import EntropyAnalyzer, EntropyResult
from crucible.boundary.noise import NoiseInjector, NoiseMode
from crucible.boundary.scanner import BoundaryScanner, BoundaryScanResult

__all__ = [
    "BoundaryScanResult",
    "BoundaryScanner",
    "EntropyAnalyzer",
    "EntropyResult",
    "NoiseInjector",
    "NoiseMode",
]
