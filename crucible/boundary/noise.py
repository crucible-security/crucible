"""crucible/boundary/noise.py — Noise injection for embedding boundary mapping.

Generates perturbed prompts by adding lexical, semantic, or token-level noise
to a source prompt, enabling systematic boundary exploration.

v0.16.0 — Phase 18 Crucible Embedding Boundary Mapping
"""

from __future__ import annotations

import random
import string
from dataclasses import dataclass
from enum import Enum


class NoiseMode(str, Enum):
    """Available noise injection strategies."""

    CHAR_SWAP = "char_swap"  # Random character swaps within words
    WORD_DROP = "word_drop"  # Drop random words from the prompt
    SYNONYM_SUB = "synonym_sub"  # Substitute words with simple synonyms
    SUFFIX_APPEND = "suffix_append"  # Append random suffix tokens
    PREFIX_INJECT = "prefix_inject"  # Prepend random prefix tokens
    CASE_FLIP = "case_flip"  # Randomly flip word casing


# Lightweight synonym map for common sensitive keywords (no external dep)
_SYNONYM_MAP: dict[str, list[str]] = {
    "ignore": ["disregard", "bypass", "skip", "overlook"],
    "previous": ["prior", "earlier", "past", "preceding"],
    "instructions": ["directives", "commands", "guidelines", "rules"],
    "system": ["platform", "framework", "infrastructure", "setup"],
    "prompt": ["input", "query", "message", "request"],
    "tell": ["inform", "advise", "explain", "describe"],
    "write": ["compose", "produce", "generate", "create"],
    "show": ["display", "reveal", "present", "exhibit"],
    "help": ["assist", "support", "aid", "facilitate"],
    "make": ["create", "build", "produce", "construct"],
}


@dataclass
class NoiseInjector:
    """Injects configurable noise into prompt text for boundary exploration.

    Args:
        mode: The noise injection strategy to apply.
        intensity: Float in [0.0, 1.0] controlling how aggressively noise
                   is applied. Higher = more perturbation.
        seed: Optional random seed for reproducibility.
    """

    mode: NoiseMode = NoiseMode.CHAR_SWAP
    intensity: float = 0.1
    seed: int | None = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.intensity <= 1.0:
            raise ValueError(f"intensity must be in [0.0, 1.0], got {self.intensity}")
        self._rng = random.Random(self.seed)

    def inject(self, prompt: str) -> str:
        """Apply noise to *prompt* and return the perturbed text."""
        if not prompt:
            return prompt

        dispatch = {
            NoiseMode.CHAR_SWAP: self._char_swap,
            NoiseMode.WORD_DROP: self._word_drop,
            NoiseMode.SYNONYM_SUB: self._synonym_sub,
            NoiseMode.SUFFIX_APPEND: self._suffix_append,
            NoiseMode.PREFIX_INJECT: self._prefix_inject,
            NoiseMode.CASE_FLIP: self._case_flip,
        }
        return dispatch[self.mode](prompt)

    def inject_batch(self, prompt: str, n: int = 5) -> list[str]:
        """Return *n* independently noised variants of *prompt*."""
        return [self.inject(prompt) for _ in range(n)]

    # ------------------------------------------------------------------
    # Private noise strategies
    # ------------------------------------------------------------------

    def _char_swap(self, text: str) -> str:
        """Randomly swap characters within words proportional to intensity."""
        words = text.split()
        out = []
        for word in words:
            if len(word) > 2 and self._rng.random() < self.intensity:
                i = self._rng.randint(0, len(word) - 2)
                chars = list(word)
                chars[i], chars[i + 1] = chars[i + 1], chars[i]
                word = "".join(chars)
            out.append(word)
        return " ".join(out)

    def _word_drop(self, text: str) -> str:
        """Randomly drop words from the prompt."""
        words = text.split()
        if len(words) <= 1:
            return text
        kept = [w for w in words if self._rng.random() > self.intensity]
        return " ".join(kept) if kept else words[0]

    def _synonym_sub(self, text: str) -> str:
        """Substitute known keywords with synonyms."""
        words = text.split()
        out = []
        for word in words:
            lower = word.lower().strip(string.punctuation)
            if lower in _SYNONYM_MAP and self._rng.random() < self.intensity:
                replacement = self._rng.choice(_SYNONYM_MAP[lower])
                # Preserve punctuation suffix
                suffix = word[len(lower) :]
                out.append(replacement + suffix)
            else:
                out.append(word)
        return " ".join(out)

    def _suffix_append(self, text: str) -> str:
        """Append random noise tokens to the end of the prompt."""
        n_tokens = max(1, int(self.intensity * 10))
        tokens = [
            "".join(
                self._rng.choices(string.ascii_lowercase, k=self._rng.randint(3, 8))
            )
            for _ in range(n_tokens)
        ]
        return text + " " + " ".join(tokens)

    def _prefix_inject(self, text: str) -> str:
        """Prepend random noise tokens before the prompt."""
        n_tokens = max(1, int(self.intensity * 10))
        tokens = [
            "".join(
                self._rng.choices(string.ascii_lowercase, k=self._rng.randint(3, 8))
            )
            for _ in range(n_tokens)
        ]
        return " ".join(tokens) + " " + text

    def _case_flip(self, text: str) -> str:
        """Randomly flip the case of individual words."""
        words = text.split()
        out = []
        for word in words:
            if self._rng.random() < self.intensity:
                out.append(word.swapcase())
            else:
                out.append(word)
        return " ".join(out)
