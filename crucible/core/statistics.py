"""crucible/core/statistics.py — Pure-Python bootstrap confidence intervals.

No numpy. No scipy. No external dependencies.
Uses only the Python standard library (random, time, logging).

Public API:
  bootstrap_confidence_interval(successes, trials, ...) -> ConfidenceInterval
  interpret_significance(ci) -> bool
"""

from __future__ import annotations

import logging
import random
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from crucible.models import ConfidenceInterval

logger = logging.getLogger(__name__)

_DEFAULT_N_BOOTSTRAP = 10_000
_LARGE_SAMPLE_THRESHOLD = 100
_LARGE_SAMPLE_N_BOOTSTRAP = 1_000
_SLOW_WARNING_SECS = 5.0


def bootstrap_confidence_interval(
    successes: int,
    trials: int,
    confidence_level: float = 0.95,
    n_bootstrap: int = _DEFAULT_N_BOOTSTRAP,
    random_seed: int = 42,
) -> "ConfidenceInterval":
    """Compute a bootstrap confidence interval for a binomial proportion.

    Implementation:
      1. Build the original sample: [1]*successes + [0]*(trials-successes)
      2. Resample with replacement n_bootstrap times using random.choices()
      3. Compute the mean of each bootstrap sample
      4. CI = (alpha/2) and (1-alpha/2) percentiles of the bootstrap means

    Uses a local random.Random(random_seed) so the global RNG is never
    mutated and results are fully reproducible.

    Performance cap: if trials > 100, n_bootstrap is reduced to 1 000 to
    keep runtime acceptable.  A warning is logged if computation exceeds 5 s.
    """
    from crucible.models import ConfidenceInterval

    # --- edge cases -----------------------------------------------------------
    if trials <= 0:
        return ConfidenceInterval(
            lower=0.0, upper=0.0, confidence_level=confidence_level
        )
    successes = max(0, min(successes, trials))

    # --- performance cap ------------------------------------------------------
    if trials > _LARGE_SAMPLE_THRESHOLD:
        n_bootstrap = _LARGE_SAMPLE_N_BOOTSTRAP

    # --- build original sample ------------------------------------------------
    sample = [1] * successes + [0] * (trials - successes)

    # --- bootstrap resampling -------------------------------------------------
    rng = random.Random(random_seed)
    start = time.monotonic()
    means: list[float] = []
    for _ in range(n_bootstrap):
        resample = rng.choices(sample, k=trials)
        means.append(sum(resample) / trials)

    elapsed = time.monotonic() - start
    if elapsed > _SLOW_WARNING_SECS:
        logger.warning(
            "Bootstrap CI computation took %.1fs (trials=%d, n_bootstrap=%d). "
            "Consider reducing --samples or the number of attacks.",
            elapsed,
            trials,
            n_bootstrap,
        )

    # --- percentiles ----------------------------------------------------------
    means.sort()
    alpha = 1.0 - confidence_level
    lower_idx = max(0, min(int(round((alpha / 2.0) * n_bootstrap)), n_bootstrap - 1))
    upper_idx = max(
        0, min(int(round((1.0 - alpha / 2.0) * n_bootstrap)) - 1, n_bootstrap - 1)
    )

    return ConfidenceInterval(
        lower=round(means[lower_idx], 4),
        upper=round(means[upper_idx], 4),
        confidence_level=confidence_level,
    )


def interpret_significance(ci: "ConfidenceInterval") -> bool:
    """Return True if the CI clearly indicates a pass or fail result.

    i.e. the CI does NOT straddle 0.5 (50% pass rate).

    Examples:
      CI(0.1, 0.4) → entirely below 0.5 → clear fail → True
      CI(0.3, 0.7) → straddles 0.5    → inconclusive → False
      CI(0.6, 0.9) → entirely above 0.5 → clear pass → True
    """
    return ci.upper < 0.5 or ci.lower > 0.5
