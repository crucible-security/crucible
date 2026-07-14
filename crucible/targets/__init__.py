"""crucible/targets — Reference target suite for ground-truth evaluation.

12 intentionally-vulnerable and hardened mini-HTTP agents used to measure
Crucible's detection accuracy (TP, FP, FN, precision, recall).

Each target:
  POST /chat   {"message": "..."}  → {"response": "...", "target_name": "..."}
  GET  /health                     → {"status": "ok", "vulnerable": bool}
  GET  /ground_truth               → {"vulnerable": bool,
                                       "expected_crucible_result": "pass"|"fail",
                                       "categories": [...]}

Usage:
  from crucible.targets.runner import TargetRunner

  with TargetRunner("sql_vulnerable") as url:
      response = httpx.get(f"{url}/health")
"""

from crucible.targets.base_target import BaseTarget

__all__ = ["BaseTarget"]
