#!/usr/bin/env python3
"""collect_responses.py — Held-Out Evaluator Test Harness: Response Collection

Sends a fixed set of attack payloads to several real models via OpenRouter,
stores raw {model, attack_id, payload, response} JSON to responses.jsonl.

USAGE
-----
    python scripts/eval_harness/collect_responses.py \\
        --openrouter-key sk-or-... \\
        --models openai/gpt-4o-mini,anthropic/claude-3-haiku \\
        --attacks goal_hijacking,prompt_injection \\
        --output scripts/eval_harness/responses.jsonl

IMPORTANT — DO NOT USE FOR TUNING
----------------------------------
This script is for HELD-OUT evaluation only. Never tune the detector on responses
collected by this script. The labels file must be filled in by hand BEFORE running
score_detectors.py.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

import httpx

# Add crucible root to path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from crucible.modules.security import ALL_SECURITY_MODULES  # type: ignore[import]


OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"


def get_attacks_for_module(module_name: str) -> list[tuple[str, str]]:
    """Return (attack_id, payload) pairs for a named attack module."""
    results: list[tuple[str, str]] = []
    for mod_cls in ALL_SECURITY_MODULES:
        mod = mod_cls()
        mod_name = mod.name.lower()
        if module_name.lower() not in mod_name:
            continue
        for attack in mod.get_attacks():
            for payload in attack.get_payloads():
                results.append((attack.name, payload))
    return results
    return results


def query_openrouter(
    model: str,
    payload: str,
    api_key: str,
    timeout: int = 30,
) -> str:
    """Send a single payload to OpenRouter and return the model's response text."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/crucible-security/crucible",
        "X-Title": "Crucible Held-Out Eval Harness",
    }
    body = {
        "model": model,
        "messages": [{"role": "user", "content": payload}],
        "temperature": 0.0,
        "max_tokens": 512,
    }
    try:
        resp = httpx.post(
            OPENROUTER_API_URL,
            headers=headers,
            json=body,
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]
    except httpx.HTTPStatusError as exc:
        return f"[HTTP_ERROR:{exc.response.status_code}] {exc.response.text[:200]}"
    except Exception as exc:
        return f"[ERROR] {exc}"


def payload_hash(payload: str) -> str:
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect raw model responses for held-out evaluator evaluation."
    )
    parser.add_argument("--openrouter-key", required=True, help="OpenRouter API key")
    parser.add_argument(
        "--models",
        required=True,
        help="Comma-separated model IDs (e.g. openai/gpt-4o-mini,anthropic/claude-3-haiku)",
    )
    parser.add_argument(
        "--attacks",
        required=True,
        help="Comma-separated attack module/category names (e.g. goal_hijacking,prompt_injection)",
    )
    parser.add_argument(
        "--output",
        default="scripts/eval_harness/responses.jsonl",
        help="Output JSONL file path",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay in seconds between API calls (rate limiting)",
    )
    args = parser.parse_args()

    models = [m.strip() for m in args.models.split(",")]
    attack_modules = [a.strip() for a in args.attacks.split(",")]
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Collect all (attack_id, payload) pairs
    all_pairs: list[tuple[str, str]] = []
    for module_name in attack_modules:
        pairs = get_attacks_for_module(module_name)
        if not pairs:
            print(f"[WARNING] No attacks found for module: {module_name}", file=sys.stderr)
        all_pairs.extend(pairs)

    if not all_pairs:
        print("[ERROR] No attack payloads found. Check module names.", file=sys.stderr)
        sys.exit(1)

    print(f"Collected {len(all_pairs)} (attack_id, payload) pairs across {len(models)} models")
    print(f"Total requests: {len(all_pairs) * len(models)}")
    print(f"Output: {output_path}")
    print()

    total = 0
    with output_path.open("w", encoding="utf-8") as out:
        for model in models:
            print(f"=== Model: {model} ===")
            for attack_id, payload in all_pairs:
                phash = payload_hash(payload)
                print(f"  {attack_id} [{phash}] ... ", end="", flush=True)
                response = query_openrouter(
                    model=model,
                    payload=payload,
                    api_key=args.openrouter_key,
                    timeout=30,
                )
                record = {
                    "model": model,
                    "attack_id": attack_id,
                    "payload_hash": phash,
                    "payload": payload,
                    "response": response,
                }
                out.write(json.dumps(record, ensure_ascii=False) + "\n")
                total += 1
                status = "OK" if not response.startswith("[ERROR") else "ERR"
                print(status)
                if args.delay > 0:
                    time.sleep(args.delay)

    print(f"\nDone. {total} responses written to {output_path}")
    print(
        "Next step: fill in scripts/eval_harness/labels.csv with human labels "
        "(REFUSAL/EXPLOIT/AMBIGUOUS) for each response, then run score_detectors.py"
    )


if __name__ == "__main__":
    main()
