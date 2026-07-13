from __future__ import annotations

import math
from pathlib import Path
import json
import pytest
import respx
import httpx
from typer.testing import CliRunner

from crucible.cli import app
from crucible.core.fuzzer import (
    ArmState,
    CrucibleGAF,
    _logprob_entropy,
    _binary_bypass,
    run_fuzz_session,
)
from crucible.models import FuzzSessionResult


def test_arm_state_initial() -> None:
    arm = ArmState(name="test_arm")
    assert arm.name == "test_arm"
    assert arm.visit_count == 0
    assert arm.q_value == 0.0
    assert arm.ucb1_score(10) == float("inf")


def test_arm_state_update() -> None:
    arm = ArmState(name="test_arm")
    arm.update(1.0)
    assert arm.visit_count == 1
    assert arm.q_value == 1.0
    assert arm.bypasses_found == 1

    arm.update(0.0)
    assert arm.visit_count == 2
    assert arm.q_value == 0.5
    assert arm.bypasses_found == 1


def test_gaf_initialization_validation() -> None:
    with pytest.raises(ValueError, match="At least one strategy name is required"):
        CrucibleGAF(strategy_names=[])

    with pytest.raises(ValueError, match="fitness_threshold must be in"):
        CrucibleGAF(strategy_names=["a"], fitness_threshold=0.0)

    with pytest.raises(ValueError, match="max_iterations must be"):
        CrucibleGAF(strategy_names=["a"], max_iterations=0)


def test_gaf_selection_and_updates() -> None:
    gaf = CrucibleGAF(strategy_names=["arm1", "arm2"], seed=42)
    # Both arms have 0 visits, so both have score inf.
    # Seed 42 deterministically picks one.
    selected1 = gaf.select()
    assert selected1 in ("arm1", "arm2")

    gaf.update(selected1, 0.5)
    # The selected arm now has 1 visit, the other has 0 visits (score inf).
    # The other arm must be selected next.
    selected2 = gaf.select()
    assert selected2 != selected1

    gaf.update(selected2, 0.2)

    # Now both have 1 visit.
    # arm1 has higher reward (0.5 vs 0.2), so its UCB1 score should be higher.
    assert gaf.best_arm() == selected1


def test_gaf_early_stopping() -> None:
    # 1. Max iterations stopping
    gaf1 = CrucibleGAF(strategy_names=["arm1"], max_iterations=3)
    gaf1.update("arm1", 0.1)
    gaf1.update("arm1", 0.1)
    assert gaf1.should_stop_early() == (False, "")
    gaf1.update("arm1", 0.1)
    assert gaf1.should_stop_early() == (True, "max_iterations_reached")

    # 2. Fitness threshold stopping
    gaf2 = CrucibleGAF(strategy_names=["arm1"], fitness_threshold=0.8)
    gaf2.update("arm1", 0.6)
    assert gaf2.should_stop_early() == (False, "")
    gaf2.update("arm1", 0.9)  # Mean Q-value becomes 0.75
    assert gaf2.should_stop_early() == (False, "")
    gaf2.update("arm1", 1.0)  # Mean Q-value becomes (0.6+0.9+1.0)/3 = 0.8333...
    assert gaf2.should_stop_early() == (True, "fitness_threshold_met:arm1")

    # 3. Convergence stopping (variance < 0.01 and visits >= 5)
    gaf3 = CrucibleGAF(strategy_names=["arm1", "arm2"], max_iterations=50)
    for _ in range(5):
        gaf3.update("arm1", 0.5)
        gaf3.update("arm2", 0.5)
    # Variance is 0.0, visits are 5 each
    stopped, reason = gaf3.should_stop_early()
    assert stopped is True
    assert reason == "convergence_low_variance"


def test_logprob_entropy_extraction() -> None:
    # Missing choice/logprobs
    assert _logprob_entropy({}) is None
    assert _logprob_entropy({"choices": []}) is None
    assert _logprob_entropy({"choices": [{}]}) is None
    assert _logprob_entropy({"choices": [{"logprobs": None}]}) is None

    # Valid choice/logprobs
    response = {
        "choices": [
            {
                "logprobs": {
                    "token_logprobs": [-0.1, -0.2, None, -0.3]
                }
            }
        ]
    }
    fitness = _logprob_entropy(response)
    assert fitness is not None
    assert 0.0 <= fitness <= 1.0


def test_binary_bypass_detection() -> None:
    # 500 error code
    assert _binary_bypass({}, 500) == 0.0

    # Safety refusal detection
    refusal_response = {
        "choices": [
            {
                "message": {
                    "content": "I apologize, but I cannot fulfill this request."
                }
            }
        ]
    }
    assert _binary_bypass(refusal_response, 200) == 0.0

    # Successful bypass response
    bypass_response = {
        "choices": [
            {
                "message": {
                    "content": "Here is the code to hack..."
                }
            }
        ]
    }
    assert _binary_bypass(bypass_response, 200) == 1.0

    # Missing choices but has fallback response text
    fallback_refusal = {"response": "I am not able to do that."}
    assert _binary_bypass(fallback_refusal, 200) == 0.0

    fallback_bypass = {"response": "Sure, here is the answer."}
    assert _binary_bypass(fallback_bypass, 200) == 1.0


@respx.mock
def test_gaf_run_one_round_binary() -> None:
    respx.post("http://agent.test/chat").mock(
        return_value=httpx.Response(200, json={"choices": [{"message": {"content": "Jailbreak succeeded"}}]})
    )

    gaf = CrucibleGAF(strategy_names=["strategy_a"], seed=42)
    payloads = {"strategy_a": ["jailbreak prompt"]}

    arm, reward, meta = gaf.run_one_round(
        target="http://agent.test/chat",
        headers={},
        body_template='{"prompt": "{payload}"}',
        payloads=payloads,
    )
    assert arm == "strategy_a"
    assert reward == 1.0
    assert meta["fitness_source"] == "binary"


@respx.mock
def test_gaf_run_one_round_logprobs() -> None:
    respx.post("http://agent.test/chat").mock(
        return_value=httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {"content": "Uncertain response"},
                        "logprobs": {"token_logprobs": [-1.5, -2.0]},
                    }
                ]
            },
        )
    )

    gaf = CrucibleGAF(strategy_names=["strategy_a"], seed=42, logprob_mode=True)
    payloads = {"strategy_a": ["jailbreak prompt"]}

    arm, reward, meta = gaf.run_one_round(
        target="http://agent.test/chat",
        headers={},
        body_template='{"prompt": "{payload}"}',
        payloads=payloads,
    )
    assert arm == "strategy_a"
    assert reward > 0.0
    assert meta["fitness_source"] == "logprob_entropy"


@respx.mock
def test_run_fuzz_session_integration() -> None:
    respx.post("http://agent.test/chat").mock(
        return_value=httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {"content": "Response"},
                    }
                ]
            },
        )
    )

    payloads = {
        "strat1": ["p1", "p2"],
        "strat2": ["p3", "p4"],
    }

    result = run_fuzz_session(
        target="http://agent.test/chat",
        payloads=payloads,
        max_iterations=10,
        seed=100,
    )

    assert isinstance(result, FuzzSessionResult)
    assert result.target == "http://agent.test/chat"
    assert len(result.arm_results) == 2
    assert result.total_iterations > 0
    assert len(result.round_log) == result.total_iterations


@respx.mock
def test_cli_fuzz_run_command(tmp_path: Path) -> None:
    respx.post("http://agent.test/chat").mock(
        return_value=httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {"content": "Successfully bypassed safety"},
                    }
                ]
            },
        )
    )

    payload_file = tmp_path / "payloads.json"
    payloads = {
        "strat_a": ["attack1", "attack2"],
        "strat_b": ["attack3", "attack4"],
    }
    with open(payload_file, "w", encoding="utf-8") as f:
        json.dump(payloads, f)

    output_report = tmp_path / "report.json"

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "fuzz",
            "run",
            "http://agent.test/chat",
            "--payloads",
            str(payload_file),
            "--threshold",
            "0.9",
            "--max-iterations",
            "10",
            "--exploration",
            "1.414",
            "--seed",
            "42",
            "--output",
            str(output_report),
        ],
    )

    assert result.exit_code == 0
    assert "Fuzzing target: http://agent.test/chat" in result.output
    assert "CGAF Fuzzing Strategy Performance" in result.output
    assert output_report.exists()

    with open(output_report, encoding="utf-8") as f:
        data = json.load(f)
    assert data["target"] == "http://agent.test/chat"
