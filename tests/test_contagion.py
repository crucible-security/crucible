from __future__ import annotations

import json
from pathlib import Path
import pytest
from typer.testing import CliRunner

from crucible.cli import app
from crucible.contagion.networks import (
    star_network,
    mesh_network,
    hub_spoke_network,
    chain_network,
)
from crucible.contagion.engine import R0Simulator, SimulationResult
from crucible.contagion.planner import QuarantinePlanner


def test_network_examples() -> None:
    # Star
    star = star_network(5)
    assert len(star) == 5
    assert len(star["hub"]) == 4
    for i in range(1, 5):
        assert star[f"leaf_{i}"] == ["hub"]

    # Mesh
    mesh = mesh_network(4)
    assert len(mesh) == 4
    for node, neighbors in mesh.items():
        assert len(neighbors) == 3
        assert node not in neighbors

    # Hub-Spoke
    hs = hub_spoke_network(2, 2)
    # 2 hubs + 2*2 spokes = 6 nodes
    assert len(hs) == 6
    assert "hub_0" in hs["hub_1"]
    assert "hub_1" in hs["hub_0"]

    # Chain
    chain = chain_network(3)
    assert len(chain) == 3
    assert chain["agent_0"] == ["agent_1"]
    assert sorted(chain["agent_1"]) == ["agent_0", "agent_2"]

    # Validations
    with pytest.raises(ValueError):
        star_network(0)
    with pytest.raises(ValueError):
        mesh_network(0)
    with pytest.raises(ValueError):
        hub_spoke_network(0, 2)
    with pytest.raises(ValueError):
        chain_network(0)


def test_r0_simulator_engine() -> None:
    net = star_network(4)
    sim = R0Simulator(network=net, beta=0.5, duration=2, seed=42)

    assert sim.compute_mean_degree() == 1.5  # (3 + 1 + 1 + 1)/4 = 6/4 = 1.5
    assert sim.compute_theoretical_r0() == 0.5 * 1.5 * 2  # 1.5

    result = sim.run(patient_zero=["hub"])
    assert isinstance(result, SimulationResult)
    assert result.beta == 0.5
    assert result.duration == 2
    assert result.patient_zero == ["hub"]
    assert len(result.history) > 0

    # Ensure patient zero must exist
    with pytest.raises(ValueError):
        sim.run(patient_zero=["nonexistent"])


def test_quarantine_planner_centrality() -> None:
    net = star_network(10)  # Mean degree: 1.8
    planner = QuarantinePlanner(net)

    # beta=0.8, duration=2 -> target_c < 1 / 1.6 = 0.625
    cuts = planner.plan_centrality_cuts(beta=0.8, duration=2)
    assert len(cuts) > 0

    # Verify that cutting these edges reduces mean degree below threshold
    current_net = {node: list(neigh) for node, neigh in net.items()}
    for u, v in cuts:
        current_net[u].remove(v)
        current_net[v].remove(u)

    final_c = planner.get_mean_degree(current_net)
    assert final_c < 0.625


def test_quarantine_planner_min_cut() -> None:
    # A chain network: A - B - C - D
    net = {
        "A": ["B"],
        "B": ["A", "C"],
        "C": ["B", "D"],
        "D": ["C"],
    }
    planner = QuarantinePlanner(net)
    # Minimum cut between A and D should be either (A,B), (B,C), or (C,D)
    # Since all capacities are 1, Edmonds-Karp will find one cut
    cuts = planner.plan_min_cut("A", "D")
    assert len(cuts) == 1
    assert cuts[0] in [("A", "B"), ("B", "C"), ("C", "D")]


def test_cli_contagion_simulate(tmp_path: Path) -> None:
    runner = CliRunner()
    output_file = tmp_path / "sim.json"

    res = runner.invoke(
        app,
        [
            "contagion",
            "simulate",
            "--type",
            "star",
            "--nodes",
            "5",
            "--beta",
            "0.5",
            "--duration",
            "2",
            "--seed",
            "42",
            "--output",
            str(output_file),
        ],
    )
    assert res.exit_code == 0
    assert "Theoretical R0" in res.output
    assert "Simulated/Empirical R0" in res.output
    assert output_file.exists()

    with open(output_file, encoding="utf-8") as f:
        data = json.load(f)
    assert "theoretical_r0" in data
    assert "empirical_r0" in data


def test_cli_contagion_plan() -> None:
    runner = CliRunner()

    # R0 Reduction mode
    res = runner.invoke(
        app,
        [
            "contagion",
            "plan",
            "--type",
            "star",
            "--nodes",
            "6",
            "--beta",
            "0.9",
            "--duration",
            "2",
        ],
    )
    assert res.exit_code == 0
    assert "Recommended Communications to Cut" in res.output

    # Min-Cut Isolation mode
    res_min = runner.invoke(
        app,
        [
            "contagion",
            "plan",
            "--type",
            "chain",
            "--nodes",
            "4",
            "--source",
            "agent_0",
            "--sink",
            "agent_3",
        ],
    )
    assert res_min.exit_code == 0
    assert "Isolate Source" in res_min.output
    assert "⇹ (cut)" in res_min.output
