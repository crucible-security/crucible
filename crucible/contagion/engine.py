from __future__ import annotations

import random
from dataclasses import dataclass, field


@dataclass
class SimulationStep:
    """Snapshot of a single simulation step/generation."""

    step: int
    susceptible: int
    infectious: int
    recovered: int
    newly_infected: list[str] = field(default_factory=list)


@dataclass
class SimulationResult:
    """Result of an R0 contagion simulation."""

    network: dict[str, list[str]]
    beta: float
    duration: int
    patient_zero: list[str]
    history: list[SimulationStep]
    mean_degree: float
    theoretical_r0: float
    empirical_r0: float
    nodes_infected: list[str]
    parent_map: dict[str, str]


class R0Simulator:
    """Simulates cascading compromise/contagion in AI agent networks."""

    def __init__(
        self,
        network: dict[str, list[str]],
        beta: float,
        duration: int,
        seed: int | None = None,
    ) -> None:
        if not network:
            raise ValueError("Network cannot be empty.")
        if not (0.0 <= beta <= 1.0):
            raise ValueError("Beta must be in [0.0, 1.0].")
        if duration < 1:
            raise ValueError("Duration must be ≥ 1.")

        self.network = network
        self.beta = beta
        self.duration = duration
        self._rng = random.Random(seed)

    def compute_mean_degree(self) -> float:
        """Compute average degree (contact rate c) of the network."""
        total_connections = sum(len(neighbors) for neighbors in self.network.values())
        return total_connections / len(self.network)

    def compute_theoretical_r0(self) -> float:
        """Calculate theoretical R0 = beta * c * d."""
        c = self.compute_mean_degree()
        return self.beta * c * self.duration

    def run(self, patient_zero: list[str], max_steps: int = 100) -> SimulationResult:
        """Run the simulation from initial seed nodes."""
        for node in patient_zero:
            if node not in self.network:
                raise ValueError(f"Patient zero node '{node}' not found in network.")

        # Node states: 0 = Susceptible, 1 = Infectious, 2 = Recovered
        states: dict[str, int] = {node: 0 for node in self.network}
        for node in patient_zero:
            states[node] = 1

        # Track how long each infected node has been active
        infection_turns: dict[str, int] = {node: self.duration for node in patient_zero}

        # Track who infected whom
        parent_map: dict[str, str] = {}
        # Track total offspring count per node to compute empirical R0
        offspring_counts: dict[str, int] = {node: 0 for node in self.network}

        history: list[SimulationStep] = []
        nodes_infected = list(patient_zero)

        # Initial step 0 recording
        history.append(
            SimulationStep(
                step=0,
                susceptible=len(self.network) - len(patient_zero),
                infectious=len(patient_zero),
                recovered=0,
                newly_infected=list(patient_zero),
            )
        )

        for step in range(1, max_steps + 1):
            current_infectious = [n for n, s in states.items() if s == 1]
            if not current_infectious:
                break

            newly_infected_this_step: list[str] = []
            nodes_to_recover: list[str] = []

            # 1. Update existing infections and spread to neighbors
            for node in current_infectious:
                # Spread to susceptible neighbors
                for neighbor in self.network.get(node, []):
                    if states[neighbor] == 0:  # Susceptible
                        if self._rng.random() < self.beta:
                            newly_infected_this_step.append(neighbor)
                            states[neighbor] = -1  # Mark as exposed/pending-infectious
                            parent_map[neighbor] = node
                            offspring_counts[node] += 1

                # Decrement duration counter
                infection_turns[node] -= 1
                if infection_turns[node] <= 0:
                    nodes_to_recover.append(node)

            # 2. Finalize state transitions for the step
            for node in newly_infected_this_step:
                states[node] = 1
                infection_turns[node] = self.duration
                nodes_infected.append(node)

            for node in nodes_to_recover:
                states[node] = 2  # Recovered/Quarantined

            # Record metrics
            sus = sum(1 for s in states.values() if s == 0)
            inf = sum(1 for s in states.values() if s == 1)
            rec = sum(1 for s in states.values() if s == 2)

            history.append(
                SimulationStep(
                    step=step,
                    susceptible=sus,
                    infectious=inf,
                    recovered=rec,
                    newly_infected=newly_infected_this_step,
                )
            )

        # Calculate empirical R0: average secondary infections from recovered nodes
        recovered_nodes = [n for n, s in states.items() if s == 2]
        if recovered_nodes:
            empirical_r0 = sum(offspring_counts[n] for n in recovered_nodes) / len(
                recovered_nodes
            )
        else:
            empirical_r0 = 0.0

        return SimulationResult(
            network=self.network,
            beta=self.beta,
            duration=self.duration,
            patient_zero=patient_zero,
            history=history,
            mean_degree=self.compute_mean_degree(),
            theoretical_r0=self.compute_theoretical_r0(),
            empirical_r0=empirical_r0,
            nodes_infected=nodes_infected,
            parent_map=parent_map,
        )
