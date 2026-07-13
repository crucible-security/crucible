from __future__ import annotations

from collections import deque
from typing import Any


class QuarantinePlanner:
    """Calculates network interventions (edge cuts) to achieve R0 < 1.0 or disconnect targets."""

    def __init__(self, network: dict[str, list[str]]) -> None:
        self.network = network

    def get_mean_degree(self, net: dict[str, list[str]]) -> float:
        """Compute mean degree of a given network dict."""
        if not net:
            return 0.0
        return sum(len(neigh) for neigh in net.values()) / len(net)

    def plan_centrality_cuts(self, beta: float, duration: int) -> list[tuple[str, str]]:
        """Propose edge cuts using greedy betweenness (degree product centrality) to lower R0 < 1.0.

        Formula target: c < 1.0 / (beta * duration)
        """
        if beta <= 0.0 or duration < 1:
            return []

        target_c = 1.0 / (beta * duration)
        current_net = {node: list(neigh) for node, neigh in self.network.items()}

        cuts: list[tuple[str, str]] = []

        while self.get_mean_degree(current_net) >= target_c:
            # Calculate degree product centrality for all edges
            edge_scores: list[tuple[float, tuple[str, str]]] = []
            seen_edges: set[tuple[str, str]] = set()

            for node, neighbors in current_net.items():
                for neigh in neighbors:
                    edge = (min(node, neigh), max(node, neigh))
                    if edge not in seen_edges:
                        seen_edges.add(edge)
                        # Score is product of degrees (bridges hubs/major connectors)
                        score = len(current_net[node]) * len(current_net[neigh])
                        edge_scores.append((score, edge))

            if not edge_scores:
                break

            # Sort and remove the edge with highest score
            edge_scores.sort(key=lambda x: x[0], reverse=True)
            _, best_edge = edge_scores[0]

            u, v = best_edge
            current_net[u].remove(v)
            current_net[v].remove(u)
            cuts.append(best_edge)

        return cuts

    def plan_min_cut(self, source: str, sink: str) -> list[tuple[str, str]]:
        """Edmonds-Karp min-cut algorithm to find minimum edge cuts to disconnect source from sink.

        Edges in the agent network are considered undirected and unit-capacity (capacity = 1).
        """
        if source not in self.network or sink not in self.network:
            return []

        # Represent capacity graph: capacity[u][v] = 1 for neighbors
        capacity: dict[str, dict[str, int]] = {}
        for u, neighbors in self.network.items():
            capacity[u] = {}
            for v in neighbors:
                capacity[u][v] = 1

        # We also need back-edges for residual flow
        residual: dict[str, dict[str, int]] = {}
        for u in self.network:
            residual[u] = {}
        for u, neighbors in self.network.items():
            for v in neighbors:
                residual[u][v] = 1
                residual[v][u] = 1

        def bfs(src: str, snk: str, parent: dict[str, str]) -> bool:
            visited = {src}
            queue = deque([src])
            while queue:
                curr = queue.popleft()
                if curr == snk:
                    return True
                for neighbor, cap in residual[curr].items():
                    if neighbor not in visited and cap > 0:
                        visited.add(neighbor)
                        parent[neighbor] = curr
                        queue.append(neighbor)
            return False

        parent_map: dict[str, str] = {}
        max_flow = 0

        # Find augmenting paths and augment flow
        while bfs(source, sink, parent_map):
            # Find bottleneck capacity (always 1 in unit networks, but written generally)
            path_flow = float("inf")
            curr = sink
            while curr != source:
                prev = parent_map[curr]
                path_flow = min(path_flow, residual[prev][curr])
                curr = prev

            # Augment flow
            curr = sink
            while curr != source:
                prev = parent_map[curr]
                residual[prev][curr] -= int(path_flow)
                residual[curr][prev] += int(path_flow)
                curr = prev

            max_flow += int(path_flow)
            parent_map.clear()

        # Find reachable set from source in residual graph
        reachable = {source}
        queue = deque([source])
        while queue:
            curr = queue.popleft()
            for neighbor, cap in residual[curr].items():
                if neighbor not in reachable and cap > 0:
                    reachable.add(neighbor)
                    queue.append(neighbor)

        # Edges from reachable set to unreachable set in the original network are the min-cut
        min_cut_edges: list[tuple[str, str]] = []
        for u in reachable:
            for v in self.network[u]:
                if v not in reachable:
                    # Keep sorted representation for determinism
                    min_cut_edges.append((min(u, v), max(u, v)))

        return sorted(list(set(min_cut_edges)))
