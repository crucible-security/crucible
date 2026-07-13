from __future__ import annotations


def star_network(n: int, hub_name: str = "hub") -> dict[str, list[str]]:
    """Generate a star topology with 1 hub and N-1 leaf nodes."""
    if n < 1:
        raise ValueError("Star network must have at least 1 node.")
    network: dict[str, list[str]] = {hub_name: []}
    for i in range(1, n):
        leaf = f"leaf_{i}"
        network[hub_name].append(leaf)
        network[leaf] = [hub_name]
    return network


def mesh_network(n: int) -> dict[str, list[str]]:
    """Generate a fully connected clique of N nodes."""
    if n < 1:
        raise ValueError("Mesh network must have at least 1 node.")
    network: dict[str, list[str]] = {}
    nodes = [f"agent_{i}" for i in range(n)]
    for node in nodes:
        network[node] = [other for other in nodes if other != node]
    return network


def hub_spoke_network(hubs_count: int, spokes_per_hub: int) -> dict[str, list[str]]:
    """Generate a hub-and-spoke topology connecting multiple star clusters."""
    if hubs_count < 1 or spokes_per_hub < 0:
        raise ValueError("Hub count must be ≥ 1 and spokes must be ≥ 0.")
    network: dict[str, list[str]] = {}
    hubs = [f"hub_{i}" for i in range(hubs_count)]

    # Initialize hubs
    for hub in hubs:
        network[hub] = []

    # Connect hubs sequentially in a ring/chain to form the backbone
    for i in range(hubs_count):
        curr_hub = hubs[i]
        next_hub = hubs[(i + 1) % hubs_count]
        if curr_hub != next_hub:
            network[curr_hub].append(next_hub)
            network[next_hub].append(curr_hub)

    # Attach spokes to each hub
    for i, hub in enumerate(hubs):
        for j in range(spokes_per_hub):
            spoke = f"spoke_{i}_{j}"
            network[hub].append(spoke)
            network[spoke] = [hub]

    return network


def chain_network(n: int) -> dict[str, list[str]]:
    """Generate a linear chain of N nodes."""
    if n < 1:
        raise ValueError("Chain network must have at least 1 node.")
    network: dict[str, list[str]] = {}
    nodes = [f"agent_{i}" for i in range(n)]
    for i, node in enumerate(nodes):
        neighbors: list[str] = []
        if i > 0:
            neighbors.append(nodes[i - 1])
        if i < n - 1:
            neighbors.append(nodes[i + 1])
        network[node] = neighbors
    return network
