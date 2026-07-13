# Epidemiological Modeling of Cascading Compromise in Multi-Agent AI Networks
### Research & Implementation Notes | Crucible Security v0.14.0

---

## 1. Mathematical Formulation of Agent-to-Agent Contagion

When AI agents are given autonomous communication capabilities (such as tool-use, inter-agent messaging, or shared workspace memory), they form a directed or undirected interaction graph \(G = (V, E)\). If one agent is compromised via prompt injection or execution abuse, the compromise can cascade to connected agents.

To model this risk quantitatively, we adapt the classical **SIR (Susceptible-Infectious-Recovered)** epidemiological framework to multi-agent security:

\[R_0 = \beta \times c \times d\]

where:
- \(\beta \in [0, 1]\) is the **Transmission Probability** (or bypass rate): the likelihood that an adversarial prompt sent from a compromised agent successfully bypasses the guardrails of a neighboring recipient agent.
- \(c\) is the **Contact Rate**: the average node degree (average number of communication channels per agent) in the network topology:
  \[c = \frac{1}{|V|} \sum_{v \in V} \text{deg}(v)\]
- \(d\) is the **Duration of Infectiousness**: the number of communication turns a compromised agent remains active before anomaly detection mechanisms (such as `crucible watch` or `crucible identity diff`) detect the compromise and trigger automatic quarantine (recovery).

### 1.1 The Epidemic Threshold
An epidemic outbreak (complete or majority contagion of the agent swarm) occurs if and only if:
\[R_0 \ge 1.0\]
If \(R_0 < 1.0\), the compromise is guaranteed to die out exponentially, affecting only a small, bounded subset of agents.

---

## 2. Theoretical vs. Empirical \(R_0\)

In complex topologies, the theoretical \(R_0\) (calculated using the network's global mean degree) can diverge from the *empirical* \(R_0\) observed during simulations:
1. **Theoretical \(R_0\)** assumes homogeneous mixing (every node has equal probability of communicating with every other node).
2. **Empirical \(R_0\)** captures local clustering and structural bottlenecks. In a star network, for example, leaf nodes cannot infect other leaves directly; they must go through the hub. If the hub is quarantined early, the outbreak ceases instantly, resulting in an empirical \(R_0\) much lower than the theoretical expectation.

---

## 3. Intervention Strategies (Quarantine Planning)

To enforce containment and guarantee \(R_0 < 1.0\), security architects can perform two types of topology interventions:

### 3.1 Global R0 Reduction (Herd Immunity)
By removing communication edges, we reduce the contact rate \(c\) to a safe threshold \(c_{\text{target}}\):
\[c_{\text{target}} < \frac{1}{\beta \times d}\]
We use a **greedy degree-product centrality heuristic** to identify the most critical edges to cut:
\[\text{Score}(u, v) = \text{deg}(u) \times \text{deg}(v)\]
Cutting edges with the highest score targets connections between hubs first, quickly partitioning the network and halting contagion with the minimum number of disabled channels.

### 3.2 Targeted Path Isolation (Min-Cut)
When protecting a specific high-value asset (e.g., an administrative agent or database connector `sink` \(T\)) from a potentially compromised ingestion agent (`source` \(S\)), we find the absolute minimum number of edge cuts required to guarantee disconnection.

We implement the **Edmonds-Karp max-flow/min-cut algorithm** on unit-capacity undirected edges. BFS finds augmenting paths in the residual network:
1. Augment flow along shortest paths.
2. Construct the reachable set \(R\) from source \(S\) in the final residual graph.
3. The boundary edges crossing from \(R\) to \(V \setminus R\) constitute the optimal quarantine cuts.
