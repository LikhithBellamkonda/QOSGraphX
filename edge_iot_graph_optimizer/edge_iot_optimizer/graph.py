"""
graph.py — Dynamic IoT network graph with modified Dijkstra routing.

The graph models IoT devices as vertices and communication links as weighted
directed edges.  Edge weights encode multiple QoS metrics: latency, bandwidth,
packet-loss, congestion, and trust.

The modified Dijkstra implementation rejects paths whose minimum per-hop trust
falls below the configured threshold, making security a hard routing constraint
rather than just another cost term.

Classes
-------
DynamicGraph   — Directed multi-metric graph with real-time edge updates.
"""

from __future__ import annotations

import heapq
import math
from typing import Optional

from edge_iot_optimizer.models import EdgeMetrics, OptimizationConfig


class DynamicGraph:
    """Directed graph of IoT nodes with weighted, multi-metric edges.

    Each edge carries latency, bandwidth, loss, congestion and trust data.
    The path-cost formula combines all five metrics into a single scalar that
    Dijkstra can minimise:

    .. math::

        cost_{uv} = w_l \\cdot \\hat{lat}_{uv}
                  + w_p \\cdot loss_{uv}
                  + w_c \\cdot cong_{uv}
                  + w_t \\cdot (1 - trust_{uv})
                  + w_b \\cdot \\frac{1}{bw_{uv} + \\varepsilon}

    where all :math:`w_x` are drawn from :class:`~models.OptimizationConfig`.

    Parameters
    ----------
    config : OptimizationConfig
        Shared configuration object (weights, thresholds, etc.).
    """

    # Maximum latency used for normalisation (ms).  Links faster than this
    # are scaled linearly into [0, 1].
    _MAX_LATENCY_MS: float = 500.0

    def __init__(self, config: OptimizationConfig) -> None:
        self.config = config
        # adjacency list: node → list of EdgeMetrics
        self._adj: dict[str, list[EdgeMetrics]] = {}

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def add_node(self, node_id: str) -> None:
        """Ensure *node_id* exists in the adjacency list."""
        self._adj.setdefault(node_id, [])

    def add_edge(self, edge: EdgeMetrics) -> None:
        """Add (or replace) a directed edge from ``edge.source`` to
        ``edge.target``.

        If an edge between the same pair of nodes already exists it is removed
        before the new one is inserted, so the graph always holds at most one
        directed edge between any ordered pair of vertices.

        Parameters
        ----------
        edge : EdgeMetrics
            The new edge to insert.
        """
        self.add_node(edge.source)
        self.add_node(edge.target)
        # Remove any existing edge with the same (source, target)
        self._adj[edge.source] = [
            e for e in self._adj[edge.source] if e.target != edge.target
        ]
        self._adj[edge.source].append(edge)

    def update_congestion(self, source: str, target: str,
                          congestion: float) -> None:
        """Dynamically update the congestion level of a specific link.

        Parameters
        ----------
        source, target : str
            The directed edge to update.
        congestion : float
            New congestion value on [0, 1].
        """
        for edge in self._adj.get(source, []):
            if edge.target == target:
                edge.congestion = max(0.0, min(1.0, congestion))
                return

    def nodes(self) -> list[str]:
        """Return the list of all vertex IDs."""
        return list(self._adj.keys())

    def edges_from(self, node: str) -> list[EdgeMetrics]:
        """Return all outgoing edges from *node*."""
        return list(self._adj.get(node, []))

    # ------------------------------------------------------------------
    # Cost computation
    # ------------------------------------------------------------------

    def edge_cost(self, edge: EdgeMetrics) -> float:
        """Compute the scalar cost of a single edge.

        Latency is normalised to [0, 1] using :attr:`_MAX_LATENCY_MS`.
        Bandwidth is inverted so higher bandwidth = lower cost.

        Parameters
        ----------
        edge : EdgeMetrics
            The edge to evaluate.

        Returns
        -------
        float
            Non-negative cost scalar.  Lower is better.
        """
        cfg = self.config
        lat_norm = min(edge.latency_ms / self._MAX_LATENCY_MS, 1.0)
        bw_inv   = 1.0 / (edge.bandwidth_kb + 1e-9)

        cost = (
            cfg.latency_weight    * lat_norm
            + cfg.loss_weight     * edge.loss_rate
            + cfg.congestion_weight * edge.congestion
            + cfg.trust_weight    * (1.0 - edge.trust)
            + cfg.bandwidth_weight  * bw_inv
        )
        return cost

    # ------------------------------------------------------------------
    # Modified Dijkstra
    # ------------------------------------------------------------------

    def best_path(
        self,
        source: str,
        destination: str,
        min_trust: Optional[float] = None,
    ) -> tuple[list[str], float, float]:
        """Find the minimum-cost path from *source* to *destination*.

        The search prunes any edge whose trust is below *min_trust*, making
        security a hard routing constraint.

        Parameters
        ----------
        source : str
            Starting vertex.
        destination : str
            Target vertex.
        min_trust : float, optional
            Per-hop minimum trust threshold.  Defaults to
            ``config.min_trust``.

        Returns
        -------
        path : list[str]
            Ordered vertex IDs from source to destination.
            Empty if no path found.
        total_cost : float
            Accumulated edge cost along the chosen path.
            ``math.inf`` if no path found.
        path_min_trust : float
            Minimum trust encountered along the chosen path.
            1.0 if the path is a single node (trivial).
            0.0 if no path found.
        """
        if min_trust is None:
            min_trust = self.config.min_trust

        if source not in self._adj or destination not in self._adj:
            return [], math.inf, 0.0

        if source == destination:
            return [source], 0.0, 1.0

        # dist[node] = (accumulated_cost, min_trust_along_path)
        dist: dict[str, tuple[float, float]] = {
            n: (math.inf, 0.0) for n in self._adj
        }
        dist[source] = (0.0, 1.0)

        # prev[node] = predecessor vertex on cheapest path
        prev: dict[str, Optional[str]] = {n: None for n in self._adj}

        # Priority queue entries: (cost, node)
        pq: list[tuple[float, str]] = [(0.0, source)]

        visited: set[str] = set()

        while pq:
            cost_u, u = heapq.heappop(pq)
            if u in visited:
                continue
            visited.add(u)

            if u == destination:
                break  # optimal path to destination found

            for edge in self._adj.get(u, []):
                v = edge.target

                # Hard security constraint: prune untrusted edges
                if edge.trust < min_trust:
                    continue

                new_cost = cost_u + self.edge_cost(edge)
                current_min_trust = dist[u][1]
                new_min_trust = min(current_min_trust, edge.trust)

                if new_cost < dist[v][0]:
                    dist[v] = (new_cost, new_min_trust)
                    prev[v] = u
                    heapq.heappush(pq, (new_cost, v))

        # Reconstruct path
        if dist[destination][0] == math.inf:
            return [], math.inf, 0.0  # unreachable

        path: list[str] = []
        node: Optional[str] = destination
        while node is not None:
            path.append(node)
            node = prev[node]
        path.reverse()

        total_cost, path_min_trust = dist[destination]
        return path, total_cost, path_min_trust
