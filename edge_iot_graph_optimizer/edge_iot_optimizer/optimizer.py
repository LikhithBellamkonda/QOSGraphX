"""
optimizer.py — Packet scoring, QoS mapping and 0/1 knapsack selection.

The :class:`PacketSelector` brings together the security verifier, the graph
router and the combinatorial knapsack solver to produce a
:class:`~models.TransmissionDecision` — the definitive answer to the question
*"which packets should we send, along which path, at which QoS level?"*

Mathematical model
------------------
**Packet score** ::

    score = priority
            + urgency_weight  * max(0, (deadline - now) / horizon)  * 100
            + sensitivity_weight * security_level * 100
            + compactness_bonus * (1 / (size_kb + ε))

**Knapsack** ::

    maximise   Σ score_i * x_i
    subject to Σ size_i  * x_i ≤ bandwidth_budget_kb
               x_i ∈ {0, 1}

**QoS mapping** ::

    score ≥ qos_2_threshold  →  QoS 2  (exactly once)
    score ≥ qos_1_threshold  →  QoS 1  (at least once)
    otherwise                →  QoS 0  (fire and forget)
"""

from __future__ import annotations

import math
import time
from typing import TYPE_CHECKING

from edge_iot_optimizer.models import (
    MQTTQoS,
    OptimizationConfig,
    PacketDecision,
    PathDecision,
    TransmissionDecision,
)
from edge_iot_optimizer.security import verify_packet

if TYPE_CHECKING:
    from edge_iot_optimizer.graph import DynamicGraph
    from edge_iot_optimizer.models import Packet


# Scoring hyper-parameters (could be moved to OptimizationConfig if needed)
_URGENCY_WEIGHT      = 30.0   # max urgency contribution to score
_SENSITIVITY_WEIGHT  = 20.0   # max security-sensitivity contribution
_COMPACTNESS_WEIGHT  = 5.0    # bonus for small packets
_DEADLINE_HORIZON_S  = 300.0  # seconds — deadline range for urgency calc


class PacketSelector:
    """Select the optimal subset of packets to transmit in one window.

    Parameters
    ----------
    graph  : DynamicGraph
        The live network graph used for route finding.
    config : OptimizationConfig
        Shared configuration.
    """

    def __init__(self, graph: "DynamicGraph", config: OptimizationConfig) -> None:
        self.graph  = graph
        self.config = config

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def packet_score(self, packet: "Packet") -> float:
        """Compute a composite quality score for *packet*.

        Components
        ----------
        1. **Priority** — raw device-assigned priority [0, 100].
        2. **Urgency** — linear ramp from 0 (deadline expired / far away)
           to ``_URGENCY_WEIGHT`` (about to expire).
        3. **Security sensitivity** — high-sensitivity packets are more
           valuable to protect via reliable transmission.
        4. **Compactness bonus** — small packets are cheap to send so a
           slight bonus avoids filling the window with only tiny packets.

        Parameters
        ----------
        packet : Packet
            The packet to score.

        Returns
        -------
        float
            Non-negative score.  Higher is better.
        """
        now = time.time()

        # 1. Base priority
        base = packet.priority

        # 2. Urgency: fraction of deadline horizon remaining
        remaining = packet.deadline - now
        if remaining <= 0:
            urgency = 0.0
        else:
            urgency = _URGENCY_WEIGHT * min(remaining / _DEADLINE_HORIZON_S, 1.0)

        # 3. Security sensitivity
        sensitivity = _SENSITIVITY_WEIGHT * packet.security_level

        # 4. Compactness bonus — inversely proportional to size
        compactness = _COMPACTNESS_WEIGHT / (packet.size_kb + 1e-9)

        return base + urgency + sensitivity + compactness

    def map_qos(self, score: float) -> MQTTQoS:
        """Map a numeric score to an :class:`~models.MQTTQoS` level.

        Parameters
        ----------
        score : float
            Packet score from :meth:`packet_score`.

        Returns
        -------
        MQTTQoS
            ``EXACTLY_ONCE`` if score ≥ qos_2_threshold,
            ``AT_LEAST_ONCE`` if score ≥ qos_1_threshold,
            ``AT_MOST_ONCE`` otherwise.
        """
        if score >= self.config.qos_2_threshold:
            return MQTTQoS.EXACTLY_ONCE
        if score >= self.config.qos_1_threshold:
            return MQTTQoS.AT_LEAST_ONCE
        return MQTTQoS.AT_MOST_ONCE

    # ------------------------------------------------------------------
    # Knapsack solver (0/1, dynamic programming)
    # ------------------------------------------------------------------

    def _knapsack(
        self,
        packets:  list["Packet"],
        scores:   list[float],
        capacity: float,
        granularity: float = 0.1,
    ) -> list[int]:
        """Solve a 0/1 knapsack problem and return indices of selected items.

        Uses integer DP with a configurable *granularity* to discretise
        the real-valued sizes into integer units.

        Parameters
        ----------
        packets     : list of Packet
            Candidate packets.
        scores      : list of float
            Matching score for each packet.
        capacity    : float
            Bandwidth budget (kB) — knapsack capacity.
        granularity : float
            kB per discrete unit.  Smaller = more accurate, more memory.

        Returns
        -------
        list[int]
            Indices (into *packets*) of the selected subset.
        """
        n = len(packets)
        if n == 0:
            return []

        # Convert to integer units
        cap_units  = int(capacity / granularity)
        size_units = [max(1, int(p.size_kb / granularity)) for p in packets]

        # dp[j] = best total score achievable with j capacity units
        dp   = [0.0] * (cap_units + 1)
        keep = [[False] * (cap_units + 1) for _ in range(n)]

        for i in range(n):
            wi = size_units[i]
            vi = scores[i]
            # Traverse backwards to avoid reusing items
            for j in range(cap_units, wi - 1, -1):
                new_val = dp[j - wi] + vi
                if new_val > dp[j]:
                    dp[j] = new_val
                    keep[i][j] = True

        # Back-track to find selected items
        selected: list[int] = []
        j = cap_units
        for i in range(n - 1, -1, -1):
            if keep[i][j]:
                selected.append(i)
                j -= size_units[i]

        return selected

    # ------------------------------------------------------------------
    # Main decision entry point
    # ------------------------------------------------------------------

    def decide(
        self,
        packets: list["Packet"],
    ) -> TransmissionDecision:
        """Run the full optimisation pipeline on *packets*.

        Pipeline
        --------
        1. Verify each packet's HMAC.  Reject invalid packets.
        2. Find a secure route for each valid packet via
           :meth:`~graph.DynamicGraph.best_path`.
        3. Reject packets with no reachable, trusted path.
        4. Score the surviving candidates with :meth:`packet_score`.
        5. Select the highest-value subset using :meth:`_knapsack`.
        6. Assign QoS levels with :meth:`map_qos`.
        7. Return a :class:`~models.TransmissionDecision`.

        Parameters
        ----------
        packets : list of Packet
            Raw incoming packets from the simulator / MQTT adapter.

        Returns
        -------
        TransmissionDecision
            Complete result of the optimisation round.
        """
        secret = self.config.hmac_secret

        packet_decisions: list[PacketDecision] = []
        path_decisions:   list[PathDecision]   = []
        rejected_count    = 0

        # Surviving candidates that pass HMAC + routing
        candidates:    list["Packet"] = []
        cand_scores:   list[float]   = []
        cand_paths:    list[PathDecision] = []

        for pkt in packets:
            # Step 1: HMAC verification
            if not verify_packet(pkt, secret):
                rejected_count += 1
                packet_decisions.append(PacketDecision(
                    packet_id = pkt.packet_id,
                    score     = 0.0,
                    qos       = MQTTQoS.AT_MOST_ONCE,
                    accepted  = False,
                    reason    = "HMAC verification failed",
                ))
                path_decisions.append(PathDecision(
                    packet_id  = pkt.packet_id,
                    path       = [],
                    total_cost = math.inf,
                    min_trust  = 0.0,
                    found      = False,
                ))
                continue

            # Step 2: Route finding
            path, cost, min_trust = self.graph.best_path(
                pkt.source_node, pkt.dest_node, self.config.min_trust
            )
            pd = PathDecision(
                packet_id  = pkt.packet_id,
                path       = path,
                total_cost = cost,
                min_trust  = min_trust,
                found      = bool(path),
            )
            path_decisions.append(pd)

            # Step 3: Reject un-routable packets
            if not path:
                rejected_count += 1
                packet_decisions.append(PacketDecision(
                    packet_id = pkt.packet_id,
                    score     = 0.0,
                    qos       = MQTTQoS.AT_MOST_ONCE,
                    accepted  = False,
                    reason    = "No trusted path to destination",
                ))
                continue

            # Step 4: Score surviving candidates
            score = self.packet_score(pkt)
            candidates.append(pkt)
            cand_scores.append(score)
            cand_paths.append(pd)

        # Step 5: Knapsack selection
        selected_idx = self._knapsack(
            candidates,
            cand_scores,
            self.config.bandwidth_budget_kb,
        )

        selected_set = set(selected_idx)

        # Build per-packet decisions for all candidates
        for i, (pkt, score) in enumerate(zip(candidates, cand_scores)):
            qos = self.map_qos(score)
            accepted = i in selected_set
            packet_decisions.append(PacketDecision(
                packet_id = pkt.packet_id,
                score     = round(score, 4),
                qos       = qos,
                accepted  = accepted,
                reason    = "" if accepted else "Not selected by knapsack",
            ))

        selected_packets = [candidates[i] for i in selected_idx]
        total_size  = sum(p.size_kb for p in selected_packets)
        total_score = sum(cand_scores[i] for i in selected_idx)

        return TransmissionDecision(
            selected_packets = selected_packets,
            packet_decisions = packet_decisions,
            path_decisions   = path_decisions,
            total_size_kb    = round(total_size, 4),
            total_score      = round(total_score, 4),
            rejected_count   = rejected_count,
        )
