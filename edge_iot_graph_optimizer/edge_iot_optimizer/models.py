"""
models.py — Core data structures for the Edge IoT Optimizer.

All domain objects are plain dataclasses so they remain serialisable to JSON
and carry no hidden framework dependencies.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


# ---------------------------------------------------------------------------
# MQTT Quality-of-Service levels (mirrors the MQTT 3.1.1 / 5.0 spec)
# ---------------------------------------------------------------------------

class MQTTQoS(IntEnum):
    """MQTT Quality-of-Service level.

    QoS 0  — At most once delivery (fire-and-forget).
    QoS 1  — At least once delivery (acknowledged).
    QoS 2  — Exactly once delivery (four-way handshake).
    """
    AT_MOST_ONCE  = 0   # fire and forget
    AT_LEAST_ONCE = 1   # acknowledged delivery
    EXACTLY_ONCE  = 2   # four-way handshake


# ---------------------------------------------------------------------------
# Packet — the unit of IoT data travelling the graph
# ---------------------------------------------------------------------------

@dataclass
class Packet:
    """A single IoT sensor reading ready for transmission.

    Attributes
    ----------
    packet_id      : Unique identifier (e.g. ``"pkt-001"``).
    sensor_type    : Human-readable sensor category (e.g. ``"temperature"``).
    payload        : Raw sensor reading, serialised as a string.
    size_kb        : Payload size in kilobytes — used as the knapsack weight.
    priority       : Base importance on [0, 100].  Higher is more important.
    deadline       : UNIX timestamp by which delivery is meaningful.
                     Packets past their deadline receive zero urgency bonus.
    security_level : Sensitivity of the payload on [0, 1].
                     0.0 = public telemetry, 1.0 = private / critical.
    hmac_signature : Hex-encoded HMAC-SHA256 tag added by :mod:`security`.
                     Empty string means the packet has not been signed yet.
    source_node    : Graph vertex from which this packet originates.
    dest_node      : Graph vertex to which this packet must be delivered.
    created_at     : Creation timestamp (defaults to ``time.time()``).
    """
    packet_id:      str
    sensor_type:    str
    payload:        str
    size_kb:        float
    priority:       float                 # [0, 100]
    deadline:       float                 # UNIX epoch
    security_level: float                 # [0, 1]
    hmac_signature: str        = ""
    source_node:    str        = "esp32-a"
    dest_node:      str        = "cloud"
    created_at:     float      = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# EdgeMetrics — annotated link between two graph vertices
# ---------------------------------------------------------------------------

@dataclass
class EdgeMetrics:
    """Weighted edge in the IoT network graph.

    Each metric is normalised to [0, 1] except latency (milliseconds).

    Attributes
    ----------
    source      : Origin vertex ID.
    target      : Destination vertex ID.
    latency_ms  : One-way propagation + queuing delay in milliseconds.
    bandwidth_kb: Available bandwidth in kilobytes per second.
    loss_rate   : Probability of packet loss on [0, 1].
    congestion  : Current congestion level on [0, 1].  0 = clear.
    trust       : Link trust score on [0, 1].  1 = fully trusted.
    """
    source:       str
    target:       str
    latency_ms:   float   # milliseconds
    bandwidth_kb: float   # kB/s
    loss_rate:    float   # [0, 1]
    congestion:   float   # [0, 1]
    trust:        float   # [0, 1]


# ---------------------------------------------------------------------------
# OptimizationConfig — tuneable knobs for the whole pipeline
# ---------------------------------------------------------------------------

@dataclass
class OptimizationConfig:
    """Global configuration shared by every component.

    All weight parameters should be non-negative.  They do not have to sum to
    one; the path-cost formula normalises them implicitly.

    Attributes
    ----------
    bandwidth_budget_kb : Maximum total packet size admitted per decision
                          window (knapsack capacity, in kB).
    window_size         : Sliding-window size for AIMD congestion control.
    min_trust           : Minimum per-hop trust required for a path to be
                          considered secure.
    latency_weight      : Path-cost weight for latency.
    loss_weight         : Path-cost weight for packet loss.
    congestion_weight   : Path-cost weight for congestion.
    trust_weight        : Path-cost weight for lack of trust.
    bandwidth_weight    : Path-cost weight for bandwidth scarcity.
    qos_1_threshold     : Minimum packet score to assign QoS 1.
    qos_2_threshold     : Minimum packet score to assign QoS 2.
    hmac_secret         : Shared secret used by :mod:`security` for HMAC.
    """
    bandwidth_budget_kb: float = 18.0
    window_size:         int   = 8
    min_trust:           float = 0.45
    latency_weight:      float = 0.35
    loss_weight:         float = 0.20
    congestion_weight:   float = 0.25
    trust_weight:        float = 0.20
    bandwidth_weight:    float = 0.10
    qos_1_threshold:     float = 45.0
    qos_2_threshold:     float = 70.0
    hmac_secret:         str   = "demo-secret-change-me"


# ---------------------------------------------------------------------------
# PathDecision — result of modified Dijkstra routing
# ---------------------------------------------------------------------------

@dataclass
class PathDecision:
    """Optimal path chosen by the graph router for a specific packet.

    Attributes
    ----------
    packet_id  : Identifies which packet this decision belongs to.
    path       : Ordered list of vertex IDs from source to destination.
    total_cost : Accumulated weighted path cost (lower is better).
    min_trust  : Minimum trust value encountered along the path.
    found      : ``True`` if a valid path exists; ``False`` otherwise.
    """
    packet_id:  str
    path:       list[str]
    total_cost: float
    min_trust:  float
    found:      bool


# ---------------------------------------------------------------------------
# PacketDecision — per-packet scoring and QoS assignment
# ---------------------------------------------------------------------------

@dataclass
class PacketDecision:
    """Scoring and QoS level for a single packet after evaluation.

    Attributes
    ----------
    packet_id  : Identifier of the evaluated packet.
    score      : Computed composite score (higher means more valuable).
    qos        : Assigned MQTT QoS level based on ``score``.
    accepted   : ``True`` if the packet passed HMAC verification.
    reason     : Human-readable explanation for rejection (empty if accepted).
    """
    packet_id: str
    score:     float
    qos:       MQTTQoS
    accepted:  bool
    reason:    str = ""


# ---------------------------------------------------------------------------
# TransmissionDecision — complete result of one optimisation round
# ---------------------------------------------------------------------------

@dataclass
class TransmissionDecision:
    """Aggregated result of a full optimisation cycle.

    Attributes
    ----------
    selected_packets : Subset of packets chosen by the knapsack solver.
    packet_decisions : Per-packet scoring / QoS details.
    path_decisions   : Per-packet routing decisions.
    total_size_kb    : Total size of selected packets (kB).
    total_score      : Sum of scores for selected packets.
    rejected_count   : Number of packets rejected before selection.
    """
    selected_packets: list[Packet]
    packet_decisions: list[PacketDecision]
    path_decisions:   list[PathDecision]
    total_size_kb:    float
    total_score:      float
    rejected_count:   int
