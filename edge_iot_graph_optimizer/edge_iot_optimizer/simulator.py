"""
simulator.py — Demo network builder and synthetic IoT packet generator.

This module creates a realistic 6-node IoT topology and generates random
signed packets so that the full pipeline can be exercised without real
hardware.

Topology
--------
::

    esp32-a ──┐
    esp32-b ──┼──► edge-1 ──► cloud
    esp32-c ──┘
                   edge-2 ──► cloud   (alternative path via edge-2)
    esp32-a also connects to edge-2 directly.

"""

from __future__ import annotations

import random
import time
import uuid

from edge_iot_optimizer.graph import DynamicGraph
from edge_iot_optimizer.models import EdgeMetrics, OptimizationConfig, Packet
from edge_iot_optimizer.security import sign_packet


# ---------------------------------------------------------------------------
# Sensor meta-data — used to generate realistic-looking packets
# ---------------------------------------------------------------------------

_SENSOR_TYPES = [
    ("temperature",  0.3, 70.0),   # (type, security_level, priority_mean)
    ("humidity",     0.2, 50.0),
    ("gas",          0.9, 90.0),
    ("motion",       0.8, 85.0),
    ("ultrasonic",   0.4, 55.0),
    ("pressure",     0.5, 65.0),
]

_SOURCE_NODES = ["esp32-a", "esp32-b", "esp32-c"]


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------

def build_demo_graph(config: OptimizationConfig) -> DynamicGraph:
    """Construct the 6-node demo IoT topology.

    Nodes
    -----
    * ``esp32-a``, ``esp32-b``, ``esp32-c`` — leaf sensor nodes.
    * ``edge-1``, ``edge-2`` — local edge computing nodes.
    * ``cloud`` — final destination.

    All edges are directed (sensor → edge → cloud).  Multiple paths exist so
    the Dijkstra router has genuine choices to make.

    Parameters
    ----------
    config : OptimizationConfig
        Used when constructing the :class:`~graph.DynamicGraph`.

    Returns
    -------
    DynamicGraph
        Fully populated graph ready for routing.
    """
    g = DynamicGraph(config)

    edges = [
        # source,    target,   lat_ms,  bw_kb,  loss,  cong,  trust
        EdgeMetrics("esp32-a", "edge-1",  12.0,  100.0, 0.02, 0.10, 0.92),
        EdgeMetrics("esp32-a", "edge-2",  18.0,   80.0, 0.03, 0.15, 0.85),
        EdgeMetrics("esp32-b", "edge-1",  15.0,   90.0, 0.04, 0.20, 0.88),
        EdgeMetrics("esp32-b", "edge-2",  22.0,   70.0, 0.05, 0.25, 0.80),
        EdgeMetrics("esp32-c", "edge-1",  10.0,  110.0, 0.01, 0.05, 0.95),
        EdgeMetrics("esp32-c", "edge-2",  20.0,   75.0, 0.03, 0.18, 0.82),
        EdgeMetrics("edge-1",  "cloud",   25.0,  200.0, 0.01, 0.08, 0.98),
        EdgeMetrics("edge-2",  "cloud",   30.0,  180.0, 0.02, 0.12, 0.94),
        # Cross-link for redundancy
        EdgeMetrics("edge-1",  "edge-2",   5.0,  150.0, 0.00, 0.05, 0.99),
        EdgeMetrics("edge-2",  "edge-1",   5.0,  150.0, 0.00, 0.05, 0.99),
    ]

    for edge in edges:
        g.add_edge(edge)

    return g


# ---------------------------------------------------------------------------
# Packet generator
# ---------------------------------------------------------------------------

def generate_packets(
    n: int,
    config: OptimizationConfig,
    *,
    seed: int | None = None,
    tamper_fraction: float = 0.05,
) -> list[Packet]:
    """Generate *n* synthetic, signed IoT packets.

    A small fraction of packets (``tamper_fraction``) have their payload
    mutated *after* signing so the HMAC verifier has genuine rejections to
    handle.

    Parameters
    ----------
    n : int
        Number of packets to generate.
    config : OptimizationConfig
        Used for the HMAC secret and routing destinations.
    seed : int, optional
        Random seed for reproducibility.
    tamper_fraction : float
        Proportion of packets to deliberately tamper.

    Returns
    -------
    list of Packet
        Signed (and occasionally tampered) packet list.
    """
    rng = random.Random(seed)
    now = time.time()
    packets: list[Packet] = []

    for i in range(n):
        sensor_type, sec_level, prio_mean = rng.choice(_SENSOR_TYPES)

        # Add realistic jitter around the mean priority
        priority = max(0.0, min(100.0, rng.gauss(prio_mean, 10.0)))
        size_kb  = round(rng.uniform(0.5, 4.0), 2)

        # Deadline: between 30 s and 5 min from now
        deadline = now + rng.uniform(30.0, 300.0)

        source = rng.choice(_SOURCE_NODES)
        payload = (
            f"{sensor_type}:{round(rng.uniform(10.0, 99.9), 2)}"
            f"@{source}"
        )

        pkt = Packet(
            packet_id      = f"pkt-{i:04d}-{uuid.uuid4().hex[:6]}",
            sensor_type    = sensor_type,
            payload        = payload,
            size_kb        = size_kb,
            priority       = round(priority, 2),
            deadline       = deadline,
            security_level = sec_level,
            source_node    = source,
            dest_node      = "cloud",
        )

        # Sign the packet with the shared secret
        sign_packet(pkt, config.hmac_secret)

        # Optionally tamper to simulate adversarial injection
        if rng.random() < tamper_fraction:
            pkt.payload = pkt.payload + "_TAMPERED"   # invalidates HMAC

        packets.append(pkt)

    return packets
