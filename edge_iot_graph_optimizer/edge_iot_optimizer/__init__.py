"""
edge_iot_optimizer
==================

Combinatorics-Driven Graph Optimization for Secure & QoS-Aware Edge IoT Networks.

Modules
-------
models         — Core dataclasses (Packet, EdgeMetrics, OptimizationConfig, …).
graph          — Dynamic IoT graph + modified Dijkstra routing.
security       — HMAC-SHA256 packet signing and verification.
optimizer      — Packet scoring, QoS mapping and 0/1 knapsack selection.
scheduler      — AIMD congestion control and heap-based priority scheduling.
simulator      — Demo network builder and synthetic packet generator.
config_loader  — JSON → OptimizationConfig loader.
main           — Command-line demo runner.
mqtt_adapter   — Optional MQTT integration (requires paho-mqtt).
"""

from edge_iot_optimizer.models import (
    EdgeMetrics,
    MQTTQoS,
    OptimizationConfig,
    Packet,
    PacketDecision,
    PathDecision,
    TransmissionDecision,
)

__version__ = "1.0.0"
__all__ = [
    "EdgeMetrics",
    "MQTTQoS",
    "OptimizationConfig",
    "Packet",
    "PacketDecision",
    "PathDecision",
    "TransmissionDecision",
]
