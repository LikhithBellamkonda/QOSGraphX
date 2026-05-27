"""
tests/test_optimizer.py — Unit tests for the Edge IoT Optimizer pipeline.

Run with:
    python -m unittest discover -s tests

No external dependencies (paho-mqtt, networkx, etc.) are required.
"""

from __future__ import annotations

import math
import time
import unittest

from edge_iot_optimizer.graph import DynamicGraph
from edge_iot_optimizer.models import (
    EdgeMetrics,
    MQTTQoS,
    OptimizationConfig,
    Packet,
)
from edge_iot_optimizer.optimizer import PacketSelector
from edge_iot_optimizer.scheduler import AdaptiveWindow, PriorityScheduler
from edge_iot_optimizer.security import (
    canonical_packet_data,
    payload_hash,
    sign_packet,
    verify_packet,
)
from edge_iot_optimizer.simulator import build_demo_graph, generate_packets


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_packet(
    packet_id:      str   = "pkt-test-001",
    sensor_type:    str   = "temperature",
    payload:        str   = "temperature:25.0@esp32-a",
    size_kb:        float = 1.5,
    priority:       float = 70.0,
    deadline_delta: float = 120.0,  # seconds from now
    security_level: float = 0.5,
    source_node:    str   = "esp32-a",
    dest_node:      str   = "cloud",
) -> Packet:
    return Packet(
        packet_id      = packet_id,
        sensor_type    = sensor_type,
        payload        = payload,
        size_kb        = size_kb,
        priority       = priority,
        deadline       = time.time() + deadline_delta,
        security_level = security_level,
        source_node    = source_node,
        dest_node      = dest_node,
    )


def _default_config(**overrides) -> OptimizationConfig:
    kwargs = dict(
        bandwidth_budget_kb = 18.0,
        window_size         = 8,
        min_trust           = 0.45,
        hmac_secret         = "test-secret",
        qos_1_threshold     = 45.0,
        qos_2_threshold     = 70.0,
    )
    kwargs.update(overrides)
    return OptimizationConfig(**kwargs)


def _small_graph(config: OptimizationConfig) -> DynamicGraph:
    """Build a minimal 3-node graph: src → mid → dst."""
    g = DynamicGraph(config)
    g.add_edge(EdgeMetrics("src", "mid", 10.0, 100.0, 0.01, 0.05, 0.90))
    g.add_edge(EdgeMetrics("mid", "dst",  8.0, 120.0, 0.01, 0.05, 0.95))
    return g


# ---------------------------------------------------------------------------
# 1. HMAC Security Tests
# ---------------------------------------------------------------------------

class TestHMACSecurity(unittest.TestCase):
    """Tests for HMAC-SHA256 signing and verification."""

    SECRET = "unit-test-secret"

    def _signed_packet(self, **kwargs) -> Packet:
        pkt = _make_packet(**kwargs)
        return sign_packet(pkt, self.SECRET)

    # --- canonical_packet_data ---

    def test_canonical_data_is_bytes(self):
        pkt = _make_packet()
        data = canonical_packet_data(pkt)
        self.assertIsInstance(data, bytes)

    def test_canonical_data_contains_packet_id(self):
        pkt = _make_packet(packet_id="unique-xyz")
        data = canonical_packet_data(pkt).decode()
        self.assertIn("unique-xyz", data)

    def test_canonical_data_excludes_signature(self):
        """Signature field must NOT be part of the canonical data."""
        pkt       = _make_packet()
        pkt.hmac_signature = "some-signature"
        data = canonical_packet_data(pkt).decode()
        self.assertNotIn("some-signature", data)

    def test_canonical_data_deterministic(self):
        """Same packet → identical canonical bytes."""
        pkt = _make_packet()
        self.assertEqual(
            canonical_packet_data(pkt),
            canonical_packet_data(pkt),
        )

    def test_different_payloads_give_different_canonical(self):
        p1 = _make_packet(payload="val:1")
        p2 = _make_packet(payload="val:2")
        self.assertNotEqual(canonical_packet_data(p1), canonical_packet_data(p2))

    # --- sign_packet ---

    def test_sign_sets_hmac_signature(self):
        pkt = _make_packet()
        self.assertEqual(pkt.hmac_signature, "")
        sign_packet(pkt, self.SECRET)
        self.assertNotEqual(pkt.hmac_signature, "")

    def test_sign_returns_same_object(self):
        pkt = _make_packet()
        result = sign_packet(pkt, self.SECRET)
        self.assertIs(result, pkt)

    def test_sign_is_hex_string(self):
        pkt = self._signed_packet()
        # SHA-256 hex digest = 64 chars
        self.assertEqual(len(pkt.hmac_signature), 64)
        int(pkt.hmac_signature, 16)  # must be valid hex

    # --- verify_packet ---

    def test_verify_accepts_correctly_signed_packet(self):
        pkt = self._signed_packet()
        self.assertTrue(verify_packet(pkt, self.SECRET))

    def test_verify_rejects_tampered_payload(self):
        pkt = self._signed_packet()
        pkt.payload += "_TAMPERED"
        self.assertFalse(verify_packet(pkt, self.SECRET))

    def test_verify_rejects_wrong_secret(self):
        pkt = self._signed_packet()
        self.assertFalse(verify_packet(pkt, "wrong-secret"))

    def test_verify_rejects_empty_signature(self):
        pkt = _make_packet()  # not signed
        self.assertFalse(verify_packet(pkt, self.SECRET))

    def test_verify_rejects_tampered_priority(self):
        pkt = self._signed_packet(priority=50.0)
        pkt.priority = 99.9  # tamper
        self.assertFalse(verify_packet(pkt, self.SECRET))

    def test_verify_rejects_tampered_packet_id(self):
        pkt = self._signed_packet()
        pkt.packet_id = "fake-id"
        self.assertFalse(verify_packet(pkt, self.SECRET))

    def test_different_secrets_produce_different_signatures(self):
        p1 = _make_packet()
        p2 = _make_packet()
        sign_packet(p1, "secret-A")
        sign_packet(p2, "secret-B")
        self.assertNotEqual(p1.hmac_signature, p2.hmac_signature)

    # --- payload_hash ---

    def test_payload_hash_returns_64_char_hex(self):
        h = payload_hash("test data")
        self.assertEqual(len(h), 64)
        int(h, 16)

    def test_payload_hash_deterministic(self):
        self.assertEqual(payload_hash("abc"), payload_hash("abc"))

    def test_payload_hash_different_inputs(self):
        self.assertNotEqual(payload_hash("abc"), payload_hash("xyz"))


# ---------------------------------------------------------------------------
# 2. Modified Dijkstra / Graph Tests
# ---------------------------------------------------------------------------

class TestDynamicGraph(unittest.TestCase):
    """Tests for the DynamicGraph and modified Dijkstra router."""

    def setUp(self):
        self.config = _default_config()
        self.graph  = _small_graph(self.config)

    def test_nodes_registered(self):
        nodes = self.graph.nodes()
        self.assertIn("src", nodes)
        self.assertIn("mid", nodes)
        self.assertIn("dst", nodes)

    def test_simple_path_found(self):
        path, cost, min_trust = self.graph.best_path("src", "dst")
        self.assertEqual(path, ["src", "mid", "dst"])
        self.assertGreater(cost, 0)
        self.assertGreater(min_trust, 0)
        self.assertLessEqual(min_trust, 1.0)

    def test_trivial_path_same_node(self):
        path, cost, min_trust = self.graph.best_path("src", "src")
        self.assertEqual(path, ["src"])
        self.assertEqual(cost, 0.0)
        self.assertEqual(min_trust, 1.0)

    def test_unknown_source_returns_empty(self):
        path, cost, _ = self.graph.best_path("unknown", "dst")
        self.assertEqual(path, [])
        self.assertEqual(cost, math.inf)

    def test_unknown_dest_returns_empty(self):
        path, cost, _ = self.graph.best_path("src", "nowhere")
        self.assertEqual(path, [])
        self.assertEqual(cost, math.inf)

    def test_trust_filter_blocks_low_trust_edge(self):
        """Setting min_trust above edge trust should block the path."""
        config = _default_config(min_trust=0.99)  # very strict
        g = DynamicGraph(config)
        # Edge with trust=0.5 — below 0.99 threshold
        g.add_edge(EdgeMetrics("A", "B", 10.0, 100.0, 0.0, 0.0, 0.50))
        path, cost, _ = g.best_path("A", "B", min_trust=0.99)
        self.assertEqual(path, [])
        self.assertEqual(cost, math.inf)

    def test_trust_filter_passes_high_trust_edge(self):
        config = _default_config(min_trust=0.45)
        g = DynamicGraph(config)
        g.add_edge(EdgeMetrics("A", "B", 10.0, 100.0, 0.01, 0.05, 0.95))
        path, cost, _ = g.best_path("A", "B", min_trust=0.45)
        self.assertEqual(path, ["A", "B"])

    def test_prefers_lower_cost_path(self):
        """Dijkstra should pick the cheaper path when alternatives exist."""
        config = _default_config()
        g = DynamicGraph(config)
        # Direct path: high latency
        g.add_edge(EdgeMetrics("S", "D", 200.0, 10.0, 0.1, 0.5, 0.9))
        # Two-hop path: much lower cost
        g.add_edge(EdgeMetrics("S", "M",   5.0, 200.0, 0.0, 0.0, 0.99))
        g.add_edge(EdgeMetrics("M", "D",   5.0, 200.0, 0.0, 0.0, 0.99))
        path, _, _ = g.best_path("S", "D")
        self.assertEqual(path, ["S", "M", "D"])

    def test_edge_cost_non_negative(self):
        edge = EdgeMetrics("a", "b", 50.0, 100.0, 0.05, 0.10, 0.90)
        cost = self.graph.edge_cost(edge)
        self.assertGreaterEqual(cost, 0.0)

    def test_update_congestion(self):
        config = _default_config()
        g = DynamicGraph(config)
        g.add_edge(EdgeMetrics("X", "Y", 10.0, 100.0, 0.01, 0.10, 0.90))
        g.update_congestion("X", "Y", 0.80)
        edge = g.edges_from("X")[0]
        self.assertAlmostEqual(edge.congestion, 0.80)

    def test_demo_graph_all_nodes_reachable(self):
        config = _default_config()
        g      = build_demo_graph(config)
        for source in ["esp32-a", "esp32-b", "esp32-c"]:
            path, cost, _ = g.best_path(source, "cloud")
            self.assertTrue(path, f"No path from {source} to cloud")
            self.assertLess(cost, math.inf)


# ---------------------------------------------------------------------------
# 3. Knapsack / Packet Selection Tests
# ---------------------------------------------------------------------------

class TestKnapsackSelection(unittest.TestCase):
    """Tests for packet scoring, QoS mapping and knapsack selection."""

    def setUp(self):
        self.config   = _default_config()
        self.graph    = build_demo_graph(self.config)
        self.selector = PacketSelector(self.graph, self.config)

    def _signed(self, **kwargs) -> Packet:
        pkt = _make_packet(**kwargs)
        return sign_packet(pkt, self.config.hmac_secret)

    # --- packet_score ---

    def test_score_is_non_negative(self):
        pkt   = _make_packet()
        score = self.selector.packet_score(pkt)
        self.assertGreaterEqual(score, 0.0)

    def test_higher_priority_gives_higher_score(self):
        low_prio  = self.selector.packet_score(_make_packet(priority=10.0))
        high_prio = self.selector.packet_score(_make_packet(priority=90.0))
        self.assertGreater(high_prio, low_prio)

    def test_higher_security_level_gives_higher_score(self):
        low_sec  = self.selector.packet_score(_make_packet(security_level=0.1))
        high_sec = self.selector.packet_score(_make_packet(security_level=0.9))
        self.assertGreater(high_sec, low_sec)

    def test_expired_deadline_reduces_urgency(self):
        near_deadline = self.selector.packet_score(
            _make_packet(deadline_delta=10.0)
        )
        past_deadline = self.selector.packet_score(
            _make_packet(deadline_delta=-100.0)   # already expired
        )
        self.assertGreater(near_deadline, past_deadline)

    # --- map_qos ---

    def test_map_qos_2_for_high_score(self):
        qos = self.selector.map_qos(self.config.qos_2_threshold + 1)
        self.assertEqual(qos, MQTTQoS.EXACTLY_ONCE)

    def test_map_qos_1_for_medium_score(self):
        score = (self.config.qos_1_threshold + self.config.qos_2_threshold) / 2
        qos   = self.selector.map_qos(score)
        self.assertEqual(qos, MQTTQoS.AT_LEAST_ONCE)

    def test_map_qos_0_for_low_score(self):
        qos = self.selector.map_qos(self.config.qos_1_threshold - 1)
        self.assertEqual(qos, MQTTQoS.AT_MOST_ONCE)

    def test_map_qos_boundary_exactly_qos2_threshold(self):
        qos = self.selector.map_qos(self.config.qos_2_threshold)
        self.assertEqual(qos, MQTTQoS.EXACTLY_ONCE)

    # --- _knapsack ---

    def test_knapsack_empty_input(self):
        result = self.selector._knapsack([], [], 10.0)
        self.assertEqual(result, [])

    def test_knapsack_selects_best_items(self):
        """Given capacity for 2 items, should pick the two highest scores."""
        pkts   = [_make_packet(packet_id=f"p{i}", size_kb=1.0) for i in range(4)]
        scores = [10.0, 50.0, 30.0, 80.0]
        result = self.selector._knapsack(pkts, scores, capacity=2.0)
        # Indices 1 and 3 (scores 50 and 80) should be selected
        self.assertIn(1, result)
        self.assertIn(3, result)
        self.assertEqual(len(result), 2)

    def test_knapsack_respects_capacity(self):
        pkts   = [_make_packet(packet_id=f"p{i}", size_kb=5.0) for i in range(5)]
        scores = [100.0] * 5
        result = self.selector._knapsack(pkts, scores, capacity=10.0)
        total_size = sum(pkts[i].size_kb for i in result)
        self.assertLessEqual(total_size, 10.0)

    def test_knapsack_zero_capacity_selects_nothing(self):
        pkts   = [_make_packet(size_kb=1.0)]
        scores = [100.0]
        result = self.selector._knapsack(pkts, scores, capacity=0.0)
        self.assertEqual(result, [])

    def test_knapsack_all_fit_within_budget(self):
        """If all items fit, all should be selected."""
        pkts   = [_make_packet(packet_id=f"p{i}", size_kb=1.0) for i in range(3)]
        scores = [10.0, 20.0, 30.0]
        result = self.selector._knapsack(pkts, scores, capacity=5.0)
        self.assertEqual(sorted(result), [0, 1, 2])

    # --- decide (full pipeline) ---

    def test_decide_rejects_unsigned_packets(self):
        pkt      = _make_packet()   # not signed
        decision = self.selector.decide([pkt])
        rejected = [d for d in decision.packet_decisions if not d.accepted]
        self.assertTrue(any(d.packet_id == pkt.packet_id for d in rejected))
        self.assertEqual(decision.rejected_count, 1)

    def test_decide_rejects_tampered_packets(self):
        pkt = self._signed()
        pkt.payload += "_TAMPERED"  # invalidate HMAC
        decision = self.selector.decide([pkt])
        self.assertEqual(decision.rejected_count, 1)

    def test_decide_accepts_valid_signed_packets(self):
        packets  = [self._signed(packet_id=f"pkt-{i}") for i in range(5)]
        decision = self.selector.decide(packets)
        self.assertGreater(len(decision.selected_packets), 0)

    def test_decide_total_size_within_budget(self):
        packets  = [self._signed(packet_id=f"pkt-{i}") for i in range(10)]
        decision = self.selector.decide(packets)
        self.assertLessEqual(
            decision.total_size_kb,
            self.config.bandwidth_budget_kb + 0.5,   # small floating-point slack
        )

    def test_decide_empty_input_returns_empty_decision(self):
        decision = self.selector.decide([])
        self.assertEqual(decision.selected_packets, [])
        self.assertEqual(decision.total_size_kb, 0.0)
        self.assertEqual(decision.rejected_count, 0)

    def test_decide_mixed_valid_invalid(self):
        valid   = self._signed(packet_id="valid-001")
        invalid = _make_packet(packet_id="invalid-001")  # unsigned
        decision = self.selector.decide([valid, invalid])
        self.assertEqual(decision.rejected_count, 1)
        selected_ids = {p.packet_id for p in decision.selected_packets}
        self.assertIn("valid-001", selected_ids)

    def test_decide_path_decisions_recorded(self):
        pkt      = self._signed()
        decision = self.selector.decide([pkt])
        self.assertEqual(len(decision.path_decisions), 1)
        pd = decision.path_decisions[0]
        self.assertTrue(pd.found)
        self.assertGreater(len(pd.path), 0)

    def test_decide_packet_decisions_have_scores(self):
        packets  = [self._signed(packet_id=f"pkt-{i}") for i in range(3)]
        decision = self.selector.decide(packets)
        for d in decision.packet_decisions:
            if d.accepted:
                self.assertGreater(d.score, 0.0)

    def test_decide_with_simulator_packets(self):
        """End-to-end: simulator → signer → decide."""
        packets  = generate_packets(15, self.config, seed=99)
        decision = self.selector.decide(packets)
        # At least some should be accepted
        self.assertGreater(len(decision.selected_packets), 0)


# ---------------------------------------------------------------------------
# 4. Scheduler Tests
# ---------------------------------------------------------------------------

class TestScheduler(unittest.TestCase):
    """Tests for AdaptiveWindow and PriorityScheduler."""

    def test_adaptive_window_initial_size(self):
        w = AdaptiveWindow(initial_size=6)
        self.assertEqual(w.window_size, 6)

    def test_adaptive_window_ack_increases(self):
        w = AdaptiveWindow(initial_size=4)
        w.on_ack()
        self.assertEqual(w.window_size, 5)

    def test_adaptive_window_loss_halves(self):
        w = AdaptiveWindow(initial_size=8)
        w.on_loss()
        self.assertEqual(w.window_size, 4)

    def test_adaptive_window_floor_at_one(self):
        w = AdaptiveWindow(initial_size=1)
        w.on_loss()
        self.assertEqual(w.window_size, 1)

    def test_adaptive_window_ceiling(self):
        w = AdaptiveWindow(initial_size=64)
        w.on_ack()
        self.assertEqual(w.window_size, 64)  # already at ceiling

    def test_scheduler_push_and_pop(self):
        w  = AdaptiveWindow(8)
        ps = PriorityScheduler(w)
        pkt = _make_packet(packet_id="high-prio")
        ps.push(pkt, score=95.0)
        out = ps.pop()
        self.assertEqual(out.packet_id, "high-prio")

    def test_scheduler_orders_by_score(self):
        w  = AdaptiveWindow(8)
        ps = PriorityScheduler(w)
        for i, score in enumerate([10.0, 90.0, 50.0]):
            ps.push(_make_packet(packet_id=f"p{i}"), score)
        first  = ps.pop()
        second = ps.pop()
        self.assertEqual(first.packet_id,  "p1")   # score 90
        self.assertEqual(second.packet_id, "p2")   # score 50

    def test_scheduler_drain_respects_window(self):
        w  = AdaptiveWindow(initial_size=3)
        ps = PriorityScheduler(w)
        for i in range(10):
            ps.push(_make_packet(packet_id=f"p{i}"), float(i))
        drained = ps.drain()
        self.assertLessEqual(len(drained), 3)


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
