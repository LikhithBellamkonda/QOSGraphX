# Combinatorics-Driven Graph Optimization for Secure & QoS-Aware Edge IoT Networks

A clean academic/production-grade Python implementation where IoT routing,
packet selection, congestion control, security and QoS are unified as a
**graph + combinatorial optimisation** problem.

---

## Architecture at a glance

| Concept | Implementation |
|---|---|
| IoT devices | Graph vertices |
| Wireless/wired links | Weighted directed edges (`EdgeMetrics`) |
| Packets | Weighted objects for combinatorial selection |
| Packet selection | 0/1 knapsack (DP) |
| Routing | Modified Dijkstra (trust-filtered) |
| Congestion control | Adaptive sliding window (AIMD) |
| Security | HMAC-SHA256 per-packet authentication |
| QoS | Score → MQTT QoS 0 / 1 / 2 mapping |

---

## File tree

```
edge_iot_graph_optimizer/
├── edge_iot_optimizer/
│   ├── __init__.py          # Package entry-point, re-exports core types
│   ├── models.py            # All dataclasses + MQTTQoS enum
│   ├── graph.py             # DynamicGraph + modified Dijkstra
│   ├── security.py          # HMAC-SHA256 signing & verification
│   ├── optimizer.py         # PacketSelector (scoring, knapsack, decide)
│   ├── scheduler.py         # AdaptiveWindow (AIMD) + PriorityScheduler
│   ├── simulator.py         # Demo 6-node graph + random packet generator
│   ├── config_loader.py     # JSON → OptimizationConfig loader
│   ├── main.py              # CLI runner (argparse)
│   └── mqtt_adapter.py      # Optional paho-mqtt bridge
├── tests/
│   ├── __init__.py
│   └── test_optimizer.py    # 40+ unit tests (no external deps needed)
├── config/
│   └── default_config.json  # Tuneable parameters
├── esp32/
│   └── esp32_mqtt_sensor.ino  # Arduino sketch for ESP32 sensor node
└── requirements.txt
```

---

## Data flow pipeline

```
ESP32 sensors / Simulator
        │
        ▼
[ security.sign_packet ]  ◄── HMAC-SHA256 with shared secret
        │
        ▼
[ optimizer.PacketSelector.decide ]
    ├── verify_packet()          — reject tampered/unsigned
    ├── graph.best_path()        — modified Dijkstra (trust-filtered)
    ├── packet_score()           — priority + urgency + security + compactness
    ├── _knapsack()              — 0/1 DP under bandwidth budget
    └── map_qos()                — score → MQTT QoS 0/1/2
        │
        ▼
[ scheduler.PriorityScheduler ]  ◄── AIMD window + heap ordering
        │
        ▼
[ mqtt_adapter.MQTTAdapter ]     ◄── publish to broker (optional)
        │
        ▼
    cloud / edge consumers
```

---

## Mathematical formulation

### Packet score
```
score = priority
      + urgency_weight  × max(0, remaining_time / horizon) × 100
      + sensitivity_weight × security_level × 100
      + compactness_weight / (size_kb + ε)
```

### Edge cost (path metric for Dijkstra)
```
cost_uv = w_lat   × (latency_ms / 500)
        + w_loss  × loss_rate
        + w_cong  × congestion
        + w_trust × (1 − trust)
        + w_bw    × (1 / bandwidth_kb)
```

### Knapsack optimisation
```
maximise   Σ score_i × x_i
subject to Σ size_i  × x_i ≤ bandwidth_budget_kb
           x_i ∈ {0, 1}
```

### AIMD congestion control
```
W_{t+1} = W_t + 1          (no congestion — additive increase)
W_{t+1} = W_t × 0.5        (congestion — multiplicative decrease)
```

### QoS mapping
```
score ≥ qos_2_threshold  →  QoS 2  (exactly once)
score ≥ qos_1_threshold  →  QoS 1  (at least once)
otherwise                →  QoS 0  (fire and forget)
```

---

## Quick start

### Install (core — no external libs needed)
```bash
cd edge_iot_graph_optimizer
python -m edge_iot_optimizer.main --packets 20
```

### With custom config
```bash
python -m edge_iot_optimizer.main --packets 30 --config config/default_config.json
```

### Reproducible run
```bash
python -m edge_iot_optimizer.main --packets 20 --seed 42
```

### Run all unit tests
```bash
python -m unittest discover -s tests -v
```

### MQTT support (optional)
```bash
pip install paho-mqtt
# then use MQTTAdapter in your own script or extend main.py
```

---

## Configuration (`config/default_config.json`)

| Key | Default | Description |
|---|---|---|
| `bandwidth_budget_kb` | 18 | Knapsack capacity per window (kB) |
| `window_size` | 8 | AIMD initial window size |
| `min_trust` | 0.45 | Minimum per-hop trust for routing |
| `latency_weight` | 0.35 | Dijkstra edge-cost weight |
| `loss_weight` | 0.20 | " |
| `congestion_weight` | 0.25 | " |
| `trust_weight` | 0.20 | " |
| `bandwidth_weight` | 0.10 | " |
| `qos_1_threshold` | 45.0 | Score floor for QoS 1 |
| `qos_2_threshold` | 70.0 | Score floor for QoS 2 |
| `hmac_secret` | `"demo-secret-change-me"` | **Change in production!** |
