"""
main.py — Command-line demo runner for the Edge IoT Optimizer.

Usage
-----
::

    # Run with 20 random packets, default config:
    python -m edge_iot_optimizer.main --packets 20

    # Use a custom config file:
    python -m edge_iot_optimizer.main --packets 30 --config config/default_config.json

    # Reproducible run with a fixed seed:
    python -m edge_iot_optimizer.main --packets 20 --seed 42
"""

from __future__ import annotations

import argparse
import sys

from edge_iot_optimizer.config_loader import default_config, load_config
from edge_iot_optimizer.graph import DynamicGraph
from edge_iot_optimizer.optimizer import PacketSelector
from edge_iot_optimizer.scheduler import AdaptiveWindow, PriorityScheduler
from edge_iot_optimizer.simulator import build_demo_graph, generate_packets


# ---------------------------------------------------------------------------
# Pretty-printing helpers
# ---------------------------------------------------------------------------

_SEP = "─" * 72


def _header(title: str) -> None:
    print(f"\n{_SEP}")
    print(f"  {title}")
    print(_SEP)


def _print_summary(decision, scheduler: PriorityScheduler) -> None:
    """Print the full optimisation result to stdout."""

    # Build lookup maps for quick access
    pd_map   = {d.packet_id: d for d in decision.packet_decisions}
    path_map = {d.packet_id: d for d in decision.path_decisions}

    _header("OPTIMISATION RESULT — SELECTED PACKETS")
    print(
        f"  Selected : {len(decision.selected_packets):>3} packets"
        f"   ({decision.total_size_kb:.2f} kB)"
    )
    print(f"  Rejected : {decision.rejected_count:>3} packets")
    print(f"  Total score : {decision.total_score:.2f}\n")

    fmt = "{:<18}  {:<14}  {:>7}  {:>5}  {:<40}"
    print(fmt.format("Packet ID", "Sensor", "Score", "QoS", "Path"))
    print("  " + "·" * 70)

    for pkt in decision.selected_packets:
        pd   = pd_map.get(pkt.packet_id)
        path = path_map.get(pkt.packet_id)
        score_str = f"{pd.score:.2f}"  if pd   else "—"
        qos_str   = f"QoS {pd.qos}"   if pd   else "—"
        path_str  = " → ".join(path.path) if path and path.found else "no path"
        print(fmt.format(
            pkt.packet_id[:18],
            pkt.sensor_type,
            score_str,
            qos_str,
            path_str,
        ))

    _header("SCHEDULER STATE")
    print(f"  Window size : {scheduler.window.window_size}")
    print(f"  Queue depth : {scheduler.queue_depth}")

    _header("REJECTION DETAILS")
    rejected = [d for d in decision.packet_decisions if not d.accepted]
    if not rejected:
        print("  No rejections.")
    else:
        for d in rejected:
            print(f"  {d.packet_id:<20}  {d.reason}")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog        = "edge_iot_optimizer",
        description = (
            "Combinatorics-Driven Graph Optimization "
            "for Secure & QoS-Aware Edge IoT Networks"
        ),
    )
    parser.add_argument(
        "--packets",
        type    = int,
        default = 20,
        metavar = "N",
        help    = "Number of synthetic packets to generate (default: 20).",
    )
    parser.add_argument(
        "--config",
        type    = str,
        default = None,
        metavar = "PATH",
        help    = "Path to JSON config file.  Uses built-in defaults if omitted.",
    )
    parser.add_argument(
        "--seed",
        type    = int,
        default = None,
        metavar = "SEED",
        help    = "Random seed for reproducible packet generation.",
    )

    args = parser.parse_args(argv)

    # 1. Load configuration
    if args.config:
        try:
            config = load_config(args.config)
            print(f"[config] Loaded from {args.config}")
        except FileNotFoundError as exc:
            print(f"[error] {exc}", file=sys.stderr)
            return 1
    else:
        config = default_config()
        print("[config] Using built-in defaults")

    # 2. Build network graph
    graph = build_demo_graph(config)
    print(f"[graph]  Nodes: {', '.join(sorted(graph.nodes()))}")

    # 3. Generate synthetic packets
    packets = generate_packets(args.packets, config, seed=args.seed)
    print(f"[sim]    Generated {len(packets)} packets")

    # 4. Run optimiser
    selector = PacketSelector(graph, config)
    decision = selector.decide(packets)

    # 5. Schedule selected packets
    window    = AdaptiveWindow(config.window_size)
    scheduler = PriorityScheduler(window)
    scheduler.push_all(decision.selected_packets, decision.packet_decisions)

    # Simulate simple ACK / loss feedback based on average congestion
    avg_congestion = 0.15  # demo: assume mild congestion
    if avg_congestion > 0.5:
        window.on_loss()
    else:
        window.on_ack()

    # 6. Print report
    _print_summary(decision, scheduler)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
