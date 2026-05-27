"""
scheduler.py — Congestion control and priority-aware packet scheduling.

Two classes are provided:

* :class:`AdaptiveWindow` — Additive-Increase / Multiplicative-Decrease
  (AIMD) sliding-window congestion controller.  This mirrors TCP's congestion
  avoidance behaviour at the IoT gateway layer.

* :class:`PriorityScheduler` — A min-heap scheduler that orders packets by
  their composite score (highest first) so that the most valuable data is
  always transmitted first when the window allows it.

AIMD formula
------------
.. math::

    W_{t+1} = \\begin{cases}
        W_t + 1        & \\text{if no congestion (additive increase)} \\\\
        W_t \\times \\beta & \\text{if congestion detected (multiplicative decrease)}
    \\end{cases}

where :math:`\\beta = 0.5` (halving on congestion, as in standard TCP).
"""

from __future__ import annotations

import heapq
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from edge_iot_optimizer.models import Packet, PacketDecision


_AIMD_BETA = 0.5      # multiplicative decrease factor (TCP default)
_MIN_WINDOW = 1       # floor to avoid zero window
_MAX_WINDOW = 64      # ceiling to prevent unbounded growth


class AdaptiveWindow:
    """AIMD sliding-window congestion controller.

    Tracks the current transmission window size and adjusts it based on
    observed ACK / loss feedback from the network layer.

    Parameters
    ----------
    initial_size : int
        Starting window size (number of packets).  Defaults to
        ``config.window_size`` when constructed via :class:`PriorityScheduler`.
    """

    def __init__(self, initial_size: int = 8) -> None:
        self._window: float = float(max(_MIN_WINDOW, initial_size))

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @property
    def window_size(self) -> int:
        """Current window size (floored to int)."""
        return int(self._window)

    def on_ack(self) -> None:
        """Signal a successful delivery — additive increase.

        Increases the window by exactly 1 (additive increase phase), up to
        :data:`_MAX_WINDOW`.
        """
        self._window = min(self._window + 1.0, float(_MAX_WINDOW))

    def on_loss(self) -> None:
        """Signal packet loss or congestion — multiplicative decrease.

        Halves the window (multiplicative decrease phase), floored at
        :data:`_MIN_WINDOW`.
        """
        self._window = max(self._window * _AIMD_BETA, float(_MIN_WINDOW))

    def on_congestion(self, level: float) -> None:
        """Proportional reduction based on observed congestion level.

        Unlike :meth:`on_loss` (which always halves), this allows the window
        to shrink proportionally to how congested the network is.

        Parameters
        ----------
        level : float
            Congestion level on [0, 1].  At 0 → no change; at 1 → full
            multiplicative decrease.
        """
        factor = 1.0 - level * (1.0 - _AIMD_BETA)
        self._window = max(self._window * factor, float(_MIN_WINDOW))

    def can_send(self, queue_depth: int) -> bool:
        """Return ``True`` if *queue_depth* is within the current window."""
        return queue_depth < self.window_size

    def __repr__(self) -> str:  # pragma: no cover
        return f"AdaptiveWindow(window={self.window_size})"


# ---------------------------------------------------------------------------
# Priority scheduler
# ---------------------------------------------------------------------------

class PriorityScheduler:
    """Heap-based scheduler that dispatches the highest-score packets first.

    Internally wraps a *min-heap* of ``(-score, sequence, packet)`` tuples.
    Negating the score converts the min-heap into an effective max-heap for
    priority ordering.  A monotonic *sequence* counter breaks ties so that
    ``heapq`` never has to compare ``Packet`` objects directly.

    Parameters
    ----------
    window : AdaptiveWindow
        Congestion controller that limits how many packets are in-flight.
    """

    def __init__(self, window: AdaptiveWindow) -> None:
        self.window   = window
        self._heap:   list[tuple[float, int, "Packet"]] = []
        self._seq:    int = 0       # monotonic tie-breaker

    # ------------------------------------------------------------------
    # Queue management
    # ------------------------------------------------------------------

    def push(self, packet: "Packet", score: float) -> None:
        """Enqueue *packet* with the given *score*.

        Parameters
        ----------
        packet : Packet
            Packet to schedule.
        score : float
            Composite score from :meth:`~optimizer.PacketSelector.packet_score`.
        """
        heapq.heappush(self._heap, (-score, self._seq, packet))
        self._seq += 1

    def push_all(
        self,
        packets: list["Packet"],
        decisions: list["PacketDecision"],
    ) -> None:
        """Bulk-enqueue *packets* using scores from *decisions*.

        Only packets whose ``accepted`` flag is ``True`` in *decisions* are
        enqueued; rejected packets are silently skipped.

        Parameters
        ----------
        packets   : list of Packet
        decisions : list of PacketDecision
            Must be in 1-to-1 correspondence with *packets*.
        """
        score_map = {d.packet_id: d.score for d in decisions if d.accepted}
        for pkt in packets:
            if pkt.packet_id in score_map:
                self.push(pkt, score_map[pkt.packet_id])

    def pop(self) -> "Packet":
        """Remove and return the highest-score packet.

        Raises
        ------
        IndexError
            If the queue is empty.
        """
        _, _, pkt = heapq.heappop(self._heap)
        return pkt

    def peek_score(self) -> float:
        """Return the score of the highest-priority packet without removing it.

        Returns ``0.0`` if the queue is empty.
        """
        if not self._heap:
            return 0.0
        return -self._heap[0][0]

    # ------------------------------------------------------------------
    # Window-aware dispatch
    # ------------------------------------------------------------------

    def drain(self, max_packets: int | None = None) -> list["Packet"]:
        """Drain packets up to the current window size.

        Parameters
        ----------
        max_packets : int, optional
            Hard cap on the number of packets returned.  Defaults to
            ``self.window.window_size``.

        Returns
        -------
        list of Packet
            Ordered from highest to lowest priority.
        """
        limit = min(
            max_packets if max_packets is not None else _MAX_WINDOW,
            self.window.window_size,
        )
        result: list["Packet"] = []
        while self._heap and len(result) < limit:
            result.append(self.pop())
        return result

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def queue_depth(self) -> int:
        """Number of packets currently queued."""
        return len(self._heap)

    def is_empty(self) -> bool:
        """Return ``True`` if no packets are queued."""
        return len(self._heap) == 0

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"PriorityScheduler(queued={self.queue_depth}, "
            f"window={self.window.window_size})"
        )
