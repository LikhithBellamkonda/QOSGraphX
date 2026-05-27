"""
mqtt_adapter.py — Optional MQTT integration layer.

This module wraps ``paho-mqtt`` so the optimizer can receive raw sensor
packets from a broker and publish routing decisions back.  Because
``paho-mqtt`` is an optional dependency (the core pipeline runs without it),
any attempt to instantiate :class:`MQTTAdapter` when the library is not
installed raises a clear :class:`RuntimeError` rather than an
``ImportError``.

Topics
------
* **Subscribe** ``iot/packets/#``  — incoming JSON-serialised :class:`~models.Packet`.
* **Publish**   ``iot/decisions``  — JSON-serialised :class:`~models.TransmissionDecision`.

Packet JSON schema (minimal)
----------------------------
::

    {
        "packet_id":      "pkt-0001",
        "sensor_type":    "temperature",
        "payload":        "temperature:23.5@esp32-a",
        "size_kb":        1.2,
        "priority":       70.0,
        "deadline":       1716000060.0,
        "security_level": 0.3,
        "hmac_signature": "abcdef...",
        "source_node":    "esp32-a",
        "dest_node":      "cloud"
    }
"""

from __future__ import annotations

import json
import logging
import time
from typing import Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from edge_iot_optimizer.models import OptimizationConfig, Packet, TransmissionDecision
    from edge_iot_optimizer.optimizer import PacketSelector

logger = logging.getLogger(__name__)


def _require_paho() -> None:
    """Raise RuntimeError if paho-mqtt is not installed."""
    try:
        import paho.mqtt.client  # noqa: F401
    except ImportError:
        raise RuntimeError(
            "paho-mqtt is required for MQTT support but is not installed.\n"
            "Install it with:  pip install paho-mqtt"
        )


class MQTTAdapter:
    """Bridge between an MQTT broker and the packet optimiser.

    Parameters
    ----------
    selector : PacketSelector
        The optimiser used to process incoming packets.
    config : OptimizationConfig
        Shared configuration (broker details, HMAC secret, etc.).
    broker_host : str
        MQTT broker hostname or IP address.
    broker_port : int
        MQTT broker port (default: 1883).
    subscribe_topic : str
        Topic pattern to subscribe to (default: ``"iot/packets/#"``).
    publish_topic : str
        Topic to publish decisions on (default: ``"iot/decisions"``).
    on_decision : callable, optional
        Optional callback invoked with the :class:`~models.TransmissionDecision`
        after each batch is processed.

    Raises
    ------
    RuntimeError
        If ``paho-mqtt`` is not installed.
    """

    def __init__(
        self,
        selector:        "PacketSelector",
        config:          "OptimizationConfig",
        broker_host:     str  = "localhost",
        broker_port:     int  = 1883,
        subscribe_topic: str  = "iot/packets/#",
        publish_topic:   str  = "iot/decisions",
        on_decision:     Callable[["TransmissionDecision"], None] | None = None,
    ) -> None:
        _require_paho()

        import paho.mqtt.client as mqtt  # type: ignore[import]

        self._selector        = selector
        self._config          = config
        self._broker_host     = broker_host
        self._broker_port     = broker_port
        self._subscribe_topic = subscribe_topic
        self._publish_topic   = publish_topic
        self._on_decision     = on_decision

        # Buffer incoming packets between broker messages
        self._pending: list["Packet"] = []

        self._client = mqtt.Client(client_id="edge-iot-optimizer")
        self._client.on_connect    = self._on_connect
        self._client.on_message    = self._on_message
        self._client.on_disconnect = self._on_disconnect

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Connect to the MQTT broker.

        Raises
        ------
        ConnectionRefusedError / OSError
            If the broker is unreachable.
        """
        logger.info(
            "Connecting to MQTT broker %s:%d",
            self._broker_host, self._broker_port,
        )
        self._client.connect(self._broker_host, self._broker_port, keepalive=60)

    def subscribe_packets(self, qos: int = 1) -> None:
        """Subscribe to the packet topic.

        Parameters
        ----------
        qos : int
            MQTT subscription QoS level (default: 1).
        """
        self._client.subscribe(self._subscribe_topic, qos=qos)
        logger.info("Subscribed to %s (QoS %d)", self._subscribe_topic, qos)

    def publish_decision(self, decision: "TransmissionDecision") -> None:
        """Serialise and publish a :class:`~models.TransmissionDecision`.

        The QoS level used for publishing is derived from the maximum QoS
        of all selected packets in the decision — ensuring the most critical
        data receives the strongest delivery guarantee.

        Parameters
        ----------
        decision : TransmissionDecision
        """
        # Determine the highest QoS among selected packets
        pd_map    = {d.packet_id: d for d in decision.packet_decisions if d.accepted}
        max_qos   = 0
        for d in pd_map.values():
            if d.qos > max_qos:
                max_qos = int(d.qos)

        payload = json.dumps({
            "timestamp":       time.time(),
            "selected_count":  len(decision.selected_packets),
            "total_size_kb":   decision.total_size_kb,
            "total_score":     decision.total_score,
            "rejected_count":  decision.rejected_count,
            "packets": [
                {
                    "packet_id":  pkt.packet_id,
                    "sensor_type": pkt.sensor_type,
                    "score":      pd_map[pkt.packet_id].score,
                    "qos":        int(pd_map[pkt.packet_id].qos),
                }
                for pkt in decision.selected_packets
                if pkt.packet_id in pd_map
            ],
        })

        self._client.publish(self._publish_topic, payload, qos=max_qos)
        logger.debug(
            "Published decision to %s (QoS %d, %d packets)",
            self._publish_topic, max_qos, len(decision.selected_packets),
        )

    def loop_forever(self) -> None:
        """Block and process MQTT events indefinitely.

        This calls ``paho``'s blocking ``loop_forever()`` which handles
        reconnections automatically.  Use :meth:`loop_start` /
        :meth:`loop_stop` for non-blocking operation.

        To exit cleanly, send a SIGINT (Ctrl-C).
        """
        logger.info("Entering MQTT event loop …")
        self._client.loop_forever()

    def loop_start(self) -> None:
        """Start the MQTT network loop in a background thread."""
        self._client.loop_start()

    def loop_stop(self) -> None:
        """Stop the background MQTT network thread."""
        self._client.loop_stop()
        self._client.disconnect()

    # ------------------------------------------------------------------
    # Internal callbacks
    # ------------------------------------------------------------------

    def _on_connect(self, client, userdata, flags, rc: int) -> None:  # noqa: ANN001
        if rc == 0:
            logger.info("MQTT connected (rc=0)")
            self.subscribe_packets()
        else:
            logger.error("MQTT connection refused (rc=%d)", rc)

    def _on_disconnect(self, client, userdata, rc: int) -> None:  # noqa: ANN001
        logger.warning("MQTT disconnected (rc=%d)", rc)

    def _on_message(self, client, userdata, msg) -> None:  # noqa: ANN001
        """Parse an incoming MQTT message into a :class:`~models.Packet`."""
        from edge_iot_optimizer.models import Packet  # local import avoids circular

        try:
            data = json.loads(msg.payload.decode("utf-8"))
            pkt  = Packet(
                packet_id      = data["packet_id"],
                sensor_type    = data["sensor_type"],
                payload        = data["payload"],
                size_kb        = float(data["size_kb"]),
                priority       = float(data["priority"]),
                deadline       = float(data["deadline"]),
                security_level = float(data.get("security_level", 0.5)),
                hmac_signature = data.get("hmac_signature", ""),
                source_node    = data.get("source_node", "esp32-a"),
                dest_node      = data.get("dest_node", "cloud"),
            )
            self._pending.append(pkt)

            # Process once we have a reasonable batch size
            batch_size = self._config.window_size
            if len(self._pending) >= batch_size:
                self._flush()

        except (KeyError, ValueError, json.JSONDecodeError) as exc:
            logger.warning("Dropped malformed MQTT message: %s", exc)

    def _flush(self) -> None:
        """Run the optimiser on the current pending batch and publish."""
        if not self._pending:
            return

        batch          = self._pending[:]
        self._pending  = []

        decision = self._selector.decide(batch)
        self.publish_decision(decision)

        if self._on_decision is not None:
            self._on_decision(decision)
