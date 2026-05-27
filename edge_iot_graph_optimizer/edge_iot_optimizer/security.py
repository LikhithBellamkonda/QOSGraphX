"""
security.py — HMAC-SHA256 packet authentication.

Every packet that enters the optimisation pipeline must be signed by its
originating device.  The verifier rejects packets whose signature does not
match, preventing injection of forged or tampered sensor data.

Public API
----------
canonical_packet_data(packet)   → deterministic bytes representation
sign_packet(packet, secret)     → mutates packet.hmac_signature in-place
verify_packet(packet, secret)   → bool
payload_hash(payload)           → hex digest of the raw payload
"""

from __future__ import annotations

import hashlib
import hmac
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from edge_iot_optimizer.models import Packet


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def canonical_packet_data(packet: "Packet") -> bytes:
    """Return a stable, deterministic byte string that uniquely represents the
    packet's identity and content — **excluding** the signature field itself.

    The canonical form concatenates the most security-relevant fields with a
    ``|`` separator so that any tampering with packet_id, payload, priority,
    deadline, size or routing changes the HMAC tag.

    Parameters
    ----------
    packet : Packet
        The packet object to serialise.

    Returns
    -------
    bytes
        UTF-8 encoded canonical representation.
    """
    parts = [
        packet.packet_id,
        packet.sensor_type,
        packet.payload,
        f"{packet.size_kb:.6f}",
        f"{packet.priority:.6f}",
        f"{packet.deadline:.6f}",
        f"{packet.security_level:.6f}",
        packet.source_node,
        packet.dest_node,
    ]
    return "|".join(parts).encode("utf-8")


def payload_hash(payload: str) -> str:
    """Return the SHA-256 hex digest of a raw payload string.

    Useful for lightweight integrity checks when full HMAC is not needed
    (e.g., logging or quick deduplication).

    Parameters
    ----------
    payload : str
        Raw sensor payload.

    Returns
    -------
    str
        64-character lowercase hex digest.
    """
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Signing and verification
# ---------------------------------------------------------------------------

def sign_packet(packet: "Packet", secret: str) -> "Packet":
    """Compute and attach an HMAC-SHA256 signature to *packet*.

    The signature is derived from :func:`canonical_packet_data` using the
    provided *secret*.  The packet's ``hmac_signature`` field is updated
    **in-place** and the same object is returned for convenience.

    Parameters
    ----------
    packet : Packet
        The packet to sign.  ``hmac_signature`` will be overwritten.
    secret : str
        Shared HMAC key known to both the sender and the verifier.

    Returns
    -------
    Packet
        The same packet object with ``hmac_signature`` set.
    """
    key = secret.encode("utf-8")
    data = canonical_packet_data(packet)
    tag = hmac.new(key, data, hashlib.sha256).hexdigest()
    packet.hmac_signature = tag
    return packet


def verify_packet(packet: "Packet", secret: str) -> bool:
    """Verify that *packet*'s HMAC signature is authentic.

    Re-computes the expected signature from the packet fields and compares it
    with the stored ``hmac_signature`` using a constant-time comparison to
    prevent timing-oracle attacks.

    Parameters
    ----------
    packet : Packet
        The received packet (must already have ``hmac_signature`` set).
    secret : str
        Shared HMAC key.

    Returns
    -------
    bool
        ``True`` if the signature is valid; ``False`` otherwise.
    """
    if not packet.hmac_signature:
        return False

    key = secret.encode("utf-8")
    data = canonical_packet_data(packet)
    expected = hmac.new(key, data, hashlib.sha256).hexdigest()

    # hmac.compare_digest is constant-time — resist timing attacks
    return hmac.compare_digest(expected, packet.hmac_signature)
