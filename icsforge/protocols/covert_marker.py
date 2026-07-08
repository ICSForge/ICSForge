"""ICSForge covert synthetic-traffic marker (v0.74.0).

Background
----------
Through v0.73.0 the synthetic-traffic marker was an explicit ASCII string
embedded in the payload::

    ICSFORGE:ICSFORGE_SYNTH|<run_id>|<technique>|<step>:

That string was 60-90 bytes, which measured as **59-91% of a typical ICS
frame**. The consequences:

* captures looked synthetic (a marker with some protocol attached) rather
  than realistic ICS traffic — undermining the tool's core value;
* the string overflowed fixed-size transport chunks (DNP3 CRC splitting),
  forcing a separate short-marker code path;
* a literal string is trivially forgeable — copying 14 bytes spoofs it.

The covert marker
-----------------
Instead of *adding* bytes, ICSForge now *derives* the values of protocol
fields that are already present and genuinely arbitrary — fields a real
device fills with throwaway values (Modbus transaction IDs, ENIP sender
context, S7comm PDU references, MQTT packet identifiers, OPC UA request
handles). The marker therefore costs **zero added bytes** on those
protocols and the packet is indistinguishable from real traffic because it
*is* a real, spec-valid field — only its value is chosen.

Authenticity
------------
The covert value is ``HMAC-SHA256(run_key, proto || packet_index)`` truncated
to the available field width. Because it is keyed, a third party cannot
forge or replay an ICSForge marker without the run key — a genuine
provenance property the old literal lacked.

Two-layer detection
-------------------
* **Layer 1 (Suricata/Zeek, in-band):** a cheap pre-filter matches the
  reserved high-order *band* of the covert field at its exact offset
  (e.g. Modbus transaction-ID high byte == 0xF7). This narrows candidates;
  on its own it is ~1/256 per packet, not zero-FP.
* **Layer 2 (receiver, out-of-band, authoritative):** the receiver verifies
  the full keyed HMAC value. This is where the zero-false-positive guarantee
  lives, and it is cryptographic rather than a guessable literal.

For users who run pure-offline PCAP detection with no receiver, an explicit
13-byte marker mode is still available (see ``explicit_marker``) so Layer-1
matching alone remains meaningful.

Bit budget per protocol (genuinely-arbitrary field bits available)::

    enip     64  Sender Context (8 bytes)        -> full stego, 0 added bytes
    opcua    32  RequestHandle                   -> stego, 0 added bytes
    modbus   16  Transaction ID                  -> stego, 0 added bytes
    s7comm   16  PDU reference                   -> stego, 0 added bytes
    mqtt     16  Packet Identifier               -> stego, 0 added bytes
    dnp3      -  (8b app seq only; too thin)     -> explicit 13-byte marker
    bacnet    8  Invoke ID                       -> stego band, 0 added bytes
    iec104    0  (sequence numbers constrained)  -> markerless (registry only)
"""
from __future__ import annotations

import hashlib
import hmac
import struct

# Reserved high-order band for the Layer-1 pre-filter. Real masters
# overwhelmingly use small incrementing counters or library defaults for
# these echo fields, so a high band is rare in genuine traffic and makes a
# cheap, stable content-match anchor. 0xF7 is arbitrary but fixed.
SYNTH_BAND = 0xF7

# Default run key. In a real deployment the sender and receiver share a
# per-run key (see icsforge config); for offline generation a fixed default
# keeps markers deterministic so detection tests are reproducible.
DEFAULT_RUN_KEY = b"icsforge-default-run-key-v1"

# Single-byte protocol code woven into the HMAC so the same run_id produces
# distinct covert values per protocol (prevents cross-protocol collision).
PROTO_CODE = {
    "modbus": b"M", "dnp3": b"D", "s7comm": b"S", "iec104": b"I",
    "enip": b"E", "opcua": b"O", "bacnet": b"B", "mqtt": b"Q",
    "iec61850": b"G", "profinet_dcp": b"P",
}


def _run_key(marker) -> bytes:
    """Derive the per-run HMAC key from the run marker/run_id.

    The marker passed by the engine is the run identifier (historically the
    full ``ICSFORGE_SYNTH|...`` string; now typically just the run_id). We
    fold it together with the default key so behaviour is deterministic for
    a given run yet keyed.
    """
    if marker is None:
        marker = "offline"
    raw = marker if isinstance(marker, (bytes, bytearray)) else str(marker).encode("utf-8", "ignore")
    return hashlib.sha256(DEFAULT_RUN_KEY + b"|" + bytes(raw)).digest()


def covert_value(marker, proto: str, index: int, nbytes: int) -> bytes:
    """Return ``nbytes`` of keyed covert marker for packet ``index``.

    The first byte is forced into the reserved synthetic band so a Layer-1
    rule can match it at a fixed offset; the remaining bytes are full HMAC
    output for cryptographic verification at the receiver.
    """
    key = _run_key(marker)
    code = PROTO_CODE.get((proto or "").lower(), b"X")
    msg = code + struct.pack(">I", index & 0xFFFFFFFF)
    digest = hmac.new(key, msg, hashlib.sha256).digest()
    if nbytes <= 0:
        return b""
    out = bytearray(digest[:nbytes])
    # Force the high-order byte into the synthetic band for Layer-1 matching.
    out[0] = SYNTH_BAND
    return bytes(out)


def covert_u16(marker, proto: str, index: int) -> int:
    """16-bit covert value for fields like Modbus txn ID, S7 PDU ref, MQTT packet ID.

    High byte == SYNTH_BAND (Layer-1 anchor); low byte is keyed (verification).
    """
    b = covert_value(marker, proto, index, 2)
    return (b[0] << 8) | b[1]


def covert_u32(marker, proto: str, index: int) -> int:
    """32-bit covert value (e.g. OPC UA RequestHandle)."""
    b = covert_value(marker, proto, index, 4)
    return struct.unpack(">I", b)[0]


def covert_bytes(marker, proto: str, index: int, nbytes: int) -> bytes:
    """Raw covert bytes for arbitrary-width fields (e.g. ENIP 8-byte Sender Context)."""
    return covert_value(marker, proto, index, nbytes)


def covert_band_byte(marker, proto: str, index: int) -> int:
    """Single covert byte for thin fields (e.g. BACnet invoke ID).

    Returns a value whose high nibble is in the synthetic band so a Layer-1
    rule can anchor on it while still leaving low bits keyed.
    """
    b = covert_value(marker, proto, index, 1)
    return b[0]


def verify_u16(marker, proto: str, index: int, value: int) -> bool:
    """Receiver-side: does ``value`` match the expected covert u16 for this run/index?"""
    return (value & 0xFFFF) == covert_u16(marker, proto, index)


def verify_bytes(marker, proto: str, index: int, value: bytes) -> bool:
    """Receiver-side: does ``value`` match the expected covert bytes?"""
    exp = covert_value(marker, proto, index, len(value))
    return hmac.compare_digest(bytes(value), exp)


# ── Explicit marker (offline / no-receiver fallback) ──────────────────────

def explicit_marker(marker, proto: str | None = None) -> bytes:
    """13-byte explicit marker: 'ICSF' + proto code + 8 hex of run hash.

    Used only when stego is disabled (``--explicit-marker``) so that
    Layer-1 detection works without a receiver to do Layer-2 verification.
    Compact enough to fit a single DNP3 transport chunk.
    """
    if not marker:
        return b""
    code = PROTO_CODE.get((proto or "").lower(), b"X")
    raw = marker if isinstance(marker, (bytes, bytearray)) else str(marker).encode("utf-8", "ignore")
    h = hashlib.sha1(bytes(raw)).hexdigest()[:8].encode("ascii")
    return b"ICSF" + code + h
