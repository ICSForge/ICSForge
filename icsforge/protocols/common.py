from __future__ import annotations
import random

__all__ = ["marker_bytes", "tcp_packet", "ether_frame"]

def marker_bytes(marker: str) -> bytes:
    """Return a deterministic marker payload for correlation and debugging."""
    if not marker:
        return b""
    if isinstance(marker, str):
        marker_b = marker.encode("utf-8", errors="ignore")
    else:
        marker_b = bytes(marker)
    return b"ICSFORGE:" + marker_b + b":"

def tcp_packet(src_ip: str, dst_ip: str, dport: int, payload: bytes):
    # Lazy import to avoid scapy initialization on hosts that only do live sending
    from scapy.all import IP, TCP, Raw
    return IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=dport, flags="PA") / Raw(payload)

def ether_frame(src_mac: str, dst_mac: str, ethertype: int, payload: bytes):
    from scapy.all import Ether, Raw
    return Ether(src=src_mac, dst=dst_mac, type=ethertype) / Raw(payload)
