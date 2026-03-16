"""
ICSForge protocol common utilities — pure Python, zero scapy dependency.

tcp_packet()  → complete Ethernet+IP+TCP frame as raw bytes
ether_frame() → complete Ethernet II frame as raw bytes
marker_bytes()→ marker embedding helper
"""
import random
import socket
import struct

__all__ = ["marker_bytes", "tcp_packet", "udp_packet", "ether_frame"]

# ── Helpers ───────────────────────────────────────────────────────────

def _mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))

def _ip_csum(hdr: bytes) -> int:
    """One's-complement checksum over an even-length byte string."""
    if len(hdr) % 2:
        hdr += b"\x00"
    s = sum(struct.unpack(f">{len(hdr)//2}H", hdr))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def _tcp_csum(src_ip: str, dst_ip: str, tcp_seg: bytes) -> int:
    """TCP checksum over IPv4 pseudo-header + TCP segment."""
    pseudo = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack(">BBH", 0, 6, len(tcp_seg))
    )
    data = pseudo + tcp_seg
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f">{len(data)//2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

# ── Public API ────────────────────────────────────────────────────────

def marker_bytes(marker: str) -> bytes:
    """Return a deterministic marker payload for correlation."""
    if not marker:
        return b""
    mb = marker.encode("utf-8", errors="ignore") if isinstance(marker, str) else bytes(marker)
    return b"ICSFORGE:" + mb + b":"


def tcp_packet(src_ip: str, dst_ip: str, dport: int, payload: bytes) -> bytes:
    """
    Build a complete Ethernet II + IPv4 + TCP frame as raw bytes.

    MAC addressing:
      src 02:00:00:11:22:33  (synthetic sender, locally-administered)
      dst ff:ff:ff:ff:ff:ff  (broadcast; receiver ignores MAC layer)
    Ethernet type: 0x0800 (IPv4)
    IP + TCP checksums are computed correctly (Wireshark-valid).
    """
    rnd   = random.Random()
    sport = rnd.randint(1024, 65535)
    seq   = rnd.randint(0, 0xFFFF_FFFF)

    # ── TCP header (checksum placeholder = 0) ────────────────────
    # offset=5 (20 bytes header), flags PSH|ACK = 0x18
    tcp_hdr = struct.pack(">HHIIBBHHH",
        sport, dport,
        seq, 0,
        0x50, 0x18,
        8192, 0, 0,
    )
    tcp_seg  = tcp_hdr + payload
    tcp_c    = _tcp_csum(src_ip, dst_ip, tcp_seg)
    tcp_seg  = tcp_hdr[:16] + struct.pack(">H", tcp_c) + tcp_hdr[18:] + payload

    # ── IP header (checksum placeholder = 0) ─────────────────────
    total_len = 20 + len(tcp_seg)
    ip_hdr = struct.pack(">BBHHHBBH4s4s",
        0x45, 0,
        total_len,
        rnd.randint(0, 0xFFFF),
        0x4000,
        64, 6, 0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    ip_hdr = ip_hdr[:10] + struct.pack(">H", _ip_csum(ip_hdr)) + ip_hdr[12:]

    # ── Ethernet II frame ─────────────────────────────────────────
    eth   = _mac_bytes("ff:ff:ff:ff:ff:ff") + _mac_bytes("02:00:00:11:22:33") + struct.pack(">H", 0x0800)
    frame = eth + ip_hdr + tcp_seg
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))
    return frame


def ether_frame(src_mac: str, dst_mac: str, ethertype: int, payload: bytes) -> bytes:
    """Build a raw Ethernet II frame as bytes (no scapy)."""
    frame = _mac_bytes(dst_mac) + _mac_bytes(src_mac) + struct.pack(">H", ethertype) + payload
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))
    return frame


def udp_packet(src_ip: str, dst_ip: str, dport: int, payload: bytes, sport: int = 0) -> bytes:
    """
    Build a complete Ethernet II + IPv4 + UDP frame as raw bytes.

    Used for BACnet/IP (UDP 47808) and any future UDP-based protocols.
    IP + UDP checksums are computed correctly (Wireshark-valid).
    """
    rnd = random.Random()
    if sport == 0:
        sport = rnd.randint(49152, 65535)

    # ── UDP header ────────────────────────────────────────────────
    udp_len = 8 + len(payload)
    # Checksum placeholder, compute after pseudo-header
    udp_hdr = struct.pack(">HHHH", sport, dport, udp_len, 0)
    udp_seg = udp_hdr + payload

    # UDP checksum over pseudo-header + UDP segment
    pseudo = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack(">BBH", 0, 17, len(udp_seg))  # proto=17=UDP
    )
    csum_data = pseudo + udp_seg
    if len(csum_data) % 2:
        csum_data += b"\x00"
    s = sum(struct.unpack(f">{len(csum_data)//2}H", csum_data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    udp_csum = (~s) & 0xFFFF
    if udp_csum == 0:
        udp_csum = 0xFFFF  # UDP: 0 means "no checksum", use 0xFFFF instead
    udp_seg = udp_hdr[:6] + struct.pack(">H", udp_csum) + payload

    # ── IP header ─────────────────────────────────────────────────
    total_len = 20 + len(udp_seg)
    ip_hdr = struct.pack(">BBHHHBBH4s4s",
        0x45, 0,
        total_len,
        rnd.randint(0, 0xFFFF),
        0x4000,
        64, 17, 0,  # TTL=64, proto=17 (UDP)
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    ip_hdr = ip_hdr[:10] + struct.pack(">H", _ip_csum(ip_hdr)) + ip_hdr[12:]

    # ── Ethernet II frame ─────────────────────────────────────────
    eth = _mac_bytes("ff:ff:ff:ff:ff:ff") + _mac_bytes("02:00:00:11:22:33") + struct.pack(">H", 0x0800)
    frame = eth + ip_hdr + udp_seg
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))
    return frame
