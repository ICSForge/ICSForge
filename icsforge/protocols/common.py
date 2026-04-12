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


def tcp_packet(src_ip: str, dst_ip: str, dport: int, payload: bytes,
               src_mac: bytes | None = None, tcp_seq: int | None = None,
               dst_mac: bytes | None = None, proto: str | None = None,
               sport: int | None = None) -> bytes:
    """
    Build a complete Ethernet II + IPv4 + TCP frame as raw bytes.

    MAC addressing:
      src: derived from src_ip via _src_mac_from_ip()
      dst: dst_mac if provided, else ff:ff:ff:ff:ff:ff (offline PCAP)
    Ethernet type: 0x0800 (IPv4)
    IP + TCP checksums are computed correctly (Wireshark-valid).
    """
    rnd   = random.Random()
    _sport = sport if sport is not None else rnd.randint(49152, 65534)
    seq   = (tcp_seq if tcp_seq is not None else rnd.randint(0, 0xFFFF_FFFF)) & 0xFFFF_FFFF

    # ── TCP header (checksum placeholder = 0) ────────────────────
    # offset=5 (20 bytes header), flags PSH|ACK = 0x18
    tcp_hdr = struct.pack(">HHIIBBHHH",
        _sport, dport,
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
    _smac = src_mac if src_mac is not None else _src_mac_from_ip(src_ip)
    _dmac = dst_mac if dst_mac is not None else _mac_bytes("ff:ff:ff:ff:ff:ff")
    eth   = _dmac + _smac + struct.pack(">H", 0x0800)
    frame = eth + ip_hdr + tcp_seg
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))
    return frame



# ── Realistic OUI table — maps protocol to real OT vendor MAC prefixes ─────────
# Source: IEEE OUI registry + known OT device manufacturers.
# Using registered OUI prefixes means MACs pass vendor lookups in Wireshark,
# Defender for IoT, Claroty, Dragos etc. — no locally-administered flag.
_OUI_BY_PROTO: dict[str, list[bytes]] = {
    # Siemens AG (S7comm, S7-300/400/1200/1500, PROFINET controllers)
    "s7comm":        [b"\x00\x0E\x8C", b"\x00\x1B\x1B", b"\xAC\x64\x17"],
    # Rockwell Automation / Allen-Bradley (EtherNet/IP, ControlLogix, CompactLogix)
    "enip":          [b"\x00\x00\xBC", b"\x00\x0E\x8C", b"\xEC\x9A\x74"],
    # Schneider Electric (Modbus, Quantum PLC, Modicon M340)
    "modbus":        [b"\x00\x80\xF4", b"\x00\x10\xEC", b"\x00\x60\x9C"],
    # GE Grid Solutions / SEL (DNP3, protective relays, RTUs)
    "dnp3":          [b"\x00\x90\x69", b"\x00\x30\xA7", b"\xD4\xBE\xD9"],
    # ABB / Siemens (IEC-104, RTU/telecontrol equipment)
    "iec104":        [b"\x00\x0A\xDC", b"\x00\x0E\x8C", b"\x00\x1A\x4B"],
    # GE / ABB / Alstom (IEC 61850 GOOSE, protection relays, bay controllers)
    "iec61850":      [b"\x00\x90\x69", b"\x00\x0A\xDC", b"\x00\x01\x72"],
    # Unified Automation / Prosys / Inductive Automation (OPC UA — SCADA/HMI hosts)
    # Use Dell/HP server OUIs — OPC UA servers run on standard x86 hardware
    "opcua":         [b"\x18\xDB\xF2", b"\x14\xFE\xB5", b"\x00\x25\x64"],
    # Automated Logic / Delta Controls / Distech (BACnet/IP building automation)
    "bacnet":        [b"\x00\x60\x35", b"\x00\xA0\xA5", b"\x00\x20\x85"],
    # Siemens / Phoenix Contact (PROFINET DCP)
    "profinet_dcp":  [b"\x00\x0E\x8C", b"\x00\xA0\x45", b"\xAC\x64\x17"],
    # Moxa / Advantech / AVEVA (MQTT — IoT gateways, edge devices)
    "mqtt":          [b"\x00\x90\xE8", b"\x00\xD0\xC9", b"\x00\x10\x8B"],
}

# Fallback OUI pool for unknown protocols — generic industrial vendor MACs
_OUI_FALLBACK: list[bytes] = [
    b"\x00\x80\xF4",  # Schneider Electric
    b"\x00\x0E\x8C",  # Siemens
    b"\x00\x00\xBC",  # Rockwell
    b"\x00\x90\x69",  # GE Grid Solutions
    b"\x00\x0A\xDC",  # ABB
]


def _src_mac_from_ip(src_ip: str, proto: str | None = None) -> bytes:
    """
    Derive a realistic source MAC from the sender IP and protocol.

    Selects a registered OUI from the real OT vendor list for the given
    protocol so Wireshark/Defender-for-IoT vendor lookups return a plausible
    manufacturer name. The last 3 bytes are derived deterministically from
    the IP address so the MAC is stable within a session but varies per host.

    The old approach (0x02:... prefix) set the locally-administered bit,
    which immediately identifies synthetic traffic to any OT-aware NSM tool.
    """
    import random as _rnd
    try:
        b = socket.inet_aton(src_ip)
    except OSError:
        b = b"\x7f\x00\x00\x01"

    # Pick OUI deterministically from the IP address
    oui_pool = _OUI_BY_PROTO.get(proto or "", _OUI_FALLBACK)
    oui = oui_pool[b[3] % len(oui_pool)]  # last IP octet selects OUI

    # Last 3 bytes: XOR of IP bytes for per-host variation, seeded for reproducibility
    suffix = bytes([
        (b[0] ^ b[2] ^ 0x01) & 0xFE,   # keep unicast (bit0=0) and globally-admin (bit1=0)
        (b[1] ^ b[3] ^ 0x55) & 0xFF,
        (b[0] ^ b[1] ^ b[2] ^ b[3]) & 0xFF,
    ])
    return oui + suffix


def _resolve_dst_mac(dst_ip: str) -> bytes:
    """
    Resolve destination MAC for PCAP realism.

    Priority:
      1. Kernel ARP cache (/proc/net/arp on Linux, arp -n on macOS/BSD)
         — populated automatically after live TCP/UDP sends to the host.
      2. Deterministic locally-administered unicast MAC derived from dst_ip
         (same algorithm as _src_mac_from_ip) — used when ARP cache is empty
         (offline/container/unreachable host) or on unsupported platforms.

    Never returns ff:ff:ff:ff:ff:ff (broadcast).
    """
    import subprocess as _sp
    import re as _re

    # ── 1. Linux /proc/net/arp ─────────────────────────────────────────────
    try:
        with open("/proc/net/arp") as _f:
            for _line in _f.readlines()[1:]:
                _parts = _line.split()
                if len(_parts) >= 4 and _parts[0] == dst_ip:
                    _mac = _parts[3]
                    if _mac and _mac != "00:00:00:00:00:00":
                        return _mac_bytes(_mac)
    except OSError:
        pass

    # ── 2. arp -n / ip neigh (macOS, BSD, Linux fallback) ─────────────────
    try:
        _out = _sp.check_output(
            ["arp", "-n", dst_ip], stderr=_sp.DEVNULL, timeout=1
        ).decode()
        _m = _re.search(r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", _out)
        if _m:
            return _mac_bytes(_m.group(1))
    except Exception:
        pass

    # ── 3. Deterministic synthetic MAC (offline / unreachable) ─────────────
    return _src_mac_from_ip(dst_ip)


def ether_frame(src_mac: str, dst_mac: str, ethertype: int, payload: bytes) -> bytes:
    """Build a raw Ethernet II frame as bytes (no scapy)."""
    frame = _mac_bytes(dst_mac) + _mac_bytes(src_mac) + struct.pack(">H", ethertype) + payload
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))
    return frame


def udp_packet(src_ip: str, dst_ip: str, dport: int, payload: bytes, sport: int = 0, src_mac: bytes | None = None, dst_mac: bytes | None = None, proto: str | None = None) -> bytes:
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
    _smac = src_mac if src_mac is not None else _src_mac_from_ip(src_ip, proto)
    _dmac = dst_mac if dst_mac is not None else _mac_bytes("ff:ff:ff:ff:ff:ff")
    eth = _dmac + _smac + struct.pack(">H", 0x0800)
    frame = eth + ip_hdr + udp_seg
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))
    return frame
