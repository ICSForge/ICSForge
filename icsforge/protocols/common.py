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

_PROTO_CODE = {
    "modbus": b"M", "dnp3": b"D", "s7comm": b"S", "iec104": b"I",
    "enip": b"E", "opcua": b"O", "bacnet": b"B", "mqtt": b"Q",
    "iec61850": b"G", "profinet_dcp": b"P",
}


def _run_hash(marker) -> bytes:
    """8 lowercase-hex chars (~32 bits) of SHA1(marker) for correlation."""
    import hashlib
    if not marker:
        marker = "offline"
    raw = bytes(marker) if isinstance(marker, (bytes, bytearray)) else str(marker).encode("utf-8", errors="ignore")
    return hashlib.sha1(raw).hexdigest()[:8].encode("ascii")


def marker_bytes(marker: str, proto: str | None = None) -> bytes:
    """Return the compact ICSForge synthetic-traffic marker (13 bytes).

    Format:  'ICSF' (4) + <proto code> (1) + <8 hex chars of SHA1(run_id)> (8)

    Rationale (v0.74.0): the historical marker was
    ``ICSFORGE:ICSFORGE_SYNTH|<run_id>|<technique>|<step>:`` — 60-90 bytes,
    which was 59-91% of a typical ICS frame. That dominated payloads (so
    captures looked synthetic rather than realistic), overflowed fixed-size
    transport chunks (the DNP3 CRC-splitting that forced a separate
    short-marker code path), and the double ``ICSFORGE:`` wrapper produced
    the malformed payload-preview marker.

    The compact marker:
      * is 13 bytes for **every** protocol (one code path, no special cases)
      * is 7-15% of a frame instead of 59-91% — realistic traffic
      * fits inside a single 16-byte DNP3 transport chunk with no splitting
      * keeps a deterministic 32-bit run hash for correlation

    Attribution no longer relies on an inline run_id/technique/step string.
    Defenders correlate via the expectation registry
    (``/api/receiver/expect``), and the 8-char hash lets the receiver
    *verify* a packet belongs to the expected run. The 4-byte ``ICSF``
    magic (optionally plus the 1-byte proto code) is the Tier-1
    detection fast-pattern.

    proto: protocol name (e.g. "modbus"); selects the 1-byte code. If
    omitted or unknown, a generic 'X' code is used — detection still
    fires on the 4-byte ``ICSF`` magic.
    """
    if not marker:
        return b""
    code = _PROTO_CODE.get((proto or "").lower(), b"X")
    return b"ICSF" + code + _run_hash(marker)


def short_marker_bytes(marker: str, proto_code: bytes = b"D") -> bytes:
    """Deprecated alias — retained for backward compatibility.

    Since v0.74.0 the standard marker_bytes() is already compact (13 bytes)
    and fits inside a DNP3 transport chunk, so a separate short marker is no
    longer needed. This now returns the same unified format. proto_code is
    accepted for signature compatibility; the first byte is used as the
    protocol code.
    """
    pc = proto_code[:1] if proto_code else b"D"
    return b"ICSF" + pc + _run_hash(marker)


def tcp_segment(src_ip: str, dst_ip: str, sport: int, dport: int,
                seq: int, ack: int, flags: int, payload: bytes = b"",
                src_mac: bytes | None = None, dst_mac: bytes | None = None,
                window: int = 8192, ip_id: int | None = None) -> bytes:
    """
    Build one complete Ethernet II + IPv4 + TCP frame with explicit control
    fields. Unlike tcp_packet() (which hardcodes PSH|ACK for the attacker→target
    data model), this lets the caller set seq, ack, flags and direction, so a
    full stateful conversation — SYN / SYN-ACK / ACK handshake, ACKs for data,
    FIN/ACK teardown — can be emitted. IP + TCP checksums are computed correctly.

    flags: TCP control bits, e.g. 0x02=SYN, 0x12=SYN|ACK, 0x10=ACK,
           0x18=PSH|ACK, 0x11=FIN|ACK, 0x04=RST.
    """
    rnd = random.Random()
    seq &= 0xFFFF_FFFF
    ack &= 0xFFFF_FFFF
    # offset=5 (20-byte header), checksum placeholder = 0
    tcp_hdr = struct.pack(">HHIIBBHHH",
        sport, dport,
        seq, ack,
        0x50, flags & 0xFF,
        window, 0, 0,
    )
    tcp_seg = tcp_hdr + payload
    tcp_c   = _tcp_csum(src_ip, dst_ip, tcp_seg)
    tcp_seg = tcp_hdr[:16] + struct.pack(">H", tcp_c) + tcp_hdr[18:] + payload

    total_len = 20 + len(tcp_seg)
    ip_hdr = struct.pack(">BBHHHBBH4s4s",
        0x45, 0,
        total_len,
        (ip_id if ip_id is not None else rnd.randint(0, 0xFFFF)),
        0x4000,
        64, 6, 0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    ip_hdr = ip_hdr[:10] + struct.pack(">H", _ip_csum(ip_hdr)) + ip_hdr[12:]

    _smac = src_mac if src_mac is not None else _src_mac_from_ip(src_ip)
    _dmac = dst_mac if dst_mac is not None else _mac_bytes("ff:ff:ff:ff:ff:ff")
    eth   = _dmac + _smac + struct.pack(">H", 0x0800)
    frame = eth + ip_hdr + tcp_seg
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))
    return frame


def tcp_packet(src_ip: str, dst_ip: str, dport: int, payload: bytes,
               src_mac: bytes | None = None, tcp_seq: int | None = None,
               dst_mac: bytes | None = None, proto: str | None = None,
               sport: int | None = None) -> bytes:
    """
    Build a complete Ethernet II + IPv4 + TCP frame as raw bytes.

    This is the stateless attacker→target data model: a single PSH|ACK segment,
    no handshake, ack=0. For a full stateful conversation use tcp_segment() via
    the TCPFlow helper instead.

    MAC addressing:
      src: derived from src_ip via _src_mac_from_ip()
      dst: dst_mac if provided, else ff:ff:ff:ff:ff:ff (offline PCAP)
    Ethernet type: 0x0800 (IPv4)
    IP + TCP checksums are computed correctly (Wireshark-valid).
    """
    rnd    = random.Random()
    _sport = sport if sport is not None else rnd.randint(49152, 65534)
    seq    = (tcp_seq if tcp_seq is not None else rnd.randint(0, 0xFFFF_FFFF)) & 0xFFFF_FFFF
    _smac  = src_mac if src_mac is not None else _src_mac_from_ip(src_ip)
    # PSH|ACK (0x18), ack=0 — preserves the historical stateless byte layout.
    return tcp_segment(src_ip, dst_ip, _sport, dport, seq, 0, 0x18, payload,
                       src_mac=_smac, dst_mac=dst_mac)

class TCPFlow:
    """Stateful TCP conversation builder for offline pcaps.

    Emits a real handshake, ACKs each data segment from the peer, and tears the
    connection down — so the resulting pcap survives stream reassembly and looks
    like a genuine flow to a stateful IDS (Suricata stream engine, Zeek conn
    tracking). The default stateless model (tcp_packet) stays the contract; this
    is opt-in via the generator's `stateful` mode.

    Direction model: the *client* is the attacker/sender (src_ip), the *server*
    is the target (dst_ip). Only the client sends application payloads (ICSForge
    is attacker→target); the server contributes SYN-ACK and bare ACKs, which is
    what gives the stream engine a two-sided conversation to track. Synthesising
    full application-layer responses is Phase B; this phase delivers the
    transport-layer handshake/teardown.
    """

    def __init__(self, src_ip: str, dst_ip: str, sport: int, dport: int,
                 client_isn: int, server_isn: int | None = None,
                 src_mac: bytes | None = None, dst_mac: bytes | None = None,
                 proto: str | None = None):
        self.src_ip, self.dst_ip = src_ip, dst_ip
        self.sport, self.dport = sport, dport
        self.cseq = client_isn & 0xFFFF_FFFF                       # client next seq
        rnd = random.Random((client_isn or 1) ^ 0x5A5A5A5A)
        self.sseq = (server_isn if server_isn is not None
                     else rnd.randint(0, 0xFFFF_FFFF)) & 0xFFFF_FFFF
        self.cack = 0                                              # client's ack of server
        self.sack = 0                                              # server's ack of client
        self._cmac = src_mac if src_mac is not None else _src_mac_from_ip(src_ip, proto)
        self._smac = dst_mac if dst_mac is not None else _resolve_dst_mac(dst_ip)
        self.handshake_done = False

    # client→server frame
    def _c(self, flags: int, payload: bytes = b"") -> bytes:
        return tcp_segment(self.src_ip, self.dst_ip, self.sport, self.dport,
                           self.cseq, self.cack, flags, payload,
                           src_mac=self._cmac, dst_mac=self._smac)

    # server→client frame
    def _s(self, flags: int, payload: bytes = b"") -> bytes:
        return tcp_segment(self.dst_ip, self.src_ip, self.dport, self.sport,
                           self.sseq, self.sack, flags, payload,
                           src_mac=self._smac, dst_mac=self._cmac)

    def handshake(self) -> list[bytes]:
        """SYN → SYN-ACK → ACK. Advances both ISNs by 1 (SYN consumes a seq)."""
        frames = []
        # SYN (client)
        frames.append(self._c(0x02))
        self.cseq = (self.cseq + 1) & 0xFFFF_FFFF
        # SYN-ACK (server) acks client's SYN
        self.sack = self.cseq
        frames.append(self._s(0x12))
        self.sseq = (self.sseq + 1) & 0xFFFF_FFFF
        # ACK (client) acks server's SYN
        self.cack = self.sseq
        frames.append(self._c(0x10))
        self.handshake_done = True
        return frames

    def client_data(self, payload: bytes) -> list[bytes]:
        """One PSH|ACK data segment from client + a bare ACK back from server."""
        frames = [self._c(0x18, payload)]
        self.cseq = (self.cseq + max(len(payload), 1)) & 0xFFFF_FFFF
        # server ACKs the data (no payload — Phase A is transport-only)
        self.sack = self.cseq
        frames.append(self._s(0x10))
        return frames

    def teardown(self) -> list[bytes]:
        """FIN-ACK (client) → FIN-ACK (server) → ACK (client). Graceful close."""
        frames = []
        frames.append(self._c(0x11))                 # client FIN|ACK
        self.cseq = (self.cseq + 1) & 0xFFFF_FFFF
        self.sack = self.cseq
        frames.append(self._s(0x11))                 # server FIN|ACK
        self.sseq = (self.sseq + 1) & 0xFFFF_FFFF
        self.cack = self.sseq
        frames.append(self._c(0x10))                 # client final ACK
        return frames

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
    import re as _re
    import subprocess as _sp

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
