"""
ICSForge core — pure Python, zero scapy dependency.

write_pcap()   : struct-based pcap writer, LINKTYPE_ETHERNET (1)
replay_pcap()  : sends TCP payloads from PCAP via raw sockets (scapy optional)
build_marker() : on-wire correlation marker bytes
"""

import ipaddress
import json
import os
import random
import socket
import struct
import time
from contextlib import suppress
from datetime import datetime, timezone

from icsforge.log import get_logger as _get_logger

_log = _get_logger(__name__)

TEST_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]

MARKER = b"ICSFORGE_SYNTH"

# ── PCAP file format constants ────────────────────────────────────────
# Global header: magic(4) major(2) minor(2) thiszone(4) sigfigs(4) snaplen(4) network(4)
# magic 0xa1b2c3d4 → native-endian pcap; network 1 = LINKTYPE_ETHERNET
_PCAP_GLOBAL_HDR = struct.pack("<IHHiIII",
    0xa1b2c3d4,  # magic
    2, 4,        # major.minor
    0, 0,        # thiszone, sigfigs
    65535,       # snaplen
    1,           # LINKTYPE_ETHERNET
)

def is_allowed_dest(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in TEST_NETS)

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def parse_interval(s: str) -> float:
    s = (s or "0s").strip().lower()
    if s in ("0", "0s"):
        return 0.0
    if s.endswith("ms"):
        return float(s[:-2]) / 1000.0
    if s.endswith("s"):
        return float(s[:-1])
    if s.endswith("m"):
        return float(s[:-1]) * 60.0
    if s.endswith("h"):
        return float(s[:-1]) * 3600.0
    raise ValueError("Invalid interval, use e.g. 100ms / 1s / 5m / 1h")

def rand_ip(rnd: random.Random) -> str:
    return ".".join(str(rnd.randint(1, 254)) for _ in range(4))

# ── Output dispatchers ────────────────────────────────────────────────
def output_sender(spec: str):
    if spec == "stdout":
        return ("stdout", None)
    if spec.startswith("file:"):
        return ("file", spec.split(":", 1)[1])
    if spec.startswith("http:") or spec.startswith("https:"):
        return ("http", spec)
    if spec.startswith("syslog:"):
        _, host, port = spec.split(":", 2)
        return ("syslog", (host, int(port)))
    if spec.startswith("kafka:"):
        _, host, port, topic = spec.split(":", 3)
        return ("kafka", (f"{host}:{port}", topic))
    raise ValueError("Invalid output spec.")

def _send_stdout(event: dict):
    print(json.dumps(event, separators=(",", ":"), ensure_ascii=False))

def _send_file(path: str, event: dict, fh_cache: dict):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fh = fh_cache.get(path)
    if fh is None:
        fh = open(path, "a", encoding="utf-8")  # noqa: SIM115
        fh_cache[path] = fh
    fh.write(json.dumps(event, separators=(",", ":"), ensure_ascii=False) + "\n")
    fh.flush()

def _send_http(url: str, event: dict):
    try:
        import requests
        requests.post(url, json=event, timeout=3)
    except Exception as e:
        _log.warning("HTTP output to %s failed: %s", url, e)

def _send_syslog(host: str, port: int, event: dict):
    if not is_allowed_dest(host):
        raise ValueError("Syslog blocked: host must be loopback/TEST-NET.")
    msg = f"<134>{datetime.now(timezone.utc):%b %d %H:%M:%S} icsforge app: {json.dumps(event, separators=(',',':'), ensure_ascii=False)}"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(msg.encode("utf-8"), (host, port))
    finally:
        sock.close()

def _send_kafka(bootstrap: str, topic: str, event: dict):
    try:
        from kafka import KafkaProducer
    except Exception as e:
        raise RuntimeError("Kafka output requires kafka-python") from e
    host = bootstrap.split(":")[0]
    if not is_allowed_dest(host):
        raise ValueError("Kafka blocked: bootstrap host must be loopback/TEST-NET.")
    prod = KafkaProducer(
        bootstrap_servers=[bootstrap],
        value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode("utf-8"),
    )
    prod.send(topic, event)
    prod.flush(2)

def dispatch_send(kind, target, event, fh_cache):
    if kind == "stdout":
        _send_stdout(event)
    elif kind == "file":
        _send_file(target, event, fh_cache)
    elif kind == "http":
        _send_http(target, event)
    elif kind == "syslog":
        _send_syslog(*target, event)
    elif kind == "kafka":
        _send_kafka(*target, event)
    else:
        raise ValueError(f"Unknown output kind '{kind}'")

# ── Event model ───────────────────────────────────────────────────────
def event_base(technique: str | None, source: str, **fields) -> dict:
    ev = {
        "@timestamp":          now_iso(),
        "icsforge.synthetic":  True,
        "icsforge.marker":     MARKER.decode("ascii"),
        "mitre.ics.technique": technique,
        "event.source":        source,
    }
    ev.update(fields)
    return ev

# ── Pure-Python pcap writer (LINKTYPE_ETHERNET) ───────────────────────
def write_pcap(packets: list, out_path: str, base_interval_ms: float = 50.0) -> int:
    """
    Write a list of raw-bytes packets to a pcap file.

    All packets are written as Ethernet frames (LINKTYPE_ETHERNET = 1).
    Timestamps include realistic jitter (±30% of base_interval_ms) to avoid
    the uniform-spacing pattern that flags synthetic PCAPs.
    """
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    base_ts = time.time()
    rnd = random.Random(42)  # deterministic jitter for reproducibility
    current_ts = base_ts
    with open(out_path, "wb") as f:
        f.write(_PCAP_GLOBAL_HDR)
        for _i, pkt in enumerate(packets):
            raw = bytes(pkt) if not isinstance(pkt, bytes) else pkt
            ts_sec = int(current_ts)
            ts_usec = int((current_ts - ts_sec) * 1_000_000)
            f.write(struct.pack("<IIII", ts_sec, ts_usec, len(raw), len(raw)))
            f.write(raw)
            # Add jitter: base interval ± 30%
            jitter = base_interval_ms * (0.7 + rnd.random() * 0.6) / 1000.0
            current_ts += jitter
    return len(packets)


def replay_pcap(pcap_path: str, dst_ip: str, interval: float = 0.05) -> int:
    """
    Re-send TCP payloads from a pcap to dst_ip.

    Reads Ethernet frames, extracts IP+TCP payload, and sends it via a
    TCP connection.  Falls back to scapy if available for non-TCP frames.
    """
    if not is_allowed_dest(dst_ip):
        raise ValueError("Replay blocked: destination IP not allowed (loopback/TEST-NET only).")

    sent = 0
    with open(pcap_path, "rb") as f:
        # Parse global header
        gh = f.read(24)
        if len(gh) < 24:
            return 0
        magic = struct.unpack_from("<I", gh)[0]
        endian = "<" if magic == 0xa1b2c3d4 else ">"

        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            _, _, incl_len, _ = struct.unpack(f"{endian}IIII", ph)
            raw = f.read(incl_len)
            if len(raw) < incl_len:
                break

            # Parse Ethernet + IPv4 + TCP
            if len(raw) < 34:
                continue
            ethertype = struct.unpack(">H", raw[12:14])[0]
            if ethertype != 0x0800:
                continue  # skip non-IPv4 (e.g. PROFINET)
            proto = raw[23]
            if proto != 6:
                continue  # skip non-TCP
            ihl = (raw[14] & 0x0F) * 4
            tcp_offset = 14 + ihl
            if len(raw) < tcp_offset + 20:
                continue
            dport = struct.unpack(">H", raw[tcp_offset + 2: tcp_offset + 4])[0]
            tcp_hdr_len = ((raw[tcp_offset + 12] >> 4) & 0xF) * 4
            payload = raw[tcp_offset + tcp_hdr_len:]
            if not payload:
                continue

            try:
                s = socket.create_connection((dst_ip, dport), timeout=2.0)
                try:
                    s.sendall(payload)
                finally:
                    with suppress(Exception):
                        s.shutdown(socket.SHUT_RDWR)
                    s.close()
                sent += 1
            except Exception:
                pass

            if interval:
                time.sleep(interval)

    return sent

# ── Run ID generation ────────────────────────────────────────────────
_NATO = [
    "ALPHA", "BRAVO", "CHARLIE", "DELTA", "ECHO", "FOXTROT",
    "GOLF", "HOTEL", "INDIA", "JULIET", "KILO", "LIMA",
    "MIKE", "NOVEMBER", "OSCAR", "PAPA", "QUEBEC", "ROMEO",
    "SIERRA", "TANGO", "UNIFORM", "VICTOR", "WHISKEY", "XRAY",
    "YANKEE", "ZULU",
]

def generate_run_id() -> str:
    """
    Human-readable run ID: YYYY-MM-DD-NATO-NN
    e.g. 2026-03-05-BRAVO-07

    Sortable by date, memorable by word, 00-99 handles same-second collisions.
    Legacy hex IDs (12-char alphanumeric) remain valid everywhere — they are
    displayed with a 'legacy' badge in the dashboard but never rejected.
    """
    date  = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    word  = random.choice(_NATO)
    num   = random.randint(0, 99)
    return f"{date}-{word}-{num:02d}"

def is_legacy_run_id(run_id: str) -> bool:
    """Return True for old hex run IDs (12 lowercase hex chars)."""
    import re
    return bool(re.fullmatch(r"[0-9a-f]{12}", run_id or ""))

# ── On-wire correlation marker ────────────────────────────────────────
def build_marker(run_id: str | None, technique: str | None = None, step: str | None = None) -> bytes:
    """Marker: ICSFORGE_SYNTH|<run_id>|<technique>|<step>"""
    parts = [
        b"ICSFORGE_SYNTH",
        (run_id or "offline").encode("utf-8"),
        (technique or "").encode("utf-8"),
        (step or "").encode("utf-8"),
    ]
    return b"|".join(parts)

def marker_prefix() -> bytes:
    return b"ICSFORGE_SYNTH|"
