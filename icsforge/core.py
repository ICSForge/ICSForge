
from __future__ import annotations

import json, os, time, socket, ipaddress, random
from datetime import datetime, timezone

TEST_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]

MARKER = b"ICSFORGE_SYNTH"

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

# ---------------- Outputs (JSON) ----------------
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
    raise ValueError("Invalid output spec. Use stdout | file:path | http(s)://... | syslog:ip:port | kafka:ip:port:topic")

def _send_stdout(event: dict):
    print(json.dumps(event, separators=(",", ":"), ensure_ascii=False))

def _send_file(path: str, event: dict, fh_cache: dict):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fh = fh_cache.get(path)
    if fh is None:
        fh = open(path, "a", encoding="utf-8")
        fh_cache[path] = fh
    fh.write(json.dumps(event, separators=(",", ":"), ensure_ascii=False) + "\n")
    fh.flush()

def _send_http(url: str, event: dict):
    try:
        import requests
        requests.post(url, json=event, timeout=3)
    except Exception:
        pass

def _send_syslog(host: str, port: int, event: dict):
    if not is_allowed_dest(host):
        raise ValueError("Syslog blocked: host must be loopback/TEST-NET.")
    msg = f"<134>{datetime.utcnow():%b %d %H:%M:%S} icsforge app: {json.dumps(event, separators=(',',':'), ensure_ascii=False)}"
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
        host, port = target
        _send_syslog(host, port, event)
    elif kind == "kafka":
        bootstrap, topic = target
        _send_kafka(bootstrap, topic, event)
    else:
        raise ValueError(f"Unknown output kind '{kind}'")

# ---------------- Event model ----------------
def event_base(technique: str | None, source: str, **fields) -> dict:
    ev = {
        "@timestamp": now_iso(),
        "icsforge.synthetic": True,
        "icsforge.marker": MARKER.decode("ascii"),
        "mitre.ics.technique": technique,
        "event.source": source,
    }
    ev.update(fields)
    return ev

# ---------------- PCAP helpers ----------------
def write_pcap(packets, out_path: str) -> int:
    from scapy.all import wrpcap
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    wrpcap(out_path, packets)
    return len(packets)

def replay_pcap(pcap_path: str, dst_ip: str, interval: float = 0.05) -> int:
    # Safety: replay only to loopback/TEST-NET.
    if not is_allowed_dest(dst_ip):
        raise ValueError("Replay blocked: destination IP not allowed (loopback/TEST-NET only).")
    from scapy.all import rdpcap, send
    pkts = rdpcap(pcap_path)
    sent = 0
    for p in pkts:
        if p.haslayer("IP"):
            p["IP"].dst = dst_ip
            send(p, verbose=False)
            sent += 1
            if interval:
                time.sleep(interval)
    return sent

# ---- Phase 3.5: on-wire correlation marker ----
def build_marker(run_id: str|None, technique: str|None=None, step: str|None=None) -> bytes:
    """Marker: ICSFORGE_SYNTH|<run_id>|<technique>|<step>"""
    rid = (run_id or "offline")
    parts=[b"ICSFORGE_SYNTH", rid.encode("utf-8"),
           (technique or "").encode("utf-8"),
           (step or "").encode("utf-8")]
    return b"|".join(parts)

def marker_prefix() -> bytes:
    return b"ICSFORGE_SYNTH|"
