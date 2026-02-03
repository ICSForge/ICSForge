from __future__ import annotations
import socket, time, uuid
from typing import List
import yaml
from icsforge.core import build_marker, parse_interval
from icsforge.protocols import modbus, dnp3, s7comm, iec104, opcua, enip, profinet_dcp

TCP_PROTOS = {
    "modbus": (502, modbus.build_payload),
    "dnp3": (20000, dnp3.build_payload),
    "s7comm": (102, s7comm.build_payload),
    "iec104": (2404, iec104.build_payload),
    "opcua": (4840, opcua.build_payload),
    "enip": (44818, enip.build_payload),
}

def _tcp_send(dst_ip: str, port: int, payload: bytes, timeout: float):
    s = socket.create_connection((dst_ip, port), timeout=timeout)
    try:
        s.sendall(payload)
    finally:
        try: s.shutdown(socket.SHUT_RDWR)
        except Exception: pass
        s.close()

def _send_profinet_dcp(iface: str, payload: bytes):
    from scapy.all import sendp
    from scapy.layers.l2 import Ether
    frame = Ether(src="02:00:00:12:34:56", dst="01:0e:cf:00:00:00", type=0x8892)/payload
    sendp(frame, iface=iface, verbose=False)

def load_scenarios(path: str) -> dict:
    with open(path,"r",encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def send_scenario_live(scenario_file: str, scenario_name: str, dst_ip: str,
                       iface: str|None=None, confirm_live_network: bool=False,
                       receiver_allowlist: List[str]|None=None, timeout: float=2.0) -> dict:
    if not confirm_live_network:
        raise ValueError("Live send blocked: pass --confirm-live-network to enable.")
    allow = receiver_allowlist or [dst_ip]
    if dst_ip not in allow:
        raise ValueError("Live send blocked: dst_ip not in receiver allowlist.")
    doc = load_scenarios(scenario_file)
    sc = (doc.get("scenarios") or {}).get(scenario_name)
    if not sc:
        raise ValueError(f"Scenario '{scenario_name}' not found")
    run_id = uuid.uuid4().hex[:12]
    sent = 0
    for idx, step in enumerate(sc.get("steps", []), start=1):
        stype = (step.get("type") or "packet").strip().lower()
        if stype not in ("packet","pcap"):
            continue
        proto = step.get("proto")
        tech = step.get("technique")
        count = int(step.get("count",1))
        interval = parse_interval(step.get("interval","0s"))
        step_id = f"{scenario_name}:{idx}:{proto}"
        if proto == "profinet_dcp":
            if not iface:
                raise ValueError("profinet_dcp live send requires --iface")
            for _ in range(count):
                payload = profinet_dcp.build_payload(build_marker(run_id, tech, step_id))
                _send_profinet_dcp(iface, payload)
                sent += 1
                if interval: time.sleep(interval)
        else:
            if proto not in TCP_PROTOS:
                raise ValueError(f"Unsupported proto for live send: {proto}")
            port, builder = TCP_PROTOS[proto]
            for _ in range(count):
                payload = builder(build_marker(run_id, tech, step_id))
                _tcp_send(dst_ip, port, payload, timeout)
                sent += 1
                if interval: time.sleep(interval)
    return {"run_id": run_id, "dst_ip": dst_ip, "sent": sent}
