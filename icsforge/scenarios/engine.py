from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional

import yaml

from icsforge.core import event_base, is_allowed_dest, parse_interval, write_pcap, build_marker
from icsforge.protocols import modbus, dnp3, s7comm, iec104, opcua, enip, profinet_dcp
from icsforge.protocols.common import tcp_packet, ether_frame

# Payload builders (return bytes) + default destination ports
PROTO_PAYLOADS = {
    "modbus": (502, modbus.build_payload),
    "dnp3": (20000, dnp3.build_payload),
    "s7comm": (102, s7comm.build_payload),
    "iec104": (2404, iec104.build_payload),
    "opcua": (4840, opcua.build_payload),
    "enip": (44818, enip.build_payload),
}

def load_scenarios(scenario_path: str) -> Dict[str, Any]:
    with open(scenario_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def run_scenario(
    scenario_path: str,
    name: str,
    outdir: str = "out",
    dst_ip: str = "127.0.0.1",
    src_ip: str = "127.0.0.1",
    run_id: Optional[str] = None,
    build_pcap: bool = True,
) -> Dict[str, Any]:
    """Offline scenario runner.

    Produces:
    - Ground-truth events JSONL (always)
    - PCAP (optional) with per-step correlation markers embedded in payloads

    NOTE: Live sending is handled by icsforge.live.sender; this runner is for
    offline generation and evidence artifacts.
    """
    doc = load_scenarios(scenario_path)
    scenarios = doc.get("scenarios") or {}
    aliases = doc.get("aliases") or {}
    if name not in scenarios and name in aliases:
        name = aliases[name]
    sc = scenarios.get(name)
    if not sc:
        raise ValueError(f"Scenario '{name}' not found in {scenario_path}")

    os.makedirs(outdir, exist_ok=True)
    run_id = run_id or os.environ.get("ICSFORGE_RUN_ID")  # optional, can be None

    events_dir = os.path.join(outdir, "events")
    pcaps_dir = os.path.join(outdir, "pcaps")
    os.makedirs(events_dir, exist_ok=True)
    os.makedirs(pcaps_dir, exist_ok=True)
    rid = (run_id or "offline")
    events_path = os.path.join(events_dir, f"{rid}.jsonl")
    pcap_path = os.path.join(pcaps_dir, f"{rid}.pcap")
    
    packets: List[Any] = []

    with open(events_path, "w", encoding="utf-8") as ef:
        for idx, step in enumerate((sc.get("steps") or []), start=1):
            stype = (step.get("type") or "event").strip().lower()
            proto = step.get("proto")
            tech = step.get("technique")
            count = int(step.get("count", 1))
            interval = parse_interval(step.get("interval", "0s"))
            style = step.get("style", "auto")
            options = step.get("options") or {}

            step_id = f"{name}:{idx}:{proto or ''}"

            # Build PCAP packets (optional)
            pcap_step = (stype == "pcap") or (stype == "packet" and bool(step.get("pcap")))
            if build_pcap and pcap_step:
                if proto == "profinet_dcp":
                    for _ in range(count):
                        marker = build_marker(run_id, tech, step_id)
                        payload = profinet_dcp.build_payload(marker)
                        # Default multicast dst for DCP Identify
                        pkt = ether_frame(
                            src_mac="02:00:00:11:22:33",
                            dst_mac="01:0e:cf:00:00:00",
                            ethertype=0x8892,
                            payload=payload,
                        )
                        packets.append(pkt)
                        if interval:
                            time.sleep(interval)
                else:
                    pb = PROTO_PAYLOADS.get(proto)
                    if not pb:
                        raise ValueError(f"Unknown proto '{proto}'")
                    dport, payload_builder = pb
                    for _ in range(count):
                        marker = build_marker(run_id, tech, step_id)
                        packets.append(tcp_packet(src_ip, dst_ip, dport, payload_builder(marker, style=style, **options)))
                        if interval:
                            time.sleep(interval)

            # Always write ground-truth events
            for _ in range(count):
                ev = event_base(
                    tech,
                    source=stype,
                    scenario=name,
                    proto=proto,
                    message=step.get("message", ""),
                )
                if run_id:
                    ev["run_id"] = run_id
                    ev["icsforge.run_id"] = run_id
                ef.write(json.dumps(ev, ensure_ascii=False) + "\n")

    if build_pcap and packets:
        write_pcap(packets, pcap_path)

    return {"run_id": (run_id or "offline"), "events": events_path, "pcap": pcap_path if (build_pcap and packets) else None}
