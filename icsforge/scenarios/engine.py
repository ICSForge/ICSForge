
import json
import os
import time
from typing import Any

import yaml

from icsforge.log import get_logger
from icsforge.core import build_marker, event_base, parse_interval, write_pcap
from icsforge.protocols import (
    bacnet, dnp3, enip, iec104, modbus, mqtt, opcua, profinet_dcp, s7comm,
    TCP_PROTOS as PROTO_PAYLOADS,
    UDP_PROTOS as UDP_PAYLOADS,
)
from icsforge.protocols.common import ether_frame, tcp_packet, udp_packet

def load_scenarios(scenario_path: str) -> dict[str, Any]:
    with open(scenario_path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

log = get_logger(__name__)


def run_scenario(
    scenario_path: str,
    name: str,
    outdir: str = "out",
    dst_ip: str = "127.0.0.1",
    src_ip: str = "127.0.0.1",
    run_id: str | None = None,
    build_pcap: bool = True,
    skip_intervals: bool = False,
) -> dict[str, Any]:
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

    packets: list[Any] = []

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

            # Write ground-truth events FIRST — before pcap building.
            # This ensures events are always recorded even if pcap building
            # fails, raises, or is interrupted (e.g. KeyboardInterrupt).
            for _ in range(count):
                ev = event_base(
                    tech,
                    source=stype,
                    scenario=name,
                    proto=proto,
                    message=step.get("message", ""),
                )
                ev["run_id"] = rid          # always present; "offline" when no run_id given
                ev["icsforge.run_id"] = rid
                ef.write(json.dumps(ev, ensure_ascii=False) + "\n")
            ef.flush()  # flush after each step so partial runs are readable

            # Build PCAP packets (optional) — after events are safely written
            pcap_step = (stype == "pcap") or (stype == "packet" and bool(step.get("pcap")))
            if build_pcap and pcap_step:
                if proto == "profinet_dcp":
                    for _ in range(count):
                        marker = build_marker(run_id, tech, step_id)
                        payload = profinet_dcp.build_payload(marker, style=style)
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
                    upb = UDP_PAYLOADS.get(proto)
                    if not pb and not upb:
                        log.warning("PCAP skipped for step %d: unknown proto '%s' (events already written)", idx, proto)
                    elif pb:
                        dport, payload_builder = pb
                        for _ in range(count):
                            marker = build_marker(run_id, tech, step_id)
                            packets.append(tcp_packet(src_ip, dst_ip, dport, payload_builder(marker, style=style, **options)))
                            if interval and not skip_intervals:
                                time.sleep(interval)
                    elif upb:
                        dport, payload_builder = upb
                        for _ in range(count):
                            marker = build_marker(run_id, tech, step_id)
                            packets.append(udp_packet(src_ip, dst_ip, dport, payload_builder(marker, style=style, **options)))
                            if interval and not skip_intervals:
                                time.sleep(interval)

    if build_pcap and packets:
        write_pcap(packets, pcap_path)

    return {"run_id": (run_id or "offline"), "events": events_path, "pcap": pcap_path if (build_pcap and packets) else None}
