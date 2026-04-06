import json
import os
import random as _rnd_eng
import time
from typing import Any

import yaml

from icsforge.core import build_marker, event_base, parse_interval, write_pcap
from icsforge.log import get_logger
from icsforge.protocols import TCP_PROTOS as PROTO_PAYLOADS
from icsforge.protocols import UDP_PROTOS as UDP_PAYLOADS
from icsforge.protocols import iec61850, profinet_dcp
from icsforge.protocols.common import ether_frame, tcp_packet, udp_packet, _src_mac_from_ip


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
    no_marker: bool = False,
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

    # Session-level protocol contexts — keep sequence numbers coherent
    # across all steps within this scenario run
    _opcua_ctx = {
        "secure_channel_id": _rnd_eng.randint(1, 0xFFFFFF),
        "security_token":    _rnd_eng.randint(1, 0xFFFFFF),
        "sequence_number":   _rnd_eng.randint(1, 0xFFFFFF),
        "request_id":        _rnd_eng.randint(1, 0xFFFF),
        "dst_ip":            dst_ip,
    }
    _dnp3_seq:    int = _rnd_eng.randint(0, 15)           # DNP3 app seq (0-15)
    _tcp_seq:     int = _rnd_eng.randint(0, 0xFFFFFFFF)    # TCP ISN
    _iec104_seq:  int = _rnd_eng.randint(0, 0x7FFF)        # IEC-104 send seq (15-bit)
    _s7_pdu_ref:  int = _rnd_eng.randint(1, 0xFFFF)        # S7comm PDU reference
    _modbus_tid:  int = _rnd_eng.randint(0, 0xFFFF)        # Modbus transaction ID
    _bacnet_inv:  int = _rnd_eng.randint(0, 255)           # BACnet invoke ID

    with open(events_path, "w", encoding="utf-8") as ef:
        for idx, step in enumerate((sc.get("steps") or []), start=1):
            stype = (step.get("type") or "event").strip().lower()
            proto = step.get("proto")
            tech = step.get("technique")
            count = int(step.get("count", 1))
            interval = parse_interval(step.get("interval", "0s"))
            style = step.get("style", "auto")
            options = step.get("options") or {}
            # Inject session-level OPC UA context (per-packet increment in TCP loop)
            if proto == "opcua":
                options = {**_opcua_ctx, **options}
            # Inject dst_ip for protocols that encode the target address in payload
            if proto in ("opcua", "s7comm"):
                options = {"dst_ip": dst_ip, **options}

            step_id = f"{name}:{idx}:{proto or ''}"

            # Write ground-truth events FIRST — before pcap building.
            # This ensures events are always recorded even if pcap building
            # fails, raises, or is interrupted (e.g. KeyboardInterrupt).
            for _ in range(count):
                ev = event_base(
                    tech,
                    source=stype,
                    no_marker=no_marker,
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
                        marker = b'' if no_marker else build_marker(run_id, tech, step_id)
                        payload = profinet_dcp.build_payload(marker, style=style)
                        # Default multicast dst for DCP Identify
                        pkt = ether_frame(
                            src_mac=_src_mac_from_ip(src_ip).hex(":"),
                            dst_mac="01:0e:cf:00:00:00",
                            ethertype=0x8892,
                            payload=payload,
                        )
                        packets.append(pkt)
                        if interval:
                            time.sleep(interval)
                elif proto == "iec61850":
                    for _ in range(count):
                        marker = b'' if no_marker else build_marker(run_id, tech, step_id)
                        # iec61850.build_payload returns a complete Ethernet frame
                        # (GOOSE: EtherType 0x88B8, GOOSE multicast DST)
                        pkt = iec61850.build_payload(marker, style=style, **options)
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
                            marker = b'' if no_marker else build_marker(run_id, tech, step_id)
                            _pkt_opts = {**options}
                            if proto == "opcua":
                                _pkt_opts["sequence_number"] = _opcua_ctx["sequence_number"]
                                _pkt_opts["request_id"]      = _opcua_ctx["request_id"]
                                _opcua_ctx["sequence_number"] = (_opcua_ctx["sequence_number"] + 1) & 0xFFFFFF
                                _opcua_ctx["request_id"]      = (_opcua_ctx["request_id"]      + 1) & 0xFFFF
                            elif proto == "dnp3":
                                _pkt_opts["dnp3_seq"] = _dnp3_seq
                                _dnp3_seq = (_dnp3_seq + 1) & 0x0F
                            elif proto == "iec104":
                                _pkt_opts["iec104_seq"] = _iec104_seq
                                _iec104_seq = (_iec104_seq + 1) & 0x7FFF
                            elif proto == "s7comm":
                                _pkt_opts["s7_pdu_ref"] = _s7_pdu_ref
                                _s7_pdu_ref = (_s7_pdu_ref + 1) & 0xFFFF
                            elif proto == "modbus":
                                _pkt_opts["modbus_tid"] = _modbus_tid
                                _modbus_tid = (_modbus_tid + 1) & 0xFFFF
                            _payload = payload_builder(marker, style=style, **_pkt_opts)
                            packets.append(tcp_packet(src_ip, dst_ip, dport,
                                _payload, tcp_seq=_tcp_seq))
                            _tcp_seq = (_tcp_seq + max(len(_payload), 1)) & 0xFFFF_FFFF
                            if interval and not skip_intervals:
                                time.sleep(interval)
                    elif upb:
                        dport, payload_builder = upb
                        for _ in range(count):
                            marker = b'' if no_marker else build_marker(run_id, tech, step_id)
                            _udp_opts = {**options}
                            if proto == "bacnet":
                                _udp_opts["bacnet_invoke_id"] = _bacnet_inv
                                _bacnet_inv = (_bacnet_inv + 1) & 0xFF
                            packets.append(udp_packet(src_ip, dst_ip, dport, payload_builder(marker, style=style, **_udp_opts)))
                            if interval and not skip_intervals:
                                time.sleep(interval)

    if build_pcap and packets:
        write_pcap(packets, pcap_path)

    return {"run_id": (run_id or "offline"), "events": events_path, "pcap": pcap_path if (build_pcap and packets) else None}
