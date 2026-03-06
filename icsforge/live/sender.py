"""
ICSForge live sender — pure Python, zero scapy dependency.

TCP protocols: standard socket.create_connection()
UDP protocols: standard socket.SOCK_DGRAM (BACnet/IP)
PROFINET DCP:  AF_PACKET raw socket (Linux only; requires root/CAP_NET_RAW)
"""
from typing import List
import socket, struct, time

import yaml

from icsforge.core import build_marker, parse_interval, generate_run_id
from icsforge.log import get_logger
from icsforge.protocols import modbus, dnp3, s7comm, iec104, opcua, enip, profinet_dcp, bacnet


log = get_logger(__name__)

TCP_PROTOS = {
    "modbus":       (502,   modbus.build_payload),
    "dnp3":         (20000, dnp3.build_payload),
    "s7comm":       (102,   s7comm.build_payload),
    "iec104":       (2404,  iec104.build_payload),
    "opcua":        (4840,  opcua.build_payload),
    "enip":         (44818, enip.build_payload),
}

UDP_PROTOS = {
    "bacnet":       (47808, bacnet.build_payload),
}

# PROFINET DCP multicast MAC (DCP Identify / Hello target)
_PN_DST_MAC   = b"\x01\x0e\xcf\x00\x00\x00"
_PN_SRC_MAC   = b"\x02\x00\x00\x12\x34\x56"   # locally-administered synthetic MAC
_PN_ETHERTYPE = struct.pack(">H", 0x8892)
_ETH_P_ALL    = 0x0003


def _tcp_send(dst_ip: str, port: int, payload: bytes, timeout: float):
    s = socket.create_connection((dst_ip, port), timeout=timeout)
    try:
        s.sendall(payload)
    finally:
        try: s.shutdown(socket.SHUT_RDWR)
        except Exception: pass
        s.close()


def _udp_send(dst_ip: str, port: int, payload: bytes, timeout: float):
    """Send a UDP datagram. Used for BACnet/IP (port 47808)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, (dst_ip, port))
    finally:
        s.close()


def _send_profinet_dcp(iface: str, dcp_payload: bytes):
    """
    Send a PROFINET DCP Ethernet frame via AF_PACKET raw socket.

    Correct pattern:
      socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))  — protocol in constructor
      sendto(frame, (iface, 0))                        — interface in sendto addr

    Frame: dst_mac(6) + src_mac(6) + ethertype 0x8892 (2) + dcp_payload
    Padded to 60 bytes minimum Ethernet payload.

    Requires Linux + root/CAP_NET_RAW.
    """
    if not hasattr(socket, "AF_PACKET"):
        raise RuntimeError(
            "AF_PACKET not available (Linux only). "
            "PROFINET DCP live send requires Linux with root/CAP_NET_RAW."
        )

    frame = _PN_DST_MAC + _PN_SRC_MAC + _PN_ETHERTYPE + dcp_payload
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))

    # Use ETH_P_ALL so the socket can send any ethertype.
    # sendto address tuple: (ifname, proto) — proto=0 means "use ethertype from frame"
    sock = socket.socket(
        socket.AF_PACKET,                    # type: ignore[attr-defined]
        socket.SOCK_RAW,
        socket.htons(_ETH_P_ALL),
    )
    try:
        sock.sendto(frame, (iface, 0))
    finally:
        sock.close()


def load_scenarios(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def send_scenario_live(
    scenario_file: str,
    scenario_name: str,
    dst_ip: str,
    iface: str | None = None,
    confirm_live_network: bool = False,
    receiver_allowlist: List[str] | None = None,
    timeout: float = 2.0,
) -> dict:
    if not confirm_live_network:
        raise ValueError("Live send blocked: pass confirm_live_network=True to enable.")

    allow = receiver_allowlist or [dst_ip]
    if dst_ip not in allow:
        raise ValueError("Live send blocked: dst_ip not in receiver allowlist.")

    doc   = load_scenarios(scenario_file)
    sc    = (doc.get("scenarios") or {}).get(scenario_name)
    if not sc:
        raise ValueError(f"Scenario '{scenario_name}' not found")

    run_id = generate_run_id()
    sent   = 0
    errors = []

    for idx, step in enumerate(sc.get("steps", []), start=1):
        stype = (step.get("type") or "packet").strip().lower()
        if stype not in ("packet", "pcap"):
            continue

        proto    = step.get("proto")
        tech     = step.get("technique")
        style    = step.get("style", "auto")
        count    = int(step.get("count", 1))
        interval = parse_interval(step.get("interval", "0s"))
        step_id  = f"{scenario_name}:{idx}:{proto}"

        if proto == "profinet_dcp":
            if not iface:
                errors.append(f"step {idx}: profinet_dcp requires --iface (skipped)")
                continue
            for _ in range(count):
                marker  = build_marker(run_id, tech, step_id)
                payload = profinet_dcp.build_payload(marker, style=style)
                try:
                    _send_profinet_dcp(iface, payload)
                    sent += 1
                except Exception as e:
                    errors.append(f"step {idx} profinet_dcp send: {e}")
                if interval:
                    time.sleep(interval)

        else:
            if proto in TCP_PROTOS:
                port, builder = TCP_PROTOS[proto]
                for _ in range(count):
                    marker  = build_marker(run_id, tech, step_id)
                    payload = builder(marker, style=style)
                    try:
                        _tcp_send(dst_ip, port, payload, timeout)
                        sent += 1
                    except Exception as e:
                        errors.append(f"step {idx} {proto} TCP send: {e}")
                    if interval:
                        time.sleep(interval)
            elif proto in UDP_PROTOS:
                port, builder = UDP_PROTOS[proto]
                for _ in range(count):
                    marker  = build_marker(run_id, tech, step_id)
                    payload = builder(marker, style=style)
                    try:
                        _udp_send(dst_ip, port, payload, timeout)
                        sent += 1
                    except Exception as e:
                        errors.append(f"step {idx} {proto} UDP send: {e}")
                    if interval:
                        time.sleep(interval)
            else:
                errors.append(f"step {idx}: unsupported proto '{proto}' (skipped)")
                continue

    result: dict = {"run_id": run_id, "dst_ip": dst_ip, "sent": sent}
    if errors:
        result["warnings"] = errors
    return result
