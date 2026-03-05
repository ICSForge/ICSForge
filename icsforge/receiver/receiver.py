"""
ICSForge Receiver — pure Python, zero scapy dependency.

TCP listeners   : SOCK_STREAM accept loop per protocol/port
L2 PROFINET DCP : AF_PACKET raw socket with promiscuous mode (Linux only)
"""
from __future__ import annotations
import fcntl, os, json, socket, struct, threading, hashlib, time
from datetime import datetime, timezone
import yaml
from icsforge.core import marker_prefix

def _now():
    return datetime.now(timezone.utc).isoformat()

def _ensure_dir(p: str):
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)

def _parse_marker(payload: bytes) -> dict:
    pref = marker_prefix()
    i = payload.find(pref)
    if i < 0:
        return {"marker_found": False}
    tail  = payload[i:]
    parts = tail.split(b"|", 3)
    run_id = parts[1].decode("utf-8", "ignore") if len(parts) > 1 else ""
    tech   = parts[2].decode("utf-8", "ignore") if len(parts) > 2 else ""
    step   = parts[3].decode("utf-8", "ignore") if len(parts) > 3 else ""
    return {"marker_found": True, "run_id": run_id, "technique": tech, "step": step}

def _write_receipt(path: str, ev: dict):
    _ensure_dir(path)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(ev, ensure_ascii=False) + "\n")


# ── TCP listener (Modbus/DNP3/S7comm/IEC-104/OPC-UA/EtherNet-IP) ─────

def _handle_tcp(conn: socket.socket, addr, proto: str, port: int,
                receipts_path: str, max_payload: int):
    try:
        data = conn.recv(max_payload)
        if not data:
            return
        meta = _parse_marker(data)
        ev = {
            "@timestamp":     _now(),
            "receiver.proto": proto,
            "receiver.port":  port,
            "src_ip":         addr[0],
            "src_port":       addr[1],
            "bytes":          len(data),
            "sha256":         hashlib.sha256(data).hexdigest(),
            **meta,
        }
        _write_receipt(receipts_path, ev)
    finally:
        try: conn.close()
        except Exception: pass

def _tcp_server(bind_ip: str, port: int, proto: str,
                receipts_path: str, max_payload: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_ip, port))
    s.listen(200)
    print(f"[ICSForge Receiver] {proto} TCP listening on {bind_ip}:{port}")
    while True:
        c, a = s.accept()
        threading.Thread(
            target=_handle_tcp,
            args=(c, a, proto, port, receipts_path, max_payload),
            daemon=True,
        ).start()


# ── L2 PROFINET DCP listener ──────────────────────────────────────────
#
# PROFINET DCP uses ethertype 0x8892, multicast dst MAC 01:0e:cf:00:00:00.
# Three requirements for reliable capture:
#
# 1. AF_PACKET / SOCK_RAW with ETH_P_ALL in the constructor (htons'd)
# 2. Promiscuous mode ON the interface — without it, the NIC hardware
#    filter drops 01:0e:cf:00:00:00 frames because the host hasn't joined
#    that multicast group via IGMP/MLD.
# 3. Use recvfrom() not recv() so we get the (ifname, proto, pkttype, ...)
#    tuple and can confirm the frame arrived on the right interface and
#    filter out PACKET_OUTGOING (pkttype=4) loopback copies.

_ETH_P_PN_DCP   = 0x8892
_ETH_P_ALL      = 0x0003

# ioctl constants for promiscuous mode
_SIOCGIFFLAGS   = 0x8913
_SIOCSIFFLAGS   = 0x8914
_IFF_PROMISC    = 0x100

# PACKET_ADD_MEMBERSHIP / PACKET_MR_PROMISC constants
_SOL_PACKET            = 263
_PACKET_ADD_MEMBERSHIP = 1
_PACKET_DROP_MEMBERSHIP= 2
_PACKET_MR_PROMISC     = 1


def _get_ifindex(iface: str) -> int:
    """Return the interface index for iface via SIOCGIFINDEX ioctl."""
    SIOCGIFINDEX = 0x8933
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack("16sI", iface.encode()[:15], 0)
        res   = fcntl.ioctl(s.fileno(), SIOCGIFINDEX, ifreq)
        return struct.unpack("16sI", res)[1]
    finally:
        s.close()


def _set_promisc(sock: socket.socket, iface: str, enable: bool):
    """
    Enable/disable promiscuous mode on *iface* for *sock* via
    PACKET_ADD_MEMBERSHIP / PACKET_DROP_MEMBERSHIP setsockopt.

    This is the per-socket approach: promisc is automatically released
    when the socket is closed, so we don't need to clean up manually.
    """
    try:
        ifindex = _get_ifindex(iface)
        # struct packet_mreq: mr_ifindex(4) + mr_type(2) + mr_alen(2) + mr_address(8)
        mreq = struct.pack("IHH8s", ifindex, _PACKET_MR_PROMISC, 0, b"\x00" * 8)
        opt  = _PACKET_ADD_MEMBERSHIP if enable else _PACKET_DROP_MEMBERSHIP
        sock.setsockopt(_SOL_PACKET, opt, mreq)  # type: ignore[attr-defined]
    except Exception as e:
        # Non-fatal: log and continue. Frame may still arrive if switch forwards it.
        print(f"[ICSForge Receiver] promisc {'enable' if enable else 'disable'} "
              f"on '{iface}': {e}")


def _parse_profinet_frame(raw: bytes) -> dict | None:
    """
    Parse a raw Ethernet frame captured by AF_PACKET SOCK_RAW.
    Returns a receipt dict if it's a PROFINET DCP frame (ethertype 0x8892)
    containing an ICSForge marker; None otherwise.
    """
    if len(raw) < 14:
        return None
    ethertype = struct.unpack(">H", raw[12:14])[0]
    if ethertype != _ETH_P_PN_DCP:
        return None

    src_mac = ":".join(f"{b:02x}" for b in raw[6:12])
    dst_mac = ":".join(f"{b:02x}" for b in raw[0:6])
    payload = raw[14:]
    meta    = _parse_marker(payload)

    return {
        "@timestamp":        _now(),
        "receiver.proto":    "profinet_dcp",
        "receiver.port":     0,
        "receiver.l2":       True,
        "src_mac":           src_mac,
        "dst_mac":           dst_mac,
        "bytes":             len(raw),
        "sha256":            hashlib.sha256(raw).hexdigest(),
        **meta,
    }


def _l2_profinet_listener(iface: str, receipts_path: str, max_payload: int):
    """
    Capture PROFINET DCP frames (ethertype 0x8892) on *iface*.

    Uses AF_PACKET SOCK_RAW + ETH_P_ALL + promiscuous mode.
    Promiscuous mode is required for multicast dst MAC 01:0e:cf:00:00:00.
    Requires Linux + root/CAP_NET_RAW.
    """
    if not hasattr(socket, "AF_PACKET"):
        print("[ICSForge Receiver] PROFINET L2 listener skipped: "
              "AF_PACKET not available (Linux only)")
        return

    try:
        sock = socket.socket(
            socket.AF_PACKET,           # type: ignore[attr-defined]
            socket.SOCK_RAW,
            socket.htons(_ETH_P_ALL),
        )
    except PermissionError:
        print(f"[ICSForge Receiver] PROFINET L2 listener on '{iface}': "
              "permission denied — run receiver as root or grant CAP_NET_RAW")
        return
    except OSError as e:
        print(f"[ICSForge Receiver] PROFINET L2 listener on '{iface}': {e}")
        return

    # Bind to the specific interface
    try:
        sock.bind((iface, socket.htons(_ETH_P_ALL)))
    except OSError as e:
        print(f"[ICSForge Receiver] PROFINET L2 bind to '{iface}': {e}")
        sock.close()
        return

    # Enable promiscuous mode — REQUIRED to receive multicast 01:0e:cf:00:00:00
    _set_promisc(sock, iface, enable=True)

    print(f"[ICSForge Receiver] profinet_dcp L2 listening on '{iface}' "
          f"(ethertype 0x{_ETH_P_PN_DCP:04x}, promiscuous mode ON)")

    while True:
        try:
            # recvfrom returns (data, (ifname, proto, pkttype, hatype, addr))
            # pkttype: 0=HOST, 1=BROADCAST, 2=MULTICAST, 3=OTHERHOST, 4=OUTGOING
            raw, addr_info = sock.recvfrom(max_payload)
        except Exception:
            continue

        pkttype = addr_info[2] if len(addr_info) > 2 else 0
        # Accept all pkttypes: 0=HOST, 1=BROADCAST, 2=MULTICAST, 3=OTHERHOST, 4=OUTGOING
        # pkttype=4 (OUTGOING) occurs when sender and receiver run on the same machine —
        # we must NOT filter it or same-host testing never logs profinet frames.

        ev = _parse_profinet_frame(raw)
        if ev is not None:
            ev["pkttype"] = pkttype
            try:
                _write_receipt(receipts_path, ev)
            except Exception:
                pass


# ── Entry point ───────────────────────────────────────────────────────

def main():
    import argparse
    ap = argparse.ArgumentParser(prog="icsforge-receiver")
    ap.add_argument("--web",       action="store_true", default=True)
    ap.add_argument("--web-host",  default="0.0.0.0")
    ap.add_argument("--web-port",  type=int, default=8080)
    ap.add_argument("--host",      dest="web_host",
                    help="Alias for --web-host")
    ap.add_argument("--port",      dest="web_port", type=int,
                    help="Alias for --web-port")
    ap.add_argument("--no-web",    action="store_true")
    ap.add_argument("--config",    default=os.path.join(os.path.dirname(__file__), "config.yml"))
    ap.add_argument("--bind",      default="0.0.0.0")
    ap.add_argument("--l2-iface",  default="",
                    help="Interface for PROFINET DCP L2 capture (e.g. eth0)")
    args = ap.parse_args()

    if getattr(args, "web_host", None) and args.bind == "0.0.0.0":
        args.bind = args.web_host

    cfg           = yaml.safe_load(open(args.config, "r", encoding="utf-8")) or {}
    listen        = cfg.get("listen") or {}
    l2_listen     = cfg.get("l2_listen") or {}
    receipts_path = (cfg.get("log") or {}).get("receipts", "./receiver_out/receipts.jsonl")
    max_payload   = int((cfg.get("safety") or {}).get("max_payload", 8192))

    # TCP listeners
    for proto, port in listen.items():
        threading.Thread(
            target=_tcp_server,
            args=(args.bind, int(port), proto, receipts_path, max_payload),
            daemon=True,
        ).start()

    # L2 PROFINET listener
    pn_iface = (args.l2_iface or "").strip() or (l2_listen.get("profinet_dcp") or "").strip()
    if pn_iface:
        os.environ["ICSFORGE_L2_IFACE"] = pn_iface   # expose to web UI status check
        threading.Thread(
            target=_l2_profinet_listener,
            args=(pn_iface, receipts_path, max(max_payload, 1518)),
            daemon=True,
        ).start()
    else:
        print("[ICSForge Receiver] PROFINET L2 listener disabled "
              "(set l2_listen.profinet_dcp in config.yml or pass --l2-iface eth0)")

    print("[ICSForge Receiver] receipts:", receipts_path)

    enable_web = (not args.no_web) and args.web
    if enable_web:
        try:
            from threading import Thread
            from icsforge.web.app import main as web_main

            def _run_web():
                os.environ["ICSFORGE_UI_MODE"] = "receiver"
                import sys
                sys.argv = ["icsforge-web", "--host", args.web_host,
                            "--port", str(args.web_port)]
                web_main()

            Thread(target=_run_web, daemon=True).start()
            print(f"[ICSForge Receiver] Web UI: http://{args.web_host}:{args.web_port}")
        except Exception as e:
            print("[ICSForge Receiver] Web UI failed to start:", e)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[ICSForge Receiver] stopped.")


if __name__ == "__main__":
    main()
