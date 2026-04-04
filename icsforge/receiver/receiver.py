"""
ICSForge Receiver — pure Python, zero scapy dependency.

TCP listeners   : SOCK_STREAM accept loop per protocol/port
L2 PROFINET DCP : AF_PACKET raw socket with promiscuous mode (Linux only)

v0.4: thread-safe receipt writing, structured logging, proper error handling.
"""

import argparse
import fcntl
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time
from contextlib import suppress
from datetime import datetime, timezone

import yaml

from icsforge.core import marker_prefix
from icsforge.log import configure as configure_logging
from icsforge.log import get_logger

log = get_logger(__name__)

# ── Thread-safe receipt writer + sender callback ──────────────────────

_receipt_lock = threading.Lock()
_callback_url = ""       # set by config, CLI, or sender push
_callback_token = ""     # optional shared token for callback auth
_callback_timeout = 2


def set_callback_url(url: str):
    """Set the sender callback URL (called from config, CLI, or API)."""
    global _callback_url
    _callback_url = (url or "").strip()
    if _callback_url:
        log.info("Sender callback URL set: %s", _callback_url)


def set_callback_token(token: str):
    """Set optional shared callback token."""
    global _callback_token
    _callback_token = (token or "").strip()
    if _callback_token:
        log.info("Sender callback token configured")


def get_callback_url() -> str:
    return _callback_url


def get_callback_token() -> str:
    return _callback_token


def _now():
    return datetime.now(timezone.utc).isoformat()


def _parse_marker(payload: bytes) -> dict:
    pref = marker_prefix()
    i = payload.find(pref)
    if i < 0:
        return {"marker_found": False}
    tail = payload[i:]
    parts = tail.split(b"|", 3)
    run_id = parts[1].decode("utf-8", "ignore") if len(parts) > 1 else ""
    tech = parts[2].decode("utf-8", "ignore") if len(parts) > 2 else ""
    step = parts[3].decode("utf-8", "ignore") if len(parts) > 3 else ""
    return {"marker_found": True, "run_id": run_id, "technique": tech, "step": step}


def _send_callback(ev: dict):
    """Fire-and-forget HTTP POST to sender callback URL."""
    url = _callback_url
    if not url:
        return
    try:
        import urllib.request
        data = json.dumps(ev, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if _callback_token:
            headers["X-ICSForge-Callback-Token"] = _callback_token
        req = urllib.request.Request(
            url, data=data,
            headers=headers,
            method="POST",
        )
        urllib.request.urlopen(req, timeout=_callback_timeout)
    except Exception as e:
        log.debug("Callback to %s failed: %s", url, e)


def _write_receipt(path: str, ev: dict):
    """Thread-safe append of a receipt event to JSONL file, plus sender callback."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    line = json.dumps(ev, ensure_ascii=False) + "\n"
    with _receipt_lock, open(path, "a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
    # Send callback to sender (non-blocking via thread)
    if _callback_url and ev.get("marker_found"):
        threading.Thread(target=_send_callback, args=(ev,), daemon=True).start()


# ── TCP listener (Modbus/DNP3/S7comm/IEC-104/OPC-UA/EtherNet-IP) ─────


def _handle_tcp(conn, addr, proto, port, receipts_path, max_payload):
    try:
        data = conn.recv(max_payload)
        if not data:
            return
        meta = _parse_marker(data)
        ev = {
            "@timestamp": _now(),
            "receiver.proto": proto,
            "receiver.port": port,
            "src_ip": addr[0],
            "src_port": addr[1],
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            **meta,
        }
        _write_receipt(receipts_path, ev)
        if meta.get("marker_found"):
            log.debug("Receipt: %s %s from %s:%d", proto, meta.get("technique", "?"), addr[0], addr[1])
    except Exception as e:
        log.debug("TCP handler error (%s:%d): %s", proto, port, e)
    finally:
        with suppress(Exception):
            conn.close()


def _tcp_server(bind_ip, port, proto, receipts_path, max_payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((bind_ip, port))
    except OSError as e:
        log.error("Cannot bind %s TCP on %s:%d — %s", proto, bind_ip, port, e)
        return
    s.listen(200)
    log.info("%s TCP listening on %s:%d", proto, bind_ip, port)
    while True:
        try:
            c, a = s.accept()
            threading.Thread(
                target=_handle_tcp,
                args=(c, a, proto, port, receipts_path, max_payload),
                daemon=True,
            ).start()
        except Exception as e:
            log.error("TCP accept error (%s:%d): %s", proto, port, e)


# ── UDP listener (BACnet/IP) ──────────────────────────────────────────


def _udp_server(bind_ip, port, proto, receipts_path, max_payload):
    """UDP datagram listener. Used for BACnet/IP (port 47808)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((bind_ip, port))
    except OSError as e:
        log.error("Cannot bind %s UDP on %s:%d — %s", proto, bind_ip, port, e)
        return
    log.info("%s UDP listening on %s:%d", proto, bind_ip, port)
    while True:
        try:
            data, addr = s.recvfrom(max_payload)
            if not data:
                continue
            meta = _parse_marker(data)
            ev = {
                "@timestamp": _now(),
                "receiver.proto": proto,
                "receiver.port": port,
                "receiver.transport": "udp",
                "src_ip": addr[0],
                "src_port": addr[1],
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                **meta,
            }
            _write_receipt(receipts_path, ev)
            if meta.get("marker_found"):
                log.debug("Receipt: %s %s from %s:%d (UDP)", proto, meta.get("technique", "?"), addr[0], addr[1])
        except Exception as e:
            log.error("UDP recv error (%s:%d): %s", proto, port, e)


# ── L2 PROFINET DCP listener ──────────────────────────────────────────

_ETH_P_PN_DCP = 0x8892
_ETH_P_ALL = 0x0003
_SOL_PACKET = 263
_PACKET_ADD_MEMBERSHIP = 1
_PACKET_DROP_MEMBERSHIP = 2
_PACKET_MR_PROMISC = 1


def _get_ifindex(iface):
    SIOCGIFINDEX = 0x8933
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack("16sI", iface.encode()[:15], 0)
        res = fcntl.ioctl(s.fileno(), SIOCGIFINDEX, ifreq)
        return struct.unpack("16sI", res)[1]
    finally:
        s.close()


def _set_promisc(sock, iface, enable):
    try:
        ifindex = _get_ifindex(iface)
        mreq = struct.pack("IHH8s", ifindex, _PACKET_MR_PROMISC, 0, b"\x00" * 8)
        opt = _PACKET_ADD_MEMBERSHIP if enable else _PACKET_DROP_MEMBERSHIP
        sock.setsockopt(_SOL_PACKET, opt, mreq)
    except Exception as e:
        log.warning("promisc %s on '%s': %s", "enable" if enable else "disable", iface, e)


def _parse_profinet_frame(raw):
    if len(raw) < 14:
        return None
    ethertype = struct.unpack(">H", raw[12:14])[0]
    if ethertype != _ETH_P_PN_DCP:
        return None
    src_mac = ":".join(f"{b:02x}" for b in raw[6:12])
    dst_mac = ":".join(f"{b:02x}" for b in raw[0:6])
    payload = raw[14:]
    meta = _parse_marker(payload)
    return {
        "@timestamp": _now(),
        "receiver.proto": "profinet_dcp",
        "receiver.port": 0,
        "receiver.l2": True,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        **meta,
    }


def _l2_profinet_listener(iface, receipts_path, max_payload):
    if not hasattr(socket, "AF_PACKET"):
        log.warning("PROFINET L2 skipped: AF_PACKET not available (Linux only)")
        return
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(_ETH_P_ALL))
    except PermissionError:
        log.error("PROFINET L2 on '%s': permission denied — run as root or grant CAP_NET_RAW", iface)
        return
    except OSError as e:
        log.error("PROFINET L2 on '%s': %s", iface, e)
        return
    try:
        sock.bind((iface, socket.htons(_ETH_P_ALL)))
    except OSError as e:
        log.error("PROFINET L2 bind to '%s': %s", iface, e)
        sock.close()
        return

    _set_promisc(sock, iface, enable=True)
    log.info("profinet_dcp L2 listening on '%s' (ethertype 0x%04x, promiscuous ON)", iface, _ETH_P_PN_DCP)

    while True:
        try:
            raw, addr_info = sock.recvfrom(max_payload)
        except Exception:
            continue
        pkttype = addr_info[2] if len(addr_info) > 2 else 0
        ev = _parse_profinet_frame(raw)
        if ev is not None:
            ev["pkttype"] = pkttype
            try:
                _write_receipt(receipts_path, ev)
            except Exception as e:
                log.error("Failed to write PROFINET receipt: %s", e)


# ── Entry point ───────────────────────────────────────────────────────


def main():


    ap = argparse.ArgumentParser(prog="icsforge-receiver")
    ap.add_argument("--web", action="store_true", default=True)
    ap.add_argument("--web-host", default="0.0.0.0")
    ap.add_argument("--web-port", type=int, default=9090)
    ap.add_argument("--host", dest="web_host", help="Alias for --web-host")
    ap.add_argument("--port", dest="web_port", type=int, help="Alias for --web-port")
    ap.add_argument("--no-web", action="store_true")
    ap.add_argument("--config", default=os.path.join(os.path.dirname(__file__), "config.yml"))
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--l2-iface", default="", help="Interface for PROFINET DCP L2 capture")
    ap.add_argument("--log-level", default="INFO", help="DEBUG, INFO, WARNING, ERROR")
    ap.add_argument("--log-file", default=None, help="Log to file in addition to stderr")
    ap.add_argument("--callback-url", default="", help="Sender callback URL for live receipt forwarding")
    args = ap.parse_args()

    configure_logging(level=args.log_level, log_file=args.log_file)

    if getattr(args, "web_host", None) and args.bind == "0.0.0.0":
        args.bind = args.web_host

    with open(args.config, encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    listen = cfg.get("listen") or {}
    udp_listen = cfg.get("udp_listen") or {}
    l2_listen = cfg.get("l2_listen") or {}
    receipts_path = (cfg.get("log") or {}).get("receipts", "./receiver_out/receipts.jsonl")
    max_payload = int((cfg.get("safety") or {}).get("max_payload", 8192))

    # Sender callback URL — CLI overrides config
    global _callback_url, _callback_token, _callback_timeout
    cb_cfg = cfg.get("callback") or {}
    cb_url = (args.callback_url or "").strip() or (cb_cfg.get("url") or "").strip()
    cb_token = (cb_cfg.get("token") or "").strip()
    _callback_timeout = int(cb_cfg.get("timeout", 2))
    if cb_url:
        set_callback_url(cb_url)
    if cb_token:
        set_callback_token(cb_token)

    # TCP listeners
    for proto, port in listen.items():
        threading.Thread(target=_tcp_server, args=(args.bind, int(port), proto, receipts_path, max_payload), daemon=True).start()

    # UDP listeners (BACnet/IP)
    for proto, port in udp_listen.items():
        threading.Thread(target=_udp_server, args=(args.bind, int(port), proto, receipts_path, max_payload), daemon=True).start()

    pn_iface = (args.l2_iface or "").strip() or (l2_listen.get("profinet_dcp") or "").strip()
    if pn_iface:
        os.environ["ICSFORGE_L2_IFACE"] = pn_iface
        threading.Thread(target=_l2_profinet_listener, args=(pn_iface, receipts_path, max(max_payload, 1518)), daemon=True).start()
    else:
        log.info("PROFINET L2 listener disabled (set l2_listen.profinet_dcp or --l2-iface)")

    log.info("Receipts: %s", receipts_path)

    enable_web = (not args.no_web) and args.web
    if enable_web:
        try:
            from icsforge.web.app import main as web_main

            def _run_web():
                os.environ["ICSFORGE_UI_MODE"] = "receiver"
                sys.argv = ["icsforge-web", "--host", args.web_host, "--port", str(args.web_port)]
                web_main()

            threading.Thread(target=_run_web, daemon=True).start()
            log.info("Web UI: http://%s:%d", args.web_host, args.web_port)
        except Exception as e:
            log.error("Web UI failed to start: %s", e)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Receiver stopped.")


if __name__ == "__main__":
    main()
