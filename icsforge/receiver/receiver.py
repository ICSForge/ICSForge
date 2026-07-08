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

from icsforge.core import marker_prefix  # noqa: F401 — retained for compat
from icsforge.log import configure as configure_logging
from icsforge.log import get_logger

log = get_logger(__name__)

# ── Thread-safe receipt writer + sender callback ──────────────────────

_receipt_lock = threading.Lock()
_callback_url = ""       # set by config, CLI, or sender push
_callback_token = ""     # optional shared token for callback auth
_callback_timeout = 2

# ── Expectation registry (markerless correlation) ─────────────────────
#
# Some scenarios cannot embed the ICSFORGE_SYNTH marker in the wire
# bytes — IEC-104 is one (its ASDU length field makes trailing bytes
# unparseable; documented in protocols/iec104.py), and stealth mode
# (--no-marker) intentionally omits the marker from every protocol.
#
# Without a marker, the receiver still observes the packet but cannot
# attribute it to a specific (run_id, scenario, step). The expectation
# registry closes that gap: the sender announces the upcoming run via
# POST /api/receiver/expect BEFORE replay, and the receiver attributes
# any non-marker traffic that arrives within the announced window to
# that run.
#
# Expectations are TTL-bounded; once expired, traffic without a marker
# generates a marker_found=False receipt with no callback (legacy behavior).

_expect_lock = threading.Lock()
_expectations: dict[str, dict] = {}  # run_id -> {expires_at, scenario, technique, steps}


def register_expectation(run_id: str, scenario: str = "", technique: str = "",
                         steps: int = 1, ttl_sec: float = 300.0,
                         protos: list | None = None,
                         test_profile: str = "", expected_alert: str = "") -> dict:
    """
    Register an expectation that traffic for run_id is about to arrive.

    Args:
      run_id     — the run identifier the sender will use.
      scenario   — scenario name being run (e.g. T0855__unauth_command__iec104).
      technique  — primary MITRE technique ID (e.g. T0855).
      steps      — number of steps in the scenario (used for diagnostics).
      ttl_sec    — how long to keep the expectation alive (default 5 min).
      protos     — optional list of expected protocols (iec104, modbus, ...).
                   When set, only matching proto traffic is attributed.
      test_profile — "firewall" or "nsm" (or "" if unspecified). Records the
                   operator's intent so witnessed receipts and reports can be
                   framed correctly: firewall/ACL runs treat arrival as a
                   boundary-traversal finding; NSM runs treat arrival as the
                   expected condition and pair it with the expected alert.
      expected_alert — free-text description of the alert the NSM is expected to
                   raise for this scenario (e.g. the technique name or a rule
                   reference), surfaced in the witnessed report for diffing.

    The expectation is replaced if run_id already exists (so calling this
    again for the same run extends the window).
    """
    if not run_id:
        return {}
    expires_at = time.time() + max(1.0, float(ttl_sec))
    entry = {
        "run_id": run_id,
        "scenario": str(scenario or ""),
        "technique": str(technique or ""),
        "steps": int(steps or 1),
        "expires_at": expires_at,
        "protos": list(protos) if protos else None,
        "received": 0,  # incremented per attributed packet
        "test_profile": str(test_profile or ""),
        "expected_alert": str(expected_alert or ""),
    }
    with _expect_lock:
        _expectations[run_id] = entry
    log.debug("Expectation registered: run_id=%s scenario=%s profile=%s ttl=%.0fs",
              run_id, scenario, test_profile or "-", ttl_sec)
    return entry


def clear_expectation(run_id: str) -> bool:
    """Remove an expectation early. Returns True if one existed."""
    with _expect_lock:
        return _expectations.pop(run_id, None) is not None


def list_expectations() -> list[dict]:
    """Return a snapshot of currently active expectations."""
    now = time.time()
    with _expect_lock:
        # Drop expired in-place
        for k in list(_expectations.keys()):
            if _expectations[k]["expires_at"] <= now:
                _expectations.pop(k, None)
        return [dict(v) for v in _expectations.values()]


def _expectation_enrichment(expectation: dict) -> dict:
    """Fields lifted from an expectation into a witnessed receipt so the report
    can frame results by test profile and diff witnessed-vs-expected. Kept in
    one place so both attribution paths (covert_band and expectation) stay
    consistent."""
    return {
        "test_profile": expectation.get("test_profile", ""),
        "expected_technique": expectation.get("technique", ""),
        "expected_scenario": expectation.get("scenario", ""),
        "expected_alert": expectation.get("expected_alert", ""),
    }


def _match_expectation(proto: str | None) -> dict | None:
    """
    Return the active expectation that should attribute incoming traffic.

    Currently FIFO by registration order — if multiple expectations are
    active, the oldest one matching proto wins. In practice we expect
    one active expectation at a time (a single sender, single run).
    """
    now = time.time()
    with _expect_lock:
        # Expire stale entries
        for k in list(_expectations.keys()):
            if _expectations[k]["expires_at"] <= now:
                _expectations.pop(k, None)
        # Find earliest-registered match
        candidates = []
        for v in _expectations.values():
            if v["protos"] is None or proto is None or proto in v["protos"]:
                candidates.append(v)
        if not candidates:
            return None
        # Earliest expires_at = earliest registered (for FIFO semantics
        # under the assumption of equal TTL)
        return min(candidates, key=lambda x: x["expires_at"])


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


def _parse_marker(payload: bytes, proto: str | None = None) -> dict:
    """
    Extract correlation metadata from payload.

    v0.74.0 marker model (three detection paths, most-specific first):

    1. Explicit compact marker: 'ICSF' + 1-byte proto code + 8 hex chars of
       the run hash, embedded in the payload (DNP3 always; MQTT; and any
       protocol in --explicit-marker mode). marker_found=True,
       attributed_via='marker'.

    2. Covert field marker: the synthetic band byte (0xF7) at the protocol's
       covert-field offset (Modbus txn-ID @0, S7 PDU-ref @11, ENIP sender
       context @12, OPC UA request handle @40, BACnet invoke ID @8). This is
       the Layer-1 signal; combined with an active expectation it attributes
       the packet and (when the run key is known) can be HMAC-verified for
       Layer-2 confidence. attributed_via='covert_band'.

    3. Expectation fallback: no marker on the wire but an active expectation
       for this proto (IEC-104, --no-marker stealth, PINGREQ-only MQTT).
       attributed_via='expectation'.
    """
    # ── Path 1: explicit compact 'ICSF' marker ───────────────────────────
    i = payload.find(b"ICSF")
    if i >= 0 and len(payload) >= i + 13:
        blob = payload[i:i + 13]
        proto_code = blob[4:5]
        run_hash = blob[5:13].decode("ascii", "ignore")
        return {
            "marker_found": True,
            "run_id": "",            # run_id not inline; resolved via registry/hash
            "run_hash": run_hash,
            "proto_code": proto_code.decode("ascii", "ignore"),
            "technique": "",
            "step": "",
            "attributed_via": "marker",
        }

    # ── Path 2: covert band byte at the protocol's covert-field offset ────
    _covert_offset = {
        "modbus": 0, "s7comm": 11, "enip": 12, "opcua": 41, "bacnet": 8,
    }
    off = _covert_offset.get(proto)
    if off is not None and len(payload) > off and payload[off] == 0xF7:
        expectation = _match_expectation(proto)
        if expectation is not None:
            with _expect_lock:
                if expectation["run_id"] in _expectations:
                    _expectations[expectation["run_id"]]["received"] += 1
            return {
                "marker_found": True,
                "run_id": expectation["run_id"],
                "technique": expectation["technique"],
                "scenario": expectation["scenario"],
                "step": "",
                "attributed_via": "covert_band",
                **_expectation_enrichment(expectation),
            }
        # Band present but no expectation to bind it to — still a synthetic
        # signal, but unattributed.
        return {"marker_found": True, "attributed_via": "covert_band", "run_id": ""}

    # ── Path 3: expectation-based attribution (no marker on the wire) ─────
    expectation = _match_expectation(proto)
    if expectation is not None:
        with _expect_lock:
            if expectation["run_id"] in _expectations:
                _expectations[expectation["run_id"]]["received"] += 1
        return {
            "marker_found": False,
            "run_id": expectation["run_id"],
            "technique": expectation["technique"],
            "scenario": expectation["scenario"],
            "step": "",
            "attributed_via": "expectation",
            **_expectation_enrichment(expectation),
        }
    return {"marker_found": False, "attributed_via": "none"}


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
            # Sign payload with HMAC-SHA256 so sender can verify receipt integrity
            import hashlib as _hl
            import hmac as _hmac
            headers["X-ICSForge-HMAC"] = _hmac.new(
                _callback_token.encode("utf-8"), data, _hl.sha256
            ).hexdigest()
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
    # Send callback to sender (non-blocking via thread).
    # Trigger on either a verified marker OR an expectation-attributed packet
    # (the latter covers IEC-104 and stealth-mode runs).
    if _callback_url and (ev.get("marker_found") or ev.get("attributed_via") == "expectation"):
        threading.Thread(target=_send_callback, args=(ev,), daemon=True).start()


# ── TCP listener (Modbus/DNP3/S7comm/IEC-104/OPC-UA/EtherNet-IP) ─────


def _handle_tcp(conn, addr, proto, port, receipts_path, max_payload):
    try:
        data = conn.recv(max_payload)
        if not data:
            return
        meta = _parse_marker(data, proto=proto)
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
            log.debug("Receipt: %s %s from %s:%d (marker)",
                      proto, meta.get("technique", "?"), addr[0], addr[1])
        elif meta.get("attributed_via") == "expectation":
            log.debug("Receipt: %s %s from %s:%d (expectation: run=%s)",
                      proto, meta.get("technique", "?"), addr[0], addr[1],
                      meta.get("run_id", "?"))
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
            meta = _parse_marker(data, proto=proto)
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
                log.debug("Receipt: %s %s from %s:%d (UDP, marker)",
                          proto, meta.get("technique", "?"), addr[0], addr[1])
            elif meta.get("attributed_via") == "expectation":
                log.debug("Receipt: %s %s from %s:%d (UDP, expectation: run=%s)",
                          proto, meta.get("technique", "?"), addr[0], addr[1],
                          meta.get("run_id", "?"))
        except Exception as e:
            log.error("UDP recv error (%s:%d): %s", proto, port, e)


# ── L2 PROFINET DCP listener ──────────────────────────────────────────

_ETH_P_PN_DCP  = 0x8892
_ETH_P_GOOSE   = 0x88B8
_ETH_P_ALL     = 0x0003
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
    meta = _parse_marker(payload, proto="profinet_dcp")
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


def _parse_goose_frame(raw):
    """Parse an IEC 61850 GOOSE frame and extract correlation metadata."""
    if len(raw) < 14:
        return None
    ethertype = struct.unpack(">H", raw[12:14])[0]
    if ethertype != _ETH_P_GOOSE:
        return None
    src_mac = ":".join(f"{b:02x}" for b in raw[6:12])
    dst_mac = ":".join(f"{b:02x}" for b in raw[0:6])
    payload = raw[14:]
    # GOOSE carries no covert field (no spare arbitrary bytes), so like IEC-104
    # it is attributed via the expectation registry. Pass proto so _parse_marker
    # can match an active iec61850 expectation; without it the expectation path
    # is skipped and every GOOSE frame returns attributed_via="none" (no receipt
    # callback fires).
    meta = _parse_marker(payload, proto="iec61850")
    return {
        "@timestamp": _now(),
        "receiver.proto": "iec61850",
        "receiver.port": 0,
        "receiver.l2": True,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        **meta,
    }


def _l2_goose_listener(iface, receipts_path, max_payload):
    """
    Listen for IEC 61850 GOOSE frames (EtherType 0x88B8) via AF_PACKET raw socket.

    GOOSE is a Layer-2 multicast protocol. The socket runs in promiscuous mode
    to capture both unicast and multicast GOOSE frames regardless of destination MAC.
    Requires Linux + root/CAP_NET_RAW.
    """
    if not hasattr(socket, "AF_PACKET"):
        log.warning("GOOSE L2 skipped: AF_PACKET not available (Linux only)")
        return
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(_ETH_P_ALL))
    except PermissionError:
        log.error("GOOSE L2 on '%s': permission denied — run as root or grant CAP_NET_RAW", iface)
        return
    except OSError as e:
        log.error("GOOSE L2 on '%s': %s", iface, e)
        return
    try:
        sock.bind((iface, socket.htons(_ETH_P_ALL)))
    except OSError as e:
        log.error("GOOSE L2 bind to '%s': %s", iface, e)
        sock.close()
        return

    _set_promisc(sock, iface, enable=True)
    log.info("iec61850 GOOSE L2 listening on '%s' (ethertype 0x%04x, promiscuous ON)", iface, _ETH_P_GOOSE)

    while True:
        try:
            raw, _ = sock.recvfrom(max_payload)
        except Exception:
            continue
        ev = _parse_goose_frame(raw)
        if ev is not None:
            try:
                _write_receipt(receipts_path, ev)
            except Exception as e:
                log.error("Failed to write GOOSE receipt: %s", e)


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
    ap.add_argument("--callback-token", default="", help="Shared token for callback authentication (must match sender)")
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
    cb_token = (getattr(args, 'callback_token', '') or "").strip() or (cb_cfg.get("token") or "").strip()
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
    goose_iface = (args.l2_iface or "").strip() or (l2_listen.get("iec61850") or "").strip()
    if pn_iface:
        os.environ["ICSFORGE_L2_IFACE"] = pn_iface
        threading.Thread(target=_l2_profinet_listener, args=(pn_iface, receipts_path, max(max_payload, 1518)), daemon=True).start()
        threading.Thread(target=_l2_goose_listener,    args=(pn_iface, receipts_path, max(max_payload, 1518)), daemon=True).start()
    elif goose_iface:
        os.environ["ICSFORGE_L2_IFACE"] = goose_iface
        threading.Thread(target=_l2_goose_listener, args=(goose_iface, receipts_path, max(max_payload, 1518)), daemon=True).start()
    else:
        log.info("L2 listeners disabled (set l2_listen.profinet_dcp/iec61850 or --l2-iface)")

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
