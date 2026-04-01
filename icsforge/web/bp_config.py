"""ICSForge config blueprint — network config, callback setup, health, interfaces."""
import re
import subprocess
import sys
import socket
import threading as _threading
import time
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from icsforge.web.helpers import set_webhook_url, get_webhook_url, fire_webhook
from icsforge import __version__
from icsforge.web.helpers import (
    _build_sender_callback_url, _callback_headers, _list_packs, _repo_root, _save_persisted_config,
    log, os, json,
)
import icsforge.web.helpers as _h

bp = Blueprint("bp_config", __name__)


# ── Network config
@bp.route("/api/config/network", methods=["GET", "POST"])
def api_config_network():
    if request.method == "GET":
        return jsonify({
            "sender_ip": _h._sender_ip or "127.0.0.1",
            "receiver_ip": _h._receiver_ip or "",
            "receiver_port": _h._receiver_port,
            "sender_callback_url": _h._sender_callback_url or "",
            "callback_token": _h._callback_token or "",
            "pull_enabled": _h._pull_enabled,
        })
    data = request.get_json(force=True) or {}
    if "sender_ip" in data:
        _h._sender_ip = (data.get("sender_ip") or "").strip() or None
    if "receiver_ip" in data:
        _h._receiver_ip = (data.get("receiver_ip") or "").strip() or None
    if data.get("receiver_port"):
        _h._receiver_port = int(data["receiver_port"])
    if "sender_callback_url" in data:
        _h._sender_callback_url = (data.get("sender_callback_url") or "").strip() or None
    if "callback_token" in data:
        _h._callback_token = (data.get("callback_token") or "").strip() or None
    if "pull_enabled" in data:
        _h._pull_enabled = bool(data.get("pull_enabled"))
    _save_persisted_config()
    if _h._pull_enabled and _h._receiver_ip:
        _h.start_pull_mode()
    else:
        _h.stop_pull_mode()
    try:
        from icsforge.receiver.receiver import set_callback_token, set_callback_url  # optional
        set_callback_url(_h._sender_callback_url or "")
        set_callback_token(_h._callback_token or "")
    except ImportError:
        pass  # receiver module not loaded in sender-only deployments
    return jsonify({
        "ok": True,
        "sender_ip": _h._sender_ip or "127.0.0.1",
        "receiver_ip": _h._receiver_ip or "",
        "receiver_port": _h._receiver_port,
        "sender_callback_url": _h._sender_callback_url or "",
        "callback_token": _h._callback_token or "",
        "pull_enabled": _h._pull_enabled,
    })


# ── Receiver IP config + push
@bp.route("/api/config/receiver_ip", methods=["GET", "POST"])
def api_config_receiver_ip():
    if request.method == "GET":
        return jsonify({"receiver_ip": _h._receiver_ip, "receiver_port": _h._receiver_port})
    data = request.get_json(force=True) or {}
    ip = (data.get("receiver_ip") or "").strip()
    if not ip:
        return jsonify({"error": "receiver_ip required"}), 400
    _h._receiver_ip = ip
    if data.get("receiver_port"):
        _h._receiver_port = int(data["receiver_port"])
    if "sender_callback_url" in data:
        _h._sender_callback_url = (data.get("sender_callback_url") or "").strip() or None
    if "callback_token" in data:
        _h._callback_token = (data.get("callback_token") or "").strip() or None
    _save_persisted_config()
    callback_url = _build_sender_callback_url(request)
    configured_callback = False
    push_error = ""
    try:
        import urllib.request
        payload = json.dumps({
            "callback_url": callback_url,
            "callback_token": _h._callback_token or "",
        }).encode("utf-8")
        req_obj = urllib.request.Request(
            f"http://{ip}:{_h._receiver_port}/api/config/set_callback",
            data=payload,
            headers=_callback_headers(),
            method="POST",
        )
        resp = urllib.request.urlopen(req_obj, timeout=3)
        configured_callback = (resp.status == 200)
    except (OSError, ValueError) as exc:
        push_error = str(exc)
        log.debug("Callback push to receiver failed: %s", exc)
    return jsonify({
        "ok": True,
        "receiver_ip": _h._receiver_ip,
        "receiver_port": _h._receiver_port,
        "callback_configured": configured_callback,
        "callback_url": callback_url,
        "push_error": push_error,
    })


# ── Set callback (receiver-side, auth-exempt)
@bp.route("/api/config/set_callback", methods=["POST"])
def api_config_set_callback():
    data = request.get_json(force=True) or {}
    callback_url = (data.get("callback_url") or "").strip()
    callback_token = (data.get("callback_token") or "").strip()
    if not callback_url:
        return jsonify({"error": "callback_url required"}), 400
    try:
        from icsforge.receiver.receiver import set_callback_token, set_callback_url
        set_callback_url(callback_url)
        set_callback_token(callback_token)
        return jsonify({"ok": True, "callback_url": callback_url, "callback_token_set": bool(callback_token)})
    except (ImportError, OSError) as exc:
        log.error("set_callback failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── Test callback
@bp.route("/api/config/test_callback", methods=["POST"])
def api_config_test_callback():
    callback_url = (_h._sender_callback_url or "").strip()
    if not callback_url:
        try:
            from icsforge.receiver.receiver import get_callback_url
            callback_url = (get_callback_url() or "").strip()
        except ImportError:
            callback_url = ""
    if not callback_url:
        return jsonify({"error": "No sender callback URL configured"}), 400
    started = time.time()
    try:
        import urllib.request
        payload = json.dumps({
            "marker_found": True,
            "run_id": "TEST-CALLBACK",
            "technique": "T0000",
            "step": "receiver_callback_test",
            "receiver.proto": "http",
            "bytes": 0,
            "@timestamp": datetime.now(timezone.utc).isoformat(),
        }).encode("utf-8")
        req_obj = urllib.request.Request(
            callback_url,
            data=payload,
            headers=_callback_headers(),
            method="POST",
        )
        with urllib.request.urlopen(req_obj, timeout=3) as resp:
            body = resp.read(400).decode("utf-8", "ignore")
            return jsonify({
                "ok": True,
                "callback_url": callback_url,
                "status": resp.status,
                "response_ms": int((time.time() - started) * 1000),
                "body": body,
            })
    except (OSError, ValueError) as exc:
        return jsonify({
            "ok": False,
            "callback_url": callback_url,
            "error": str(exc),
            "response_ms": int((time.time() - started) * 1000),
        }), 502


# ── Interfaces
@bp.route("/api/interfaces")
def api_interfaces():
    ifaces = []
    try:
        out = subprocess.check_output(["ip", "-o", "link", "show"], stderr=subprocess.STDOUT, text=True)
        for line in out.splitlines():
            m = re.match(r"\d+:\s+([^:@]+)[@:]", line)
            if m:
                name = m.group(1).strip()
                if name and name != "lo":
                    ifaces.append(name)
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("ip link failed, trying ifconfig: %s", exc)
    if not ifaces:
        try:
            out = subprocess.check_output(["ifconfig", "-a"], stderr=subprocess.STDOUT, text=True)
            for line in out.splitlines():
                if line and not line.startswith("\t") and ":" in line:
                    name = line.split(":")[0].strip()
                    if name and name != "lo":
                        ifaces.append(name)
        except (OSError, subprocess.SubprocessError) as exc:
            log.debug("ifconfig also failed: %s", exc)
    return jsonify({"interfaces": sorted(set(ifaces))})


# ── Selftest
@bp.route("/api/selftest", methods=["POST"])
def api_selftest():
    data = request.get_json(force=True) or {}
    live = bool(data.get("live"))
    dst_ip = (data.get("dst_ip") or "127.0.0.1").strip()
    bind = (data.get("bind") or "127.0.0.1").strip()
    cwd = (data.get("cwd") or _repo_root()).strip()
    receipts = (data.get("receipts") or "receiver_out/receipts.jsonl").strip()
    cmd = [sys.executable, "-m", "icsforge", "selftest"]
    if live:
        cmd += ["--live", "--dst-ip", dst_ip, "--bind", bind]
    cmd += ["--cwd", cwd, "--receipts", receipts]
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=180)
        return jsonify({
            "ok": p.returncode == 0,
            "returncode": p.returncode,
            "stdout": p.stdout[-8000:],
            "stderr": p.stderr[-8000:],
            "cmd": cmd,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "selftest timed out"}), 500
    except (OSError, ValueError) as exc:
        log.error("Selftest subprocess failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── Health API
@bp.route("/api/health")
def api_health():
    rr = _repo_root()
    packs = _list_packs()
    caps: dict = {}
    try:
        if hasattr(socket, "AF_PACKET"):
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)  # type: ignore[attr-defined]
            sock.close()
            caps["af_packet"] = True
            caps["profinet_live"] = True
        else:
            caps["af_packet"] = False
            caps["profinet_live"] = False
            caps["af_packet_note"] = "AF_PACKET not available (Linux only)"
    except PermissionError:
        caps["af_packet"] = False
        caps["profinet_live"] = False
        caps["af_packet_note"] = "AF_PACKET requires root or CAP_NET_RAW"
    except (OSError, AttributeError) as exc:
        caps["af_packet"] = False
        caps["profinet_live"] = False
        caps["af_packet_note"] = str(exc)
    caps["tcp_send"] = True
    caps["pcap_write"] = True
    receiver = request.args.get("receiver", "").strip()
    receiver_ok = None
    receiver_err = None
    if receiver:
        try:
            import urllib.request
            with urllib.request.urlopen(receiver.rstrip("/") + "/api/receiver/health", timeout=2) as r:
                receiver_ok = (200 <= r.status < 300)
        except (OSError, ValueError) as exc:
            receiver_ok = False
            receiver_err = str(exc)
    return jsonify({
        "ok": True,
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "repo_root": rr,
        "scenario_pack_count": len(packs),
        "scenario_packs": packs,
        "capabilities": caps,
        "receiver": receiver if receiver else None,
        "receiver_ok": receiver_ok,
        "receiver_error": receiver_err,
    })


# ── EVE tap state (module-level) ──────────────────────────────────────
_active_eve_tap = None
_active_eve_tap_lock = _threading.Lock()


@bp.route("/api/eve/start", methods=["POST"])
def api_eve_start():
    """Start tailing a Suricata EVE JSON log for the current run."""
    global _active_eve_tap
    data = request.get_json(force=True) or {}
    eve_path = (data.get("eve_path") or "").strip()
    run_id = (data.get("run_id") or "").strip() or None
    rules_text = (data.get("rules_text") or "").strip()
    if not eve_path:
        return jsonify({"error": "eve_path required"}), 400
    rr = os.path.realpath(_repo_root())
    real = os.path.realpath(eve_path)
    allowed_prefixes = (rr, "/var/log/suricata", "/var/log", "/tmp")
    if not any(real.startswith(p) for p in allowed_prefixes):
        return jsonify({"error": "eve_path not in an allowed directory"}), 400
    try:
        from icsforge.eve.tap import EveTap, build_technique_map_from_rules
        from icsforge.web.helpers_sse import notify_sse
        technique_map = build_technique_map_from_rules(rules_text) if rules_text else {}
        def _on_match(match):
            notify_sse({**match, "type": "eve_match"})
        with _active_eve_tap_lock:
            if _active_eve_tap:
                _active_eve_tap.stop(timeout=1.0)
            tap = EveTap(real, run_id=run_id, on_match=_on_match, technique_map=technique_map)
            tap.start()
            _active_eve_tap = tap
        return jsonify({"ok": True, "eve_path": real, "run_id": run_id,
                        "technique_map_size": len(technique_map)})
    except (OSError, ImportError) as exc:
        log.error("EVE tap start failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


@bp.route("/api/eve/stop", methods=["POST"])
def api_eve_stop():
    """Stop the active EVE tap and return matched detections."""
    global _active_eve_tap
    with _active_eve_tap_lock:
        if not _active_eve_tap:
            return jsonify({"ok": True, "matches": [], "note": "no active tap"})
        matches = _active_eve_tap.stop(timeout=3.0)
        _active_eve_tap = None
    return jsonify({"ok": True, "matches": matches, "count": len(matches)})


@bp.route("/api/eve/matches")
def api_eve_matches():
    """Return current matches from the active EVE tap without stopping it."""
    with _active_eve_tap_lock:
        if not _active_eve_tap:
            return jsonify({"matches": [], "active": False})
        matches = _active_eve_tap.get_matches()
    return jsonify({"matches": matches, "count": len(matches), "active": True})

# ── Webhook config (v0.49) ────────────────────────────────────────────
@bp.route("/api/config/webhook", methods=["GET", "POST"])
def api_config_webhook():
    """Get or set the webhook URL for run/campaign completion notifications."""
    if request.method == "GET":
        return jsonify({"webhook_url": get_webhook_url() or ""})
    data = request.get_json(force=True) or {}
    url = (data.get("webhook_url") or "").strip()
    set_webhook_url(url or None)
    return jsonify({"ok": True, "webhook_url": url or ""})


@bp.route("/api/config/test_webhook", methods=["POST"])
def api_config_test_webhook():
    """Fire a test webhook event to verify the URL is reachable."""
    url = get_webhook_url()
    if not url:
        return jsonify({"error": "No webhook URL configured"}), 400
    ok = fire_webhook("run_complete", {
        "run_id": "TEST-WEBHOOK",
        "scenario": "test",
        "note": "ICSForge webhook test event",
    })
    return jsonify({"ok": ok, "webhook_url": url})
