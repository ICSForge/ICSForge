"""ICSForge receiver blueprint — overview, receipts, callback, live feed."""
import json
import os
import secrets
from datetime import datetime, timezone

from flask import Blueprint, Response, jsonify, request

import icsforge.web.helpers as _h
from icsforge.web.helpers import (
    _bin_receipts,
    _default_receipts_path,
    _live_receipts,
    _read_jsonl_tail,
    notify_sse,
    subscribe_sse,
    unsubscribe_sse,
)


def _receipt_key(r: dict) -> tuple:
    """Stable dedup key for a receipt — works across JSONL and in-memory sources."""
    return (
        r.get("run_id", ""),
        r.get("@timestamp", ""),
        r.get("technique", ""),
        r.get("proto", ""),
        r.get("src_ip", ""),
        r.get("src_port", ""),
    )

bp = Blueprint("bp_receiver", __name__)


# ── Receiver overview
@bp.route("/api/receiver/overview")
def api_receiver_overview():
    receipts_path = _default_receipts_path()
    # Count total lines in the file without loading all into memory
    total = 0
    if os.path.exists(receipts_path):
        with open(receipts_path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    total += 1
    # Load a capped tail for top-lists and run tracking
    items = _read_jsonl_tail(receipts_path, limit=2000)
    last = items[-1] if items else None
    techniques = {}
    protos = {}
    runs = set()
    for r in items:
        t = r.get("technique") or "unknown"
        p = r.get("receiver.proto") or "unknown"
        techniques[t] = techniques.get(t, 0) + 1
        protos[p]     = protos.get(p, 0) + 1
        if r.get("run_id"):
            runs.add(r["run_id"])
    top_tech  = sorted(techniques.items(), key=lambda x: x[1], reverse=True)[:8]
    top_proto = sorted(protos.items(),     key=lambda x: x[1], reverse=True)[:8]
    l2_iface  = os.environ.get("ICSFORGE_L2_IFACE", "").strip()
    return jsonify({
        "total":             total,
        "runs":              len(runs),
        "unique_techniques": len(techniques),
        "unique_protocols":  len(protos),
        "last_ts":           (last.get("@timestamp") or last.get("ts")) if last else None,
        "last_run_id":       (last.get("run_id") if last else None),
        "top_techniques":    top_tech,
        "top_protocols":     top_proto,
        "l2_iface":          l2_iface or None,
        "l2_active":         bool(l2_iface),
    })



# ── Receiver reset
@bp.route("/api/receiver/reset", methods=["POST"])
def api_receiver_reset():
    """
    Archive receipts.jsonl → receipts_YYYYMMDDTHHMMSS.jsonl, then truncate.
    Returns {archived: filename, lines: N} or {cleared: True, lines: 0} if empty.
    """
    receipts_path = _default_receipts_path()
    if not os.path.exists(receipts_path):
        return jsonify({"cleared": True, "lines": 0})
    # Count lines before archiving
    lines = 0
    with open(receipts_path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                lines += 1
    if lines == 0:
        return jsonify({"cleared": True, "lines": 0})
    # Archive with timestamp
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    archive_path = receipts_path.replace("receipts.jsonl", f"receipts_{ts}.jsonl")
    try:
        os.rename(receipts_path, archive_path)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    # Truncate (create empty file)
    os.makedirs(os.path.dirname(receipts_path), exist_ok=True)
    open(receipts_path, "w").close()
    return jsonify({
        "archived": os.path.basename(archive_path),
        "lines":    lines,
    })




# ── Receiver callback (receipt ingest)
@bp.route("/api/receiver/callback", methods=["POST"])
def api_receiver_callback():
    """Accept live receipt from receiver."""
    if _h._callback_token:
        supplied = (request.headers.get("X-ICSForge-Callback-Token") or "").strip()
        if not supplied or not secrets.compare_digest(supplied, _h._callback_token):
            return jsonify({"error": "invalid callback token"}), 401
        # HMAC integrity check — mandatory when token is configured.
        # Receiver must sign the payload body with HMAC-SHA256(token, body).
        # A token-bearing callback without a valid HMAC is rejected.
        import hmac as _hmac, hashlib as _hl
        raw_body = request.get_data()
        supplied_hmac = (request.headers.get("X-ICSForge-HMAC") or "").strip()
        if not supplied_hmac:
            return jsonify({"error": "HMAC required: receiver must sign callbacks with X-ICSForge-HMAC"}), 401
        expected = _hmac.new(
            _h._callback_token.encode("utf-8"),
            raw_body,
            _hl.sha256,
        ).hexdigest()
        if not _hmac.compare_digest(supplied_hmac, expected):
            return jsonify({"error": "HMAC verification failed"}), 401
    data = request.get_json(force=True, silent=True) or {}
    if not data.get("marker_found"):
        return jsonify({"ok": True, "stored": False})
    data["_received_at"] = datetime.now(timezone.utc).isoformat()
    _h._live_receipts.append(data)
    # Push to SSE subscribers
    notify_sse(data)
    return jsonify({"ok": True, "stored": True})


# ── SSE live stream (replaces polling)
@bp.route("/api/receiver/stream")
def api_receiver_stream():
    """Server-Sent Events stream for real-time receipt notifications."""
    def generate():
        q = subscribe_sse()
        try:
            yield "data: {\"type\":\"connected\"}\n\n"
            while True:
                try:
                    event = q.get(timeout=15)
                    yield f"data: {json.dumps(event)}\n\n"
                except Exception:
                    # Send keepalive comment every 15s
                    yield ": keepalive\n\n"
        except GeneratorExit:
            pass
        finally:
            unsubscribe_sse(q)
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})




# ── Receiver live feed
@bp.route("/api/receiver/live")
def api_receiver_live():
    """Return buffered live receipts for sender UI."""
    since = request.args.get("since", "")
    items = list(_h._live_receipts)
    if since:
        items = [r for r in items if (r.get("_received_at") or "") > since]
    return jsonify({"receipts": items, "count": len(items), "total_buffered": len(_h._live_receipts)})


@bp.route("/api/receiver/live/clear", methods=["POST"])
def api_receiver_live_clear():
    _h._live_receipts.clear()
    return jsonify({"ok": True, "cleared": True})



# ── Receipts list
@bp.route("/api/receipts")
def api_receipts():
    receipts_path = _default_receipts_path()
    items = _read_jsonl_tail(receipts_path, limit=int(request.args.get("limit", 250)))
    run_id = (request.args.get("run_id") or "").strip()
    tech = (request.args.get("technique") or "").strip()
    proto = (request.args.get("proto") or "").strip()
    since = (request.args.get("since") or "").strip()  # ISO timestamp for pull-mode
    out=[]
    for r in reversed(items):
        if since and (r.get("@timestamp") or "") <= since:
            continue
        if run_id and r.get("run_id") != run_id:
            continue
        if tech and r.get("technique") != tech:
            continue
        if proto and r.get("receiver.proto") != proto:
            continue
        out.append(r)
        if len(out) >= 200:
            break
    return jsonify({"items": out})




# ── Run detail (single)
@bp.route("/api/run")
def api_run():
    run_id = (request.args.get("run_id") or "").strip()
    if not run_id:
        return jsonify({})
    receipts_path = _default_receipts_path()
    filtered = [r for r in _read_jsonl_tail(receipts_path, limit=2000)
                if r.get("run_id") == run_id]
    # Merge live in-memory receipts (callback path)
    seen = {_receipt_key(r) for r in filtered}
    for r in _live_receipts:
        if r.get("run_id") == run_id and _receipt_key(r) not in seen:
            filtered.append(r)
            seen.add(_receipt_key(r))
    if not filtered:
        return jsonify({})
    filtered.sort(key=lambda x: x.get("@timestamp") or "")
    techs = sorted(set([r.get("technique") for r in filtered if r.get("technique")]))
    return jsonify({
        "run_id": run_id,
        "packets": len(filtered),
        "first_seen": filtered[0].get("@timestamp"),
        "last_seen": filtered[-1].get("@timestamp"),
        "techniques": techs,
    })




# ── Run detail expanded
@bp.route("/api/run_detail")
def api_run_detail():
    run_id = (request.args.get("run_id") or "").strip()
    if not run_id:
        return jsonify({})
    receipts_path = _default_receipts_path()
    items = [r for r in _read_jsonl_tail(receipts_path, limit=4000)
             if r.get("run_id") == run_id]
    # Merge live in-memory receipts (callback path)
    seen = {_receipt_key(r) for r in items}
    for r in _live_receipts:
        if r.get("run_id") == run_id and _receipt_key(r) not in seen:
            items.append(r)
            seen.add(_receipt_key(r))
    if not items:
        return jsonify({})
    items.sort(key=lambda x: x.get("@timestamp") or "")
    techs = sorted(set([r.get("technique") for r in items if r.get("technique")]))
    return jsonify({
        "run_id": run_id,
        "packets": len(items),
        "first_seen": items[0].get("@timestamp"),
        "last_seen": items[-1].get("@timestamp"),
        "techniques": techs,
        "bins": _bin_receipts(items, bins=40),
    })



