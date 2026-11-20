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
def _announce_auth_ok(require_for_action: str = "announce") -> tuple[bool, str]:
    """Shared auth for expectation announce/clear (sender -> receiver).

    Returns (ok, note). Accepts when EITHER a valid callback token+HMAC is
    supplied OR the request comes from a trusted (private/loopback/link-local)
    network. Announces/clears from untrusted networks without a valid token are
    rejected. This keeps the POST /expect and DELETE /expect endpoints consistent
    (the DELETE path previously required a token even on a trusted LAN, so a
    two-VM abort/clear with mismatched tokens failed).
    """
    if not _h._callback_token:
        return True, ""
    supplied = (request.headers.get("X-ICSForge-Callback-Token") or "").strip()
    supplied_hmac = (request.headers.get("X-ICSForge-HMAC") or "").strip()
    if supplied and secrets.compare_digest(supplied, _h._callback_token) and supplied_hmac:
        import hashlib as _hl
        import hmac as _hmac
        expected = _hmac.new(
            _h._callback_token.encode("utf-8"), request.get_data(), _hl.sha256,
        ).hexdigest()
        if _hmac.compare_digest(supplied_hmac, expected):
            return True, "token"
    # Token missing/mismatched — fall back to network trust.
    import ipaddress as _ip
    remote = (request.remote_addr or "").strip()
    try:
        ra = _ip.ip_address(remote)
        trusted = ra.is_private or ra.is_loopback or ra.is_link_local
    except ValueError:
        trusted = False
    if trusted:
        _h.log.warning(
            "%s from %s WITHOUT valid callback token (trusted network). Align "
            "the callback token on sender and receiver for authenticated %ss.",
            require_for_action, remote or "?", require_for_action)
        return True, "trusted-network"
    return False, "untrusted"


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
        t = r.get("technique") or ""
        p = r.get("receiver.proto") or "unknown"
        # Only count non-empty techniques toward the unique-technique KPI, so an
        # unattributed receipt (empty technique) doesn't wedge the counter at 1.
        if t:
            techniques[t] = techniques.get(t, 0) + 1
        protos[p]     = protos.get(p, 0) + 1
        if r.get("run_id"):
            runs.add(r["run_id"])
    # Active runs = distinct run_ids seen in receipts PLUS any live expectations
    # still within their TTL (a run announced/in-flight that hasn't produced an
    # attributed receipt yet). This makes "Active runs" reflect in-flight runs
    # rather than sitting at 0 when attribution is momentarily pending.
    try:
        from icsforge.receiver.receiver import list_expectations
        for e in (list_expectations() or []):
            if e.get("run_id"):
                runs.add(e["run_id"])
    except Exception:
        pass
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
        import hashlib as _hl
        import hmac as _hmac
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
    # Store a receipt if it is either marker-attributed OR expectation-attributed.
    # The receiver fires callbacks for both (see receiver._write_receipt): covert/
    # explicit-marker traffic has marker_found=True, while IEC-104 and stealth
    # (--no-marker) traffic is attributed purely via the expectation registry with
    # marker_found=False and attributed_via="expectation". Previously this endpoint
    # only stored marker_found receipts, silently dropping every IEC-104 / stealth
    # receipt — so those runs showed no delivery on the sender even though the
    # receiver saw the traffic.
    if not (data.get("marker_found") or data.get("attributed_via") in ("expectation", "delivery")):
        return jsonify({"ok": True, "stored": False})
    data["_received_at"] = datetime.now(timezone.utc).isoformat()
    _h._live_receipts.append(data)
    # Persist to receipts.jsonl so the overview counters (packets received, active
    # runs, techniques/protocols seen) — read by BOTH the receiver page and the
    # sender's live feed via /api/receiver/overview — actually reflect live
    # traffic. In web/demo mode there is no standalone receiver process writing
    # this file, so without this append the file stays empty and every counter
    # stays at 0 even as receipts stream into memory. This is the root cause of
    # "live statistics not working" on both pages.
    try:
        receipts_path = _default_receipts_path()
        os.makedirs(os.path.dirname(receipts_path), exist_ok=True)
        # Normalise timestamp field the overview reader looks for.
        if "@timestamp" not in data and "ts" not in data:
            data["@timestamp"] = data["_received_at"]
        with open(receipts_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(data, default=str) + "\n")
    except Exception as exc:  # noqa: BLE001 — persistence must not break the live push
        _h.log.warning("callback: failed to persist receipt: %s", exc) \
            if hasattr(_h, "log") else None
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


# ── Expectation registry endpoints ─────────────────────────────────
#
# Markerless attribution: when the sender is about to run a scenario whose
# wire format cannot embed the ICSFORGE_SYNTH marker (IEC-104) or has been
# deliberately stripped (--no-marker / stealth), the sender first POSTs an
# expectation here. The receiver attributes any matching protocol traffic
# arriving during the TTL window to that expectation, and forwards a
# callback to the sender even though the packet bytes carry no marker.

@bp.route("/api/receiver/expect", methods=["POST"])
def api_receiver_expect():
    """
    Register an expectation for an upcoming run.

    Body (JSON):
      run_id      str   required   the run_id the sender will use
      scenario    str   optional   scenario name
      technique   str   optional   primary technique
      steps       int   optional   number of steps (diagnostic)
      ttl_sec     float optional   how long to keep the expectation alive
      protos      list  optional   list of expected protocols

    Authentication: same callback-token + HMAC scheme as the callback ingest
    endpoint when token is configured. This prevents unauthenticated peers
    from attributing arbitrary traffic to fake runs.
    """
    # Auth model for the expectation announce (sender -> receiver):
    #   * If a token is configured AND the sender supplies a matching token+HMAC,
    #     accept (strong path).
    #   * If a token is configured but the sender's token/HMAC is missing or wrong,
    #     DO NOT hard-401 into a silent attribution blackout — instead accept the
    #     announce when it comes from a trusted (private/loopback) network and log a
    #     clear warning. The announce only says "traffic for run X is coming"; the
    #     real anti-forgery guarantee is the keyed covert HMAC marker on the traffic
    #     itself, verified independently. A mismatched callback-token between two
    #     VMs must not leave the receiver unable to attribute anything — that was
    #     the field failure (empty run_id/technique, Active runs stuck at 0).
    ok, _note = _announce_auth_ok("expectation announce")
    if not ok:
        return jsonify({"error": "expectation announce rejected: bad/absent "
                        "callback token from untrusted network"}), 401

    data = request.get_json(force=True, silent=True) or {}
    run_id = (data.get("run_id") or "").strip()
    if not run_id:
        return jsonify({"error": "run_id is required"}), 400

    # Lazy import — receiver module may not be in path in some test setups
    try:
        from icsforge.receiver.receiver import register_expectation
    except Exception as e:
        return jsonify({"error": f"receiver module unavailable: {e}"}), 500

    entry = register_expectation(
        run_id=run_id,
        scenario=str(data.get("scenario") or ""),
        technique=str(data.get("technique") or ""),
        steps=int(data.get("steps") or 1),
        ttl_sec=float(data.get("ttl_sec") or 300.0),
        protos=data.get("protos") if isinstance(data.get("protos"), list) else None,
        test_profile=str(data.get("test_profile") or ""),
        expected_alert=str(data.get("expected_alert") or ""),
    )
    return jsonify({"ok": True, "expectation": entry})


@bp.route("/api/receiver/expectations", methods=["GET"])
def api_receiver_expectations():
    """List currently active expectations (auto-prunes expired ones)."""
    try:
        from icsforge.receiver.receiver import list_expectations
    except Exception:
        return jsonify({"expectations": []})
    return jsonify({"expectations": list_expectations()})


@bp.route("/api/receiver/expect/<run_id>", methods=["DELETE"])
def api_receiver_expect_clear(run_id: str):
    """Clear an expectation early (e.g. on scenario abort)."""
    ok, _note = _announce_auth_ok("expectation clear")
    if not ok:
        return jsonify({"error": "expectation clear rejected: bad/absent callback "
                        "token from untrusted network"}), 401
    try:
        from icsforge.receiver.receiver import clear_expectation
    except Exception:
        return jsonify({"ok": False, "error": "receiver module unavailable"}), 500
    cleared = clear_expectation(run_id)
    return jsonify({"ok": True, "cleared": cleared})



