"""ICSForge runs blueprint — run history, alerts, validation, export, PCAP, correlation."""
import html
import json
import os
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, jsonify, request, send_file

from icsforge.detection.mapping import correlate_run
from icsforge.web.helpers import (
    _alerts_path,
    _artifact_rel,
    _bin_receipts,
    _default_receipts_path,
    _export_path,
    _is_safe_private_ip,
    _live_receipts,
    _load_run_index,
    _read_json_lines,
    _read_jsonl_tail,
    _registry,
    _repo_root,
    _update_run_entry,
    _validation_path,
    build_network_validation_report,
    log,
)

bp = Blueprint("bp_runs", __name__)


# ── Runs list
@bp.route("/api/runs")
def api_runs():
    try:
        reg = _registry()
        return jsonify({"runs": reg.list_runs(50)})
    except (OSError, ValueError) as exc:
        log.debug("Registry unavailable, falling back to run index: %s", exc)
        return jsonify({"runs": _load_run_index()[:30]})


# ── Run full detail
@bp.route("/api/run_full")
def api_run_full():
    run_id = (request.args.get("run_id") or "").strip()
    if not run_id:
        return jsonify({"error": "run_id required"}), 400
    idx: dict = {}
    try:
        reg = _registry()
        idx = reg.get_run(run_id) or {}
    except (OSError, ValueError) as exc:
        log.debug("Registry lookup failed for %s: %s", run_id, exc)
        idx = next((x for x in _load_run_index() if x.get("run_id") == run_id), None) or {}
    receipts_path = _default_receipts_path()
    receipts = [r for r in _read_jsonl_tail(receipts_path, limit=4000) if r.get("run_id") == run_id]
    # Also include live in-memory receipts (callback path, not written to JSONL)
    def _rkey(r):
        return (r.get("run_id",""), r.get("@timestamp",""),
                r.get("technique",""), r.get("proto",""),
                r.get("src_ip",""), r.get("src_port",""))
    seen_keys = {_rkey(r) for r in receipts}
    for r in _live_receipts:
        if r.get("run_id") == run_id and _rkey(r) not in seen_keys:
            receipts.append(r)
            seen_keys.add(_rkey(r))
    receipts.sort(key=lambda x: x.get("@timestamp") or "")
    techs = sorted({r.get("technique") for r in receipts if r.get("technique")})
    # Fallback 1: read techniques from ground-truth events file (single-scenario and chain runs)
    # This is the correct source for "Executed" — what ICSForge actually generated/sent.
    if not techs:
        ev_path = next(
            (a.get("path") for a in idx.get("artifacts", []) if a.get("kind") == "events"),
            idx.get("events"),
        )
        if ev_path and os.path.exists(ev_path):
            try:
                with open(ev_path, encoding="utf-8") as _f:
                    for _line in _f:
                        try:
                            _t = json.loads(_line).get("mitre.ics.technique")
                            if _t:
                                techs.append(_t)
                        except (json.JSONDecodeError, ValueError):
                            pass
                techs = sorted(set(techs))
            except OSError:
                pass
    # Fallback 2: campaign runs store techniques in meta (progress log has no mitre fields)
    if not techs:
        techs = sorted((idx.get("meta") or {}).get("techniques") or [])
    return jsonify({
        "run_id": run_id,
        "scenario": idx.get("scenario"),
        "events": next((a.get("path") for a in idx.get("artifacts", []) if a.get("kind") == "events"), idx.get("events")),
        "pcap": next((a.get("path") for a in idx.get("artifacts", []) if a.get("kind") == "pcap"), idx.get("pcap")),
        "ts": idx.get("ts"),
        "techniques": techs,
        "bins": _bin_receipts(receipts, bins=40),
        "receipts_preview": receipts[-20:],
        "artifacts": idx.get("artifacts", []),
    })


# ── Alerts save
@bp.route("/api/alerts/save", methods=["POST"])
def api_alerts_save():
    data = request.get_json(force=True) or {}
    run_id = (data.get("run_id") or "").strip()
    alerts_jsonl = data.get("alerts_jsonl") or ""
    if not run_id:
        return jsonify({"error": "run_id required"}), 400
    p = _alerts_path(run_id)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    Path(p).write_text(alerts_jsonl, encoding="utf-8")
    return jsonify({"ok": True, "path": p})


# ── Validate run
@bp.route("/api/validate", methods=["POST"])
def api_validate_run():
    data = request.get_json(force=True) or {}
    run_id = (data.get("run_id") or "").strip()
    if not run_id:
        return jsonify({"error": "run_id required"}), 400
    idx: dict = {}
    try:
        reg = _registry()
        idx = reg.get_run(run_id) or {}
    except (OSError, ValueError) as exc:
        log.debug("Registry lookup failed for %s: %s", run_id, exc)
        idx = next((x for x in _load_run_index() if x.get("run_id") == run_id), None) or {}
    # Look in artifacts list first (SQLite path), then fall back to flat "events" key (JSONL index)
    events_path = next(
        (a.get("path") for a in idx.get("artifacts", []) if a.get("kind") == "events"),
        None,
    )
    if not events_path:
        events_path = idx.get("events")
    if not events_path:
        return jsonify({"error": "Ground-truth events path not found for this run"}), 400
    if not os.path.exists(events_path):
        return jsonify({"error": f"Events file no longer exists: {events_path}"}), 400
    receipts_path = _default_receipts_path()
    # Create empty receipts file if it doesn't exist yet — validation proceeds
    # but will report 0% delivery (with a warning in the report)
    if not os.path.exists(receipts_path):
        os.makedirs(os.path.dirname(receipts_path), exist_ok=True)
        Path(receipts_path).touch()
    alerts_path = _alerts_path(run_id)
    out_path = _validation_path(run_id)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    try:
        report = build_network_validation_report(
            events_path,
            receipts_path,
            alerts_jsonl=(alerts_path if os.path.exists(alerts_path) and Path(alerts_path).stat().st_size > 0 else None),
            out_path=out_path,
        )
        return jsonify({"ok": True, "report_path": out_path, "report": report})
    except (OSError, ValueError) as exc:
        log.error("Validation failed for run %s: %s", run_id, exc)
        return jsonify({"error": str(exc)}), 500


# ── Export run
@bp.route("/api/export")
def api_export_run():
    run_id = (request.args.get("run_id") or "").strip()
    if not run_id:
        return jsonify({"error": "run_id required"}), 400
    idx: dict = {}
    try:
        reg = _registry()
        idx = reg.get_run(run_id) or {}
    except (OSError, ValueError) as exc:
        log.debug("Registry lookup failed for %s: %s", run_id, exc)
        idx = next((x for x in _load_run_index() if x.get("run_id") == run_id), None) or {}
    receipts_path = _default_receipts_path()
    receipts = [r for r in _read_jsonl_tail(receipts_path, limit=4000) if r.get("run_id") == run_id]
    def _rkey(r):
        return (r.get("run_id",""), r.get("@timestamp",""), r.get("technique",""),
                r.get("proto",""), r.get("src_ip",""), str(r.get("src_port","")))
    live_keys = {_rkey(r) for r in receipts}
    for r in _live_receipts:
        if r.get("run_id") == run_id and _rkey(r) not in live_keys:
            receipts.append(r)
    receipts.sort(key=lambda x: x.get("@timestamp") or "")
    techs = sorted({r.get("technique") for r in receipts if r.get("technique")})
    val_path = _validation_path(run_id)
    validation = None
    if os.path.exists(val_path):
        try:
            validation = json.loads(Path(val_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.debug("Could not load validation file %s: %s", val_path, exc)

    _report_html = f"""<!doctype html>
<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>ICSForge Report {run_id}</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial;background:#f6f7fb;color:#111827;margin:0}}
.wrap{{max-width:1000px;margin:0 auto;padding:28px}}
.card{{background:#fff;border:1px solid #e5e7eb;border-radius:18px;box-shadow:0 10px 25px rgba(17,24,39,.08);padding:18px;margin:14px 0}}
h1{{margin:0 0 8px 0}} .muted{{color:#6b7280;font-size:13px}} .mono{{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace}}
.badge{{display:inline-block;padding:4px 8px;border-radius:999px;border:1px solid #e5e7eb;background:#f2f4f8;font-size:12px;margin:2px}}
table{{width:100%;border-collapse:collapse}} td,th{{text-align:left;padding:8px;border-bottom:1px solid #e5e7eb;font-size:13px}}
pre{{white-space:pre-wrap;background:#f2f4f8;border:1px solid #e5e7eb;border-radius:16px;padding:12px}}
</style></head><body><div class='wrap'>
<div class='card'><h1>ICSForge SOC Validation Report</h1>
<div class='muted'>run_id: <span class='mono'>{html.escape(str(run_id))}</span> &bull; scenario: {html.escape(str(idx.get('scenario','-')))} &bull; generated: {datetime.now(timezone.utc).isoformat()}Z</div>
</div>
<div class='card'><h2>Summary</h2>
<div class='muted'>Packets received: <b>{len(receipts)}</b></div>
<div style='margin-top:8px'>Techniques:<br>
{''.join([f"<span class='badge mono'>{t}</span>" for t in techs]) or '<span class="badge">none</span>'}
</div>
<div style='margin-top:10px' class='muted'>Events: <span class='mono'>{next((a.get('path') for a in idx.get('artifacts',[]) if a.get('kind')=='events'), idx.get('events','-'))}</span><br>
PCAP: <span class='mono'>{next((a.get('path') for a in idx.get('artifacts',[]) if a.get('kind')=='pcap'), idx.get('pcap','-'))}</span></div>
</div>
<div class='card'><h2>Delivery Evidence (last 20 receipts)</h2>
<table><thead><tr><th>Time</th><th>Proto</th><th>Src</th><th>Technique</th><th>Bytes</th></tr></thead><tbody>
{''.join([f"<tr><td class='mono'>{html.escape(str(r.get('@timestamp') or ''))}</td><td>{html.escape(str(r.get('receiver.proto','') or ''))}</td><td class='mono'>{html.escape(str(r.get('src_ip','') or ''))}:{html.escape(str(r.get('src_port','') or ''))}</td><td class='mono'>{html.escape(str(r.get('technique','') or ''))}</td><td class='mono'>{html.escape(str(r.get('bytes','') or ''))}</td></tr>" for r in receipts[-20:]])}
</tbody></table></div>
<div class='card'><h2>Validation</h2>
<pre class='mono'>{json.dumps(validation, indent=2) if validation else 'Run validation from SOC Mode to populate this section.'}</pre>
</div>
<div class='muted' style='margin:20px 0'>ICSForge &bull; GPLv3 &bull; OT/ICS security coverage validation platform</div>
</div></body></html>"""

    out_path = _export_path(run_id)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    Path(out_path).write_text(_report_html, encoding="utf-8")
    return jsonify({"ok": True, "path": out_path, "download_url": f"/download?path={out_path}"})


# ── PCAP replay
@bp.route("/api/pcap/replay", methods=["POST"])
def api_pcap_replay():
    data = request.get_json(force=True) or {}
    pcap_path = (data.get("pcap_path") or "").strip()
    dst_ip = (data.get("dst_ip") or "").strip()
    interval = float(data.get("interval") or 0.05)
    allowlist = [x.strip() for x in (data.get("allowlist") or "").split(",") if x.strip()]
    if not pcap_path:
        return jsonify({"error": "pcap_path required"}), 400
    if not dst_ip:
        return jsonify({"error": "dst_ip required"}), 400
    rr = _repo_root()
    real = os.path.realpath(pcap_path)
    if not real.startswith(os.path.realpath(os.path.join(rr, "out"))):
        return jsonify({"error": "pcap_path must be inside out/"}), 400
    if not os.path.exists(real):
        return jsonify({"error": "pcap not found"}), 404
    if not _is_safe_private_ip(dst_ip):
        return jsonify({"error": "dst_ip blocked: must be private/test/link-local/loopback"}), 400
    if allowlist and dst_ip not in allowlist:
        return jsonify({"error": "dst_ip not in allowlist"}), 400
    try:
        from icsforge.core import replay_pcap as _replay
        sent = _replay(real, dst_ip, interval=interval)
        return jsonify({"ok": True, "sent": sent})
    except (OSError, ValueError) as exc:
        log.error("PCAP replay failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── Run tag
@bp.route("/api/run/tag", methods=["POST"])
def api_run_tag():
    data = request.get_json(force=True) or {}
    run_id = (data.get("run_id") or "").strip()
    tags = data.get("tags") or []
    if not run_id:
        return jsonify({"error": "run_id required"}), 400
    if not isinstance(tags, list):
        return jsonify({"error": "tags must be a list"}), 400
    if len(tags) > 20:
        return jsonify({"error": "maximum 20 tags allowed"}), 400
    tags = sorted({str(t).strip()[:50] for t in tags if str(t).strip()})
    ok = _update_run_entry(run_id, lambda it: it.__setitem__("tags", tags))
    return jsonify({"ok": ok, "run_id": run_id, "tags": tags})


# ── Run rename
@bp.route("/api/run/rename", methods=["POST"])
def api_run_rename():
    data = request.get_json(force=True) or {}
    run_id = (data.get("run_id") or "").strip()
    title = (data.get("title") or "").strip()[:200]
    if not run_id:
        return jsonify({"error": "run_id required"}), 400
    if not title:
        return jsonify({"error": "title required"}), 400
    ok = _update_run_entry(run_id, lambda it: it.__setitem__("title", title))
    return jsonify({"ok": ok, "run_id": run_id, "title": title})


# ── Run export bundle
@bp.route("/api/run/export_bundle")
def api_run_export_bundle():
    run_id = (request.args.get("run_id") or "").strip()
    if not run_id:
        return jsonify({"error": "run_id required"}), 400
    idx: dict = {}
    try:
        reg = _registry()
        idx = reg.get_run(run_id) or {}
    except (OSError, ValueError) as exc:
        log.debug("Registry lookup failed for %s: %s", run_id, exc)
        idx = next((x for x in _load_run_index() if x.get("run_id") == run_id), None) or {}
    rr = _repo_root()
    out_root = os.path.join(rr, "out")
    bundle_dir = os.path.join(out_root, "bundles")
    os.makedirs(bundle_dir, exist_ok=True)
    bundle_path = os.path.join(bundle_dir, f"{run_id}.zip")
    receipts_path = _default_receipts_path()
    receipts = [r for r in _read_jsonl_tail(receipts_path, limit=20000) if r.get("run_id") == run_id]
    receipts_extract = os.path.join(out_root, "tmp", f"{run_id}_receipts.jsonl")
    os.makedirs(os.path.dirname(receipts_extract), exist_ok=True)
    Path(receipts_extract).write_text(
        "\n".join([json.dumps(x, separators=(",", ":")) for x in receipts]) + ("\n" if receipts else ""),
        encoding="utf-8",
    )
    # Resolve artifact paths from both SQLite (artifacts list) and JSONL index (flat keys)
    def _artifact_path(kind: str) -> str | None:
        path = next((a.get("path") for a in idx.get("artifacts", []) if a.get("kind") == kind), None)
        if not path:
            path = idx.get(kind)
        return path if path and os.path.exists(path) else None

    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        def add_if(path, arc):
            if path and os.path.exists(path):
                z.write(path, arcname=arc)
        add_if(_artifact_path("events"), f"{run_id}/events.jsonl")
        add_if(_artifact_path("pcap"), f"{run_id}/traffic.pcap")
        val_path = _validation_path(run_id)
        add_if(val_path if os.path.exists(val_path) else None, f"{run_id}/validation.json")
        al_path = _alerts_path(run_id)
        add_if(al_path if os.path.exists(al_path) else None, f"{run_id}/alerts.jsonl")
        add_if(receipts_extract, f"{run_id}/receipts.jsonl")
        z.writestr(f"{run_id}/run_index_entry.json", json.dumps(idx, indent=2))
    return jsonify({"ok": True, "path": bundle_path, "download_url": f"/download?path={bundle_path}"})


# ── Download
@bp.route("/download")
def api_download():
    path = request.args.get("path")
    if not path:
        return jsonify({"error": "path required"}), 400
    rr = _repo_root()
    # If path is relative, resolve it against repo root (not CWD)
    if not os.path.isabs(path):
        path = os.path.join(rr, path)
    real = os.path.realpath(path)
    allowed = os.path.realpath(os.path.join(rr, "out"))
    if not real.startswith(allowed):
        return jsonify({"error": "blocked"}), 403
    if not os.path.exists(real):
        return jsonify({"error": "file not found"}), 404
    return send_file(real, as_attachment=True)


# ── Net validate custom
@bp.route("/api/net_validate_custom", methods=["POST"])
def api_net_validate_custom():
    data = request.get_json(force=True) or {}
    events = (data.get("events") or "").strip()
    receipts = (data.get("receipts") or "").strip()
    alerts_jsonl = (data.get("alerts_jsonl") or "").strip() or None
    out_path = (data.get("out") or "out/network_validation_custom.json").strip()
    if not events or not os.path.exists(events):
        return jsonify({"error": "events path invalid"}), 400
    if not receipts or not os.path.exists(receipts):
        return jsonify({"error": "receipts path invalid"}), 400
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    tmp_alerts = None
    try:
        if alerts_jsonl:
            tmp_alerts = os.path.join(_repo_root(), "out", "alerts", "custom_alerts.jsonl")
            os.makedirs(os.path.dirname(tmp_alerts), exist_ok=True)
            Path(tmp_alerts).write_text(alerts_jsonl, encoding="utf-8")
        report = build_network_validation_report(events, receipts, alerts_jsonl=tmp_alerts, out_path=out_path)
        return jsonify({"ok": True, "report_path": out_path, "report": report})
    except (OSError, ValueError) as exc:
        log.error("Custom validation failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── Alerts ingest
@bp.route("/api/alerts/ingest", methods=["POST"])
def api_alerts_ingest():
    data = request.get_json(force=True) or {}
    path = (data.get("path") or "").strip()
    run_id = (data.get("run_id") or "").strip()
    profile = (data.get("profile") or "suricata_eve").strip()
    if not path:
        return jsonify({"error": "Missing path"}), 400
    rr = os.path.realpath(_repo_root())
    p = os.path.realpath(os.path.join(rr, path.lstrip("/")))
    if not p.startswith(rr) or not os.path.exists(p):
        return jsonify({"error": "Path not found or not allowed"}), 400
    rows = _read_json_lines(p)
    norm = []
    for r in rows:
        if profile == "suricata_eve":
            alert = r.get("alert")
            if not isinstance(alert, dict):
                return jsonify({
                    "ok": False,
                    "error": f"Row {len(norm)+1}: 'alert' field must be an object, got {type(alert).__name__}",
                }), 400
            norm.append({
                "ts": r.get("timestamp") or r.get("time") or r.get("event_timestamp"),
                "signature": alert.get("signature") or r.get("signature") or "alert",
                "severity": alert.get("severity") or r.get("severity"),
                "src_ip": r.get("src_ip"),
                "dst_ip": r.get("dest_ip") or r.get("dst_ip"),
                "app_proto": r.get("app_proto") or r.get("proto") or r.get("event_type"),
                "raw": r,
                "run_id": run_id or None,
            })
        else:
            r2 = dict(r)
            r2["run_id"] = run_id or r.get("run_id")
            norm.append(r2)
    out_dir = os.path.join(rr, "out", "alerts")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"alerts_{run_id or 'import'}_{int(time.time())}.jsonl")
    with open(out_path, "w", encoding="utf-8") as f:
        for item in norm:
            f.write(json.dumps(item, separators=(",", ":")) + "\n")
    return jsonify({"ok": True, "imported": len(norm), "output": os.path.relpath(out_path, rr)})


# ── Export bundle (legacy)
@bp.route("/api/export_bundle")
def api_export_bundle():
    run_id = (request.args.get("run_id") or "").strip()
    if not run_id:
        return jsonify({"error": "run_id required"}), 400
    rr = _repo_root()
    reg = _registry()
    try:
        path = reg.export_bundle(run_id, rr)
        return jsonify({"ok": True, "bundle": _artifact_rel(rr, path)})
    except (OSError, ValueError, KeyError) as exc:
        log.error("Export bundle failed for %s: %s", run_id, exc)
        return jsonify({"error": str(exc)}), 500


# ── Correlate run
@bp.route("/api/correlate_run", methods=["POST"])
def api_correlate_run():
    data = request.get_json(force=True) or {}
    run_id = (data.get("run_id") or "").strip()
    alerts_path = (data.get("alerts_path") or "").strip()
    if not run_id:
        return jsonify({"error": "run_id required"}), 400
    rr = _repo_root()
    reg = _registry()
    run = reg.get_run(run_id) or {}
    events_path = next(
        (a.get("path") for a in run.get("artifacts", []) if a.get("kind") == "events"),
        None,
    )
    if not events_path:
        idx = next((x for x in _load_run_index() if x.get("run_id") == run_id), None) or {}
        events_path = idx.get("events")
    if not events_path or not os.path.exists(events_path):
        return jsonify({"error": "events artifact not found for run"}), 400

    expected = []
    try:
        with open(events_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    t = json.loads(line).get("mitre.ics.technique")
                    if t:
                        expected.append(t)
                except json.JSONDecodeError:
                    continue
    except OSError as exc:
        log.error("Cannot read events file %s: %s", events_path, exc)
        return jsonify({"error": f"Cannot read events file: {exc}"}), 500

    alerts = []
    if alerts_path:
        ap = os.path.realpath(os.path.join(rr, alerts_path.lstrip("/")))
        if not ap.startswith(os.path.realpath(rr)) or not os.path.exists(ap):
            return jsonify({"error": "alerts_path not found or not allowed"}), 400
        try:
            with open(ap, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        alerts.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError as exc:
            log.error("Cannot read alerts file %s: %s", ap, exc)
            return jsonify({"error": f"Cannot read alerts file: {exc}"}), 500

    rep = correlate_run(expected, alerts)
    out_dir = os.path.join(rr, "out", "reports")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"correlation_{run_id}_{int(time.time())}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(rep, f, indent=2)
    try:
        reg.add_artifact(run_id, "report", out_path)
        if alerts_path:
            reg.add_artifact(run_id, "alerts", os.path.join(rr, alerts_path.lstrip("/")))
    except (OSError, ValueError) as exc:
        log.debug("Could not register artifacts for %s: %s", run_id, exc)
    return jsonify({"ok": True, "report": _artifact_rel(rr, out_path), "correlation": rep})


# ── PCAP file download
@bp.route("/api/pcap/<path:fname>")
def api_download_pcap(fname):
    base = Path(__file__).resolve().parents[2] / "pcaps"
    p = (base / fname).resolve()
    if not p.exists() or not str(p).startswith(str(base)):
        return {"error": "pcap not found"}, 404
    return send_file(str(p), as_attachment=True, download_name=p.name)


_CAMPAIGNS_BUILTIN = os.path.join(os.path.dirname(__file__), "..", "campaigns", "builtin.yml")
_CAMPAIGN_THREADS: dict = {}
