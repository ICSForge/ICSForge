"""ICSForge campaigns blueprint — campaign listing, execution, abort."""
import threading

from pathlib import Path

import json
import os
import time
import yaml
from flask import Blueprint, Response, jsonify, request, stream_with_context

from icsforge.campaigns.runner import CampaignRunner, validate_campaign_file, CampaignValidationError
from icsforge.web.helpers import (
    _canonical_scenarios_path, _repo_root,
    _append_run_index, _registry,
    log,
    MATRIX_SINGLETON_PACK,
)

bp = Blueprint("bp_campaigns", __name__)

_CAMPAIGN_THREADS = {}  # run_id -> CampaignRunner thread
_CAMPAIGNS_BUILTIN = os.path.join(os.path.dirname(__file__), "..", "campaigns", "builtin.yml")


# ── Campaign list
@bp.route("/api/campaigns/list")
def api_campaigns_list():
    try:
        try:
            doc, warnings = validate_campaign_file(
                _CAMPAIGNS_BUILTIN,
                _canonical_scenarios_path() if os.path.exists(_canonical_scenarios_path()) else None,
            )
        except CampaignValidationError as ve:
            return jsonify({"error": f"Campaign validation failed: {ve}", "campaigns": []}), 400

        camps = doc.get("campaigns") or {}
        out = []
        for cid, c in camps.items():
            out.append({
                "id":          cid,
                "name":        c.get("name", cid),
                "description": c.get("description", ""),
                "icon":        c.get("icon", "⛓"),
                "estimated_duration": c.get("estimated_duration", ""),
                "step_count":  len(c.get("steps", [])),
                "steps":       [{"scenario": s["scenario"], "delay": s.get("delay","0s"),
                                 "label": s.get("label", s["scenario"])}
                                for s in c.get("steps", [])],
            })
        result = {"campaigns": out}
        if warnings:
            result["warnings"] = warnings
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500




# ── Campaign run
@bp.route("/api/campaigns/run", methods=["POST"])
def api_campaigns_run():
    """
    Start a campaign and stream SSE events back to the client.
    POST body: {campaign_id, dst_ip, iface?, timeout?}
    Returns: text/event-stream of JSON event lines.
    """
    data        = request.get_json(force=True) or {}
    campaign_id = (data.get("campaign_id") or "").strip()
    dst_ip      = (data.get("dst_ip") or "").strip()
    iface       = (data.get("iface") or "").strip() or None
    timeout     = float(data.get("timeout") or 2.0)

    if not campaign_id:
        return jsonify({"error": "campaign_id required"}), 400
    if not dst_ip:
        return jsonify({"error": "dst_ip required"}), 400

    try:
        doc   = yaml.safe_load(Path(_CAMPAIGNS_BUILTIN).read_text(encoding="utf-8")) or {}
        camps = doc.get("campaigns") or {}
        camp  = camps.get(campaign_id)
        if not camp:
            return jsonify({"error": f"campaign '{campaign_id}' not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    rr       = _repo_root()
    sc_path  = MATRIX_SINGLETON_PACK
    out_dir  = os.path.join(rr, "out")

    queue:  list[dict] = []
    done    = threading.Event()

    def _progress(ev: dict):
        queue.append(ev)

    runner = CampaignRunner(
        campaign=camp,
        scenarios_path=sc_path,
        dst_ip=dst_ip,
        iface=iface,
        timeout=timeout,
        outdir=out_dir,
        progress_cb=_progress,
    )

    def _run():
        try:
            result = runner.run()
            # Register campaign run in SQLite + JSONL so it appears in /api/runs and matrix overlay
            # Derive the techniques this campaign executed from its scenario steps
            _campaign_techniques = []
            try:
                import yaml as _yaml
                _sc_doc = _yaml.safe_load(open(sc_path, encoding="utf-8")) or {}
                _scenarios = _sc_doc.get("scenarios") or {}
                _tech_set = set()
                for _step in camp.get("steps", []):
                    _sc = _scenarios.get(_step.get("scenario", ""), {})
                    for _s in _sc.get("steps", []):
                        _t = _s.get("technique")
                        if _t:
                            _tech_set.add(_t)
                _campaign_techniques = sorted(_tech_set)
            except Exception:
                pass

            try:
                reg = _registry()
                reg.upsert_run(
                    runner.run_id,
                    scenario=camp.get("name", campaign_id),
                    pack=sc_path,
                    dst_ip=dst_ip,
                    src_ip="",
                    iface=iface,
                    mode="campaign",
                    status="ok",
                    meta={"steps_ok": result.get("steps_ok", 0),
                          "steps_err": result.get("steps_err", 0),
                          "campaign_id": campaign_id,
                          "techniques": _campaign_techniques},
                )
                if result.get("events_path"):
                    reg.add_artifact(runner.run_id, "events", result["events_path"])
            except Exception as exc:
                log.debug("Registry upsert failed for campaign %s: %s", runner.run_id, exc)
            try:
                from datetime import datetime, timezone as _tz
                _append_run_index({
                    "run_id": runner.run_id,
                    "scenario": camp.get("name", campaign_id),
                    "mode": "campaign",
                    "techniques": _campaign_techniques,
                    "events": result.get("events_path"),
                    "ts": datetime.now(_tz.utc).isoformat() + "Z",
                })
            except Exception:
                pass
        except Exception as e:
            queue.append({"event": "error", "message": str(e)})
        finally:
            done.set()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    _CAMPAIGN_THREADS[runner.run_id] = runner

    def _generate():
        yield f"data: {json.dumps({'event':'started','run_id':runner.run_id})}\n\n"
        while not done.is_set() or queue:
            while queue:
                ev = queue.pop(0)
                yield f"data: {json.dumps(ev)}\n\n"
            time.sleep(0.15)
        yield f"data: {json.dumps({'event':'stream_end'})}\n\n"

    return Response(
        stream_with_context(_generate()),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )




# ── Campaign abort
@bp.route("/api/campaigns/abort", methods=["POST"])
def api_campaigns_abort():
    run_id = (request.get_json(force=True) or {}).get("run_id", "")
    runner = _CAMPAIGN_THREADS.get(run_id)
    if runner:
        runner.stop()
        return jsonify({"aborted": True})
    return jsonify({"error": "run not found"}), 404


# ── Coverage Report APIs ───────────────────────────────────────────────────


