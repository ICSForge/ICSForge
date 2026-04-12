"""ICSForge reports blueprint — coverage report generation, download, matrix status."""
import io
import json
import os
from datetime import datetime
from pathlib import Path

from flask import Blueprint, jsonify, request, send_file

from icsforge.reports.coverage import generate_report
from icsforge.web.helpers import (
    _canonical_scenarios_path,
    _list_packs,
    _load_matrix,
    _load_yaml,
    _registry,
    _repo_root,
    log,
)

bp = Blueprint("bp_reports", __name__)


# ── Report generate
@bp.route("/api/report/generate", methods=["POST"])
def api_report_generate():
    data = request.get_json(force=True) or {}
    run_id = (data.get("run_id") or "").strip() or None
    executed = data.get("executed_techniques") or []
    detected = data.get("detected_techniques") or []
    gaps = data.get("gap_techniques") or []
    scenario = (data.get("scenario_name") or "").strip() or None
    meta = data.get("meta") or {}

    if run_id and not executed:
        try:
            reg = _registry()
            run = reg.get_run(run_id) or {}
            events_path = next(
                (a.get("path") for a in run.get("artifacts", []) if a.get("kind") == "events"),
                None,
            )
            if events_path and os.path.exists(events_path):
                with open(events_path, encoding="utf-8") as f:
                    for line in f:
                        try:
                            t = json.loads(line.strip()).get("mitre.ics.technique")
                            if t and t not in executed:
                                executed.append(t)
                        except json.JSONDecodeError:
                            continue
        except (OSError, ValueError) as exc:
            log.debug("Could not auto-derive techniques for run %s: %s", run_id, exc)

    try:
        html = generate_report(
            run_id=run_id, scenario_name=scenario,
            executed_techniques=executed, detected_techniques=detected,
            gap_techniques=gaps, protocol_gaps=data.get("protocol_gaps") or [],
            meta=meta,
        )
        return jsonify({"html": html, "executed": len(executed),
                        "detected": len(detected), "gaps": len(gaps)})
    except (OSError, ValueError, ImportError) as exc:
        log.error("Report generation failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── Report download
@bp.route("/api/report/download", methods=["POST"])
def api_report_download():
    data = request.get_json(force=True) or {}
    run_id = (data.get("run_id") or "").strip() or None
    executed = data.get("executed_techniques") or []
    detected = data.get("detected_techniques") or []
    gaps = data.get("gap_techniques") or []
    meta = data.get("meta") or {}
    try:
        html = generate_report(
            run_id=run_id, scenario_name=None,
            executed_techniques=executed, detected_techniques=detected,
            gap_techniques=gaps, meta=meta,
        )
        buf = io.BytesIO(html.encode("utf-8"))
        buf.seek(0)
        fname = f"icsforge_coverage_{run_id or 'report'}.html"
        return send_file(buf, mimetype="text/html", as_attachment=True, download_name=fname)
    except (OSError, ValueError, ImportError) as exc:
        log.error("Report download failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── Heatmap
@bp.route("/api/report/heatmap")
def api_report_heatmap():
    fmt = request.args.get("format", "html")
    try:
        pack = _canonical_scenarios_path()
        doc = _load_yaml(pack) if os.path.exists(pack) else {}
        sc = doc.get("scenarios") or {}
        executed: set = set()
        proto_counts: dict = {}
        for s in sc.values():
            for step in s.get("steps", []):
                t = step.get("technique")
                p = step.get("proto")
                if t:
                    executed.add(t)
                if p:
                    proto_counts[p] = proto_counts.get(p, 0) + 1
        mat = _load_matrix()
        tactics = []
        total = 0
        covered = 0
        for tactic in mat.get("tactics", []):
            techs = []
            for tech in tactic.get("techniques", []):
                tid = tech.get("id", "")
                total += 1
                if tid in executed:
                    covered += 1
                techs.append({"id": tid, "name": tech.get("name", tid),
                               "status": "covered" if tid in executed else "not_tested"})
            tactics.append({"tactic": tactic.get("tactic", ""), "techniques": techs})
        coverage_pct = int(100 * covered / total) if total else 0
        if fmt == "json":
            return jsonify({"total_techniques": total, "covered": covered,
                            "coverage_pct": coverage_pct, "protocols": proto_counts,
                            "scenarios": len(sc), "tactics": tactics})
        html = generate_report(
            run_id=None, scenario_name="ICSForge Coverage Heatmap",
            executed_techniques=sorted(executed), detected_techniques=[],
            gap_techniques=[],
            meta={"assess_date": datetime.now().strftime("%Y-%m-%d"),
                  "assessor": "ICSForge Coverage Heatmap",
                  "note": f"{len(sc)} scenarios · {len(proto_counts)} protocols · {coverage_pct}% coverage"},
        )
        buf = io.BytesIO(html.encode("utf-8"))
        buf.seek(0)
        return send_file(buf, mimetype="text/html", as_attachment=True,
                         download_name=f"icsforge_heatmap_{coverage_pct}pct.html")
    except (OSError, ValueError, ImportError) as exc:
        log.error("Heatmap generation failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── Matrix status
@bp.route("/api/matrix_status")
def api_matrix_status():
    run_id = (request.args.get("run_id") or "").strip()
    rr = _repo_root()
    mat = _load_matrix()
    support: dict = {}
    try:
        support = json.loads(
            Path(os.path.join(rr, "icsforge", "data", "technique_support.json")).read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        log.debug("Could not load technique_support.json: %s", exc)

    covered: set = set()
    try:
        for pack in _list_packs():
            doc = _load_yaml(pack) or {}
            for s in (doc.get("scenarios") or {}).values():
                for step in s.get("steps", []):
                    tid = step.get("technique")
                    if tid:
                        covered.add(tid)
    except (OSError, ValueError) as exc:
        log.debug("Could not scan packs for coverage: %s", exc)

    runnable = {t for t in covered
                if not support.get(t, {}).get("precursor", False)
                or support.get(t, {}).get("runnable", False)}
    precursor = {t for t in covered
                 if support.get(t, {}).get("precursor", False)
                 and not support.get(t, {}).get("runnable", False)}
    runnable -= precursor

    executed: set = set()
    detected: set = set()
    gaps: set = set()
    if run_id == "__all__":
        # Aggregate executed/detected/gaps across ALL runs in the registry.
        # list_runs() is lightweight (no artifacts); call get_run() per run_id
        # to get the artifacts list, then scan each events JSONL.
        try:
            reg = _registry()
            slim_runs = reg.list_runs(limit=500) if hasattr(reg, "list_runs") else []
            for slim in slim_runs:
                run = reg.get_run(slim["run_id"])
                if not run:
                    continue
                # Techniques from events JSONL (ground-truth, most reliable)
                ev_path = next(
                    (a.get("path") for a in (run.get("artifacts") or [])
                     if a.get("kind") == "events"), None
                )
                if ev_path and os.path.exists(ev_path):
                    with open(ev_path, encoding="utf-8") as f:
                        for line in f:
                            try:
                                t = json.loads(line).get("mitre.ics.technique")
                                if t: executed.add(t)
                            except json.JSONDecodeError:
                                continue
                # Fallback: techniques in run meta (campaign runs)
                meta = run.get("meta") or {}
                for t in (meta.get("techniques") or []):
                    executed.add(t)
                # Detections/gaps from correlation reports
                for a in reversed(run.get("artifacts") or []):
                    if a.get("kind") == "report" and a.get("path", "").endswith(".json"):
                        try:
                            corr = json.loads(Path(a["path"]).read_text(encoding="utf-8"))
                            detected |= set(corr.get("observed") or [])
                            gaps     |= set(corr.get("gaps")     or [])
                            break
                        except (OSError, json.JSONDecodeError):
                            continue
        except Exception as exc:
            log.debug("Could not aggregate all runs for matrix status: %s", exc)
    elif run_id:
        try:
            reg = _registry()
            run = reg.get_run(run_id) or {}
            ev_path = next(
                (a.get("path") for a in run.get("artifacts", []) if a.get("kind") == "events"),
                None,
            )
            if ev_path and os.path.exists(ev_path):
                with open(ev_path, encoding="utf-8") as f:
                    for line in f:
                        try:
                            t = json.loads(line).get("mitre.ics.technique")
                            if t:
                                executed.add(t)
                        except json.JSONDecodeError:
                            continue
            # Fallback: campaign runs store techniques in meta (their events file is a
            # progress log, not a ground-truth scenario events file with mitre.ics.technique)
            if not executed:
                meta = run.get("meta") or {}
                for t in (meta.get("techniques") or []):
                    executed.add(t)
            corr = None
            for a in reversed(run.get("artifacts", [])):
                if a.get("kind") == "report" and a.get("path", "").endswith(".json"):
                    try:
                        corr = json.loads(Path(a["path"]).read_text(encoding="utf-8"))
                        break
                    except (OSError, json.JSONDecodeError):
                        continue
            if corr:
                detected = set(corr.get("observed") or [])
                gaps = set(corr.get("gaps") or [])
        except (OSError, ValueError) as exc:
            log.debug("Could not load run data for matrix status %s: %s", run_id, exc)

    status: dict = {}
    for tac in mat.get("tactics", []):
        for tech in tac.get("techniques", []):
            tid = tech.get("id")
            if not tid:
                continue
            sup_entry = support.get(tid, {})
            is_precursor = (tid in precursor) or (
                sup_entry.get("precursor") and not sup_entry.get("runnable") and tid not in runnable
            )
            is_runnable = (tid in runnable) and not is_precursor
            status[tid] = {
                "runnable": is_runnable,
                "precursor": is_precursor,
                "class": sup_entry.get("class", "unknown"),
                "executed": tid in executed,
                "detected": tid in detected,
                "gap": tid in gaps,
                "reason": sup_entry.get("reason", "") if sup_entry.get("class") != "unknown" else "",
            }
    # Build matrix summary — note: some techniques appear under multiple tactics
    # (e.g. T0856 under Evasion AND Impair Process Control), so total matrix
    # entries (94) > unique technique IDs (83). Both counts are intentional.
    total_entries  = sum(len(tac.get("techniques", [])) for tac in mat.get("tactics", []))
    unique_ids     = len({t["id"] for tac in mat.get("tactics", []) for t in tac.get("techniques", [])})
    return jsonify({
        "run_id": run_id or None,
        "status": status,
        "matrix_info": {
            "total_entries": total_entries,
            "unique_technique_ids": unique_ids,
            "note": "total_entries > unique_technique_ids because some techniques appear under multiple tactics",
        },
    })
