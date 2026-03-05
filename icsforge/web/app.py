from __future__ import annotations
import json
import os
import sys
import subprocess
import collections
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Blueprint, Flask, jsonify, render_template, request, session, redirect, url_for, Response, stream_with_context, send_file

from icsforge import __version__
from icsforge.live.sender import send_scenario_live
from icsforge.scenarios.engine import run_scenario
from icsforge.reports.network_validation import build_network_validation_report
from icsforge.state import RunRegistry, default_db_path
from icsforge.detection.mapping import correlate_run

# ATT&CK for ICS matrix data (bundled)
MATRIX_JSON_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "ics_attack_matrix.json")
MATRIX_SINGLETON_PACK = os.path.join(os.path.dirname(__file__), "..", "scenarios", "scenarios.yml")
TECH_VARIANTS = os.path.join(os.path.dirname(__file__), "..", "data", "technique_variants.json")

def _load_matrix() -> dict:
    try:
        return json.loads(Path(MATRIX_JSON_PATH).read_text(encoding="utf-8"))
    except Exception:
        return {"tactics": [], "x_mitre_version": "?"}


import yaml

web = Blueprint("web", __name__, template_folder="templates", static_folder="static")

@web.app_context_processor
def inject_ui_mode():
    # UI mode is fixed at process start by launcher: 'sender' or 'receiver'
    mode = os.environ.get("ICSFORGE_UI_MODE", "sender").strip().lower()
    if mode not in ("sender", "receiver"):
        mode = "sender"
    return {"ui_mode": mode}

@web.before_app_request
def _guard_ui_mode():
    mode = os.environ.get("ICSFORGE_UI_MODE", "sender").strip().lower()
    if mode not in ("sender", "receiver"):
        mode = "sender"

    ep = (request.endpoint or "")

    if mode == "sender":
        # Sender web should not expose receiver console
        if ep == "web.receiver":
            return redirect(url_for("web.sender"))
    else:
        # Receiver web should be an appliance UI
        if ep in ("web.sender",):
            return redirect(url_for("web.receiver"))
        if ep == "web.index":
            return redirect(url_for("web.receiver"))




def _registry():
    rr = _repo_root()
    return RunRegistry(default_db_path(rr))

def _artifact_rel(repo_root: str, path: str) -> str:
    if not path:
        return ""
    p = os.path.realpath(path if os.path.isabs(path) else os.path.join(repo_root, path))
    rr = os.path.realpath(repo_root)
    if p.startswith(rr):
        return os.path.relpath(p, rr)
    return path

def _repo_root() -> str:
    # assume web package lives at icsforge/web
    return str(Path(__file__).resolve().parents[2])
def _is_safe_private_ip(ip: str) -> bool:
    """Allow RFC1918, loopback, link-local, and TEST-NET ranges. Block public/global."""
    try:
        import ipaddress
        a = ipaddress.ip_address(ip)
        if a.is_loopback or a.is_private or a.is_link_local:
            return True
        # TEST-NETs
        for net in ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]:
            if a in ipaddress.ip_network(net):
                return True
        return False
    except Exception:
        return False
def _resolve_pack(pack: str) -> str | None:
    """Resolve a scenario pack path sent by the browser.
    Accepts absolute paths (preferred) and repo-relative paths (more portable).
    Returns an absolute path if found and safe, otherwise None.
    """
    if not pack:
        return None
    rr = os.path.realpath(_repo_root())
    # First try as-is
    cand = os.path.realpath(pack)
    if os.path.exists(cand) and cand.startswith(rr):
        return cand
    # Then try repo-relative
    cand = os.path.realpath(os.path.join(rr, pack.lstrip("/")))
    if os.path.exists(cand) and cand.startswith(rr):
        return cand
    return None

def _canonical_scenarios_path() -> str:
    """Single source of truth for scenarios for all web UIs."""
    return str(Path(_repo_root()) / "icsforge" / "scenarios" / "scenarios.yml")



def _tech_name(tid: str) -> str:
    try:
        mat = _load_matrix()
        for tac in mat.get("tactics", []):
            for tech in tac.get("techniques", []):
                if tech.get("id") == tid:
                    return tech.get("name") or tid
    except Exception:
        pass
    return tid






def _default_receipts_path() -> str:
    return os.path.join(_repo_root(), "receiver_out", "receipts.jsonl")


def _load_yaml(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _list_packs() -> List[str]:
    rr = _repo_root()
    # Keep it simple and predictable
    candidates = [
        os.path.join(rr, "icsforge", "scenarios", "scenarios.yml"),
        os.path.join(rr, "catalog", "scenarios.yml"),
    ]
    return [p for p in candidates if os.path.exists(p)]


def _default_pack() -> str | None:
    return _canonical_scenarios_path()




def _list_profiles() -> List[str]:
    rr = _repo_root()
    pdir = os.path.join(rr, "icsforge", "profiles")
    if not os.path.isdir(pdir):
        return []
    return sorted([str(Path(pdir, f)) for f in os.listdir(pdir) if f.endswith(".yml")])


def _read_jsonl_tail(path: str, limit: int = 250) -> List[dict]:
    if not os.path.exists(path):
        return []
    items = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except Exception:
                continue
    return items[-limit:]



# Phase 4.3: run index (for SOC Mode)
def _run_index_path() -> str:
    return os.path.join(_repo_root(), "out", "run_index.json")

def _load_run_index() -> List[dict]:
    p = _run_index_path()
    if not os.path.exists(p):
        return []
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception:
        return []

def _append_run_index(entry: dict) -> None:
    os.makedirs(os.path.dirname(_run_index_path()), exist_ok=True)
    items = _load_run_index()
    items.insert(0, entry)
    Path(_run_index_path()).write_text(json.dumps(items[:100], indent=2), encoding="utf-8")

def _alerts_path(run_id: str) -> str:
    return os.path.join(_repo_root(), "out", "alerts", f"{run_id}.jsonl")

def _validation_path(run_id: str) -> str:
    return os.path.join(_repo_root(), "out", "validation", f"{run_id}.json")

def _export_path(run_id: str) -> str:
    return os.path.join(_repo_root(), "out", "exports", f"{run_id}.html")

def _bin_receipts(items: List[dict], bins: int = 40) -> List[dict]:
    ts = []
    for r in items:
        t = r.get("@timestamp")
        if not t:
            continue
        try:
            dt = datetime.fromisoformat(t.replace("Z","+00:00"))
            ts.append(dt.timestamp())
        except Exception:
            continue
    if len(ts) < 2:
        step = max(1, len(items)//bins)
        out=[]
        for i in range(0, len(items), step):
            out.append({"i": len(out), "count": len(items[i:i+step])})
        return out[:bins]
    tmin, tmax = min(ts), max(ts)
    span = max(1.0, tmax - tmin)
    out=[{"i": i, "count": 0} for i in range(bins)]
    for t in ts:
        idx = int((t - tmin) / span * (bins-1))
        out[idx]["count"] += 1
    return out


def _stats_from_receipts(items: List[dict]) -> dict:
    runs = set()
    techs = set()
    protos = set()
    for r in items:
        if r.get("run_id"): runs.add(r["run_id"])
        if r.get("technique"): techs.add(r["technique"])
        if r.get("receiver.proto"): protos.add(r["receiver.proto"])
    return {
        "total": len(items),
        "runs": len(runs),
        "techniques": len(techs),
        "protocols": len(protos),
    }


@web.route("/")
def index():
    mode = os.environ.get('ICSFORGE_UI_MODE','sender').strip().lower()
    if mode == 'receiver':
        return redirect(url_for('web.receiver'))
    packs = _list_packs()

    # Aggregate counts + build browse data for the landing page.
    scenarios_total = 0
    proto_set = set()
    tech_counter = collections.Counter()
    pack_cards = []  # [{name,count,techniques,protocols}]

    for p in packs:
        doc = _load_yaml(p) or {}
        sc = (doc.get("scenarios") or {})
        scenarios_total += len(sc)

        p_protos = set()
        p_techs = set()

        for _, v in sc.items():
            for step in (v.get("steps") or []):
                if step.get("proto"):
                    p_protos.add(str(step["proto"]).lower())
                if step.get("technique"):
                    tid = str(step["technique"])
                    p_techs.add(tid)
                    tech_counter[tid] += 1

        proto_set |= p_protos
        pack_cards.append(
            {
                "name": Path(p).stem,
                "count": len(sc),
                "protocols": sorted(p_protos),
                "techniques": sorted(p_techs),
            }
        )

    profiles_total = len(_list_profiles())

    # Top techniques (by number of scenarios referencing them)
    top_tech = []
    for tid, cnt in tech_counter.most_common(30):
        top_tech.append({"id": tid, "name": _tech_name(tid), "scenario_refs": cnt})

    # Sample scenarios (fast browse) from the first pack (same default as Sender UI)
    scenarios_sample = []
    try:
        first = packs[0] if packs else None
        if first:
            doc = _load_yaml(first) or {}
            sc = (doc.get("scenarios") or {})
            # Sort by ID to keep it readable (your new naming makes this great)
            for sid in sorted(sc.keys())[:40]:
                title = sc[sid].get("title") or sid
                scenarios_sample.append({"id": sid, "title": title})
    except Exception:
        pass

    return render_template(
        "index.html",
        title="ICSForge",
        subtitle="Enterprise OT/ICS Telemetry Lab",
        env_label="LOCAL",
        version=__version__,
        active_tab=True,
        kpis={
            "scenarios": scenarios_total,
            "protocols": len(proto_set),
            "techniques": len(tech_counter.keys()),
            "profiles": profiles_total,
        },
        pack_cards=sorted(pack_cards, key=lambda x: (-x["count"], x["name"])),
        top_techniques=top_tech,
        scenarios_sample=scenarios_sample,
    )
@web.route("/receiver")
def receiver():
    receipts_path = _default_receipts_path()
    items = _read_jsonl_tail(receipts_path, limit=300)
    return render_template(
        "receiver.html",
        title="ICSForge Receiver",
        subtitle="Passive Proof-of-Delivery",
        env_label="RECEIVER",
        version=__version__,
        active_tab=True,
        receipts_path=receipts_path,
        stats=_stats_from_receipts(items),
    )


@web.route("/tools")
def tools():
    return render_template(
        "tools.html",
        title="ICSForge Tools",
        subtitle="Offline Generate • Custom Validation • Selftest",
        env_label="TOOLS",
        version=__version__,
        active_tab=True,
    )


@web.route("/matrix")
def matrix():
    mat = _load_matrix()
    import json as _json
    support = {}
    try:
        support = _json.loads(Path(os.path.join(_repo_root(), "icsforge", "data", "technique_support.json")).read_text(encoding="utf-8"))
    except Exception:
        pass
    covered = set()
    try:
        for pack_path in _list_packs():
            doc = _load_yaml(pack_path) or {}
            for sc in (doc.get("scenarios") or {}).values():
                for step in sc.get("steps", []):
                    tid = step.get("technique")
                    if tid: covered.add(tid)
    except Exception:
        pass
    precursor = set(t for t in covered if support.get(t, {}).get("precursor") and not support.get(t, {}).get("runnable"))
    runnable  = covered - precursor
    status = {}
    for tac in mat.get("tactics", []):
        for tech in tac.get("techniques", []):
            tid = tech.get("id")
            if not tid: continue
            status[tid] = {"runnable": tid in runnable, "precursor": tid in precursor}
    supported = sorted(t for t in status if status[t]["runnable"] or status[t]["precursor"])

    return render_template(
        "matrix.html",
        title="ATT&CK Matrix",
        subtitle="Interactive ATT&CK v18 for ICS",
        env_label="MATRIX",
        version=__version__,
        active_tab=True,
        matrix=mat,
        status=status,
        supported=supported,
    )



@web.route("/soc")
def soc():
    """SOC Mode removed — redirect to Sender."""
    return redirect(url_for("web.sender"))
def _soc_removed():
    return render_template(
        "soc.html",
        title="ICSForge SOC Mode",
        subtitle="Send → Receive → Alert → Validate",
        env_label="SOC",
        version=__version__,
        active_tab=True,
    )


@web.route("/sender")
def sender():
    packs = _list_packs()
    first_pack = packs[0] if packs else None
    scenarios_initial = []
    try:
        if first_pack:
            doc = _load_yaml(first_pack) or {}
            scenarios_initial = sorted(list((doc.get("scenarios") or {}).keys()))
    except Exception:
        scenarios_initial = []

    return render_template(
        "sender.html",
        title="ICSForge Sender",
        subtitle="Scenario Control Plane",
        env_label="SENDER",
        version=__version__,
        active_tab=True,
        packs=packs,
        first_pack=first_pack,
        scenarios_initial=scenarios_initial,
    )



@web.route("/api/receiver/overview")
def api_receiver_overview():
    receipts_path = _default_receipts_path()
    items = _read_jsonl_tail(receipts_path, limit=2000)
    total=len(items)
    last = items[-1] if items else None
    techniques={}
    protos={}
    for r in items:
        t=r.get("technique") or "unknown"
        p=r.get("receiver.proto") or "unknown"
        techniques[t]=techniques.get(t,0)+1
        protos[p]=protos.get(p,0)+1
    top_tech=sorted(techniques.items(), key=lambda x: x[1], reverse=True)[:8]
    top_proto=sorted(protos.items(), key=lambda x: x[1], reverse=True)[:8]
    # L2 listener status — set by receiver main() when thread starts
    l2_iface = os.environ.get("ICSFORGE_L2_IFACE", "").strip()
    return jsonify({
        "total": total,
        "last_ts": (last.get("@timestamp") or last.get("ts")) if last else None,
        "last_run_id": (last.get("run_id") if last else None),
        "top_techniques": top_tech,
        "top_protocols": top_proto,
        "l2_iface": l2_iface or None,
        "l2_active": bool(l2_iface),
    })

@web.route("/api/receipts")
def api_receipts():
    receipts_path = _default_receipts_path()
    items = _read_jsonl_tail(receipts_path, limit=int(request.args.get("limit", 250)))
    run_id = (request.args.get("run_id") or "").strip()
    tech = (request.args.get("technique") or "").strip()
    proto = (request.args.get("proto") or "").strip()
    out=[]
    for r in reversed(items):
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


@web.route("/api/run")
def api_run():
    receipts_path = _default_receipts_path()
    items = _read_jsonl_tail(receipts_path, limit=2000)
    run_id = (request.args.get("run_id") or "").strip()
    if not run_id:
        return jsonify({})
    filtered = [r for r in items if r.get("run_id") == run_id]
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


@web.route("/api/scenarios")
def api_scenarios():
    real = _canonical_scenarios_path()
    if not os.path.exists(real):
        return jsonify({'scenarios': []})
    doc = _load_yaml(real)
    sc = sorted((doc.get("scenarios") or {}).keys())
    return jsonify({"scenarios": sc})


@web.route("/api/preview")
def api_preview():
    name = request.args.get('name')
    real = _canonical_scenarios_path()
    if not os.path.exists(real):
        return jsonify({'error':'Scenario pack not found'}), 404
    doc = _load_yaml(real)
    scenarios = (doc.get("scenarios") or {})
    aliases = (doc.get("aliases") or {})
    if name not in scenarios and name in aliases:
        name = aliases[name]
    sc = scenarios.get(name)
    if not sc:
        return jsonify({"error": "Scenario not found"})
    steps = sc.get("steps") or []
    techs = sorted(set([s.get("technique") for s in steps if s.get("technique")]))
    slim = [{
        "type": s.get("type"),
        "proto": s.get("proto"),
        "technique": s.get("technique"),
        "style": s.get("style", "auto"),
        "count": s.get("count", 1),
        "interval": s.get("interval", "0s"),
        "message": s.get("message", ""),
    } for s in steps]
    return jsonify({
        "name": name,
        "title": sc.get("title", name),
        "description": sc.get("description", ""),
        "steps": slim,
        "techniques": techs,
        "is_chain": name.startswith("CHAIN__"),
    })


@web.route("/api/preview_payload")
def api_preview_payload():
    """Return hex dump of actual PDU bytes for a scenario step."""
    name = request.args.get('name')
    step_idx = int(request.args.get('step', 0))
    real = _canonical_scenarios_path()
    if not os.path.exists(real):
        return jsonify({'error': 'Scenario pack not found'}), 404
    doc = _load_yaml(real)
    scenarios = doc.get("scenarios") or {}
    aliases = doc.get("aliases") or {}
    if name not in scenarios and name in aliases:
        name = aliases[name]
    sc = scenarios.get(name)
    if not sc:
        return jsonify({"error": "Scenario not found"}), 404
    steps = [s for s in (sc.get("steps") or []) if s.get("proto") and s.get("type") in ("packet", "pcap")]
    if not steps:
        return jsonify({"error": "No packet steps in scenario"}), 400
    step_idx = max(0, min(step_idx, len(steps) - 1))
    step = steps[step_idx]
    proto = step.get("proto")
    style = step.get("style", "auto")
    tech = step.get("technique", "")
    marker = f"ICSFORGE:PREVIEW:{name[:20]}:{tech}:"
    try:
        from icsforge.protocols import modbus, dnp3, s7comm, iec104, opcua, enip, profinet_dcp
        builders = {
            "modbus": modbus.build_payload,
            "dnp3": dnp3.build_payload,
            "s7comm": s7comm.build_payload,
            "iec104": iec104.build_payload,
            "opcua": opcua.build_payload,
            "enip": enip.build_payload,
            "profinet_dcp": profinet_dcp.build_payload,
        }
        ports = {"modbus": 502, "dnp3": 20000, "s7comm": 102, "iec104": 2404,
                 "opcua": 4840, "enip": 44818, "profinet_dcp": 0}
        if proto not in builders:
            return jsonify({"error": f"Unknown proto: {proto}"}), 400
        # profinet_dcp expects bytes marker; TCP builders accept string
        marker_b = marker.encode() if proto == "profinet_dcp" else marker
        data = builders[proto](marker_b, style=style)
        width = 16
        lines = []
        for i in range(0, len(data), width):
            chunk = data[i:i+width]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:04x}  {hex_part:<{width*3}}  {ascii_part}")
        return jsonify({
            "proto": proto,
            "style": style,
            "technique": tech,
            "port": ports.get(proto, 0),
            "length": len(data),
            "step_index": step_idx,
            "step_count": len(steps),
            "hexdump": "\n".join(lines),
            "hex_raw": data.hex(),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@web.route("/api/scenarios_grouped")
def api_scenarios_grouped():
    """Return scenarios grouped by tactic, with metadata for UI rendering."""
    real = _canonical_scenarios_path()
    if not os.path.exists(real):
        return jsonify({"groups": []}), 404
    doc = _load_yaml(real)
    scenarios = doc.get("scenarios") or {}
    mat = _load_matrix()
    tid_tactic = {}
    tid_name = {}
    for tac in mat.get("tactics", []):
        for tech in tac.get("techniques", []):
            tid = tech.get("id", "")
            tid_tactic[tid] = tac.get("name", "Other")
            tid_name[tid] = tech.get("name", "")
    groups = {}
    for sc_name, sc in scenarios.items():
        steps = sc.get("steps") or []
        techs = sorted(set(s.get("technique") for s in steps if s.get("technique")))
        protos = sorted(set(s.get("proto") for s in steps if s.get("proto")))
        if sc_name.startswith("CHAIN__"):
            group = "\u26d3 Attack Chains"
        elif techs:
            group = tid_tactic.get(techs[0], "Other")
        else:
            group = "Other"
        groups.setdefault(group, [])
        groups[group].append({
            "id": sc_name,
            "title": sc.get("title", sc_name),
            "techniques": techs,
            "tech_names": [tid_name.get(t, t) for t in techs],
            "protocols": protos,
            "is_chain": sc_name.startswith("CHAIN__"),
            "step_count": len(steps),
        })
    order = ["\u26d3 Attack Chains", "Initial Access", "Discovery", "Collection",
             "Lateral Movement", "Execution", "Persistence", "Evasion",
             "Impair Process Control", "Inhibit Response Function", "Impact", "Other"]
    sorted_groups = []
    seen = set()
    for g in order:
        if g in groups:
            sorted_groups.append({"name": g, "scenarios": sorted(groups[g], key=lambda x: x["id"])})
            seen.add(g)
    for g, items in groups.items():
        if g not in seen:
            sorted_groups.append({"name": g, "scenarios": sorted(items, key=lambda x: x["id"])})
    return jsonify({"groups": sorted_groups})


@web.route("/api/send", methods=["POST"])
def api_send():
    if os.environ.get('ICSFORGE_UI_MODE','sender').strip().lower() == 'receiver':
        return jsonify({'ok': False, 'error': 'send disabled in receiver mode'}), 403
    data = request.get_json(force=True) or {}
    pack = _canonical_scenarios_path()
    name = data.get("name")
    dst_ip = (data.get("dst_ip") or "").strip()
    outdir = (data.get("outdir") or "out").strip()
    allowlist = (data.get("allowlist") or "").strip()
    timeout = float(data.get("timeout") or 2.0)
    also_build_pcap = bool(data.get("also_build_pcap"))
    timeout = float(data.get("timeout") or 2.0)
    allowlist = (data.get("allowlist") or "").strip()
    iface = (data.get("iface") or "").strip() or None
    outdir = (data.get("outdir") or "out").strip()
    src_ip = (data.get("src_ip") or "127.0.0.1").strip()
    iface = (data.get("iface") or "").strip() or None
    src_ip = (data.get("src_ip") or "127.0.0.1").strip()
    if not name:
        return jsonify({"error": "Scenario name missing"}), 400
    if not dst_ip:
        return jsonify({"error": "Destination IP missing"}), 400

    allow = [x.strip() for x in allowlist.split(",") if x.strip()] or [dst_ip]

    try:
        res = send_scenario_live(
            scenario_file=pack,
            scenario_name=name,
            dst_ip=dst_ip,
            iface=iface,
            confirm_live_network=True,
            receiver_allowlist=allow,
            timeout=timeout,
        )

        # Create ground-truth artifacts (events jsonl + optional pcap)
        gt = run_scenario(
            pack,
            name,
            outdir,
            dst_ip=dst_ip,
            src_ip=src_ip,
            run_id=res["run_id"],
            build_pcap=also_build_pcap,
        )

        # Index run for SOC Mode (legacy JSONL + enterprise DB)
        try:
            reg = _registry()
            reg.upsert_run(res["run_id"], scenario=name, pack=pack, dst_ip=dst_ip, src_ip=src_ip, iface=iface, mode="live", status="ok", meta={"sent": res.get("sent")})
            reg.add_artifact(res["run_id"], "events", gt.get("events"))
            if gt.get("pcap"):
                reg.add_artifact(res["run_id"], "pcap", gt.get("pcap"))
        except Exception:
            pass

        # Index run for SOC Mode
        entry = {
            "run_id": res["run_id"],
            "scenario": name,
            "pack": pack,
            "events": gt.get("events"),
            "pcap": gt.get("pcap"),
            "ts": datetime.utcnow().isoformat() + "Z",
        }
        try:
            _append_run_index(entry)
        except Exception:
            pass

        return jsonify(
            {
                "run_id": res["run_id"],
                "sent": res["sent"],
                "events": gt.get("events"),
                "pcap": gt.get("pcap"),
                "warnings": res.get("warnings", []),
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500




def create_app() -> Flask:
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.register_blueprint(web)
    # Expose blueprint routes
    app.add_url_rule("/", endpoint="web.index", view_func=index)
    return app


def main():
    import argparse
    ap = argparse.ArgumentParser(prog="icsforge-web")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    app = Flask(__name__, static_folder=os.path.join(os.path.dirname(__file__), "static"),
                template_folder=os.path.join(os.path.dirname(__file__), "templates"))
    app.register_blueprint(web)
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()

@web.route("/api/runs")
def api_runs():
    try:
        reg=_registry()
        return jsonify({"runs": reg.list_runs(50)})
    except Exception:
        return jsonify({"runs": _load_run_index()[:30]})


@web.route("/api/run_full")
def api_run_full():
    run_id = (request.args.get("run_id") or "").strip()
    if not run_id:
        return jsonify({"error": "run_id required"}), 400
    idx = {}
    try:
        reg=_registry()
        idx = reg.get_run(run_id) or {}
    except Exception:
        idx = next((x for x in _load_run_index() if x.get("run_id") == run_id), None) or {}
    receipts_path = _default_receipts_path()
    receipts = [r for r in _read_jsonl_tail(receipts_path, limit=4000) if r.get("run_id") == run_id]
    receipts.sort(key=lambda x: x.get("@timestamp") or "")
    techs = sorted(set([r.get("technique") for r in receipts if r.get("technique")]))
    return jsonify({
        "run_id": run_id,
        "scenario": idx.get("scenario"),
        "events": idx.get("events"),
        "pcap": idx.get("pcap"),
        "ts": idx.get("ts"),
        "techniques": techs,
        "bins": _bin_receipts(receipts, bins=40),
        "receipts_preview": receipts[-20:],
        "artifacts": idx.get("artifacts", []),
    })


@web.route("/api/run_detail")
def api_run_detail():
    run_id = (request.args.get("run_id") or "").strip()
    if not run_id:
        return jsonify({})
    receipts_path = _default_receipts_path()
    items = [r for r in _read_jsonl_tail(receipts_path, limit=4000) if r.get("run_id") == run_id]
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


@web.route("/api/alerts/save", methods=["POST"])
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


@web.route("/api/validate", methods=["POST"])
def api_validate_run():
    data = request.get_json(force=True) or {}
    run_id = (data.get("run_id") or "").strip()
    if not run_id:
        return jsonify({"error": "run_id required"}), 400
    idx = {}
    try:
        reg=_registry()
        idx = reg.get_run(run_id) or {}
    except Exception:
        idx = next((x for x in _load_run_index() if x.get("run_id") == run_id), None) or {}
    events_path = idx.get("events")
    if not events_path:
        return jsonify({"error": "Ground-truth events path not found for this run"}), 400
    receipts_path = _default_receipts_path()
    alerts_path = _alerts_path(run_id)
    out_path = _validation_path(run_id)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    try:
        report = build_network_validation_report(
            events_path,
            receipts_path,
            alerts_jsonl=(alerts_path if os.path.exists(alerts_path) and Path(alerts_path).stat().st_size>0 else None),
            out_path=out_path,
        )
        return jsonify({"ok": True, "report_path": out_path, "report": report})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@web.route("/api/export")
def api_export_run():
    run_id = (request.args.get("run_id") or "").strip()
    if not run_id:
        return jsonify({"error": "run_id required"}), 400
    idx = {}
    try:
        reg=_registry()
        idx = reg.get_run(run_id) or {}
    except Exception:
        idx = next((x for x in _load_run_index() if x.get("run_id") == run_id), None) or {}
    receipts_path = _default_receipts_path()
    receipts = [r for r in _read_jsonl_tail(receipts_path, limit=4000) if r.get("run_id") == run_id]
    receipts.sort(key=lambda x: x.get("@timestamp") or "")
    techs = sorted(set([r.get("technique") for r in receipts if r.get("technique")]))
    val_path = _validation_path(run_id)
    validation = None
    if os.path.exists(val_path):
        try:
            validation = json.loads(Path(val_path).read_text(encoding="utf-8"))
        except Exception:
            validation = None

    html = f"""<!doctype html>
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
<div class='muted'>run_id: <span class='mono'>{run_id}</span> • scenario: {idx.get('scenario','-')} • generated: {datetime.utcnow().isoformat()}Z</div>
</div>

<div class='card'><h2>Summary</h2>
<div class='muted'>Packets received: <b>{len(receipts)}</b></div>
<div style='margin-top:8px'>Techniques observed:<br>
{''.join([f"<span class='badge mono'>{t}</span>" for t in techs]) or '<span class="badge">none</span>'}
</div>
<div style='margin-top:10px' class='muted'>Ground truth events: <span class='mono'>{idx.get('events','-')}</span><br>
PCAP: <span class='mono'>{idx.get('pcap','-')}</span></div>
</div>

<div class='card'><h2>Delivery Evidence (last 20 receipts)</h2>
<table><thead><tr><th>Time</th><th>Proto</th><th>Src</th><th>Technique</th><th>Bytes</th></tr></thead><tbody>
{''.join([f"<tr><td class='mono'>{(r.get('@timestamp') or '')}</td><td>{r.get('receiver.proto','')}</td><td class='mono'>{r.get('src_ip','')}:{r.get('src_port','')}</td><td class='mono'>{r.get('technique','')}</td><td class='mono'>{r.get('bytes','')}</td></tr>" for r in receipts[-20:]])}
</tbody></table></div>

<div class='card'><h2>Validation</h2>
<div class='muted'>Validation file: <span class='mono'>{val_path if os.path.exists(val_path) else '-'}</span></div>
<pre class='mono'>{json.dumps(validation, indent=2) if validation else 'Run validation from SOC Mode to populate this section.'}</pre>
</div>

<div class='muted' style='margin:20px 0'>ICSForge • GPLv3 • Enterprise OT/ICS Telemetry Lab</div>
</div></body></html>"""

    out_path = _export_path(run_id)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    Path(out_path).write_text(html, encoding="utf-8")
    return jsonify({"ok": True, "path": out_path, "download_url": f"/download?path={out_path}"})



@web.route("/api/interfaces")
def api_interfaces():
    """List local interfaces for L2/L3 sends (best-effort)."""
    ifaces = []
    # Prefer `ip link` on Linux
    try:
        out = subprocess.check_output(["ip", "-o", "link", "show"], stderr=subprocess.STDOUT, text=True)
        for line in out.splitlines():
            # format: "2: eth0: <...>"
            m = re.match(r"\d+:\s+([^:]+):", line)
            if m:
                name = m.group(1)
                if name != "lo":
                    ifaces.append(name)
    except Exception:
        pass
    # Fallback: `ifconfig -a`
    if not ifaces:
        try:
            out = subprocess.check_output(["ifconfig", "-a"], stderr=subprocess.STDOUT, text=True)
            for line in out.splitlines():
                if line and not line.startswith("\t") and ":" in line:
                    name = line.split(":")[0].strip()
                    if name and name != "lo":
                        ifaces.append(name)
        except Exception:
            pass
    ifaces = sorted(set(ifaces))
    return jsonify({"interfaces": ifaces})



@web.route("/api/pcap/replay", methods=["POST"])
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
    safe_root = os.path.join(rr, "out")
    real = os.path.realpath(pcap_path)
    if not real.startswith(os.path.realpath(safe_root)):
        return jsonify({"error": "pcap_path must be inside out/"}), 400
    if not os.path.exists(real):
        return jsonify({"error": "pcap not found"}), 404

    # Safety: block global/public IPs; require private/test/link-local/loopback.
    if not _is_safe_private_ip(dst_ip):
        return jsonify({"error": "dst_ip blocked: must be private/test/link-local/loopback"}), 400
    # Optional allowlist: if provided, dst must be in it
    if allowlist and dst_ip not in allowlist:
        return jsonify({"error": "dst_ip not in allowlist"}), 400

    try:
        from icsforge.core import replay_pcap as _replay
        sent = _replay(real, dst_ip, interval=interval)
        return jsonify({"ok": True, "sent": sent})
    except Exception as e:
        return jsonify({"error": str(e)}), 500



def _save_run_index(items: List[dict]) -> None:
    os.makedirs(os.path.dirname(_run_index_path()), exist_ok=True)
    Path(_run_index_path()).write_text(json.dumps(items[:200], indent=2), encoding="utf-8")

def _update_run_entry(run_id: str, fn):
    items = _load_run_index()
    changed = False
    for it in items:
        if it.get("run_id") == run_id:
            fn(it)
            changed = True
            break
    if changed:
        _save_run_index(items)
    return changed

@web.route("/api/run/tag", methods=["POST"])
def api_run_tag():
    data = request.get_json(force=True) or {}
    run_id = (data.get("run_id") or "").strip()
    tags = data.get("tags") or []
    if not run_id:
        return jsonify({"error": "run_id required"}), 400
    if not isinstance(tags, list):
        return jsonify({"error": "tags must be a list"}), 400
    tags = sorted(set([str(t).strip() for t in tags if str(t).strip()]))
    ok = _update_run_entry(run_id, lambda it: it.__setitem__("tags", tags))
    return jsonify({"ok": ok, "run_id": run_id, "tags": tags})

@web.route("/api/run/rename", methods=["POST"])
def api_run_rename():
    data = request.get_json(force=True) or {}
    run_id = (data.get("run_id") or "").strip()
    title = (data.get("title") or "").strip()
    if not run_id:
        return jsonify({"error": "run_id required"}), 400
    if not title:
        return jsonify({"error": "title required"}), 400
    ok = _update_run_entry(run_id, lambda it: it.__setitem__("title", title))
    return jsonify({"ok": ok, "run_id": run_id, "title": title})

@web.route("/api/run/export_bundle")
def api_run_export_bundle():
    run_id = (request.args.get("run_id") or "").strip()
    if not run_id:
        return jsonify({"error": "run_id required"}), 400
    idx = {}
    try:
        reg=_registry()
        idx = reg.get_run(run_id) or {}
    except Exception:
        idx = next((x for x in _load_run_index() if x.get("run_id") == run_id), None) or {}
    rr = _repo_root()
    out_root = os.path.join(rr, "out")
    bundle_dir = os.path.join(out_root, "bundles")
    os.makedirs(bundle_dir, exist_ok=True)
    bundle_path = os.path.join(bundle_dir, f"{run_id}.zip")

    events_path = idx.get("events")
    pcap_path = idx.get("pcap")
    val_path = _validation_path(run_id)
    alerts_path = _alerts_path(run_id)
    receipts_path = _default_receipts_path()

    # Extract receipts for this run into bundle
    receipts = [r for r in _read_jsonl_tail(receipts_path, limit=20000) if r.get("run_id") == run_id]
    receipts_extract = os.path.join(out_root, "tmp", f"{run_id}_receipts.jsonl")
    os.makedirs(os.path.dirname(receipts_extract), exist_ok=True)
    Path(receipts_extract).write_text("\n".join([json.dumps(x, separators=(',',':')) for x in receipts]) + ("\n" if receipts else ""), encoding="utf-8")

    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        def add_if(path, arc):
            if path and os.path.exists(path):
                z.write(path, arcname=arc)
        add_if(events_path, f"{run_id}/events.jsonl")
        add_if(pcap_path, f"{run_id}/traffic.pcap")
        add_if(val_path if os.path.exists(val_path) else None, f"{run_id}/validation.json")
        add_if(alerts_path if os.path.exists(alerts_path) else None, f"{run_id}/alerts.jsonl")
        add_if(receipts_extract, f"{run_id}/receipts.jsonl")
        # Include index metadata snapshot
        z.writestr(f"{run_id}/run_index_entry.json", json.dumps(idx, indent=2))

    return jsonify({"ok": True, "path": bundle_path, "download_url": f"/download?path={bundle_path}"})


@web.route("/download")
def api_download():
    path = request.args.get("path")
    if not path:
        return jsonify({"error": "path required"}), 400
    rr = _repo_root()
    safe_root = os.path.join(rr, "out")
    real = os.path.realpath(path)
    if not real.startswith(os.path.realpath(safe_root)):
        return jsonify({"error": "blocked"}), 403
    return send_file(real, as_attachment=True)


@web.route("/api/technique/variants")
def api_technique_variants():
    technique = (request.args.get("technique") or "").strip()
    if not technique:
        return jsonify({"error": "technique required"}), 400
    try:
        doc = json.loads(Path(TECH_VARIANTS).read_text(encoding="utf-8"))
        v = (doc.get("variants") or {}).get(technique) or []
        return jsonify({"technique": technique, "variants": v})
    except Exception as e:
        return jsonify({"error": f"variants load failed: {e}"}), 500


@web.route("/api/technique/send", methods=["POST"])
def api_technique_send():
    data = request.get_json(force=True) or {}
    technique = (data.get("technique") or "").strip()
    variant = (data.get("variant") or "").strip()
    dst_ip = (data.get("dst_ip") or "").strip()
    also_build_pcap = bool(data.get("also_build_pcap"))
    timeout = float(data.get("timeout") or 2.0)
    allowlist = (data.get("allowlist") or "").strip()
    iface = (data.get("iface") or "").strip() or None
    outdir = (data.get("outdir") or "out").strip()
    src_ip = (data.get("src_ip") or "127.0.0.1").strip()
    iface = (data.get("iface") or "").strip() or None
    src_ip = (data.get("src_ip") or "127.0.0.1").strip()

    if not technique:
        return jsonify({"error": "technique required"}), 400
    if not dst_ip:
        return jsonify({"error": "dst_ip required"}), 400

    scenario_name = technique if not variant else f"{technique}__{variant}"

    try:
        pack = yaml.safe_load(Path(MATRIX_SINGLETON_PACK).read_text(encoding="utf-8")) or {}
        if scenario_name not in (pack.get("scenarios") or {}):
            if scenario_name != technique and technique in (pack.get("scenarios") or {}):
                scenario_name = technique
            else:
                return jsonify({"error": f"Technique {technique} is not supported for network simulation in this build."}), 400
    except Exception:
        return jsonify({"error": "Matrix scenario pack missing"}), 500

    try:
        res = send_scenario_live(
            scenario_file=MATRIX_SINGLETON_PACK,
            scenario_name=scenario_name,
            dst_ip=dst_ip,
            iface=iface,
            confirm_live_network=True,
            receiver_allowlist=([x.strip() for x in allowlist.split(',') if x.strip()] or [dst_ip]),
            timeout=timeout,
        )

        gt = run_scenario(
            MATRIX_SINGLETON_PACK,
            scenario_name,
            outdir=outdir,
            dst_ip=dst_ip,
            src_ip=src_ip,
            run_id=res["run_id"],
            build_pcap=also_build_pcap,
        )

        entry = {
            "run_id": res["run_id"],
            "scenario": scenario_name,
            "pack": MATRIX_SINGLETON_PACK,
            "events": gt.get("events"),
            "pcap": gt.get("pcap"),
            "ts": datetime.utcnow().isoformat() + "Z",
        }
        try:
            _append_run_index(entry)
        except Exception:
            pass

        return jsonify({"ok": True, "run_id": res["run_id"], "sent": res.get("sent"), "events": gt.get("events"), "pcap": gt.get("pcap")})
    except Exception as e:
        return jsonify({"error": str(e)}), 500




@web.route("/api/generate_offline", methods=["POST"])
def api_generate_offline():
    data = request.get_json(force=True) or {}
    pack = _canonical_scenarios_path()
    name = (data.get("name") or "").strip()
    outdir = (data.get("outdir") or "out").strip()
    dst_ip = (data.get("dst_ip") or "198.51.100.42").strip()
    src_ip = (data.get("src_ip") or "127.0.0.1").strip()
    build_pcap = bool(data.get("build_pcap"))
    run_id = (data.get("run_id") or "").strip() or None
    if not name:
        return jsonify({"error": "Scenario name missing"}), 400

    try:
        gt = run_scenario(pack, name, outdir, dst_ip=dst_ip, src_ip=src_ip, run_id=run_id, build_pcap=build_pcap)
        entry = {"run_id": gt.get("run_id") or run_id or "offline", "scenario": name, "pack": pack, "events": gt.get("events"), "pcap": gt.get("pcap"), "ts": datetime.utcnow().isoformat()+"Z"}
        try:
            _append_run_index(entry)
        except Exception:
            pass
        return jsonify({"ok": True, "run_id": entry["run_id"], "events": gt.get("events"), "pcap": gt.get("pcap")})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@web.route("/api/net_validate_custom", methods=["POST"])
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
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@web.route("/api/selftest", methods=["POST"])
def api_selftest():
    data = request.get_json(force=True) or {}
    live = bool(data.get("live"))
    dst_ip = (data.get("dst_ip") or "127.0.0.1").strip()
    bind = (data.get("bind") or "127.0.0.1").strip()
    cwd = (data.get("cwd") or _repo_root()).strip()
    receipts = (data.get("receipts") or "receiver_out/receipts.jsonl").strip()

    # Run via subprocess to mirror CLI behavior (safe, explicit)
    cmd = [sys.executable, "-m", "icsforge", "selftest"]
    if live:
        cmd += ["--live", "--dst-ip", dst_ip, "--bind", bind]
    cmd += ["--cwd", cwd, "--receipts", receipts]

    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=180)
        return jsonify({"ok": p.returncode == 0, "returncode": p.returncode, "stdout": p.stdout[-8000:], "stderr": p.stderr[-8000:], "cmd": cmd})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "selftest timed out"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@web.route("/api/packs")
def api_packs():
    return jsonify(_list_packs())


@web.route("/api/health")
def api_health():
    rr = _repo_root()
    packs = _list_packs()
    caps = {}
    # AF_PACKET (Linux raw L2 socket) — needed for PROFINET DCP live send/recv
    try:
        import socket as _s
        if hasattr(_s, "AF_PACKET"):
            sock = _s.socket(_s.AF_PACKET, _s.SOCK_RAW)  # type: ignore[attr-defined]
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
    except Exception as e:
        caps["af_packet"] = False
        caps["profinet_live"] = False
        caps["af_packet_note"] = str(e)

    # TCP raw socket for IP-layer protocols (no longer required — uses SOCK_STREAM now)
    caps["tcp_send"] = True
    caps["pcap_write"] = True  # pure-Python pcap writer always available

    receiver = request.args.get("receiver", "").strip()
    receiver_ok = None
    receiver_err = None
    if receiver:
        try:
            import urllib.request
            with urllib.request.urlopen(receiver.rstrip("/") + "/api/receiver/health", timeout=2) as r:
                receiver_ok = (200 <= r.status < 300)
        except Exception as e:
            receiver_ok = False
            receiver_err = str(e)

    return jsonify({
        "ok": True,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "repo_root": rr,
        "scenario_pack_count": len(packs),
        "scenario_packs": packs,
        "capabilities": caps,
        "receiver": receiver if receiver else None,
        "receiver_ok": receiver_ok,
        "receiver_error": receiver_err,
    })

@web.route("/health")
def health_page():
    return render_template("health.html", title="ICSForge Health", subtitle="Diagnostics & Readiness")


def _read_json_lines(path: str):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows

@web.route("/alerts")
def alerts_page():
    return render_template("alerts.html", title="ICSForge Alerts", subtitle="Ingest & Normalize")

@web.route("/api/alerts/ingest", methods=["POST"])
def api_alerts_ingest():
    data = request.get_json(force=True) or {}
    path = (data.get("path") or "").strip()
    run_id = (data.get("run_id") or "").strip()
    profile = (data.get("profile") or "suricata_eve").strip()

    if not path:
        return jsonify({"ok": False, "error": "Missing path"}), 400

    rr = os.path.realpath(_repo_root())
    p = os.path.realpath(os.path.join(rr, path.lstrip("/")))
    if not p.startswith(rr) or not os.path.exists(p):
        return jsonify({"ok": False, "error": "Path not found or not allowed"}), 400

    rows = _read_json_lines(p)
    norm = []
    for r in rows:
        if profile == "suricata_eve":
            ts = r.get("timestamp") or r.get("time") or r.get("event_timestamp")
            alert = r.get("alert") or {}
            sig = alert.get("signature") or r.get("signature") or "alert"
            sev = alert.get("severity") or r.get("severity")
            src = r.get("src_ip")
            dst = r.get("dest_ip") or r.get("dst_ip")
            app_proto = r.get("app_proto") or r.get("proto") or r.get("event_type")
            norm.append({
                "ts": ts,
                "signature": sig,
                "severity": sev,
                "src_ip": src,
                "dst_ip": dst,
                "app_proto": app_proto,
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


@web.route("/api/export_bundle")
def api_export_bundle():
    run_id = (request.args.get("run_id") or "").strip()
    if not run_id:
        return jsonify({"error": "run_id required"}), 400
    rr = _repo_root()
    reg = _registry()
    try:
        path = reg.export_bundle(run_id, rr)
        return jsonify({"ok": True, "bundle": _artifact_rel(rr, path)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@web.route("/api/correlate_run", methods=["POST"])
def api_correlate_run():
    data = request.get_json(force=True) or {}
    run_id = (data.get("run_id") or "").strip()
    alerts_path = (data.get("alerts_path") or "").strip()
    if not run_id:
        return jsonify({"error": "run_id required"}), 400
    rr = _repo_root()
    reg = _registry()
    run = reg.get_run(run_id) or {}
    events_path = None
    for a in run.get("artifacts", []):
        if a.get("kind") == "events":
            events_path = a.get("path")
            break
    if not events_path:
        # fallback to legacy index
        idx = next((x for x in _load_run_index() if x.get("run_id")==run_id), None) or {}
        events_path = idx.get("events")

    if not events_path or not os.path.exists(events_path):
        return jsonify({"error": "events artifact not found for run"}), 400

    # load expected techniques from events jsonl
    expected = []
    with open(events_path, "r", encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line: 
                continue
            try:
                j=json.loads(line)
                t=j.get("mitre.ics.technique")
                if t: expected.append(t)
            except Exception:
                continue

    # load alerts jsonl (normalized ingest output recommended)
    alerts = []
    if alerts_path:
        ap = os.path.realpath(os.path.join(rr, alerts_path.lstrip("/")))
        if not ap.startswith(os.path.realpath(rr)) or not os.path.exists(ap):
            return jsonify({"error": "alerts_path not found or not allowed"}), 400
        with open(ap, "r", encoding="utf-8") as f:
            for line in f:
                line=line.strip()
                if not line: continue
                try: alerts.append(json.loads(line))
                except Exception: continue

    rep = correlate_run(expected, alerts)
    # persist report artifact
    out_dir = os.path.join(rr, "out", "reports")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"correlation_{run_id}_{int(time.time())}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(rep, f, indent=2)
    try:
        reg.add_artifact(run_id, "report", out_path)
        if alerts_path:
            reg.add_artifact(run_id, "alerts", os.path.join(rr, alerts_path.lstrip('/')))
    except Exception:
        pass
    return jsonify({"ok": True, "report": _artifact_rel(rr, out_path), "correlation": rep})


@web.route("/api/matrix_status")
def api_matrix_status():
    # Returns per-technique status: runnable, precursor, host_or_process, executed, detected (optional by run_id)
    run_id = (request.args.get("run_id") or "").strip()
    rr = _repo_root()
    mat = _load_matrix()
    support = {}
    try:
        support = json.loads(Path(os.path.join(rr, "icsforge", "data", "technique_support.json")).read_text(encoding="utf-8"))
    except Exception:
        support = {}

    # runnable if scenario exists; precursor if technique_support says so
    covered=set()
    try:
        for pack in _list_packs():
            doc = _load_yaml(pack) or {}
            for sc in (doc.get("scenarios") or {}).values():
                for step in sc.get("steps", []):
                    tid = step.get("technique")
                    if tid:
                        covered.add(tid)
    except Exception:
        pass
    # Use technique_support.json to classify covered techniques
    runnable = set(t for t in covered if not support.get(t, {}).get('precursor', False) or support.get(t, {}).get('runnable', False))
    precursor = set(t for t in covered if support.get(t, {}).get('precursor', False) and not support.get(t, {}).get('runnable', False))
    runnable -= precursor

    executed=set()
    detected=set()
    gaps=set()
    if run_id:
        try:
            reg=_registry()
            run=reg.get_run(run_id) or {}
            ev_path=None
            for a in run.get("artifacts", []):
                if a.get("kind")=="events":
                    ev_path=a.get("path"); break
            if ev_path and os.path.exists(ev_path):
                with open(ev_path,"r",encoding="utf-8") as f:
                    for line in f:
                        try:
                            j=json.loads(line); t=j.get("mitre.ics.technique")
                            if t: executed.add(t)
                        except Exception:
                            pass
            # if there is a correlation report artifact, use it
            corr=None
            for a in reversed(run.get("artifacts", [])):
                if a.get("kind")=="report" and a.get("path","").endswith(".json"):
                    try:
                        corr=json.loads(Path(a["path"]).read_text(encoding="utf-8")); break
                    except Exception:
                        pass
            if corr:
                detected=set(corr.get("observed") or [])
                gaps=set(corr.get("gaps") or [])
        except Exception:
            pass

    status={}
    # matrix techniques list
    for tac in mat.get("tactics", []):
        for tech in tac.get("techniques", []):
            tid = tech.get("id")
            if not tid: 
                continue
            cls = support.get(tid, {}).get("class","unknown")
            # A technique is precursor if support says so AND it's not classified as fully runnable
            sup_entry = support.get(tid, {})
            is_precursor = (tid in precursor) or (
                sup_entry.get("precursor") and not sup_entry.get("runnable")
                and tid not in runnable
            )
            is_runnable = (tid in runnable) and not is_precursor
            status[tid]={
                "runnable": is_runnable,
                "precursor": is_precursor,
                "class": cls,
                "executed": tid in executed,
                "detected": tid in detected,
                "gap": tid in gaps,
                "reason": support.get(tid, {}).get("reason","") if cls!="unknown" else "",
            }
    return jsonify({"run_id": run_id or None, "status": status})
def _supported_techniques() -> set:
    """Return technique IDs that have at least one scenario step (pcap/live) across all packs."""
    techs=set()
    for pack_path in _list_packs():
        doc=_load_yaml(pack_path) or {}
        for sc in (doc.get("scenarios") or {}).values():
            for step in (sc.get("steps") or []):
                tid = step.get("technique")
                if tid:
                    techs.add(tid)
    return techs

@web.route("/api/pcap/<path:fname>")
def api_download_pcap(fname):
    base = Path(__file__).resolve().parents[2] / "pcaps"
    p = (base / fname).resolve()
    if not p.exists() or not str(p).startswith(str(base)):
        return {"error": "pcap not found"}, 404
    return send_file(str(p), as_attachment=True, download_name=p.name)


# ═══════════════════════════════════════════════════════════════════════════
# v0.30 — Campaign Playbook, Coverage Report, Detection Export
# ═══════════════════════════════════════════════════════════════════════════

import io, zipfile, threading

_CAMPAIGNS_BUILTIN = os.path.join(os.path.dirname(__file__), "..", "campaigns", "builtin.yml")
_CAMPAIGN_THREADS: dict = {}   # run_id -> CampaignRunner (for abort)


# ── Page routes ────────────────────────────────────────────────────────────

@web.route("/campaigns")
def campaigns():
    import yaml as _yaml
    try:
        doc   = _yaml.safe_load(Path(_CAMPAIGNS_BUILTIN).read_text(encoding="utf-8")) or {}
        camps = doc.get("campaigns") or {}
    except Exception:
        camps = {}
    return render_template(
        "campaigns.html",
        title="Campaign Playbooks",
        subtitle="Multi-scenario sequenced attack campaigns",
        env_label="CAMPAIGNS",
        version=__version__,
        campaigns=camps,
    )


@web.route("/report")
def report():
    return render_template(
        "report.html",
        title="Coverage Report",
        subtitle="ATT&CK for ICS detection coverage analysis",
        env_label="REPORT",
        version=__version__,
    )


# ── Campaign APIs ──────────────────────────────────────────────────────────

@web.route("/api/campaigns/list")
def api_campaigns_list():
    import yaml as _yaml
    try:
        doc   = _yaml.safe_load(Path(_CAMPAIGNS_BUILTIN).read_text(encoding="utf-8")) or {}
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
        return jsonify({"campaigns": out})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@web.route("/api/campaigns/run", methods=["POST"])
def api_campaigns_run():
    """
    Start a campaign and stream SSE events back to the client.
    POST body: {campaign_id, dst_ip, iface?, timeout?}
    Returns: text/event-stream of JSON event lines.
    """
    import yaml as _yaml
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
        doc   = _yaml.safe_load(Path(_CAMPAIGNS_BUILTIN).read_text(encoding="utf-8")) or {}
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

    from icsforge.campaigns.runner import CampaignRunner
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
            runner.run()
        except Exception as e:
            queue.append({"event": "error", "message": str(e)})
        finally:
            done.set()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    _CAMPAIGN_THREADS[runner.run_id] = runner

    def _generate():
        import time
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


@web.route("/api/campaigns/abort", methods=["POST"])
def api_campaigns_abort():
    run_id = (request.get_json(force=True) or {}).get("run_id", "")
    runner = _CAMPAIGN_THREADS.get(run_id)
    if runner:
        runner.stop()
        return jsonify({"aborted": True})
    return jsonify({"error": "run not found"}), 404


# ── Coverage Report APIs ───────────────────────────────────────────────────

@web.route("/api/report/generate", methods=["POST"])
def api_report_generate():
    """Generate a self-contained HTML coverage report."""
    data     = request.get_json(force=True) or {}
    run_id   = (data.get("run_id") or "").strip() or None
    executed = data.get("executed_techniques") or []
    detected = data.get("detected_techniques") or []
    gaps     = data.get("gap_techniques")     or []
    scenario = (data.get("scenario_name") or "").strip() or None
    meta     = data.get("meta") or {}

    # If run_id given, try to auto-derive executed techniques from events
    if run_id and not executed:
        try:
            reg    = _registry()
            run    = reg.get_run(run_id) or {}
            events_path = None
            for a in run.get("artifacts", []):
                if a.get("kind") == "events":
                    events_path = a.get("path")
                    break
            if events_path and os.path.exists(events_path):
                with open(events_path, "r", encoding="utf-8") as f:
                    for line in f:
                        try:
                            j = json.loads(line.strip())
                            t = j.get("mitre.ics.technique")
                            if t and t not in executed:
                                executed.append(t)
                        except Exception:
                            pass
        except Exception:
            pass

    try:
        from icsforge.reports.coverage import generate_report
        html = generate_report(
            run_id=run_id,
            scenario_name=scenario,
            executed_techniques=executed,
            detected_techniques=detected,
            gap_techniques=gaps,
            protocol_gaps=data.get("protocol_gaps") or [],
            meta=meta,
        )
        return jsonify({"html": html, "executed": len(executed),
                        "detected": len(detected), "gaps": len(gaps)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@web.route("/api/report/download", methods=["POST"])
def api_report_download():
    """Return the coverage report HTML as a file download."""
    data     = request.get_json(force=True) or {}
    run_id   = (data.get("run_id") or "").strip() or None
    executed = data.get("executed_techniques") or []
    detected = data.get("detected_techniques") or []
    gaps     = data.get("gap_techniques")     or []
    meta     = data.get("meta") or {}
    try:
        from icsforge.reports.coverage import generate_report
        html = generate_report(run_id=run_id, scenario_name=None,
                               executed_techniques=executed,
                               detected_techniques=detected,
                               gap_techniques=gaps, meta=meta)
        buf = io.BytesIO(html.encode("utf-8"))
        buf.seek(0)
        fname = f"icsforge_coverage_{run_id or 'report'}.html"
        return send_file(buf, mimetype="text/html",
                                as_attachment=True, download_name=fname)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Detection Rule Export APIs ─────────────────────────────────────────────

@web.route("/api/detections/preview")
def api_detections_preview():
    """Return metadata about available detection rules."""
    try:
        from icsforge.detections.generator import generate_all
        r = generate_all()
        return jsonify({"count": r["count"], "techniques": r["techniques"]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@web.route("/api/detections/download")
def api_detections_download():
    """
    Download all detection rules as a zip containing:
      - icsforge_ics.rules   (Suricata)
      - sigma/               (one YAML per scenario)
      - README.txt
    """
    technique_filter = request.args.getlist("technique") or None
    include_marker   = request.args.get("marker", "1") != "0"

    try:
        from icsforge.detections.generator import generate_all
        r = generate_all(technique_filter=technique_filter,
                         include_marker=include_marker)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    readme = f"""ICSForge v{__version__} Detection Rules
Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
Techniques: {len(r['techniques'])} | Rules: {r['count']}

FILES
  icsforge_ics.rules   — Suricata rules (SID range 9800000–9800{r['count']-1:03d})
  sigma/               — Sigma rules (one YAML per scenario)

SURICATA USAGE
  suricata -r your_capture.pcap -S icsforge_ics.rules -l /tmp/logs/

SIGMA USAGE
  sigma convert -t splunk sigma/T0812__default_creds__s7comm_blank_auth.yml

NOTE
  Rules match the ICSForge marker bytes (ICSFORGE_SYNTH|) to fire ONLY
  on synthetic traffic. Remove the marker content match for production
  use against real OT traffic (download with ?marker=0).

ATT&CK for ICS techniques covered:
  {chr(10).join('  ' + t for t in r['techniques'])}
"""

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("icsforge_ics.rules", r["suricata"])
        zf.writestr("README.txt", readme)
        for sc_id, sigma_text in r["sigma"].items():
            zf.writestr(f"sigma/{sc_id}.yml", sigma_text)
    buf.seek(0)

    fname = f"icsforge_detection_rules_v{__version__}.zip"
    return send_file(buf, mimetype="application/zip",
                            as_attachment=True, download_name=fname)
