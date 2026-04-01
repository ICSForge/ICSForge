"""
ICSForge Web Application — Flask app factory + page routes.

API routes are split into blueprints:
  bp_scenarios  — scenario listing, preview, send, offline generation
  bp_receiver   — receiver overview, callback, live feed, receipts
  bp_config     — network config, callback setup, health, interfaces
  bp_runs       — run history, alerts, validation, export, PCAP, correlation
  bp_campaigns  — campaign listing, execution, abort
  bp_detections — Suricata/Sigma rule preview and download
  bp_reports    — coverage report generation, download, matrix status
"""
import argparse
import json
import os
import yaml
import collections
import secrets
from datetime import timedelta
from pathlib import Path

from flask import (
    Blueprint,
    Flask,
    redirect,
    render_template,
    request,
    url_for,
)

from icsforge import __version__
from icsforge.log import configure as configure_logging, get_logger
from contextlib import suppress

from icsforge.web.helpers import (
    _default_receipts_path, _list_packs, _list_profiles,
    _load_matrix, _load_yaml, _read_jsonl_tail, _repo_root,
    _stats_from_receipts, _tech_name,
)

log = get_logger(__name__)

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




# ── Page routes ───────────────────────────────────────────────────────

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
            for sid in sorted(sc.keys()):
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
    support = {}
    with suppress(Exception):
        support = json.loads(
            Path(os.path.join(_repo_root(), "icsforge", "data", "technique_support.json")).read_text(encoding="utf-8")
        )
    covered = set()
    try:
        for pack_path in _list_packs():
            doc = _load_yaml(pack_path) or {}
            for sc in (doc.get("scenarios") or {}).values():
                for step in sc.get("steps", []):
                    tid = step.get("technique")
                    if tid:
                        covered.add(tid)
    except Exception:
        pass
    precursor = set(t for t in covered if support.get(t, {}).get("precursor") and not support.get(t, {}).get("runnable"))
    runnable  = covered - precursor
    status = {}
    for tac in mat.get("tactics", []):
        for tech in tac.get("techniques", []):
            tid = tech.get("id")
            if not tid:
                continue
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



@web.route("/health")
def health_page():
    return render_template("health.html", title="ICSForge Health", subtitle="Diagnostics & Readiness")








_CAMPAIGNS_BUILTIN = os.path.join(os.path.dirname(__file__), "..", "campaigns", "builtin.yml")

@web.route("/campaigns")
def campaigns():
    try:
        doc   = yaml.safe_load(Path(_CAMPAIGNS_BUILTIN).read_text(encoding="utf-8")) or {}
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




# ── App factory ───────────────────────────────────────────────────────


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("ICSFORGE_SECRET_KEY") or secrets.token_hex(32)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)

    # Register main blueprint (pages)
    app.register_blueprint(web)

    # Register API blueprints
    from icsforge.web.bp_scenarios import bp as bp_scenarios
    from icsforge.web.bp_receiver import bp as bp_receiver
    from icsforge.web.bp_config import bp as bp_config
    from icsforge.web.bp_runs import bp as bp_runs
    from icsforge.web.bp_campaigns import bp as bp_campaigns
    from icsforge.web.bp_detections import bp as bp_detections
    from icsforge.web.bp_reports import bp as bp_reports

    app.register_blueprint(bp_scenarios)
    app.register_blueprint(bp_receiver)
    app.register_blueprint(bp_config)
    app.register_blueprint(bp_runs)
    app.register_blueprint(bp_campaigns)
    app.register_blueprint(bp_detections)
    app.register_blueprint(bp_reports)

    # Authentication
    from icsforge.auth import init_auth
    init_auth(app)

    return app

def main():
    ap = argparse.ArgumentParser(
        prog="icsforge-web",
        description="ICSForge Web UI. Preferred: python -m icsforge.web (avoids runpy warning).",
    )
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--log-level", default="INFO")
    ap.add_argument("--no-auth", action="store_true", help="Disable authentication (dev mode)")
    args = ap.parse_args()

    configure_logging(level="DEBUG" if args.debug else args.log_level)
    if args.no_auth:
        os.environ["ICSFORGE_NO_AUTH"] = "1"

    # Use the full app factory — registers all API blueprints and auth
    app = create_app()
    log.info("ICSForge Web UI v%s starting on %s:%d", __version__, args.host, args.port)
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":  # pragma: no cover
    main()

