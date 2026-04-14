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
import collections
import json
import os
import secrets
from contextlib import suppress
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
import yaml

from icsforge import __version__
from icsforge.log import configure as configure_logging
from icsforge.log import get_logger
from icsforge.web.helpers import (
    _default_receipts_path,
    _list_packs,
    _list_profiles,
    _load_matrix,
    _load_yaml,
    _read_jsonl_tail,
    _repo_root,
    _stats_from_receipts,
    _tech_name,
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

@web.app_context_processor
def inject_token_status():
    """Expose callback_token_set and no_auth to all templates."""
    from icsforge.web import helpers as _helpers
    return {
        "callback_token_set": bool(_helpers._callback_token),
        "no_auth": bool(os.environ.get("ICSFORGE_NO_AUTH")),
    }

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
    proto_set_by_tech: dict = {}  # tid -> set of protocols
    pack_cards = []  # [{name,count,techniques,protocols}]

    for p in packs:
        doc = _load_yaml(p) or {}
        sc = (doc.get("scenarios") or {})
        # Count standalone scenarios only (exclude CHAIN__ prefixed ones for KPI)
        scenarios_total += sum(1 for k in sc if not k.startswith("CHAIN__"))

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
                    if step.get("proto"):
                        if tid not in proto_set_by_tech:
                            proto_set_by_tech[tid] = set()
                        proto_set_by_tech[tid].add(str(step["proto"]).lower())

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

    # Top techniques by protocol coverage breadth (how many of the 10 protocols covered)
    top_tech = []
    for tid, protos in sorted(proto_set_by_tech.items(), key=lambda x: (-len(x[1]), -tech_counter[x[0]])):
        top_tech.append({"id": tid, "name": _tech_name(tid),
                         "scenario_refs": tech_counter[tid],
                         "protocol_count": len(protos),
                         "protocols": sorted(protos)})

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
        subtitle="OT/ICS Cybersecurity Coverage Validation Platform",
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
    app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB — sufficient for real PCAPs
    # Persist session secret across restarts so sessions survive app restarts.
    # Priority: ICSFORGE_SECRET_KEY env var → persisted file → generate+save new.
    _sk = os.environ.get("ICSFORGE_SECRET_KEY", "").strip()
    if not _sk:
        _sk_path = os.path.join(os.path.expanduser("~"), ".icsforge", "secret_key")
        try:
            if os.path.exists(_sk_path):
                _sk = open(_sk_path).read().strip()
            if not _sk:
                _sk = secrets.token_hex(32)
                os.makedirs(os.path.dirname(_sk_path), exist_ok=True)
                with open(_sk_path, "w") as _f:
                    _f.write(_sk)
                os.chmod(_sk_path, 0o600)
        except OSError:
            _sk = secrets.token_hex(32)  # fallback: ephemeral
    app.secret_key = _sk
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)
    # Enable Secure cookies if explicitly configured (e.g. behind TLS reverse proxy)
    if os.environ.get("ICSFORGE_SECURE_COOKIES"):
        app.config["SESSION_COOKIE_SECURE"] = True
        app.config["PREFERRED_URL_SCHEME"] = "https"

    # Register main blueprint (pages)
    app.register_blueprint(web)

    # Register API blueprints
    from icsforge.web.bp_campaigns import bp as bp_campaigns
    from icsforge.web.bp_config import bp as bp_config
    from icsforge.web.bp_detections import bp as bp_detections
    from icsforge.web.bp_receiver import bp as bp_receiver
    from icsforge.web.bp_reports import bp as bp_reports
    from icsforge.web.bp_runs import bp as bp_runs
    from icsforge.web.bp_scenarios import bp as bp_scenarios

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



    # ── Custom 404 handler ──────────────────────────────────────────────────
    @app.errorhandler(404)
    def _not_found(e):
        from flask import request as req
        if req.path.startswith("/api/"):
            from flask import jsonify as _jfy
            return _jfy({"error": "Endpoint not found"}), 404
        return render_template("404.html"), 404

    # ── Security headers ────────────────────────────────────────────────────
    @app.after_request
    def _security_headers(response):
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Permissive CSP — the UI uses inline scripts and CDN resources
        response.headers["Content-Security-Policy"] = (
            "default-src \'self\'; "
            "script-src \'self\' \'unsafe-inline\'; "
            "style-src \'self\' \'unsafe-inline\'; "
            "img-src \'self\' data:; "
            "connect-src \'self\'"
        )
        return response

    # ── CSRF token: generate on every request so GET page loads populate the meta tag
    @app.before_request
    def _csrf_token_init():
        from flask import session
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)

    # ── CSRF protection: validate on all state-mutating requests ────────────
    @app.before_request
    def _csrf_protect():
        from flask import abort, session, request as req
        if req.method in ("GET", "HEAD", "OPTIONS"):
            return
        # Skip CSRF for public API paths (callback, health, static)
        path = req.path
        skip = ("/api/receiver/callback", "/api/config/set_callback",
                "/api/health", "/api/auth/")
        if any(path.startswith(s) for s in skip) or path.startswith("/static/"):
            return
        # Skip if auth is disabled
        if os.environ.get("ICSFORGE_NO_AUTH"):
            return
        # Validate token from header or form
        supplied = (req.headers.get("X-CSRF-Token") or
                    (req.get_json(silent=True) or {}).get("_csrf") or
                    req.form.get("_csrf") or "")
        if not supplied or not secrets.compare_digest(supplied, session["csrf_token"]):
            # CSRF token missing or invalid — block the request
            log.warning("CSRF token mismatch for %s %s from %s",
                        req.method, req.path, req.remote_addr)
            abort(403)

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
        import warnings
        warnings.warn(
            "\n⚠  ICSFORGE_NO_AUTH=1 — authentication is DISABLED. "
            "Do not expose this instance on a shared network.\n",
            stacklevel=1
        )

    # Use the full app factory — registers all API blueprints and auth
    app = create_app()
    log.info("ICSForge Web UI v%s starting on %s:%d", __version__, args.host, args.port)
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":  # pragma: no cover
    main()

