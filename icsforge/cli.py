
import argparse
import datetime as _dt
import json
import os
import random as _rnd
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from icsforge.live.sender import send_scenario_live
from icsforge.log import configure as configure_logging
from icsforge.log import get_logger
from icsforge.reports.network_validation import build_network_validation_report
from icsforge.scenarios.engine import run_scenario
from icsforge.state import RunRegistry, default_db_path
from icsforge.web.helpers_io import _append_run_index

log = get_logger(__name__)


def cmd_generate(args) -> int:
    # Resolve --file to absolute path so command works from any directory
    if not os.path.isabs(args.file) and not os.path.exists(args.file):
        import icsforge as _pkg
        candidate = os.path.join(os.path.dirname(_pkg.__file__), "scenarios", "scenarios.yml")
        if os.path.exists(candidate):
            args.file = candidate
    args.file = os.path.abspath(args.file)
    args.outdir = os.path.abspath(args.outdir)

    # Generate a meaningful run_id (same convention as web generate_offline)
    # so artifacts are named T0855__unauth_command__2026-04-01__BRAVO instead of offline
    _NATO = ["ALPHA","BRAVO","CHARLIE","DELTA","ECHO","FOXTROT","GOLF","HOTEL",
             "INDIA","JULIET","KILO","LIMA","MIKE","NOVEMBER","OSCAR","PAPA",
             "QUEBEC","ROMEO","SIERRA","TANGO","UNIFORM","VICTOR","WHISKEY",
             "XRAY","YANKEE","ZULU"]
    _date = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
    _word = _rnd.choice(_NATO)
    _parts = args.name.split("__")[:2]
    _run_id = "__".join(_parts) + f"__{_date}__{_word}"

    res = run_scenario(args.file, args.name, args.outdir,
                       dst_ip=args.dst_ip, src_ip=args.src_ip,
                       run_id=_run_id, build_pcap=True,
                       no_marker=getattr(args, "no_marker", False))
    log.info("Generate complete:\n%s", json.dumps(res, indent=2))
    return 0


def cmd_send(args) -> int:
    allowlist: list[str] = [x.strip() for x in (args.allowlist.split(",") if args.allowlist else []) if x.strip()] or [args.dst_ip]

    # Resolve --file to an absolute path so the command works from any working directory.
    # If the given path doesn't exist relative to CWD, fall back to the installed package.
    if not os.path.isabs(args.file) and not os.path.exists(args.file):
        import icsforge as _pkg
        candidate = os.path.join(os.path.dirname(_pkg.__file__), "scenarios", "scenarios.yml")
        if os.path.exists(candidate):
            log.debug("--file %s not found from CWD; using installed path %s", args.file, candidate)
            args.file = candidate
    args.file = os.path.abspath(args.file)

    # Resolve --outdir relative to CWD (not the package dir)
    args.outdir = os.path.abspath(args.outdir)

    res = send_scenario_live(
        scenario_file=args.file,
        scenario_name=args.name,
        dst_ip=args.dst_ip,
        iface=args.iface,
        confirm_live_network=args.confirm_live_network,
        receiver_allowlist=allowlist,
        timeout=args.timeout,
        no_marker=getattr(args, "no_marker", False),
    )

    # Use try/finally so the run registry is always updated,
    # even if the user interrupts (Ctrl+C) during ground-truth generation.
    gt: dict = {"events": None, "pcap": None}
    try:
        gt = run_scenario(
            args.file,
            args.name,
            args.outdir,
            dst_ip=args.dst_ip,
            src_ip=args.src_ip,
            run_id=res["run_id"],
            build_pcap=args.also_build_pcap,
            skip_intervals=True,  # live traffic already paced; pcap needs no delays
        )
        events_path = gt.get("events")
        pcap_path = gt.get("pcap")
        log.info("  events: %s", events_path)
        if pcap_path:
            log.info("  pcap:   %s", pcap_path)
        elif args.also_build_pcap:
            log.warning("PCAP was requested (--also-build-pcap) but was not generated")
        # Validate events file actually has content
        if events_path and os.path.exists(events_path):
            with open(events_path, encoding="utf-8") as _events_f:
                event_count = sum(1 for _ in _events_f)
            if event_count == 0:
                log.warning(
                    "Ground-truth events file is EMPTY: %s\n"
                    "  This can happen if pcap building raised an exception before events were written.\n"
                    "  The live send itself succeeded (%d packets). Run net-validate against receipts only.",
                    events_path, res.get("sent", 0)
                )
            else:
                log.info("  events written: %d lines", event_count)
        else:
            log.warning("Events file not found: %s", events_path)
    except KeyboardInterrupt:
        log.warning("Ground-truth generation interrupted — run will still be registered")
    except Exception as exc:
        log.error("Ground-truth artifact generation failed: %s", exc)

    # Enterprise run registry (out/runs.db) + JSONL fallback
    repo_root = str(Path(__file__).resolve().parents[1])
    try:
        reg = RunRegistry(default_db_path(repo_root))
        reg.upsert_run(res["run_id"], scenario=args.name, pack=args.file, dst_ip=args.dst_ip, src_ip=args.src_ip,
                       iface=args.iface, mode="live", status="ok", meta={"sent": res.get("sent")})
        reg.add_artifact(res["run_id"], "events", gt.get("events"))
        if gt.get("pcap"):
            reg.add_artifact(res["run_id"], "pcap", gt.get("pcap"))
        log.debug("Run registered in SQLite: %s", res["run_id"])
    except (OSError, ValueError, sqlite3.Error) as exc:
        log.warning("SQLite registry failed for %s: %s — falling back to JSONL index", res["run_id"], exc)
    # Always write to JSONL run index (web UI fallback + visibility)
    try:
        _append_run_index({
            "run_id": res["run_id"],
            "scenario": args.name,
            "pack": args.file,
            "events": gt.get("events"),
            "pcap": gt.get("pcap"),
            "dst_ip": args.dst_ip,
            "mode": "live",
            "ts": _dt.datetime.now(_dt.timezone.utc).isoformat() + "Z",
        })
    except (OSError, ImportError) as exc:
        log.debug("JSONL index write failed: %s", exc)

    log.info("Live send complete")
    log.info("  run_id: %s", res["run_id"])
    log.info("  sent: %s", res["sent"])
    log.info("  ground_truth_events: %s", gt.get("events"))
    return 0


def cmd_net_validate(args) -> int:
    rep = build_network_validation_report(args.events, args.receipts, alerts_jsonl=args.alerts, out_path=args.out)
    log.info("Network validation report: %s", args.out)
    log.info("Report:\n%s", json.dumps(rep, indent=2))
    return 0


def _read_jsonl(path: str):
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def cmd_selftest(args) -> int:
    # Live selftest: start receiver locally, send Modbus + DNP3, verify receipts contain run_id markers.
    if not args.live:
        log.error("Selftest currently supports --live only.")
        return 2

    dst_ip = args.dst_ip
    # Resolve receipts path relative to cwd so subprocess writes to same location
    receipts_path = os.path.join(os.path.abspath(args.cwd), args.receipts)

    # Check for root/CAP_NET_RAW (required for raw sockets used by receiver)
    if os.geteuid() != 0:
        log.warning(
            "Selftest --live requires root or CAP_NET_RAW to bind protocol ports (502, 20000, etc). "
            "Run with sudo or as root, otherwise the receiver may not bind and receipts will be empty."
        )

    # Clean receipts for fresh run
    os.makedirs(os.path.dirname(receipts_path) or ".", exist_ok=True)
    if os.path.exists(receipts_path):
        os.remove(receipts_path)

    recv_cmd = [
        sys.executable, "-m", "icsforge.receiver",
        "--bind", args.bind,
        "--no-web",  # avoid web server port conflict during selftest
        "--log-level", "WARNING",
    ]
    if args.receiver_config:
        recv_cmd += ["--config", args.receiver_config]

    recv = subprocess.Popen(
        recv_cmd,
        cwd=args.cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        time.sleep(2.0)  # give receiver time to bind all ports

        # Build a temp scenario file (pcap steps = live send steps)
        scenario = """scenarios:
  selftest_live:
    steps:
      - type: pcap
        proto: modbus
        technique: T0855
        count: 1
        interval: 0s
      - type: pcap
        proto: dnp3
        technique: T0848
        count: 1
        interval: 0s
"""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".yml", dir=args.cwd) as tf:
            tf.write(scenario)
            tf.flush()
            scenario_file = os.path.basename(tf.name)

        res = send_scenario_live(
            scenario_file=os.path.join(args.cwd, scenario_file),
            scenario_name="selftest_live",
            dst_ip=dst_ip,
            iface=None,
            confirm_live_network=True,
            receiver_allowlist=[dst_ip],
            timeout=2.0,
        )

        # Allow receiver to write receipts
        time.sleep(2.0)

        # Validate receipts
        if not os.path.exists(receipts_path):
            log.error("Receipts file not created: %s", receipts_path)
            return 1

        got_run = False
        got_modbus = False
        got_dnp3 = False
        for r in _read_jsonl(receipts_path):
            if r.get("run_id") == res["run_id"]:
                got_run = True
                if r.get("receiver.proto") == "modbus":
                    got_modbus = True
                if r.get("receiver.proto") == "dnp3":
                    got_dnp3 = True

        if not got_run:
            log.error("No receipt matched run_id %s", res["run_id"])
            return 1
        if not got_modbus:
            log.error("Modbus receipt missing for run_id %s", res["run_id"])
            return 1
        if not got_dnp3:
            log.error("DNP3 receipt missing for run_id %s", res["run_id"])
            return 1

        log.info("[PASS] Receiver reachable")
        log.info("[PASS] Modbus packet received")
        log.info("[PASS] DNP3 packet received")
        log.info("[PASS] Correlation run_id: %s", res["run_id"])
        return 0

    finally:
        try:
            recv.send_signal(signal.SIGINT)
            time.sleep(0.5)
            recv.kill()
        except Exception:
            pass


# ──────────────────────────────────────────────────────────────────────────
# Below this line: CLI commands added in v0.62.0 to reach parity with the Web UI.
# Mapping (command → Web UI equivalent):
#   icsforge scenarios list         -> GET  /api/scenarios
#   icsforge campaign list          -> GET  /api/campaigns
#   icsforge campaign validate      -> (implicit in /api/campaigns — returns warnings)
#   icsforge campaign run           -> POST /api/campaigns/run
#   icsforge detections preview     -> GET  /api/detections/preview
#   icsforge detections export      -> GET  /api/detections/download
#   icsforge demo up / down / fire  -> docker compose -f docker-compose.demo.yml …
#   icsforge viewer                 -> python -m icsforge.viewer
# ──────────────────────────────────────────────────────────────────────────


def _resolve_scenarios_file(path: str | None) -> str:
    """Resolve --file to an absolute path, falling back to the installed package."""
    import icsforge as _pkg
    candidate_default = os.path.join(os.path.dirname(_pkg.__file__), "scenarios", "scenarios.yml")
    chosen = path or candidate_default
    if not os.path.isabs(chosen) and not os.path.exists(chosen):
        if os.path.exists(candidate_default):
            chosen = candidate_default
    return os.path.abspath(chosen)


def _resolve_campaigns_file(path: str | None) -> str:
    """Resolve --campaigns-file, defaulting to the bundled builtin.yml."""
    import icsforge as _pkg
    candidate_default = os.path.join(os.path.dirname(_pkg.__file__), "campaigns", "builtin.yml")
    chosen = path or candidate_default
    if not os.path.isabs(chosen) and not os.path.exists(chosen):
        if os.path.exists(candidate_default):
            chosen = candidate_default
    return os.path.abspath(chosen)


def cmd_scenarios_list(args) -> int:
    """List scenarios (optionally filtered by protocol/technique/search)."""
    import yaml as _yaml

    path = _resolve_scenarios_file(getattr(args, "file", None))
    with open(path, encoding="utf-8") as f:
        doc = _yaml.safe_load(f) or {}
    scenarios = doc.get("scenarios", doc) or {}

    proto_filter = (getattr(args, "proto", None) or "").lower().strip()
    tech_filter = (getattr(args, "technique", None) or "").upper().strip()
    search = (getattr(args, "search", None) or "").lower().strip()

    rows = []
    for name, sc in sorted(scenarios.items()):
        steps = sc.get("steps", []) or []
        technique = sc.get("technique") or (steps[0].get("technique") if steps else "")
        proto = steps[0].get("proto", "") if steps else ""
        title = sc.get("title", "")
        if tech_filter and technique != tech_filter:
            continue
        if proto_filter and proto != proto_filter:
            continue
        if search and search not in name.lower() and search not in title.lower():
            continue
        rows.append((name, technique, proto, title))

    if getattr(args, "json", False):
        print(json.dumps(
            [{"name": n, "technique": t, "proto": p, "title": ti} for n, t, p, ti in rows],
            indent=2,
        ))
    else:
        for name, tech, proto, _title in rows:
            print(f"  {tech:7s}  {proto:13s}  {name}")
        print(f"\n{len(rows)} scenarios "
              f"({len(scenarios)} total{', filtered' if len(rows) != len(scenarios) else ''})")
    return 0


def cmd_campaign_list(args) -> int:
    """List campaigns from builtin.yml (or custom file)."""
    from icsforge.campaigns.runner import validate_campaign_file

    camp_path = _resolve_campaigns_file(getattr(args, "campaigns_file", None))
    sc_path = _resolve_scenarios_file(getattr(args, "file", None))
    try:
        doc, warnings = validate_campaign_file(camp_path, sc_path)
    except Exception as e:
        print(f"❌ Campaign file invalid: {e}", file=sys.stderr)
        return 2

    campaigns = doc.get("campaigns", {}) or {}
    if getattr(args, "json", False):
        out = []
        for cid, c in campaigns.items():
            out.append({
                "id": cid,
                "name": c.get("name", cid),
                "icon": c.get("icon", ""),
                "description": c.get("description", "").strip(),
                "estimated_duration": c.get("estimated_duration", ""),
                "steps": len(c.get("steps", []) or []),
            })
        print(json.dumps({"campaigns": out, "warnings": warnings}, indent=2))
    else:
        print(f"{len(campaigns)} campaigns ({camp_path})\n")
        for cid, c in campaigns.items():
            icon = c.get("icon", "")
            name = c.get("name", cid)
            steps = len(c.get("steps", []) or [])
            dur = c.get("estimated_duration", "?")
            print(f"  {icon}  {cid:28s}  {name}")
            print(f"      {steps} steps · {dur}")
        if warnings:
            print(f"\n⚠  {len(warnings)} warnings:")
            for w in warnings:
                print(f"    - {w}")
    return 0


def cmd_campaign_validate(args) -> int:
    """Validate a campaign YAML file against the scenario library."""
    from icsforge.campaigns.runner import CampaignValidationError, validate_campaign_file

    camp_path = _resolve_campaigns_file(getattr(args, "campaigns_file", None))
    sc_path = _resolve_scenarios_file(getattr(args, "file", None))
    try:
        doc, warnings = validate_campaign_file(camp_path, sc_path)
    except CampaignValidationError as e:
        print(f"❌ INVALID: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # pragma: no cover
        print(f"❌ Error: {e}", file=sys.stderr)
        return 2

    camps = doc.get("campaigns", {}) or {}
    total_steps = sum(len(c.get("steps", []) or []) for c in camps.values())
    print(f"✅ Valid — {len(camps)} campaigns, {total_steps} step references resolved")
    if warnings:
        print(f"⚠  {len(warnings)} warnings:")
        for w in warnings:
            print(f"    - {w}")
        return 1
    return 0


def cmd_campaign_run(args) -> int:
    """Run a campaign playbook locally (no Web UI needed)."""
    import yaml as _yaml

    from icsforge.campaigns.runner import CampaignRunner, CampaignValidationError, validate_campaign_file

    camp_path = _resolve_campaigns_file(getattr(args, "campaigns_file", None))
    sc_path = _resolve_scenarios_file(getattr(args, "file", None))

    try:
        doc, _warnings = validate_campaign_file(camp_path, sc_path)
    except CampaignValidationError as e:
        print(f"❌ Campaign file invalid: {e}", file=sys.stderr)
        return 2

    campaigns = doc.get("campaigns", {}) or {}
    camp_id = args.id
    if camp_id not in campaigns:
        print(f"❌ Campaign '{camp_id}' not found. Known:", file=sys.stderr)
        for cid in campaigns:
            print(f"    {cid}", file=sys.stderr)
        return 2

    camp = campaigns[camp_id]
    if "name" not in camp:
        camp["name"] = camp_id

    if not args.confirm_live_network:
        print("❌ Campaign run requires --confirm-live-network (safety rail).", file=sys.stderr)
        return 2

    def _progress(ev: dict) -> None:
        kind = ev.get("event", "?")
        if kind == "campaign_start":
            print(f"▶ Campaign '{camp.get('name')}' starting — {ev.get('total_steps')} steps")
        elif kind == "delay":
            s = ev.get("seconds", 0)
            print(f"  … waiting {s:g}s before step {ev.get('step')}")
        elif kind == "step_start":
            print(f"  [{ev.get('step')}/{ev.get('total')}] {ev.get('label', ev.get('scenario'))}")
        elif kind == "step_ok":
            print(f"      ✓ sent={ev.get('sent', 0)}")
        elif kind == "step_error":
            print(f"      ✗ error: {ev.get('error')}")
        elif kind == "campaign_complete":
            print(f"✔ Complete — {ev.get('steps_ok')} ok, {ev.get('steps_err')} errors")
        elif kind == "campaign_aborted":
            print(f"✗ Aborted at step {ev.get('at_step')}")

    runner = CampaignRunner(
        campaign=camp,
        scenarios_path=sc_path,
        dst_ip=args.dst_ip,
        iface=args.iface,
        timeout=args.timeout,
        outdir=args.outdir,
        progress_cb=_progress,
    )
    result = runner.run()
    if getattr(args, "json", False):
        print(json.dumps(result, indent=2))
    return 0 if result.get("steps_err", 1) == 0 else 1


def cmd_detections_preview(args) -> int:
    """Show rule counts per tier without writing files."""
    from icsforge.detection.generator import generate_all

    r = generate_all(technique_filter=(args.technique or None))
    if getattr(args, "json", False):
        print(json.dumps({
            "count": r["count"],
            "techniques": r["techniques"],
            "rule_counts": r["rule_counts"],
        }, indent=2))
    else:
        rc = r["rule_counts"]
        print(f"Scenarios:  {r['count']}")
        print(f"Techniques: {len(r['techniques'])}")
        print(f"Rules:")
        print(f"  Tier 1 lab_marker        {rc['lab_marker']:>4d}")
        print(f"  Tier 2 protocol_heuristic {rc['protocol_heuristic']:>4d}")
        print(f"  Tier 3 semantic          {rc['semantic']:>4d}")
    return 0


def cmd_detections_export(args) -> int:
    """Export Suricata + Sigma rules to disk (folder or zip)."""
    from icsforge.detection.generator import _write_outputs, generate_all

    r = generate_all(
        technique_filter=(args.technique or None),
        include_marker=not args.no_marker,
    )

    if args.zip:
        import io as _io
        import zipfile as _zip

        out_path = args.zip
        buf = _io.BytesIO()
        with _zip.ZipFile(buf, "w", _zip.ZIP_DEFLATED) as zf:
            zf.writestr("icsforge_lab.rules",       r["suricata_lab"])
            zf.writestr("icsforge_heuristic.rules", r["suricata_heuristic"])
            zf.writestr("icsforge_semantic.rules",  r["suricata_semantic"])
            for sc_id, sigma_text in r["sigma"].items():
                safe = "".join(c for c in sc_id if c.isalnum() or c in "._-")[:180] or "scenario"
                zf.writestr(f"sigma/{safe}.yml", sigma_text)
            rc = r["rule_counts"]
            zf.writestr("README.txt",
                        f"ICSForge detection rules\n"
                        f"Scenarios: {r['count']}  Techniques: {len(r['techniques'])}\n"
                        f"Tier 1 lab_marker: {rc['lab_marker']}\n"
                        f"Tier 2 protocol_heuristic: {rc['protocol_heuristic']}\n"
                        f"Tier 3 semantic: {rc['semantic']}\n")
        with open(out_path, "wb") as f:
            f.write(buf.getvalue())
        print(f"[export] wrote zip: {out_path}")
    else:
        _write_outputs(args.outdir, r)
        print(f"[export] wrote to {args.outdir}")

    rc = r["rule_counts"]
    print(f"[export] lab={rc['lab_marker']} "
          f"heuristic={rc['protocol_heuristic']} "
          f"semantic={rc['semantic']}")
    return 0


def _demo_compose_path() -> str:
    """Find docker-compose.demo.yml: repo root first, then package dir."""
    here = Path(__file__).resolve().parent  # icsforge/
    candidates = [
        here.parent / "docker-compose.demo.yml",
        Path.cwd() / "docker-compose.demo.yml",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return str(candidates[0])  # best effort; docker will report the real error


def cmd_demo_up(args) -> int:
    """Bring up the full demo stack via docker compose."""
    compose = _demo_compose_path()
    if not Path(compose).exists():
        print(f"❌ {compose} not found. Are you in the repo root?", file=sys.stderr)
        return 2
    cmd = ["docker", "compose", "-f", compose, "up"]
    if args.detach:
        cmd.append("-d")
    if args.build:
        cmd.append("--build")
    print("[demo] " + " ".join(cmd))
    return subprocess.call(cmd)


def cmd_demo_down(args) -> int:
    """Tear down the demo stack and remove volumes."""
    compose = _demo_compose_path()
    cmd = ["docker", "compose", "-f", compose, "down"]
    if args.volumes:
        cmd.append("-v")
    print("[demo] " + " ".join(cmd))
    return subprocess.call(cmd)


def cmd_demo_fire(args) -> int:
    """Fire a named campaign against the local demo receiver."""
    import urllib.error
    import urllib.request

    sender = args.sender.rstrip("/")
    body = json.dumps({
        "campaign_id": args.campaign,
        "dst_ip": args.dst_ip,
        "timeout": 2.0,
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{sender}/api/campaigns/run",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    print(f"[demo] POST {sender}/api/campaigns/run  campaign={args.campaign}  dst_ip={args.dst_ip}")
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            # The response is an SSE stream — relay it line-by-line
            for raw in r:
                line = raw.decode("utf-8", "replace").rstrip()
                if not line or line.startswith(":"):
                    continue
                if line.startswith("data:"):
                    payload = line[5:].strip()
                    try:
                        ev = json.loads(payload)
                        kind = ev.get("event", "")
                        if kind == "step_start":
                            print(f"  [{ev.get('step')}/{ev.get('total')}] "
                                  f"{ev.get('label', ev.get('scenario'))}")
                        elif kind == "step_ok":
                            print(f"      ✓ sent={ev.get('sent', 0)}")
                        elif kind == "step_error":
                            print(f"      ✗ {ev.get('error')}")
                        elif kind == "campaign_complete":
                            print(f"✔ Done — {ev.get('steps_ok')} ok, {ev.get('steps_err')} err")
                    except json.JSONDecodeError:
                        pass
    except urllib.error.URLError as e:
        print(f"❌ Cannot reach sender at {sender}: {e}", file=sys.stderr)
        return 2
    return 0


def cmd_viewer(args) -> int:
    """Launch the live Suricata alert viewer."""
    from icsforge.viewer import create_app
    import icsforge.viewer as _viewer

    _viewer.EVE_PATH = args.eve_path
    app = create_app()
    app.run(host=args.host, port=args.port, threaded=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="icsforge", description="ICSForge — OT/ICS Coverage Validation Framework")
    ap.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    ap.add_argument("--log-level", default="INFO", help="Log level (DEBUG, INFO, WARNING, ERROR)")
    ap.add_argument("--log-file", default=None, help="Log to file in addition to stderr")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="Generate events/pcaps offline from a scenario pack")
    g.add_argument("--file", default="icsforge/scenarios/scenarios.yml")
    g.add_argument("--name", required=True, help="Scenario name")
    g.add_argument("--outdir", default="out")
    g.add_argument("--dst-ip", default="198.51.100.42")
    g.add_argument("--src-ip", default="127.0.0.1")
    g.add_argument("--no-marker", dest="no_marker", action="store_true",
                   help="Stealth mode: generate PCAP with no synthetic tags.")
    g.set_defaults(func=cmd_generate)

    s = sub.add_parser("send", help="Send scenario traffic over the real network to an ICSForge Receiver")
    s.add_argument("--file", default="icsforge/scenarios/scenarios.yml")
    s.add_argument("--name", required=True, help="Scenario name")
    s.add_argument("--outdir", default="out")
    s.add_argument("--dst-ip", required=True, help="Receiver IP (cooperative sink)")
    s.add_argument("--iface", help="Interface for L2 (profinet_dcp), optional")
    s.add_argument("--src-ip", default="127.0.0.1")
    s.add_argument("--timeout", type=float, default=2.0)
    s.add_argument("--allowlist", help="Comma-separated allowlisted receiver IPs (defaults to dst-ip)")
    s.add_argument("--confirm-live-network", action="store_true", help="REQUIRED: enable live sending")
    s.add_argument("--also-build-pcap", action="store_true", help="Also build an offline PCAP alongside live sending")
    s.add_argument("--no-marker", dest="no_marker", action="store_true",
                   help="Stealth mode: omit ICSForge correlation tags — generates real protocol traffic indistinguishable from genuine devices. Receiver confirmation shows 0 but TCP ACK is used instead.")
    s.set_defaults(func=cmd_send)

    nv = sub.add_parser("net-validate", help="Correlate ground-truth events with receiver receipts and optional alerts")
    nv.add_argument("--events", required=True, help="Ground truth events JSONL")
    nv.add_argument("--receipts", required=True, help="Receiver receipts JSONL")
    nv.add_argument("--alerts", help="Optional alerts JSONL (normalized)")
    nv.add_argument("--out", default="out/network_validation.json")
    nv.set_defaults(func=cmd_net_validate)

    st = sub.add_parser("selftest", help="Run a local sanity test (receiver + live send + receipt validation)")
    st.add_argument("--live", action="store_true", help="Run live network selftest")
    st.add_argument("--dst-ip", default="127.0.0.1")
    st.add_argument("--bind", default="127.0.0.1", help="Receiver bind IP for selftest")
    st.add_argument("--cwd", default=".", help="Working directory (repo root)")
    st.add_argument("--receipts", default="receiver_out/receipts.jsonl")
    st.add_argument("--receiver-config", default=None)
    st.set_defaults(func=cmd_selftest)

    # ── scenarios list ────────────────────────────────────────────────
    scl = sub.add_parser("scenarios", help="Inspect the scenario library")
    scl_sub = scl.add_subparsers(dest="sub_cmd", required=True)
    sc_list = scl_sub.add_parser("list", help="List scenarios (mirrors /api/scenarios)")
    sc_list.add_argument("--file", default=None, help="scenarios.yml path (default: bundled)")
    sc_list.add_argument("--proto", default=None, help="Filter by protocol (modbus, dnp3, s7comm, …)")
    sc_list.add_argument("--technique", default=None, help="Filter by technique ID (e.g. T0855)")
    sc_list.add_argument("--search", default=None, help="Free-text filter against name/title")
    sc_list.add_argument("--json", action="store_true", help="Emit JSON instead of table")
    sc_list.set_defaults(func=cmd_scenarios_list)

    # ── campaign list / validate / run ────────────────────────────────
    cmp = sub.add_parser("campaign", help="Campaign playbook management (mirrors /campaigns Web UI)")
    cmp_sub = cmp.add_subparsers(dest="sub_cmd", required=True)

    cl = cmp_sub.add_parser("list", help="List built-in campaigns")
    cl.add_argument("--campaigns-file", default=None)
    cl.add_argument("--file", default=None, help="scenarios.yml path for cross-ref validation")
    cl.add_argument("--json", action="store_true")
    cl.set_defaults(func=cmd_campaign_list)

    cv = cmp_sub.add_parser("validate", help="Validate a campaign YAML against the scenario library")
    cv.add_argument("--campaigns-file", default=None)
    cv.add_argument("--file", default=None)
    cv.set_defaults(func=cmd_campaign_validate)

    cr = cmp_sub.add_parser("run", help="Run a campaign playbook live against a receiver")
    cr.add_argument("--id", required=True, help="Campaign id, e.g. industroyer2")
    cr.add_argument("--dst-ip", required=True, help="Receiver IP")
    cr.add_argument("--campaigns-file", default=None)
    cr.add_argument("--file", default=None, help="scenarios.yml path")
    cr.add_argument("--iface", default=None, help="L2 interface (for GOOSE/PROFINET)")
    cr.add_argument("--timeout", type=float, default=2.0)
    cr.add_argument("--outdir", default="out")
    cr.add_argument("--confirm-live-network", action="store_true",
                    help="REQUIRED: enable live sending")
    cr.add_argument("--json", action="store_true", help="Emit final summary as JSON")
    cr.set_defaults(func=cmd_campaign_run)

    # ── detections preview / export ───────────────────────────────────
    det = sub.add_parser("detections", help="Detection-content generation (Suricata + Sigma)")
    det_sub = det.add_subparsers(dest="sub_cmd", required=True)

    dp = det_sub.add_parser("preview", help="Print tier counts without writing files")
    dp.add_argument("--technique", action="append", default=None,
                    help="Filter to specific technique(s). Repeatable.")
    dp.add_argument("--json", action="store_true")
    dp.set_defaults(func=cmd_detections_preview)

    de = det_sub.add_parser("export", help="Export Suricata + Sigma rules to disk")
    de.add_argument("--outdir", default="out/detections",
                    help="Output directory (used unless --zip is given)")
    de.add_argument("--zip", default=None, help="Write a zip archive to this path instead of a folder")
    de.add_argument("--technique", action="append", default=None)
    de.add_argument("--no-marker", action="store_true",
                    help="Omit lab_marker tier")
    de.set_defaults(func=cmd_detections_export)

    # ── demo up / down / fire ─────────────────────────────────────────
    dm = sub.add_parser("demo", help="Run the end-to-end demo stack (docker compose)")
    dm_sub = dm.add_subparsers(dest="sub_cmd", required=True)

    du = dm_sub.add_parser("up", help="Bring up sender + receiver + suricata + viewer")
    du.add_argument("--detach", "-d", action="store_true", help="Run in the background")
    du.add_argument("--build", action="store_true", help="Rebuild images before starting")
    du.set_defaults(func=cmd_demo_up)

    dd = dm_sub.add_parser("down", help="Stop the demo stack")
    dd.add_argument("--volumes", "-v", action="store_true", help="Also remove volumes")
    dd.set_defaults(func=cmd_demo_down)

    df = dm_sub.add_parser("fire", help="Fire a campaign at the running demo receiver")
    df.add_argument("--campaign", default="industroyer2", help="Campaign id to fire (default: industroyer2)")
    df.add_argument("--sender", default="http://localhost:8080", help="Sender URL (default: http://localhost:8080)")
    df.add_argument("--dst-ip", default="172.28.0.20", help="Receiver IP on icsforge-net (default: 172.28.0.20)")
    df.set_defaults(func=cmd_demo_fire)

    # ── live alert viewer ─────────────────────────────────────────────
    vw = sub.add_parser("viewer", help="Live Suricata EVE JSON alert viewer (colour-coded by tier)")
    vw.add_argument("--host", default="0.0.0.0")
    vw.add_argument("--port", type=int, default=3000)
    vw.add_argument("--eve-path", default="/var/log/suricata/eve.json")
    vw.set_defaults(func=cmd_viewer)

    return ap


def main() -> None:
    ap = build_parser()
    args = ap.parse_args()
    level = "DEBUG" if args.verbose else args.log_level
    configure_logging(level=level, log_file=args.log_file)
    rc = args.func(args)
    raise SystemExit(rc)


if __name__ == "__main__":
    main()
