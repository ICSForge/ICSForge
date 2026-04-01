
import argparse
import json
import sqlite3
import os
import signal
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
    import random as _rnd
    import datetime as _dt
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
                       run_id=_run_id, build_pcap=True)
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
    )

    # Use try/finally so the run registry is always updated,
    # even if the user interrupts (Ctrl+C) during ground-truth generation.
    gt: dict = {"events": None, "pcap": None}
    interrupted = False
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
            event_count = sum(1 for _ in open(events_path, encoding="utf-8"))
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
        interrupted = True
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
        from icsforge.web.helpers_io import _append_run_index
        import datetime as _dt
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
