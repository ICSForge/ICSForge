from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
import subprocess
import signal
from typing import List

from icsforge.scenarios.engine import run_scenario
from icsforge.live.sender import send_scenario_live
from icsforge.reports.network_validation import build_network_validation_report
from icsforge.state import RunRegistry, default_db_path
from pathlib import Path


def cmd_generate(args) -> int:
    res = run_scenario(args.file, args.name, args.outdir, dst_ip=args.dst_ip, src_ip=args.src_ip)
    print(json.dumps(res, indent=2))
    return 0


def cmd_send(args) -> int:
    allowlist: List[str] = [x.strip() for x in (args.allowlist.split(",") if args.allowlist else []) if x.strip()] or [args.dst_ip]

    res = send_scenario_live(
        scenario_file=args.file,
        scenario_name=args.name,
        dst_ip=args.dst_ip,
        iface=args.iface,
        confirm_live_network=args.confirm_live_network,
        receiver_allowlist=allowlist,
        timeout=args.timeout,
    )

    gt = run_scenario(
        args.file,
        args.name,
        args.outdir,
        dst_ip=args.dst_ip,
        src_ip=args.src_ip,
        run_id=res["run_id"],
        build_pcap=args.also_build_pcap,
    )

    # Enterprise run registry (out/runs.db)
    try:
        repo_root = str(Path(__file__).resolve().parents[1])
        reg = RunRegistry(default_db_path(repo_root))
        reg.upsert_run(res["run_id"], scenario=args.name, pack=args.file, dst_ip=args.dst_ip, src_ip=args.src_ip,
                       iface=args.iface, mode="live", status="ok", meta={"sent": res.get("sent")})
        reg.add_artifact(res["run_id"], "events", gt.get("events"))
        if gt.get("pcap"):
            reg.add_artifact(res["run_id"], "pcap", gt.get("pcap"))
    except Exception:
        pass

    print("[OK] live send complete")
    print("  run_id:", res["run_id"])
    print("  sent:", res["sent"])
    print("  ground_truth_events:", gt.get("events"))
    return 0


def cmd_net_validate(args) -> int:
    rep = build_network_validation_report(args.events, args.receipts, alerts_jsonl=args.alerts, out_path=args.out)
    print("[OK] network validation report:", args.out)
    print(json.dumps(rep, indent=2))
    return 0


def _read_jsonl(path: str):
    with open(path, "r", encoding="utf-8") as f:
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
        print("Selftest currently supports --live only.", file=sys.stderr)
        return 2

    dst_ip = args.dst_ip
    receipts_path = args.receipts

    # Clean receipts for fresh run
    os.makedirs(os.path.dirname(receipts_path) or ".", exist_ok=True)
    if os.path.exists(receipts_path):
        os.remove(receipts_path)

    recv_cmd = [sys.executable, "-m", "icsforge.receiver", "--bind", args.bind]
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
        time.sleep(1.5)

        # Build a temp scenario file (pcap steps = live send steps)
        scenario = f"""scenarios:
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
        tf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".yml", dir=args.cwd)
        tf.write(scenario)
        tf.flush()
        tf.close()
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
        time.sleep(1.0)

        # Validate receipts
        if not os.path.exists(receipts_path):
            print("[FAIL] receipts file not created:", receipts_path, file=sys.stderr)
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
            print("[FAIL] No receipt matched run_id", res["run_id"], file=sys.stderr)
            return 1
        if not got_modbus:
            print("[FAIL] Modbus receipt missing for run_id", res["run_id"], file=sys.stderr)
            return 1
        if not got_dnp3:
            print("[FAIL] DNP3 receipt missing for run_id", res["run_id"], file=sys.stderr)
            return 1

        print("[PASS] Receiver reachable")
        print("[PASS] Modbus packet received")
        print("[PASS] DNP3 packet received")
        print("[PASS] Correlation run_id:", res["run_id"])
        return 0

    finally:
        try:
            recv.send_signal(signal.SIGINT)
            time.sleep(0.5)
            recv.kill()
        except Exception:
            pass


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="icsforge", description="ICSForge - Safe OT/ICS Telemetry Lab")
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
    s.add_argument("--also-build-pcap", action="store_true", help="Also build an offline PCAP alongside live sending (requires scapy working on host)")
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
    rc = args.func(args)
    raise SystemExit(rc)


if __name__ == "__main__":
    main()
