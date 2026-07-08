#!/usr/bin/env python3
"""Resumable style audit. Saves checkpoint after every style.

Usage:
    python3 scripts/audit_resumable.py [PROTO]   # audits PROTO (or all)

Checkpoint at /tmp/audit_checkpoint.json. Run repeatedly until "all done".
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
os.chdir(HERE)
sys.path.insert(0, str(HERE))

import yaml  # noqa: E402  (must come after sys.path insert above)

from icsforge.scenarios.engine import run_scenario  # noqa: E402  (same)

CKPT = Path("/tmp/audit_checkpoint.json")


def tshark_errors(pcap):
    if not shutil.which("tshark"):
        return (0, 0, [])
    r = subprocess.run(["tshark", "-r", pcap, "-T", "fields", "-e", "frame.number"],
                       capture_output=True, text=True, timeout=10)
    total = sum(1 for line in r.stdout.splitlines() if line.strip().isdigit())
    r = subprocess.run(
        ["tshark", "-r", pcap, "-Y", "_ws.malformed || _ws.expert.severity==error",
         "-T", "fields", "-e", "frame.number", "-e", "_ws.col.Info"],
        capture_output=True, text=True, timeout=10)
    errors = []
    for line in r.stdout.splitlines():
        if "\t" in line:
            errors.append(line.split("\t", 1)[1].strip()[:120])
    return (total, len(errors), errors[:3])


target = sys.argv[1] if len(sys.argv) > 1 else None
with open("icsforge/scenarios/scenarios.yml") as f:
    scs = yaml.safe_load(f)["scenarios"]

# Some styles are INTENTIONALLY malformed — they exist to test detection
# of exploitation attempts, fuzzing, or protocol violations. Wireshark will
# correctly flag them as malformed; that's the design goal. Audit treats
# these as clean.
EXPECTED_MALFORMED = {
    ("s7comm", "malformed_param"),  # T0866 over-sized parameter block
}

combos = defaultdict(list)
for name, body in scs.items():
    for step in body.get("steps", []):
        p = step.get("proto", "?")
        s = step.get("style", "?")
        if target and p != target:
            continue
        combos[(p, s)].append(name)

ordered = sorted(combos.items())
done = {}
if CKPT.exists():
    try:
        done = {(r["proto"], r["style"]): r for r in json.loads(CKPT.read_text())}
    except Exception:
        done = {}

remaining = [(k, v) for k, v in ordered if k not in done]
print(f"Total {target or 'all'} combos: {len(ordered)}, done: {len(done)}, remaining: {len(remaining)}", file=sys.stderr)

# Process up to 25 styles per invocation to fit in the bash timeout
budget = 40
for _i, ((p, s), users) in enumerate(remaining[:budget]):
    rep = users[0]
    tmpdir = tempfile.mkdtemp(prefix="aud-")
    row = {"proto": p, "style": s, "rep": rep, "uses": len(users)}
    try:
        run_scenario(scenario_path="icsforge/scenarios/scenarios.yml",
                     name=rep, outdir=tmpdir,
                     dst_ip="192.0.2.10", src_ip="192.0.2.11", skip_intervals=True)
        pcap = None
        for root, _, files in os.walk(tmpdir):
            for f in files:
                if f.endswith(".pcap"):
                    pcap = os.path.join(root, f)
                    break
            if pcap:
                break
        if pcap:
            tot, errs, samples = tshark_errors(pcap)
            row.update({"errors": errs, "total_packets": tot, "samples": samples})
            if (p, s) in EXPECTED_MALFORMED:
                row["expected_malformed"] = True
                mark = "✅(intentionally malformed)" if errs > 0 else "⚠️ (expected to be malformed but isn't)"
            else:
                mark = "✅" if errs == 0 else "❌"
            print(f"  {mark} {p}/{s} uses={len(users)} errs={errs}", file=sys.stderr)
        else:
            row["error"] = "no_pcap"
    except Exception as e:
        row["exception"] = str(e)[:200]
        print(f"  💥 {p}/{s}: {e}", file=sys.stderr)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    done[(p, s)] = row
    # Checkpoint after each style
    CKPT.write_text(json.dumps(list(done.values()), indent=2))

# Summary
print(file=sys.stderr)
broken = [
    r for r in done.values()
    if (r.get("errors", 0) > 0 or "exception" in r) and not r.get("expected_malformed")
]
print(f"Audited so far: {len(done)} styles. Broken: {len(broken)}", file=sys.stderr)
if broken:
    print("Broken styles:", file=sys.stderr)
    for b in broken:
        print(f"  {b['proto']}/{b['style']}: errs={b.get('errors', '?')} (uses {b['uses']} scenarios)", file=sys.stderr)
        for s in b.get("samples", [])[:2]:
            print(f"      {s}", file=sys.stderr)
print(f"\nCheckpoint: {CKPT}", file=sys.stderr)
print(f"Run again to continue ({len(ordered) - len(done)} combos left for {target or 'all'})", file=sys.stderr)
