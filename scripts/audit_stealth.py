#!/usr/bin/env python3
"""
Stealth-mode audit: generate every distinct (proto, style) combination in
both standard and --no-marker (stealth) modes and run both through tshark.

Stealth-mode parity is the strong claim: if stealth-mode traffic dissects
identically to standard mode, the marker isn't a "tell" that distinguishes
ICSForge synthetic traffic from real OT.

Checkpoint: /tmp/audit_stealth_checkpoint.json
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

import yaml  # noqa: E402

from icsforge.scenarios.engine import run_scenario  # noqa: E402

CKPT = Path("/tmp/audit_stealth_checkpoint.json")


# Same allowlist as the standard audit
EXPECTED_MALFORMED = {
    ("s7comm", "malformed_param"),  # T0866 over-sized parameter block
}


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


def run_one(name, no_marker):
    """Generate one scenario in std or stealth mode; return tshark stats."""
    tmpdir = tempfile.mkdtemp(prefix=f"audit-{'stl' if no_marker else 'std'}-")
    try:
        run_scenario(scenario_path="icsforge/scenarios/scenarios.yml",
                     name=name, outdir=tmpdir,
                     dst_ip="192.0.2.10", src_ip="192.0.2.11",
                     skip_intervals=True, no_marker=no_marker)
        pcap = None
        for root, _, files in os.walk(tmpdir):
            for f in files:
                if f.endswith(".pcap"):
                    pcap = os.path.join(root, f)
                    break
            if pcap:
                break
        if not pcap:
            return None
        return tshark_errors(pcap)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


target = sys.argv[1] if len(sys.argv) > 1 else None
with open("icsforge/scenarios/scenarios.yml") as f:
    scs = yaml.safe_load(f)["scenarios"]

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
print(f"Total {target or 'all'} combos: {len(ordered)}, done: {len(done)}, remaining: {len(remaining)}",
      file=sys.stderr)

# Each combo runs the scenario twice (std + stealth) — process fewer per batch
budget = 15
for (p, s), users in remaining[:budget]:
    rep = users[0]
    row = {"proto": p, "style": s, "rep": rep, "uses": len(users)}
    try:
        std_result = run_one(rep, no_marker=False)
        stealth_result = run_one(rep, no_marker=True)
        if std_result is None or stealth_result is None:
            row["error"] = "no_pcap"
        else:
            std_total, std_errs, std_samples = std_result
            stl_total, stl_errs, stl_samples = stealth_result
            row.update({
                "std": {"total": std_total, "errors": std_errs, "samples": std_samples},
                "stealth": {"total": stl_total, "errors": stl_errs, "samples": stl_samples},
            })
            if (p, s) in EXPECTED_MALFORMED:
                row["expected_malformed"] = True
            # Compare: does stealth produce the same dissection result as std?
            row["stealth_parity"] = (std_errs == stl_errs)
            mark_std = "✅" if std_errs == 0 else "❌"
            mark_stl = "✅" if stl_errs == 0 else "❌"
            mark_par = "═" if row["stealth_parity"] else "≠"
            print(f"  std={mark_std}({std_errs}) stealth={mark_stl}({stl_errs}) {mark_par}  {p}/{s}",
                  file=sys.stderr)
    except Exception as e:
        row["exception"] = str(e)[:200]
        print(f"  💥 {p}/{s}: {e}", file=sys.stderr)
    done[(p, s)] = row
    CKPT.write_text(json.dumps(list(done.values()), indent=2))

# Summary
print(file=sys.stderr)
broken_std = [r for r in done.values()
              if r.get("std", {}).get("errors", 0) > 0 and not r.get("expected_malformed")]
broken_stl = [r for r in done.values()
              if r.get("stealth", {}).get("errors", 0) > 0 and not r.get("expected_malformed")]
parity_breaks = [r for r in done.values() if r.get("stealth_parity") is False]
print(f"Audited: {len(done)} styles", file=sys.stderr)
print(f"  broken in std:    {len(broken_std)}", file=sys.stderr)
print(f"  broken in stealth: {len(broken_stl)}", file=sys.stderr)
print(f"  parity breaks (std vs stealth differ): {len(parity_breaks)}", file=sys.stderr)
if parity_breaks:
    for b in parity_breaks:
        print(f"    {b['proto']}/{b['style']}: std_errs={b['std']['errors']} stealth_errs={b['stealth']['errors']}",
              file=sys.stderr)
print(f"\n{len(ordered) - len(done)} combos left for {target or 'all'}", file=sys.stderr)
