#!/usr/bin/env python3
"""
ICSForge Detection Coverage Measurement Harness

Measures how well ICSForge's own three-tier detection rules fire against
ICSForge's own generated PCAPs. Produces a detection-rate matrix suitable
for quoting in the README, blog posts, or submission materials.

What it does:

  1. For every scenario in scenarios.yml (or a filtered subset), generate
     the offline PCAP via `icsforge generate`.
  2. Generate the current three-tier Suricata rules via
     `icsforge detections export`.
  3. For each PCAP + tier combination, run Suricata in offline mode and
     parse EVE JSON to count alerts.
  4. Produce a JSON summary + a Markdown table with:
       - per-tier hit rate (how many scenarios fired at least one alert)
       - per-protocol hit rate
       - unmatched scenarios (what we fail to detect — the honest part)
       - alert multiplicity (did a single scenario trigger 1, 5, 20 alerts?)

Requires: suricata binary on PATH.
Skip with `--dry-run` if Suricata isn't installed (just validates the
flow and emits the scenario × rule matrix without firing).

Usage:
  python scripts/measure_detection_coverage.py \\
      --out out/coverage_report.json \\
      --markdown out/coverage_report.md

  # Run against a subset only
  python scripts/measure_detection_coverage.py \\
      --technique T0855 --protocol modbus \\
      --out out/t0855_modbus.json

  # CI-friendly: just validate the generator flow, no Suricata
  python scripts/measure_detection_coverage.py --dry-run
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))


# ── Suricata helpers ──────────────────────────────────────────────────────
def _have_suricata() -> bool:
    return shutil.which("suricata") is not None


def _make_min_suricata_config(rule_files: dict[str, Path], outdir: Path) -> Path:
    """Write a minimal pcap-offline Suricata config with all three tier rule files.
       Alerts are classified by tier via the sid range (see _tier_from_sid)."""
    cfg = outdir / "suricata.yaml"
    rule_file_refs = "\n".join(f"  - {p.name}" for p in rule_files.values())
    rule_dir = next(iter(rule_files.values())).parent
    cfg.write_text(f"""%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "any"
    EXTERNAL_NET: "any"
default-log-dir: {outdir}

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            metadata: yes

logging:
  default-log-level: warning
  outputs:
    - console:
        enabled: no

app-layer:
  protocols:
    modbus:
      enabled: yes
      detection-ports: {{dp: "502"}}
    dnp3:
      enabled: yes
      detection-ports: {{dp: "20000"}}
    enip:
      enabled: yes
      detection-ports: {{dp: "44818"}}

default-rule-path: {rule_dir}
rule-files:
{rule_file_refs}

classification-file: /etc/suricata/classification.config
reference-config-file: /etc/suricata/reference.config

flow:
  memcap: 32mb
  hash-size: 4096
  prealloc: 100
stream:
  # midstream: accept flows without seeing the initial TCP handshake.
  # Required for offline PCAP replay — our generated PCAPs don't contain
  # the SYN/SYN-ACK/ACK, so flow:established alerts would never fire otherwise.
  midstream: true
  async-oneside: true
  memcap: 16mb
  reassembly:
    memcap: 32mb
    depth: 1mb
""")
    return cfg


def _tier_from_signature(sig: str) -> str:
    """Classify a Suricata alert signature into our three tiers by msg prefix."""
    s = sig.upper()
    if "SEMANTIC" in s:
        return "semantic"
    if "HEURISTIC" in s:
        return "heuristic"
    if "LAB_MARKER" in s or "LAB MARKER" in s or "LAB" in s:
        return "lab"
    return "unknown"


def _run_suricata_all_tiers(pcap: Path, rule_files: dict[str, Path],
                             tmp: Path) -> dict[str, list[dict]]:
    """Run suricata once with all three rule files and split alerts by tier."""
    outdir = tmp / f"run_{pcap.stem}"
    outdir.mkdir(parents=True, exist_ok=True)
    cfg = _make_min_suricata_config(rule_files, outdir)
    try:
        subprocess.run(
            ["suricata", "-r", str(pcap), "-c", str(cfg), "-l", str(outdir),
             "-k", "none"],
            capture_output=True, timeout=60, check=False,
        )
    except subprocess.TimeoutExpired:
        return {"lab": [], "heuristic": [], "semantic": []}
    eve = outdir / "eve.json"
    by_tier: dict[str, list[dict]] = {"lab": [], "heuristic": [], "semantic": []}
    if not eve.exists():
        return by_tier
    with open(eve, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if d.get("event_type") != "alert":
                continue
            sig = d.get("alert", {}).get("signature", "")
            tier = _tier_from_signature(sig)
            if tier in by_tier:
                by_tier[tier].append(d)
    return by_tier


def _run_suricata_batched(
    pcap_to_scenario: dict[Path, str],
    rule_files: dict[str, Path],
    tmp: Path,
) -> dict[str, dict[str, list[dict]]]:
    """
    Batched Suricata run — merge all PCAPs into one, invoke Suricata once,
    dispatch alerts back to their originating scenario via flow_id.

    Returns: {scenario_name: {tier: [alerts]}}

    Much faster than per-PCAP invocation: the per-run Suricata spin-up cost
    (~2-3 seconds) is amortised across all scenarios. For 500 scenarios the
    delta is ~25 minutes → ~1 minute.

    Matching strategy: each generated PCAP uses the same src_ip = 192.0.2.11
    and dst_ip = 192.0.2.10, so we can't dispatch by IP. Instead, we rewrite
    each PCAP with a unique src_ip before merging (one /24 host per scenario),
    then map alerts back via src_ip.
    """
    if not pcap_to_scenario:
        return {}

    # Need mergecap (from wireshark-common) and tcprewrite (tcpreplay).
    # If either is missing, fall back to per-pcap invocation.
    if not shutil.which("mergecap") or not shutil.which("tcprewrite"):
        out: dict[str, dict[str, list[dict]]] = {}
        for p, name in pcap_to_scenario.items():
            out[name] = _run_suricata_all_tiers(p, rule_files, tmp)
        return out

    batch_dir = tmp / "batch"
    batch_dir.mkdir(exist_ok=True)
    rewritten: list[Path] = []
    scenario_by_ip: dict[str, str] = {}

    for i, (pcap, name) in enumerate(pcap_to_scenario.items()):
        # Give each PCAP a unique src IP in the 192.0.2.0/24 TEST-NET-1 range,
        # spread across i=0..253 (i=254 overflows — fall back to per-pcap).
        if i >= 254:
            for p, n in list(pcap_to_scenario.items())[i:]:
                tail = _run_suricata_all_tiers(p, rule_files, tmp)
                rewritten_name = n
                scenario_by_ip[f"overflow_{rewritten_name}"] = rewritten_name
                # Merge into out dict at end; for simplicity collect separately
            break
        uniq_src = f"10.99.{i // 254}.{(i % 254) + 1}"
        rw = batch_dir / f"rw_{i:04d}_{pcap.stem}.pcap"
        try:
            subprocess.run(
                ["tcprewrite", "--srcipmap=192.0.2.11/32:" + uniq_src + "/32",
                 f"--infile={pcap}", f"--outfile={rw}"],
                capture_output=True, timeout=10, check=True,
            )
            rewritten.append(rw)
            scenario_by_ip[uniq_src] = name
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            continue

    if not rewritten:
        return {name: {"lab": [], "heuristic": [], "semantic": []}
                for name in pcap_to_scenario.values()}

    merged = batch_dir / "merged.pcap"
    subprocess.run(
        ["mergecap", "-w", str(merged), *[str(p) for p in rewritten]],
        capture_output=True, timeout=60, check=False,
    )

    if not merged.exists():
        return {name: {"lab": [], "heuristic": [], "semantic": []}
                for name in pcap_to_scenario.values()}

    outdir = batch_dir / "run"
    outdir.mkdir(exist_ok=True)
    cfg = _make_min_suricata_config(rule_files, outdir)
    subprocess.run(
        ["suricata", "-r", str(merged), "-c", str(cfg), "-l", str(outdir),
         "-k", "none"],
        capture_output=True, timeout=600, check=False,
    )

    # Dispatch alerts back to scenarios by src IP
    result: dict[str, dict[str, list[dict]]] = {
        name: {"lab": [], "heuristic": [], "semantic": []}
        for name in pcap_to_scenario.values()
    }
    eve = outdir / "eve.json"
    if not eve.exists():
        return result
    with open(eve, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if d.get("event_type") != "alert":
                continue
            src = d.get("src_ip", "")
            scenario = scenario_by_ip.get(src)
            if not scenario or scenario not in result:
                continue
            sig = d.get("alert", {}).get("signature", "")
            tier = _tier_from_signature(sig)
            if tier in result[scenario]:
                result[scenario][tier].append(d)
    return result


def _run_suricata_on_pcap(pcap: Path, rule_file: Path, tmp: Path) -> list[dict]:
    """Legacy single-tier shim — kept for compatibility. Not used by main flow."""
    return _run_suricata_all_tiers(pcap, {"only": rule_file}, tmp).get("only", [])


# ── Scenario discovery ────────────────────────────────────────────────────
def _load_scenarios(tech: str | None = None, proto: str | None = None,
                    limit: int | None = None) -> list[dict]:
    import yaml

    with open(REPO / "icsforge" / "scenarios" / "scenarios.yml", encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    out: list[dict] = []
    for name, scen in (doc.get("scenarios") or {}).items():
        technique = scen.get("technique")
        steps = scen.get("steps", []) or []
        p = steps[0].get("proto") if steps else None
        if not technique or not p:
            continue
        if tech and technique != tech.upper():
            continue
        if proto and p != proto.lower():
            continue
        if name.startswith("CHAIN__"):
            continue  # focus on standalone scenarios for per-tech measurement
        out.append({"name": name, "technique": technique, "proto": p, "title": scen.get("title", "")})
    if limit:
        out = out[:limit]
    return out


# ── PCAP + rule generation ────────────────────────────────────────────────
def _generate_pcap(scenario_name: str, outdir: Path) -> Path | None:
    """Generate a scenario PCAP in-process (no subprocess spawn, no interval sleeps).

    Uses run_scenario() directly from icsforge.scenarios.engine with
    skip_intervals=True so we don't wait out every packet's emit delay —
    for offline PCAP generation those sleeps are pointless.
    """
    from icsforge.scenarios.engine import run_scenario

    pcap_dir = outdir / "pcaps"
    pcap_dir.mkdir(parents=True, exist_ok=True)
    # Short stable run_id per scenario so we can find the output
    run_id = f"cov_{scenario_name[:40]}"
    try:
        result = run_scenario(
            str(REPO / "icsforge" / "scenarios" / "scenarios.yml"),
            scenario_name,
            str(outdir),
            dst_ip="192.0.2.10",
            src_ip="192.0.2.11",
            run_id=run_id,
            build_pcap=True,
            skip_intervals=True,
        )
    except Exception:
        return None
    p = result.get("pcap")
    return Path(p) if p else None


def _generate_rules(outdir: Path) -> dict[str, Path]:
    """Invoke `icsforge detections export` and return the three rule file paths."""
    r = subprocess.run(
        [sys.executable, "-m", "icsforge.detection", "--outdir", str(outdir), "--quiet"],
        cwd=str(REPO), capture_output=True, text=True, timeout=30,
    )
    if r.returncode != 0:
        raise RuntimeError(f"Rule generation failed: {r.stderr}")
    return {
        "lab":       outdir / "icsforge_lab.rules",
        "heuristic": outdir / "icsforge_heuristic.rules",
        "semantic":  outdir / "icsforge_semantic.rules",
    }


# ── Measurement ───────────────────────────────────────────────────────────
def measure(scenarios: list[dict], tmp: Path,
            dry_run: bool = False, batch: bool = False) -> dict:
    rules = _generate_rules(tmp / "rules")

    # Classify scenarios: PCAP generated? Suricata fired per tier?
    results: list[dict] = []
    per_tier_stats = {t: {"pcaps_tested": 0, "pcaps_hit": 0, "total_alerts": 0}
                      for t in ["lab", "heuristic", "semantic"]}
    per_proto: dict[str, dict[str, int]] = defaultdict(lambda: {
        "scenarios": 0, "pcaps_ok": 0,
        "lab_hit": 0, "heuristic_hit": 0, "semantic_hit": 0,
    })

    pcap_dir = tmp / "scenarios"
    pcap_dir.mkdir(exist_ok=True)

    # Phase 1: generate all PCAPs
    pcap_to_scenario: dict[Path, dict] = {}
    for i, scen in enumerate(scenarios, 1):
        name = scen["name"]
        per_proto[scen["proto"]]["scenarios"] += 1
        pcap = _generate_pcap(name, pcap_dir)
        if pcap:
            per_proto[scen["proto"]]["pcaps_ok"] += 1
            pcap_to_scenario[pcap] = scen

    # Build skeleton rows
    pcap_by_name = {scen["name"]: pcap for pcap, scen in pcap_to_scenario.items()}
    for scen in scenarios:
        pcap = pcap_by_name.get(scen["name"])
        results.append({
            "scenario": scen["name"], "technique": scen["technique"],
            "proto": scen["proto"], "pcap": bool(pcap),
            "tier_hits": {}, "tier_alerts": {},
        })

    if dry_run:
        return {
            "results": results, "per_tier": per_tier_stats,
            "per_proto": dict(per_proto),
            "totals": {
                "scenarios_considered": len(scenarios),
                "pcaps_generated": len(pcap_to_scenario),
            },
        }

    # Phase 2: run Suricata — batched or per-PCAP
    if batch and pcap_to_scenario:
        print(f"  [batch] merging {len(pcap_to_scenario)} PCAPs and running Suricata once…")
        per_scenario = _run_suricata_batched(
            {p: s["name"] for p, s in pcap_to_scenario.items()},
            rules, tmp,
        )
    else:
        per_scenario = {}
        for i, (pcap, scen) in enumerate(pcap_to_scenario.items(), 1):
            per_scenario[scen["name"]] = _run_suricata_all_tiers(pcap, rules, tmp)
            if i % 10 == 0:
                print(f"  [{i}/{len(pcap_to_scenario)}] processed")

    # Phase 3: aggregate
    for row in results:
        name = row["scenario"]
        if not row["pcap"]:
            continue
        by_tier = per_scenario.get(name, {})
        for tier in ("lab", "heuristic", "semantic"):
            alerts = by_tier.get(tier, [])
            n = len(alerts)
            hit = n > 0
            row["tier_hits"][tier] = hit
            row["tier_alerts"][tier] = n
            per_tier_stats[tier]["pcaps_tested"] += 1
            if hit:
                per_tier_stats[tier]["pcaps_hit"] += 1
                per_proto[row["proto"]][f"{tier}_hit"] += 1
            per_tier_stats[tier]["total_alerts"] += n

    return {
        "results": results,
        "per_tier": per_tier_stats,
        "per_proto": dict(per_proto),
        "totals": {
            "scenarios_considered": len(scenarios),
            "pcaps_generated": len(pcap_to_scenario),
        },
    }


# ── Rendering ─────────────────────────────────────────────────────────────
def render_markdown(summary: dict, dry_run: bool) -> str:
    t = summary["totals"]
    per_tier = summary["per_tier"]
    per_proto = summary["per_proto"]

    md = []
    md.append("# ICSForge — Reference Detection Coverage")
    md.append("")
    md.append(f"- Scenarios considered: **{t['scenarios_considered']}**")
    md.append(f"- PCAPs successfully generated: **{t['pcaps_generated']}**")
    if dry_run:
        md.append("- Mode: **dry-run** (Suricata not invoked — structural validation only)")
    md.append("")

    if not dry_run:
        md.append("## Per-tier hit rate")
        md.append("")
        md.append("Percentage of generated PCAPs for which a tier fired at least one alert.")
        md.append("")
        md.append("| Tier | PCAPs tested | PCAPs hit | Hit rate | Total alerts | Avg alerts / PCAP |")
        md.append("|---|---:|---:|---:|---:|---:|")
        for tier in ["lab", "heuristic", "semantic"]:
            s = per_tier[tier]
            hit_rate = (s["pcaps_hit"] / s["pcaps_tested"] * 100) if s["pcaps_tested"] else 0.0
            avg = (s["total_alerts"] / s["pcaps_tested"]) if s["pcaps_tested"] else 0.0
            md.append(f"| **{tier}** | {s['pcaps_tested']} | {s['pcaps_hit']} | "
                      f"{hit_rate:.1f}% | {s['total_alerts']} | {avg:.1f} |")
        md.append("")

        md.append("## Per-protocol hit rate (semantic tier)")
        md.append("")
        md.append("Hit rate specifically for tier 3 (semantic), which is the "
                  "recommended tier for real networks. This is the honest number.")
        md.append("")
        md.append("| Protocol | Scenarios | PCAPs OK | Semantic hits | Hit rate |")
        md.append("|---|---:|---:|---:|---:|")
        for proto in sorted(per_proto):
            s = per_proto[proto]
            rate = (s["semantic_hit"] / s["pcaps_ok"] * 100) if s["pcaps_ok"] else 0.0
            md.append(f"| {proto} | {s['scenarios']} | {s['pcaps_ok']} | "
                      f"{s['semantic_hit']} | {rate:.1f}% |")
        md.append("")

        md.append("## Gap analysis — what we don't detect")
        md.append("")
        missed = [r for r in summary["results"]
                  if r["pcap"] and not r["tier_hits"].get("semantic", False)]
        if not missed:
            md.append("*No gaps — every generated PCAP triggered at least one semantic-tier alert.*")
        else:
            md.append(f"{len(missed)} scenarios generated PCAPs but did **not** trigger a "
                      f"semantic-tier alert. These are honest coverage gaps:")
            md.append("")
            md.append("| Scenario | Technique | Protocol | Any-tier hit? |")
            md.append("|---|---|---|---|")
            for r in missed[:40]:
                any_hit = any(r["tier_hits"].values())
                md.append(f"| `{r['scenario']}` | {r['technique']} | {r['proto']} | "
                          f"{'✓ lower tier' if any_hit else '✗ missed entirely'} |")
            if len(missed) > 40:
                md.append(f"| _…and {len(missed) - 40} more_ | | | |")
        md.append("")
    else:
        # dry-run: just show the scenario × protocol matrix
        md.append("## Scenarios by protocol")
        md.append("")
        md.append("| Protocol | Scenarios | PCAPs OK |")
        md.append("|---|---:|---:|")
        for proto in sorted(per_proto):
            s = per_proto[proto]
            md.append(f"| {proto} | {s['scenarios']} | {s['pcaps_ok']} |")
        md.append("")

    md.append("---")
    md.append("")
    md.append("*Generated by `scripts/measure_detection_coverage.py`. "
              "See README for methodology.*")
    return "\n".join(md)


# ── CLI ───────────────────────────────────────────────────────────────────
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1],
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--technique", help="Filter to a single technique (e.g. T0855)")
    p.add_argument("--protocol", help="Filter to a single protocol (e.g. modbus)")
    p.add_argument("--limit", type=int, default=None,
                   help="Max scenarios to test (default: all)")
    p.add_argument("--out", default="out/coverage_report.json",
                   help="Path to JSON summary")
    p.add_argument("--markdown", default=None,
                   help="Path to Markdown summary (optional)")
    p.add_argument("--dry-run", action="store_true",
                   help="Skip Suricata; just validate PCAP generation")
    p.add_argument("--keep-workdir", action="store_true",
                   help="Don't delete the intermediate working directory")
    p.add_argument("--batch", action="store_true",
                   help="Batched mode: merge all PCAPs and run Suricata once. "
                        "Requires mergecap + tcprewrite on PATH. ~10x faster on big runs.")
    args = p.parse_args(argv)

    if not args.dry_run and not _have_suricata():
        print("❌ suricata not found on PATH. Use --dry-run to skip.",
              file=sys.stderr)
        return 2

    scenarios = _load_scenarios(tech=args.technique, proto=args.protocol,
                                limit=args.limit)
    if not scenarios:
        print("❌ No scenarios match the filters.", file=sys.stderr)
        return 2

    print(f"[coverage] scenarios selected: {len(scenarios)}")
    print(f"[coverage] suricata: {'SKIPPED (dry-run)' if args.dry_run else shutil.which('suricata')}")

    t0 = time.time()
    with tempfile.TemporaryDirectory(prefix="icsforge-cov-", delete=not args.keep_workdir) as td:
        tmp = Path(td)
        summary = measure(scenarios, tmp, dry_run=args.dry_run, batch=args.batch)
    elapsed = time.time() - t0

    summary["metadata"] = {
        "dry_run": args.dry_run,
        "filters": {"technique": args.technique, "protocol": args.protocol,
                    "limit": args.limit},
        "elapsed_sec": round(elapsed, 1),
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2))
    print(f"[coverage] wrote JSON: {out_path}")

    if args.markdown:
        md_path = Path(args.markdown)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(render_markdown(summary, dry_run=args.dry_run))
        print(f"[coverage] wrote Markdown: {md_path}")

    # Print a quick summary to stdout
    if not args.dry_run:
        for tier in ["lab", "heuristic", "semantic"]:
            s = summary["per_tier"][tier]
            rate = (s["pcaps_hit"] / s["pcaps_tested"] * 100) if s["pcaps_tested"] else 0.0
            print(f"[coverage] {tier:10s} hit rate: "
                  f"{s['pcaps_hit']}/{s['pcaps_tested']} ({rate:.1f}%)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
