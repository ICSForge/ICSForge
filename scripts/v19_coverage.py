#!/usr/bin/env python3
"""Compute canonical MITRE ATT&CK ICS v18/v19 coverage figures from
scenarios.yml and the v19 crosswalk JSON.

This script is the source of truth for technique-coverage figures
quoted in README.md, docs/MITRE_V19_CROSSWALK.md, and the /api/version
endpoint. Any documentation that disagrees with this script's output
is stale and needs updating.

Usage:
    scripts/v19_coverage.py                # human-readable table
    scripts/v19_coverage.py --json         # machine-readable
    scripts/v19_coverage.py --check        # exits non-zero if README drifts

The --check mode is intended for CI: it greps the README for the
canonical figures and fails the build if the numbers there don't
match what this script computes.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCENARIOS_YML = REPO / "icsforge" / "scenarios" / "scenarios.yml"
V18_MATRIX   = REPO / "icsforge" / "data" / "ics_attack_matrix.json"
V19_MATRIX   = REPO / "icsforge" / "data" / "ics_attack_matrix_v19.json"
CROSSWALK    = REPO / "icsforge" / "data" / "mitre_v18_v19_crosswalk.json"
README       = REPO / "README.md"


def _yaml_load(path: Path) -> dict:
    import yaml
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _json_load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def compute_coverage() -> dict:
    """Return canonical coverage figures."""
    scenarios = _yaml_load(SCENARIOS_YML).get("scenarios") or {}
    v18_matrix = _json_load(V18_MATRIX)
    v19_matrix = _json_load(V19_MATRIX)
    crosswalk  = _json_load(CROSSWALK)

    # Catalogs
    v18_standalone: set[str] = set()
    for tactic in v18_matrix.get("tactics", []):
        for tech in tactic.get("techniques", []):
            tid = tech.get("id", "")
            if tid and "." not in tid:
                v18_standalone.add(tid)

    v19_standalone: set[str] = set()
    v19_subs: set[str] = set()
    for tactic in v19_matrix.get("tactics", []):
        for tech in tactic.get("techniques", []):
            tid = tech.get("id", "")
            if "." in tid:
                v19_subs.add(tid)
            elif tid:
                v19_standalone.add(tid)

    remapped = {
        k: v.get("attack-v19-attack-id")
        for k, v in crosswalk.get("existing-techniques", {}).items()
    }
    v18_became_subs = {k for k, v in remapped.items() if v and "." in v}

    # Coverage from scenarios (incl. chain primaries)
    techs_v18: set[str] = set()
    techs_v19_subs: set[str] = set()
    for _name, body in scenarios.items():
        if not isinstance(body, dict):
            continue
        if body.get("technique"):
            techs_v18.add(body["technique"])
        for step in body.get("steps", []) or []:
            if step.get("technique"):
                techs_v18.add(step["technique"])
        v19_ann = body.get("technique_v19")
        if v19_ann and "." in v19_ann:
            techs_v19_subs.add(v19_ann)
        for step in body.get("steps", []) or []:
            v19s = step.get("technique_v19")
            if v19s and "." in v19s:
                techs_v19_subs.add(v19s)

    # v19 standalone covered = (v18 IDs we cover, still standalone in v19)
    #                       ∪ (parents of any sub-tech we annotated)
    still_standalone = (techs_v18 - v18_became_subs) & v19_standalone
    parents_covered: set[str] = set()
    for v18id, v19id in remapped.items():
        if v18id in techs_v18 and v19id and "." in v19id:
            parents_covered.add(v19id.split(".", 1)[0])
    v19_standalone_covered = still_standalone | parents_covered

    # ── Scenario counts (added v0.72.0 — second drift class catches reviewer #2)
    total_scenarios = len(scenarios)
    chain_count = sum(1 for k in scenarios if k.startswith("CHAIN__"))
    standalone_count = total_scenarios - chain_count

    conf_high = conf_med = conf_low = 0
    v19_annotated_count = 0
    for _name, body in scenarios.items():
        if not isinstance(body, dict):
            continue
        c = body.get("confidence")
        if c == "high":
            conf_high += 1
        elif c == "medium":
            conf_med += 1
        elif c == "low":
            conf_low += 1
        if body.get("technique_v19"):
            v19_annotated_count += 1

    return {
        "v18": {
            "covered": sorted(techs_v18),
            "covered_count": len(techs_v18),
            "total": len(v18_standalone),
            "uncovered": sorted(v18_standalone - techs_v18),
            "pct": round(100 * len(techs_v18) / len(v18_standalone), 1),
        },
        "v19_standalone": {
            "covered": sorted(v19_standalone_covered),
            "covered_count": len(v19_standalone_covered),
            "total": len(v19_standalone),
            "uncovered": sorted(v19_standalone - v19_standalone_covered),
            "pct": round(100 * len(v19_standalone_covered) / len(v19_standalone), 1),
        },
        "v19_subs": {
            "covered": sorted(techs_v19_subs),
            "covered_count": len(techs_v19_subs),
            "total": len(v19_subs),
            "uncovered": sorted(v19_subs - techs_v19_subs),
            "pct": round(100 * len(techs_v19_subs) / len(v19_subs), 1),
        },
        "v19_combined": {
            "covered_count": len(v19_standalone_covered) + len(techs_v19_subs),
            "total": len(v19_standalone) + len(v19_subs),
            "pct": round(
                100 * (len(v19_standalone_covered) + len(techs_v19_subs))
                / (len(v19_standalone) + len(v19_subs)),
                1,
            ),
        },
        "scenario_counts": {
            "total": total_scenarios,
            "standalone": standalone_count,
            "chains": chain_count,
            "confidence_high": conf_high,
            "confidence_medium": conf_med,
            "confidence_low": conf_low,
            "v19_annotated": v19_annotated_count,
        },
    }


def render_table(cov: dict) -> str:
    sc = cov["scenario_counts"]
    return (
        "ICSForge MITRE ATT&CK ICS coverage\n"
        "===================================\n\n"
        f"v18 standalone:        {cov['v18']['covered_count']} / {cov['v18']['total']} = {cov['v18']['pct']}%\n"
        f"v19 standalone:        {cov['v19_standalone']['covered_count']} / {cov['v19_standalone']['total']} = {cov['v19_standalone']['pct']}%\n"
        f"v19 sub-techniques:    {cov['v19_subs']['covered_count']} / {cov['v19_subs']['total']} = {cov['v19_subs']['pct']}%\n"
        f"v19 combined:          {cov['v19_combined']['covered_count']} / {cov['v19_combined']['total']} = {cov['v19_combined']['pct']}%\n"
        "\n"
        "Scenario counts\n"
        "---------------\n"
        f"Total scenarios:       {sc['total']} ({sc['standalone']} standalone + {sc['chains']} chains)\n"
        f"Confidence high:       {sc['confidence_high']}\n"
        f"Confidence medium:     {sc['confidence_medium']}\n"
        f"Confidence low:        {sc['confidence_low']}\n"
        f"v19 annotations:       {sc['v19_annotated']}\n"
        "\n"
        f"v19 standalone uncovered ({len(cov['v19_standalone']['uncovered'])}):\n"
        + "".join(f"  {t}\n" for t in cov["v19_standalone"]["uncovered"])
        + f"\nv19 sub-techs uncovered ({len(cov['v19_subs']['uncovered'])}):\n"
        + "".join(f"  {t}\n" for t in cov["v19_subs"]["uncovered"])
    )


def _live_version() -> str:
    """Read __version__ from icsforge/__init__.py without importing the package."""
    init = REPO / "icsforge" / "__init__.py"
    import re
    m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', init.read_text(encoding="utf-8"))
    return m.group(1) if m else ""


def _stale_version_tags(text: str, live: str) -> list[str]:
    """Find version-pinned headers in the README that disagree with the live
    build version. Catches the 'Key Numbers (v0.64.7)' drift class: a header
    that hardcodes a vX.Y.Z tag which then rots as the build advances."""
    import re
    bad = []
    # Match version tags like 'v0.64.7' that appear on a markdown header line.
    for line in text.splitlines():
        if not line.lstrip().startswith("#"):
            continue
        for tag in re.findall(r"v(\d+\.\d+\.\d+)", line):
            if tag != live:
                bad.append(f"README header pins stale version v{tag} "
                           f"(live build is v{live}): {line.strip()!r}")
    return bad


def check_readme(cov: dict) -> tuple[bool, list[str]]:
    """Return (ok, list_of_drift_messages)."""
    if not README.exists():
        return False, ["README.md not found"]
    text = README.read_text(encoding="utf-8")

    sc = cov["scenario_counts"]
    # Required canonical strings — adjust if README phrasing changes.
    expected = [
        # MITRE coverage strings (shipped v0.69.0)
        f"{cov['v18']['covered_count']} of {cov['v18']['total']} in ATT&CK v18 = {cov['v18']['pct']}%",
        f"{cov['v19_standalone']['covered_count']} of {cov['v19_standalone']['total']} standalone techniques",
        f"{cov['v19_subs']['covered_count']} of {cov['v19_subs']['total']} sub-techniques",
        f"= {cov['v19_combined']['pct']}%",
        # Scenario-count strings (added v0.72.0 — catches reviewer #2)
        f"{sc['standalone']} standalone + {sc['chains']} named attack chains = {sc['total']} total",
        f"{sc['confidence_high']} HIGH",
        f"{sc['confidence_medium']} MEDIUM",
        f"{sc['confidence_low']} LOW",
        f"{sc['v19_annotated']} scenarios carry `technique_v19` field",
    ]
    drift = []
    for needle in expected:
        if needle not in text:
            drift.append(f"README.md missing canonical string: {needle!r}")
    # Version-drift guard (added v0.74.9 — catches the 'Key Numbers (v0.64.7)'
    # stale-header class the defender review flagged).
    live = _live_version()
    if live:
        drift.extend(_stale_version_tags(text, live))
    return (len(drift) == 0), drift


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--check", action="store_true", help="fail if README drifts")
    args = p.parse_args()

    cov = compute_coverage()
    if args.json:
        print(json.dumps(cov, indent=2))
        return 0
    if args.check:
        ok, drift = check_readme(cov)
        if not ok:
            print("README.md DRIFT detected:")
            for msg in drift:
                print(f"  {msg}")
            print()
            print("Canonical figures:")
            print(render_table(cov))
            return 1
        print("README.md is in sync with canonical figures.")
        return 0
    print(render_table(cov))
    return 0


if __name__ == "__main__":
    sys.exit(main())
