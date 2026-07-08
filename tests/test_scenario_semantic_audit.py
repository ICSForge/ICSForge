"""
Scenario-vs-technique semantic audit (added in v0.64.4).

For every standalone scenario in scenarios.yml, this test verifies that at
least one of its protocol-step verb classes (read/write/operate/identify/
flood/spoof/etc.) intersects the catalog of allowed verb classes for the
scenario's claimed MITRE technique.

This catches the class of bug where a scenario claims technique X but only
emits traffic that is characteristic of technique Y. Example: a scenario
labeled "T0814 Denial of Service" that only emits read traffic without
high frequency would be flagged.

Catalogs:
  icsforge/data/audit_technique_requirements.json
    Per technique: {allow_classes, forbid_classes, desc}
  icsforge/data/audit_style_classification.json
    Per (proto, style) combo: list of verb classes

Both catalogs were derived from the v0.64.4 audit. They are intentionally
permissive: they only flag scenarios where NO step's verb classes match
the technique's allow set. False positives have been reduced to zero
through three rounds of catalog refinement.
"""
import json
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_PATH = REPO_ROOT / "icsforge" / "scenarios" / "scenarios.yml"
REQ_PATH = REPO_ROOT / "icsforge" / "data" / "audit_technique_requirements.json"
CLASS_PATH = REPO_ROOT / "icsforge" / "data" / "audit_style_classification.json"


@pytest.fixture(scope="module")
def catalogs():
    with open(REQ_PATH) as f:
        req_raw = json.load(f)
    requirements = {
        t: {
            "allow_classes": set(v["allow_classes"]),
            "forbid_classes": set(v["forbid_classes"]),
            "desc": v.get("desc", ""),
        }
        for t, v in req_raw.items()
    }
    with open(CLASS_PATH) as f:
        cls_raw = json.load(f)
    classification = {
        tuple(k.split("/", 1)): set(v) for k, v in cls_raw.items()
    }
    return requirements, classification


@pytest.fixture(scope="module")
def scenarios():
    with open(SCENARIO_PATH) as f:
        return yaml.safe_load(f)["scenarios"]


def test_audit_catalogs_cover_all_techniques(catalogs, scenarios):
    """Every technique used by any standalone scenario must be in the catalog."""
    requirements, _ = catalogs
    used_techs = set()
    for name, body in scenarios.items():
        if name.startswith("CHAIN__"):
            continue
        if isinstance(body, dict) and "technique" in body:
            used_techs.add(body["technique"])
    missing = used_techs - set(requirements.keys())
    assert not missing, (
        f"audit_technique_requirements.json missing entries for techniques "
        f"used in scenarios: {sorted(missing)}"
    )


def test_audit_classifier_covers_all_combos(catalogs, scenarios):
    """Every (proto, style) combo used by any scenario must be classified."""
    _, classification = catalogs
    used_combos = set()
    for name, body in scenarios.items():
        if name.startswith("CHAIN__"):
            continue
        for step in body.get("steps", []):
            p, s = step.get("proto"), step.get("style")
            if p and s:
                used_combos.add((p, s))
    missing = used_combos - set(classification.keys())
    assert not missing, (
        f"audit_style_classification.json missing entries for combos: {sorted(missing)}"
    )


def test_no_scenario_fails_semantic_check(catalogs, scenarios):
    """No standalone scenario may have ALL its protocol steps using only
    verb-classes outside the technique's allow set."""
    requirements, classification = catalogs
    flagged = []
    for name, body in scenarios.items():
        if name.startswith("CHAIN__"):
            continue
        primary = body.get("technique")
        req = requirements.get(primary)
        if not req:
            continue
        allow = req["allow_classes"]
        step_classes = []
        for step in body.get("steps", []):
            p, s = step.get("proto"), step.get("style")
            if p and s:
                step_classes.append(classification.get((p, s), set()))
        if not step_classes:
            continue
        if not any(cls & allow for cls in step_classes):
            observed = set()
            for cls in step_classes:
                observed |= cls
            flagged.append({
                "name": name,
                "technique": primary,
                "allow": sorted(allow),
                "observed": sorted(observed),
            })
    assert not flagged, (
        f"{len(flagged)} scenarios fail the semantic check. "
        f"Each scenario's verb classes do not intersect its technique's allow set:\n"
        + "\n".join(
            f"  {f['name']} (tech={f['technique']}): "
            f"observed={f['observed']}, allow={f['allow']}"
            for f in flagged
        )
    )
