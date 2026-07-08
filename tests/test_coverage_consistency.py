"""
Detection coverage consistency locks.

`icsforge/scenarios/scenarios.yml` (what users can run) and
`icsforge/data/detection_rules_specs.json` (what we generate rules for)
must stay in sync. Drift creates two kinds of bug:

  - Orphan rules: detection rules for techniques with no backing scenario
    (coverage claim that can't be validated)
  - Missing rules: scenarios with no generated rule (silent coverage gap)

v0.62.0 shipped with known drift:
    Orphan rules for T0841, T0842, T0875, T0876
    Missing rule for T0879

**v0.62.3 closes the drift entirely.** Standalone scenarios were added
for T0841, T0842, T0875, T0876 (closing the orphan rules) and T0879
(closing the missing rule). The expected sets are now empty: any new
drift will fail CI immediately.
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
SCENARIOS_YML = REPO / "icsforge" / "scenarios" / "scenarios.yml"
SPECS_JSON = REPO / "icsforge" / "data" / "detection_rules_specs.json"


# ── Expected drift (v0.62.3: zero) ───────────────────────────────────────
# Closed in v0.62.3 by adding standalone scenarios for the previously
# orphaned techniques and a HistoryRead scenario for T0879.
#
# v0.68.0: T0879 is intentionally chain-only. CHAIN__damage_to_property
# uses T0879 as the chain's tactical-objective primary, while each
# individual step uses high-confidence observable techniques (T0846,
# T0888, T0878, T0855, T0856) that DO have detection specs. T0879 itself
# is by definition an effect, not directly observable on the wire, so
# it has no standalone detection rule spec. This is the honest mapping.

EXPECTED_ORPHAN_SPEC_TECHS = frozenset()
EXPECTED_MISSING_SPEC_TECHS = frozenset({"T0879"})


def _scenario_techniques() -> set[str]:
    with open(SCENARIOS_YML, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    out: set[str] = set()
    for scen in (data.get("scenarios") or {}).values():
        if scen.get("technique"):
            out.add(scen["technique"])
        for step in scen.get("steps", []) or []:
            if step.get("technique"):
                out.add(step["technique"])
    return out


def _spec_techniques() -> set[str]:
    with open(SPECS_JSON, encoding="utf-8") as f:
        specs = json.load(f)
    return {s.get("technique") for s in specs.values() if s.get("technique")}


class TestDetectionCoverageConsistency:
    """Lock the known drift. If the drift changes, a maintainer must decide:
       fix it forward (ideal) or update the expected sets here (honest)."""

    def test_orphan_spec_techs_match_baseline(self):
        """Techniques with rules but no scenarios — exactly the v0.62.0 set."""
        specs = _spec_techniques()
        scenarios = _scenario_techniques()
        orphans = specs - scenarios
        assert orphans == EXPECTED_ORPHAN_SPEC_TECHS, (
            f"Drift changed!\n"
            f"  Now: {sorted(orphans)}\n"
            f"  Was: {sorted(EXPECTED_ORPHAN_SPEC_TECHS)}\n"
            f"  Either (1) add scenarios for new orphans, (2) remove their specs, "
            f"or (3) update EXPECTED_ORPHAN_SPEC_TECHS in this file."
        )

    def test_missing_spec_techs_match_baseline(self):
        """Techniques with scenarios but no rules — exactly the v0.62.0 set."""
        specs = _spec_techniques()
        scenarios = _scenario_techniques()
        missing = scenarios - specs
        assert missing == EXPECTED_MISSING_SPEC_TECHS, (
            f"Drift changed!\n"
            f"  Now: {sorted(missing)}\n"
            f"  Was: {sorted(EXPECTED_MISSING_SPEC_TECHS)}\n"
            f"  Either (1) add rule specs for new missing techs, (2) remove their "
            f"scenarios, or (3) update EXPECTED_MISSING_SPEC_TECHS in this file."
        )

    def test_readme_technique_count_matches_code(self):
        """README claims '68 techniques'. This test fails when the claim drifts."""
        import re

        readme = (REPO / "README.md").read_text(encoding="utf-8")
        # Extract explicit technique-count claims from the README
        matches = re.findall(r"(\d+)\s+(?:of\s+\d+\s+)?(?:unique\s+)?technique", readme)
        counts = {int(m) for m in matches if int(m) > 50 and int(m) < 100}
        scenario_techs = len(_scenario_techniques())
        assert scenario_techs in counts, (
            f"README mentions technique counts {sorted(counts)} but "
            f"scenarios.yml has {scenario_techs} unique techniques. "
            f"Either update scenarios.yml or fix the README."
        )


class TestReadmeCampaignListMatchesBuiltin:
    """The README advertises 11 named attack chains. builtin.yml must
       define exactly those 11 (or we are back to the v0.61.0 gap)."""

    EXPECTED_CAMPAIGN_NAMES_IN_README = {
        "Industroyer2",
        "TRITON",                             # safety_system_attack (README spells TRITON)
        "Stuxnet",                            # stuxnet_ttps
        "Water Treatment",                    # water_treatment
        "OPC UA Espionage",                   # opcua_espionage
        "EtherNet/IP Manufacturing",          # enip_manufacturing
        "AitM + Sensor Spoof",                # sensor_spoofing
        "Firmware Persistence",               # firmware_persistence
        "Full ICS Kill Chain",                # full_ics_kill_chain
        "Loss of Availability",               # loss_of_availability
        "Default Creds",                      # credential_harvest
    }

    def test_readme_references_every_builtin_campaign(self):
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        missing = []
        for needle in self.EXPECTED_CAMPAIGN_NAMES_IN_README:
            if needle not in readme:
                missing.append(needle)
        assert not missing, (
            f"README no longer mentions these campaigns: {missing}. "
            f"The 11-chain claim in README.md and builtin.yml must stay aligned."
        )
