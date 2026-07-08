"""
Tests for features introduced in v0.62.0:

  - 11 campaigns in builtin.yml (up from 5)
  - icsforge.viewer (live Suricata alert viewer)
  - icsforge.detection CLI (generator --outdir / --zip)
  - icsforge.cli new subcommands: scenarios, campaign, detections, demo, viewer

These tests exercise pure/offline paths only — nothing that requires the
sender, receiver, or Suricata containers to be running.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
CAMPAIGNS_YML = REPO / "icsforge" / "campaigns" / "builtin.yml"
SCENARIOS_YML = REPO / "icsforge" / "scenarios" / "scenarios.yml"


# ═══ Campaigns — must match the 11 named chains advertised in README ═══

class TestBuiltinCampaigns:
    """The README promises 11 named attack chains; builtin.yml must deliver."""

    EXPECTED_CAMPAIGNS = {
        "full_ics_kill_chain",
        "stuxnet_ttps",
        "sensor_spoofing",
        "credential_harvest",
        "safety_system_attack",
        "industroyer2",
        "water_treatment",
        "opcua_espionage",
        "enip_manufacturing",
        "firmware_persistence",
        "loss_of_availability",
    }

    def test_exactly_11_campaigns(self):
        doc = yaml.safe_load(CAMPAIGNS_YML.read_text(encoding="utf-8")) or {}
        assert set(doc.get("campaigns", {}).keys()) == self.EXPECTED_CAMPAIGNS

    def test_each_campaign_has_required_fields(self):
        doc = yaml.safe_load(CAMPAIGNS_YML.read_text(encoding="utf-8")) or {}
        for cid, camp in (doc.get("campaigns") or {}).items():
            assert camp.get("name"), f"{cid}: missing name"
            assert camp.get("description"), f"{cid}: missing description"
            assert camp.get("steps"), f"{cid}: missing steps"
            assert isinstance(camp["steps"], list) and len(camp["steps"]) >= 2, f"{cid}: too few steps"
            for i, step in enumerate(camp["steps"], 1):
                assert step.get("scenario"), f"{cid}/step{i}: missing scenario"
                assert "delay" in step, f"{cid}/step{i}: missing delay"
                assert step.get("label"), f"{cid}/step{i}: missing label"

    def test_every_scenario_reference_resolves(self):
        """No campaign can point to a scenario that doesn't exist."""
        scenarios = set((yaml.safe_load(SCENARIOS_YML.read_text(encoding="utf-8")) or {})
                        .get("scenarios", {}).keys())
        doc = yaml.safe_load(CAMPAIGNS_YML.read_text(encoding="utf-8")) or {}
        missing = []
        for cid, camp in (doc.get("campaigns") or {}).items():
            for i, step in enumerate(camp.get("steps", []), 1):
                if step["scenario"] not in scenarios:
                    missing.append(f"{cid}/step{i}:{step['scenario']}")
        assert not missing, f"Dangling scenario refs: {missing}"

    def test_official_validator_returns_no_warnings(self):
        from icsforge.campaigns.runner import validate_campaign_file

        doc, warnings = validate_campaign_file(str(CAMPAIGNS_YML), str(SCENARIOS_YML))
        assert len(doc.get("campaigns", {})) == 11
        assert warnings == []


# ═══ Live alert viewer ═════════════════════════════════════════════════

class TestViewerClassification:
    """The viewer maps Suricata alert signatures to ATT&CK technique + tier."""

    @pytest.mark.parametrize("msg,tech,tier", [
        ("[T0855] ICSForge semantic modbus FC16",       "T0855", "semantic"),
        ("[T0840] ICSForge heuristic enip",             "T0840", "heuristic"),
        ("ICSForge lab_marker s7comm [T0889]",          "T0889", "lab"),
        ("Unrelated alert [T0831]",                     "T0831", "unknown"),
        ("Nothing extractable",                         "unknown", "unknown"),
    ])
    def test_classify(self, msg, tech, tier):
        from icsforge.viewer import _classify

        got_tech, got_tier = _classify(msg)
        assert got_tech == tech
        assert got_tier == tier


class TestViewerTailer:
    def test_tailer_buffers_new_alerts(self):
        """End-to-end: write EVE JSON, verify the tailer buffers and classifies."""
        from icsforge.viewer import EveTailer

        with tempfile.TemporaryDirectory() as td:
            eve = os.path.join(td, "eve.json")
            Path(eve).touch()
            t = EveTailer(eve, buffer_size=100)
            t.start()
            time.sleep(0.6)  # let tailer reach poll loop

            with open(eve, "a", encoding="utf-8") as f:
                for sid, msg in [
                    (9800001, "[T0855] ICSForge semantic modbus FC16"),
                    (9800002, "[T0840] ICSForge heuristic enip"),
                    (9800003, "[T0889] ICSForge lab_marker s7comm"),
                ]:
                    rec = {
                        "timestamp": "2026-04-17T00:00:00.000Z",
                        "event_type": "alert",
                        "src_ip": "172.28.0.10", "src_port": 55000,
                        "dest_ip": "172.28.0.20", "dest_port": 502,
                        "proto": "TCP", "app_proto": "modbus",
                        "alert": {"signature_id": sid, "signature": msg, "severity": 2},
                    }
                    f.write(json.dumps(rec) + "\n")

            # Allow tailer to pick up
            deadline = time.time() + 5.0
            while len(t.buffer) < 3 and time.time() < deadline:
                time.sleep(0.1)
            t.stop()

            assert len(t.buffer) == 3
            tiers = [r["tier"] for r in t.buffer]
            assert set(tiers) == {"semantic", "heuristic", "lab"}
            techs = [r["technique"] for r in t.buffer]
            assert set(techs) == {"T0855", "T0840", "T0889"}

    def test_tailer_ignores_non_alert_events(self):
        from icsforge.viewer import EveTailer

        with tempfile.TemporaryDirectory() as td:
            eve = os.path.join(td, "eve.json")
            Path(eve).touch()
            t = EveTailer(eve, buffer_size=50)
            t.start()
            time.sleep(0.4)
            with open(eve, "a", encoding="utf-8") as f:
                f.write(json.dumps({"event_type": "flow", "timestamp": "x"}) + "\n")
                f.write(json.dumps({"event_type": "stats", "timestamp": "x"}) + "\n")
                f.write(json.dumps({
                    "event_type": "alert", "timestamp": "x",
                    "alert": {"signature": "[T0855] ICSForge semantic modbus"},
                }) + "\n")
            deadline = time.time() + 3.0
            while len(t.buffer) < 1 and time.time() < deadline:
                time.sleep(0.1)
            t.stop()
            # Only the one alert record should be buffered
            assert len(t.buffer) == 1
            assert t.buffer[0]["technique"] == "T0855"


class TestViewerFlaskApp:
    def test_app_routes_respond(self):
        from icsforge.viewer import create_app

        app = create_app()
        c = app.test_client()
        assert c.get("/api/health").status_code == 200
        assert c.get("/api/stats").status_code == 200
        assert c.get("/api/alerts").status_code == 200
        r = c.get("/")
        assert r.status_code == 200
        assert b"ICSForge" in r.data
        assert b"Live Detection Feed" in r.data


# ═══ Detection generator CLI ═══════════════════════════════════════════

class TestDetectionGeneratorCLI:
    def test_module_cli_writes_files(self, tmp_path):
        out = tmp_path / "detections"
        # Run as `python -m icsforge.detection --outdir <out>`
        rc = subprocess.call(
            [sys.executable, "-m", "icsforge.detection", "--outdir", str(out), "--quiet"],
            cwd=str(REPO),
        )
        assert rc == 0
        assert (out / "icsforge_lab.rules").exists()
        assert (out / "icsforge_heuristic.rules").exists()
        assert (out / "icsforge_semantic.rules").exists()
        assert (out / "README.txt").exists()
        assert (out / "sigma").is_dir()
        sigma_files = list((out / "sigma").glob("*.yml"))
        assert len(sigma_files) >= 162, f"Expected >=162 sigma files, got {len(sigma_files)}"

    def test_rule_counts_match_changelog(self):
        """v0.67.0 CHANGELOG: lab=210, heuristic=228, semantic=335, zeek=156.

        v0.67.0 introduces Zeek signature emission for L2-only protocols
        (IEC 61850 GOOSE EtherType 0x88B8, PROFINET DCP 0x8892).
        Auto-generated 43 GOOSE spec entries (216 → 259 total specs).
        Result: 12 PROFINET DCP + 144 GOOSE = 156 Zeek signatures. The
        Suricata rule counts (lab/heur/sem) are unchanged because L2
        protocols cannot be matched by Suricata's detect engine.

        Prior counts:
          v0.61.0:  149 / 145 / 227
          v0.63.0:  162 / 156 / 244
          v0.65.0:  156 / 156 / 244
          v0.66.0:  156 / 174 / 244
          v0.66.1:  210 / 228 / 335
          v0.67.0:  210 / 228 / 335 / 156 zeek (this).
        """
        from icsforge.detection.generator import generate_all

        r = generate_all()
        rc = r["rule_counts"]
        assert rc["lab_marker"] == 210
        assert rc["protocol_heuristic"] == 239
        assert rc["semantic"] == 357
        assert rc["zeek"] == 156
        # v0.77.1: ENIP semantic precision (P2) — added true CIP service-code
        # matches (Read 0x4C / Write 0x4D / Reset 0x05 …) plus corrected ENIP
        # command-word mappings. heuristic 228→239, semantic 335→357. ENIP
        # semantic coverage 44.4% → 98.6%, heuristic 70.8% → 98.6%.


# ═══ icsforge CLI new subcommands ══════════════════════════════════════

def _cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "icsforge.cli", *args],
        cwd=str(REPO), capture_output=True, text=True, timeout=30,
    )


class TestCliNewSubcommands:
    def test_help_lists_all_new_top_level_commands(self):
        r = _cli("--help")
        assert r.returncode == 0
        for cmd in ("scenarios", "campaign", "detections", "demo", "viewer"):
            assert cmd in r.stdout, f"Missing CLI command: {cmd}"

    def test_scenarios_list_filters_by_technique(self):
        r = _cli("scenarios", "list", "--technique", "T0855")
        assert r.returncode == 0
        assert "T0855__unauth_command__modbus" in r.stdout
        # No leakage of other techniques in the main list lines
        lines = [ln for ln in r.stdout.splitlines() if ln.startswith("  T")]
        for line in lines:
            assert line.strip().startswith("T0855"), f"Leaked non-T0855 row: {line}"

    def test_scenarios_list_json_output_is_valid(self):
        r = _cli("scenarios", "list", "--technique", "T0855", "--json")
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert isinstance(data, list)
        assert all(item.get("technique") == "T0855" for item in data)

    def test_scenarios_list_proto_filter(self):
        r = _cli("scenarios", "list", "--proto", "modbus")
        assert r.returncode == 0
        lines = [ln for ln in r.stdout.splitlines() if ln.startswith("  T")]
        for line in lines:
            assert "modbus" in line.lower() or line.startswith("  T0"), line

    def test_scenarios_list_limit_caps_results(self):
        """--limit N caps the output to first N matching scenarios."""
        r = _cli("scenarios", "list", "--limit", "5")
        assert r.returncode == 0
        rows = [ln for ln in r.stdout.splitlines() if ln.startswith("  T") or ln.startswith("  CHAIN")]
        assert len(rows) == 5, f"--limit 5 should produce 5 rows, got {len(rows)}"
        assert "limited to first 5" in r.stdout

    def test_scenarios_list_limit_zero_unlimited(self):
        """--limit 0 means unlimited (does not silently cap)."""
        r_full = _cli("scenarios", "list")
        r_zero = _cli("scenarios", "list", "--limit", "0")
        assert r_full.returncode == 0 and r_zero.returncode == 0
        # Same number of rows; --limit 0 is unlimited
        assert r_full.stdout == r_zero.stdout

    def test_campaign_list_shows_all_11(self):
        r = _cli("campaign", "list")
        assert r.returncode == 0
        assert "11 campaigns" in r.stdout
        for camp in ("industroyer2", "water_treatment", "opcua_espionage",
                     "enip_manufacturing", "firmware_persistence", "loss_of_availability"):
            assert camp in r.stdout, f"Missing campaign: {camp}"

    def test_campaign_validate_exits_zero_on_clean(self):
        r = _cli("campaign", "validate")
        assert r.returncode == 0
        assert "Valid" in r.stdout
        assert "11 campaigns" in r.stdout

    def test_campaign_run_rejects_without_confirm_flag(self):
        r = _cli("campaign", "run", "--id", "industroyer2", "--dst-ip", "127.0.0.1")
        assert r.returncode == 2
        assert "confirm-live-network" in r.stderr.lower()

    def test_campaign_run_rejects_unknown_id(self):
        r = _cli("campaign", "run", "--id", "no_such_campaign",
                 "--dst-ip", "127.0.0.1", "--confirm-live-network")
        assert r.returncode == 2
        assert "not found" in r.stderr.lower()

    def test_detections_preview_matches_generator(self):
        r = _cli("detections", "preview", "--json")
        assert r.returncode == 0
        data = json.loads(r.stdout)
        # v0.66.1: BACnet specs added (162→216 total), BACnet rules emitted
        # (54 lab + 54 heuristic + 91 semantic), so lab 156→210, sem 244→335.
        assert data["rule_counts"]["lab_marker"] == 210
        assert data["rule_counts"]["semantic"] == 357  # v0.77.1: ENIP CIP service-code rules

    def test_detections_export_zip(self, tmp_path):
        zp = tmp_path / "rules.zip"
        r = _cli("detections", "export", "--zip", str(zp))
        assert r.returncode == 0
        assert zp.exists()
        with zipfile.ZipFile(zp) as z:
            names = z.namelist()
        assert "icsforge_semantic.rules" in names
        assert any(n.startswith("sigma/") for n in names)

    def test_demo_subcommands_parse(self):
        """Demo subcommands should parse even without docker installed."""
        r = _cli("demo", "--help")
        assert r.returncode == 0
        assert "up" in r.stdout and "down" in r.stdout and "fire" in r.stdout

    def test_viewer_subcommand_parses(self):
        r = _cli("viewer", "--help")
        assert r.returncode == 0
        assert "--eve-path" in r.stdout


# ═══ Docker compose profiles (v0.63.0 — receiver-only support) ═════════

class TestComposeProfiles:
    """
    docker-compose.demo.yml defines profiles so users can spin up just
    the bits they need (sender-only against external receiver, receiver-only
    on a remote host, full demo stack, etc.).
    """

    @pytest.fixture
    def compose(self):
        import yaml as _yaml
        path = REPO / "docker-compose.demo.yml"
        return _yaml.safe_load(path.read_text())

    def test_compose_yaml_parses(self, compose):
        assert "services" in compose
        assert len(compose["services"]) == 5  # sender, receiver, suricata, rule-loader, viewer

    def test_each_service_has_profiles(self, compose):
        for name, cfg in compose["services"].items():
            assert "profiles" in cfg, f"Service {name} missing profiles"
            assert "default" in cfg["profiles"] or "full" in cfg["profiles"], (
                f"Service {name} should be in default or full profile"
            )

    def test_receiver_only_profile_exists(self, compose):
        receiver = compose["services"]["receiver"]
        assert "receiver-only" in receiver["profiles"]

    def test_sender_only_profile_exists(self, compose):
        sender = compose["services"]["sender"]
        assert "sender" in sender["profiles"]

    def test_receiver_dependency_on_sender_is_soft(self, compose):
        """For receiver-only profile to work, the sender dependency must be
        marked required: false so docker compose doesn't refuse to start
        the receiver when sender isn't in the profile."""
        receiver = compose["services"]["receiver"]
        sender_dep = receiver["depends_on"]["sender"]
        # New compose schema allows `required: false` for soft dependencies
        assert sender_dep.get("required") is False, (
            "receiver's depends_on sender must have required: false to support "
            "the receiver-only profile"
        )


# ═══ CLI manual coverage (v0.63.0) ═════════════════════════════════════

class TestCliManualCoverage:
    """
    docs/CLI_REFERENCE.md must document every CLI command. If a new
    subcommand or flag ships without a doc entry, this test fails — the
    manual is part of the deliverable, not an afterthought.
    """

    @pytest.fixture
    def manual(self):
        path = REPO / "docs" / "CLI_REFERENCE.md"
        assert path.exists(), "CLI_REFERENCE.md missing — write the manual"
        return path.read_text()

    def test_every_top_level_subcommand_documented(self, manual):
        """All 9 top-level subcommands must appear in the manual."""
        commands = [
            "generate", "send", "net-validate", "selftest",
            "scenarios list",
            "campaign list", "campaign validate", "campaign run",
            "detections preview", "detections export",
            "demo up", "demo down", "demo fire",
            "viewer serve", "viewer replay",
        ]
        for cmd in commands:
            assert cmd in manual, f"CLI command '{cmd}' not documented in CLI_REFERENCE.md"

    def test_v063_features_in_manual(self, manual):
        """v0.63.0 additions must be documented."""
        # --limit flag (GFI-004)
        assert "--limit" in manual, "--limit flag not documented"
        # docker compose profiles (GFI-011)
        assert "receiver-only" in manual, "receiver-only profile not documented"
        # Stealth mode
        assert "--no-marker" in manual, "--no-marker flag not documented"
        # Confirmation gate
        assert "--confirm-live-network" in manual, "--confirm-live-network not documented"


# ═══ ATT&CK metadata completeness (v0.64.0) ════════════════════════════

class TestAttackMetadataCompleteness:
    """
    Every standalone scenario must declare its top-level technique,
    tactic, and confidence. Locked in CI so a future contributor adding
    a scenario without these fields fails the build.

    Chain scenarios (CHAIN__*) intentionally span multiple tactics and
    techniques, so they're exempt from the per-scenario requirement.
    """

    @pytest.fixture
    def scenarios(self):
        import yaml as _yaml
        path = REPO / "icsforge" / "scenarios" / "scenarios.yml"
        return _yaml.safe_load(path.read_text())["scenarios"]

    def test_every_standalone_has_technique(self, scenarios):
        missing = [n for n, b in scenarios.items()
                   if not n.startswith("CHAIN__") and "technique" not in b]
        assert not missing, (
            f"{len(missing)} standalone scenarios missing top-level "
            f"'technique' field: {missing[:5]}{'...' if len(missing) > 5 else ''}"
        )

    def test_every_standalone_has_tactic(self, scenarios):
        missing = [n for n, b in scenarios.items()
                   if not n.startswith("CHAIN__") and "tactic" not in b]
        assert not missing, (
            f"{len(missing)} standalone scenarios missing top-level "
            f"'tactic' field: {missing[:5]}{'...' if len(missing) > 5 else ''}"
        )

    def test_every_standalone_has_confidence(self, scenarios):
        missing = [n for n, b in scenarios.items()
                   if not n.startswith("CHAIN__") and "confidence" not in b]
        assert not missing, (
            f"{len(missing)} standalone scenarios missing 'confidence' "
            f"field: {missing[:5]}{'...' if len(missing) > 5 else ''}"
        )

    def test_confidence_levels_are_valid(self, scenarios):
        VALID = {"high", "medium", "low"}
        bad = [(n, b.get("confidence")) for n, b in scenarios.items()
               if not n.startswith("CHAIN__") and b.get("confidence") not in VALID]
        assert not bad, f"Scenarios with invalid confidence values: {bad[:5]}"

    def test_low_and_medium_have_rationale(self, scenarios):
        """If confidence is medium/low, confidence_rationale must explain why."""
        bad = []
        for n, b in scenarios.items():
            if n.startswith("CHAIN__"):
                continue
            level = b.get("confidence")
            if level in ("medium", "low") and not b.get("confidence_rationale"):
                bad.append(n)
        assert not bad, (
            f"Scenarios with non-high confidence but no rationale: {bad}"
        )

    def test_tactic_is_canonical_mitre_ics_tactic(self, scenarios):
        """Tactic field must be one of the 12 official MITRE ATT&CK ICS tactics."""
        # Canonical MITRE ATT&CK ICS tactics, v18/v19 (unchanged).
        VALID_TACTICS = {
            "Initial Access", "Execution", "Persistence",
            "Privilege Escalation", "Evasion", "Discovery",
            "Lateral Movement", "Collection", "Command and Control",
            "Inhibit Response Function", "Impair Process Control", "Impact",
        }
        bad = []
        for n, b in scenarios.items():
            if n.startswith("CHAIN__"):
                continue
            if b.get("tactic") not in VALID_TACTICS:
                bad.append((n, b.get("tactic")))
        assert not bad, f"Scenarios with invalid tactic: {bad[:5]}"


class TestMitreV19CrosswalkPresent:
    """The v18→v19 crosswalk doc must exist and document the moved IDs."""

    def test_crosswalk_doc_exists(self):
        path = REPO / "docs" / "MITRE_V19_CROSSWALK.md"
        assert path.exists(), "MITRE_V19_CROSSWALK.md missing"

    def test_crosswalk_documents_moved_ids(self):
        path = REPO / "docs" / "MITRE_V19_CROSSWALK.md"
        text = path.read_text()
        # All 9 IDs that became sub-techniques
        for old_id, new_id in [
            ("T0803", "T1691.001"), ("T0804", "T1691.002"),
            ("T0805", "T1695.001"), ("T0812", "T1694.001"),
            ("T0839", "T1693.002"), ("T0855", "T1692.001"),
            ("T0856", "T1692.002"), ("T0857", "T1693.001"),
            ("T0891", "T1694.002"),
        ]:
            assert old_id in text and new_id in text, (
                f"Crosswalk missing mapping {old_id} → {new_id}"
            )


class TestMitreV19AuthoritativeCrosswalkApplied:
    """
    Lock the v18→v19 sub-technique mappings in scenarios.yml to the authoritative
    MITRE crosswalk JSON at https://attack.mitre.org/docs/subtechniques/ics-sub-techniques-crosswalk.json

    Every scenario whose primary technique is in the 'Became new sub-technique'
    list MUST carry the correct technique_v19 annotation.
    """

    # Authoritative remaps from the MITRE ICS sub-techniques crosswalk JSON.
    # These are the 9 v18 IDs that became sub-techniques in v19.
    AUTHORITATIVE_REMAPS = {
        "T0803": "T1691.001",
        "T0804": "T1691.002",
        "T0805": "T1695.001",
        "T0812": "T1694.001",
        "T0839": "T1693.002",
        "T0855": "T1692.001",
        "T0856": "T1692.002",
        "T0857": "T1693.001",
        "T0891": "T1694.002",
    }

    @pytest.fixture
    def scenarios(self):
        import yaml as _y
        with open(REPO / "icsforge" / "scenarios" / "scenarios.yml") as f:
            return _y.safe_load(f)["scenarios"]

    def test_all_remap_targets_are_correctly_annotated(self, scenarios):
        """Every scenario with a primary v18 ID in the remap table must have
        technique_v19 set to the authoritative v19 sub-tech ID."""
        violations = []
        for name, body in scenarios.items():
            if not isinstance(body, dict):
                continue
            if name.startswith("CHAIN__"):
                continue
            primary = body.get("technique")
            if primary not in self.AUTHORITATIVE_REMAPS:
                continue
            expected = self.AUTHORITATIVE_REMAPS[primary]
            actual = body.get("technique_v19")
            if actual != expected:
                violations.append((name, primary, expected, actual))

        assert not violations, (
            f"{len(violations)} scenarios have wrong technique_v19. "
            f"First 5: {violations[:5]}"
        )

    def test_no_invalid_v19_ids(self, scenarios):
        """technique_v19 values must be one of the 18 authoritative v19 sub-tech IDs."""
        VALID_V19_SUBS = {
            # Remapped from v18
            "T1691.001", "T1691.002",
            "T1692.001", "T1692.002",
            "T1693.001", "T1693.002",
            "T1694.001", "T1694.002",
            "T1695.001",
            # Net-new sub-techniques
            "T0843.001", "T0843.002", "T0843.003",
            "T0846.001", "T0846.002", "T0846.003",
            "T0873.001",
            "T1695.002", "T1695.003",
        }
        invalid = []
        for name, body in scenarios.items():
            if not isinstance(body, dict):
                continue
            v19 = body.get("technique_v19")
            if v19 and v19 not in VALID_V19_SUBS:
                invalid.append((name, v19))
        assert not invalid, (
            f"{len(invalid)} scenarios have invalid technique_v19 values "
            f"(not in MITRE v19 catalog): {invalid[:5]}"
        )


class TestAttackMappingSchemaV19:
    """
    v0.63.1 added the attack_mapping schema per reviewer feedback.
    Each standalone scenario should have:
      - attack_mapping.primary.technique (v18 ID)
      - attack_mapping.confidence (high/medium/low)
      - attack_mapping.evidence_type (list)
    Scenarios with v18 IDs that became v19 sub-techniques must include v19_id.
    Scenarios with overclaim caveats must have a secondary mapping.
    """

    @pytest.fixture
    def scenarios(self):
        import yaml as _y
        with open(REPO / "icsforge" / "scenarios" / "scenarios.yml") as f:
            return _y.safe_load(f)["scenarios"]

    def test_every_standalone_has_attack_mapping(self, scenarios):
        missing = []
        for n, b in scenarios.items():
            if n.startswith("CHAIN__"):
                continue
            if "attack_mapping" not in b:
                missing.append(n)
        assert not missing, (
            f"Scenarios missing attack_mapping: {len(missing)} (first 5: {missing[:5]})"
        )

    def test_attack_mapping_primary_has_technique(self, scenarios):
        bad = []
        for n, b in scenarios.items():
            if "attack_mapping" not in b:
                continue
            am = b["attack_mapping"]
            primary = am.get("primary", {})
            if not primary.get("technique"):
                bad.append(n)
        assert not bad, f"attack_mapping.primary.technique missing: {bad[:5]}"

    def test_v19_translated_ids_correct(self, scenarios):
        """For the 9 IDs that became sub-techniques in v19, attack_mapping
        must include the v19 sub-technique ID."""
        v19_map = {
            "T0803": "T1691.001", "T0804": "T1691.002", "T0805": "T1695.001",
            "T0812": "T1694.001", "T0839": "T1693.002", "T0855": "T1692.001",
            "T0856": "T1692.002", "T0857": "T1693.001", "T0891": "T1694.002",
        }
        bad = []
        for n, b in scenarios.items():
            if "attack_mapping" not in b:
                continue
            primary_tech = b["attack_mapping"].get("primary", {}).get("technique", "")
            expected_v19 = v19_map.get(primary_tech)
            if expected_v19:
                actual = b["attack_mapping"]["primary"].get("v19_id")
                if actual != expected_v19:
                    bad.append((n, primary_tech, expected_v19, actual))
        assert not bad, f"v19 ID mismatch (expected, actual): {bad[:5]}"

    def test_overclaim_techniques_have_secondary(self, scenarios):
        """The reviewer flagged specific scenarios as overclaiming. Each must
        have either a secondary mapping or an explicit caveat."""
        flagged_scenarios = [
            "T0891__hardcoded_creds__bacnet",
            "T0891__hardcoded_creds__dnp3",
            "T0891__hardcoded_creds__enip",
            "T0862__supply_chain__s7comm_dl_unknown_source",
            "T0862__supply_chain__enip_fw_unknown_oui",
            "T0860__wireless__profinet_identify_wireless",
            "T0860__wireless__enip_list_identity_wireless",
            "T0887__wireless_sniff__profinet_passive",
            "T0887__wireless_sniff__enip_multicast",
            "T0823__gui__enip_write_tag_from_hmi",
            "T0863__user_execution__enip_write_tag_hmi",
            "T0863__user_execution__opcua_call_method",
            "T0851__rootkit__s7comm_output_vs_szl",
            "T0873__project_infection__s7comm_upload_modify_dl",
        ]
        for sc_name in flagged_scenarios:
            assert sc_name in scenarios, f"{sc_name} not in scenarios"
            am = scenarios[sc_name].get("attack_mapping", {})
            has_secondary = bool(am.get("secondary"))
            has_caveat = bool(am.get("caveat") or am.get("primary", {}).get("caveat"))
            assert has_secondary or has_caveat, (
                f"{sc_name} flagged by reviewer as overclaim must have secondary "
                f"mapping or caveat in attack_mapping"
            )

    def test_overclaim_techniques_demoted_to_low_or_medium(self, scenarios):
        """Reviewer-flagged overclaim scenarios should be confidence low or medium,
        never high."""
        must_not_be_high = [
            "T0891__hardcoded_creds__bacnet",
            "T0891__hardcoded_creds__dnp3",
            "T0862__supply_chain__s7comm_dl_unknown_source",
            "T0862__supply_chain__enip_fw_unknown_oui",
            "T0860__wireless__profinet_identify_wireless",
            "T0860__wireless__enip_list_identity_wireless",
            "T0887__wireless_sniff__profinet_passive",
            "T0887__wireless_sniff__enip_multicast",
            "T0823__gui__enip_write_tag_from_hmi",
            "T0851__rootkit__s7comm_output_vs_szl",
        ]
        for sc_name in must_not_be_high:
            assert sc_name in scenarios, f"{sc_name} missing"
            c = scenarios[sc_name].get("confidence")
            assert c in ("low", "medium"), (
                f"{sc_name} reviewer-flagged as overclaim, must not be confidence={c!r}"
            )


# ═══ Walk-up /demo page ═══════════════════════════════════════════════

class TestDemoPage:
    """
    The /demo page is intentionally direct-URL-only — not linked from
    the main nav. Conference walk-up view with four big tiles.
    """

    @pytest.fixture
    def client(self):
        import os as _os
        _os.environ["ICSFORGE_NO_AUTH"] = "1"
        from icsforge.web.app import create_app
        return create_app().test_client()

    def test_demo_route_registered(self):
        import os as _os
        _os.environ["ICSFORGE_NO_AUTH"] = "1"
        from icsforge.web.app import create_app
        app = create_app()
        rules = {r.rule for r in app.url_map.iter_rules()}
        assert "/demo" in rules

    def test_demo_returns_200(self, client):
        r = client.get("/demo")
        assert r.status_code == 200

    def test_demo_has_all_four_tiles(self, client):
        html = client.get("/demo").data.decode()
        for tile_id in ("industroyer2", "water_treatment",
                        "opcua_espionage", "safety_system_attack"):
            assert f'data-id="{tile_id}"' in html, f"Tile {tile_id} missing"

    def test_demo_not_in_main_nav(self, client):
        """Direct-URL only — do not leak /demo into header nav tabs."""
        import re
        html = client.get("/demo").data.decode()
        nav = re.search(r'<nav class="nav-tabs">(.*?)</nav>', html, re.S)
        assert nav, "nav-tabs block not found in base template"
        nav_html = nav.group(1)
        assert 'href="/demo"' not in nav_html, "/demo leaked into nav"
        assert ">Demo<" not in nav_html, "Demo tab label in nav"

    def test_demo_preserves_existing_nav(self, client):
        import re
        html = client.get("/demo").data.decode()
        nav = re.search(r'<nav class="nav-tabs">(.*?)</nav>', html, re.S).group(1)
        for existing in ("/sender", "/campaigns", "/matrix", "/tools"):
            assert f'href="{existing}"' in nav, f"Existing nav tab removed: {existing}"

    def test_demo_drill_down_links(self, client):
        html = client.get("/demo").data.decode()
        # Links back into deeper UI
        assert 'href="/campaigns"' in html
        assert 'href="/sender"' in html
        # External links to sibling services in the demo stack
        assert "localhost:9090" in html   # receiver
        assert "localhost:3000" in html   # alert viewer

    def test_demo_has_target_ip_field(self, client):
        html = client.get("/demo").data.decode()
        assert 'id="dst_ip"' in html
        # Default value matches the demo stack receiver on icsforge-net
        assert '172.28.0.20' in html

# ═══ Protocol spec-compliance regressions (v0.58.8 audit closeout) ═══

class TestDnp3CrobSpecCompliance:
    """
    IEEE 1815-2012 §11.3.5.2 g12v1 CROB is 11 bytes:
        control_code(1) + count(1) + on_time(4) + off_time(4) + status(1)

    v0.58.8 flagged this as 8 bytes; v0.61.0 code had 10 bytes.
    v0.62.0 fixes to spec-compliant 11 bytes.

    Verification strategy: strip the DNP3 link-layer header, strip the
    16-byte transport-layer block CRCs, and count the actual bytes
    between the object header and the ICSForge marker.
    """

    @staticmethod
    def _strip_dnp3_block_crcs(frame: bytes) -> bytes:
        """Remove link-layer header + per-16-byte block CRCs to get raw application data."""
        # Link-layer header: 10 bytes (start(2) + len(1) + ctrl(1) + dst(2) + src(2) + crc(2))
        if len(frame) < 10 or frame[:2] != b"\x05\x64":
            return frame
        data = frame[10:]
        # Strip per-block CRC: DNP3 transport layer adds 2 bytes CRC per 16 data bytes
        out = bytearray()
        pos = 0
        while pos < len(data):
            chunk_len = min(16, len(data) - pos - 2)  # last 2 bytes of each block = CRC
            if chunk_len <= 0:
                break
            out += data[pos:pos + chunk_len]
            pos += chunk_len + 2  # skip the CRC
        return bytes(out)

    @pytest.mark.parametrize("style,ctrl_byte", [
        ("select",            0x03),  # PULSE_ON
        ("operate",           0x03),  # PULSE_ON
        ("direct_operate",    0x41),  # LATCH_ON
        ("direct_operate_nr", 0x41),  # LATCH_ON
    ])
    def test_crob_is_11_bytes(self, style, ctrl_byte):
        from icsforge.protocols.dnp3 import build_payload

        unique_marker = b"XCROBTEST_" + style.upper().encode()
        payload = build_payload(marker=unique_marker, style=style)
        app = self._strip_dnp3_block_crcs(payload)

        # Application layer: app_ctrl(1) + func(1) + obj_hdr(3) + count(1) +
        # index_prefix(1) + CROB(11) + marker.
        # v0.74.0: CROB (Group 12 Var 1) is encoded with the spec-correct
        # qualifier 0x17 ("8-bit count + 8-bit index prefix", IEEE 1815-2012
        # Table 4-4) — one index-prefixed point. Header is "0C 01 17", count
        # byte 0x01, then a 1-byte index prefix (0x00), then the 11-byte CROB.
        assert b"\x0c\x01\x17\x01\x00" in app, (
            f"CROB object header (g12v1 qual 0x17) not found in {style} app layer: {app.hex()}"
        )
        crob_start = app.index(b"\x0c\x01\x17\x01\x00") + 5
        # The CROB must start with the expected control code
        assert app[crob_start] == ctrl_byte, (
            f"Expected CROB control_code 0x{ctrl_byte:02x} at offset {crob_start}, "
            f"got 0x{app[crob_start]:02x}"
        )
        # 11 bytes later we must hit the ICSForge marker. The marker is wrapped
        # as a DNP3 Group 110 (octet string) object, so the bytes at the CROB
        # end are the g110 header "6E <len> 00 00 00" followed by 'ICSFD'…
        crob_end = crob_start + 11
        tail = app[crob_end:]
        assert tail[:1] == b"\x6e", (
            f"CROB is not 11 bytes in {style}: expected g110 marker object (0x6E) "
            f"at offset {crob_end}, got {tail[:6]!r} "
            f"(app around: {app[crob_start:crob_end+12].hex()})"
        )
        assert b"ICSFD" in tail, (
            f"compact ICSF marker not found after CROB in {style}: {tail.hex()}"
        )


class TestIec104ClockSyncRealTime:
    """
    v0.58.8 flagged CP56Time2a in clock_sync as using randomised time fields.
    v0.62.0 verification: clock_sync must use real wall-clock fields.
    """

    def test_clock_sync_minute_field_is_realistic(self):
        import struct

        from icsforge.protocols.iec104 import build_payload

        payload = build_payload(marker=b"TEST", style="clock_sync")
        # CP56Time2a layout (little-endian, 7 bytes):
        #   ms (2) + minute (1) + hour (1) + day+dow (1) + month (1) + year (1)
        # The ms field in the test environment will be < 60_000 (i.e. within one minute).
        # The minute field is masked to 0x3F so it's always 0-63, but we check
        # it's within the realistic 0-59 range — if it were random 0-255 masked,
        # the distribution would be uniform 0-63 and the minute could be 60-63.
        # We just assert it's 0-59 here.
        # Find CP56Time2a start: it's the first 7 bytes after the ASDU header.
        # ASDU header is 6 bytes (type + num + COT + CA(2) + IOA(3)).
        # APCI is 6 bytes at the start of the frame.
        # Total offset to ms: 6 (APCI) + 6 (ASDU header) + 3 (IOA) = 15
        # Safer approach: try several plausible offsets.
        from datetime import datetime, timezone
        now_minute = datetime.now(timezone.utc).minute
        # Scan the frame for a 7-byte window where the 3rd byte (minute) matches now_minute±1
        found = False
        for off in range(len(payload) - 6):
            ms = struct.unpack("<H", payload[off:off+2])[0]
            minute = payload[off+2] & 0x3F
            hour = payload[off+3] & 0x1F
            month = payload[off+5] & 0x0F
            if (ms <= 59_999 and 0 <= minute <= 59 and 0 <= hour <= 23
                    and 1 <= month <= 12 and abs(minute - now_minute) <= 1):
                found = True
                break
        assert found, "clock_sync CP56Time2a does not contain realistic wall-clock fields"


class TestApiVersionReturnsScenarioCount:
    """v0.58.8 flagged /api/version returning scenarios: null. Must be a real number."""

    def test_api_version_scenarios_non_null(self):
        import os as _os
        _os.environ["ICSFORGE_NO_AUTH"] = "1"
        from icsforge.web.app import create_app

        c = create_app().test_client()
        r = c.get("/api/version")
        assert r.status_code == 200
        body = r.get_json()
        assert body.get("scenarios") is not None
        assert isinstance(body["scenarios"], int)
        assert body["scenarios"] > 500


class TestGooseBerStructuralCorrectness:
    """
    v0.62.1 verification: GOOSE allData with multiple Data items must
    be structurally valid BER per the IEC 61850-8-1 ASN.1 module.

    Wireshark 4.2.0/4.2.1/4.2.2 (and 4.0.10–4.0.12) had a bug
    (issue #19580) that asserted "recursion_depth <= 100" on legitimate
    GOOSE messages with multi-item allData. The bug was fixed in
    Wireshark 4.2.3 and 4.0.13. Real captured GOOSE PCAPs with the
    same structure trip the same assertion on affected versions.

    Rather than rely on Wireshark, validate our BER structurally with
    pyasn1 against a schema-aware decoder.
    """

    def test_two_booleans_decode_with_pyasn1(self):
        try:
            from pyasn1.codec.ber import decoder as ber_decoder
            from pyasn1.type import namedtype, tag, univ
        except ImportError:
            import pytest
            pytest.skip("pyasn1 not installed; install with `pip install pyasn1`")

        from icsforge.protocols.iec61850 import _ber_len, _data_bool

        class Data(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('boolean', univ.Boolean().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
                namedtype.NamedType('bit-string', univ.BitString().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))),
                namedtype.NamedType('floating-point', univ.OctetString().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),
            )

        class AllData(univ.SequenceOf):
            componentType = Data()
            tagSet = univ.SequenceOf.tagSet.tagImplicitly(
                tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 11))

        items = [_data_bool(False), _data_bool(True)]
        all_data_raw = b"".join(items)
        allData = b"\xAB" + _ber_len(len(all_data_raw)) + all_data_raw

        decoded, rest = ber_decoder.decode(allData, asn1Spec=AllData())
        assert len(rest) == 0, "trailing bytes after allData decode"
        assert len(decoded) == 2, "expected 2 items in allData"

    def test_mixed_items_decode_with_pyasn1(self):
        """spoof_measurement-shape data: 2 floats + 1 bool"""
        try:
            from pyasn1.codec.ber import decoder as ber_decoder
            from pyasn1.type import namedtype, tag, univ
        except ImportError:
            import pytest
            pytest.skip("pyasn1 not installed")

        from icsforge.protocols.iec61850 import _ber_len, _data_bool, _data_float32

        class Data(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('boolean', univ.Boolean().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
                namedtype.NamedType('floating-point', univ.OctetString().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),
            )

        class AllData(univ.SequenceOf):
            componentType = Data()
            tagSet = univ.SequenceOf.tagSet.tagImplicitly(
                tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 11))

        items = [_data_float32(1.5), _data_float32(2.5), _data_bool(False)]
        all_data_raw = b"".join(items)
        allData = b"\xAB" + _ber_len(len(all_data_raw)) + all_data_raw

        decoded, rest = ber_decoder.decode(allData, asn1Spec=AllData())
        assert len(rest) == 0
        assert len(decoded) == 3


# ═══ ATT&CK matrix v18/v19 toggle (v0.64.3) ═══════════════════════════

class TestMatrixVersionToggle:
    """
    /matrix supports ?version=v18 (default) and ?version=v19. The v19
    matrix view must:
      - Render the new parent techniques T1691, T1692, T1693, T1694, T1695
      - Render sub-techniques like T0846.001, T1693.002, T0873.001
      - NOT render the v18 IDs that were relocated as sub-techniques
        (T0857, T0839, T0812, T0891, T0805, T0803, T0804, T0855, T0856)
      - Light up runnable tiles based on scenarios' technique_v19 annotations
    """

    @pytest.fixture
    def client(self):
        import os as _os
        _os.environ["ICSFORGE_NO_AUTH"] = "1"
        from icsforge.web.app import create_app
        return create_app().test_client()

    def test_matrix_v18_default(self, client):
        r = client.get("/matrix")
        assert r.status_code == 200
        body = r.data.decode("utf-8", errors="ignore")
        # v18 view should show v18 in title
        assert "ATT&CK v18 for ICS" in body or "v18" in body
        # Toggle button visible
        assert "version=v18" in body
        assert "version=v19" in body

    def test_matrix_v19_explicit(self, client):
        r = client.get("/matrix?version=v19")
        assert r.status_code == 200
        body = r.data.decode("utf-8", errors="ignore")
        assert "v19" in body

    def test_matrix_v19_has_new_parents(self, client):
        r = client.get("/matrix?version=v19")
        assert r.status_code == 200
        body = r.data.decode("utf-8", errors="ignore")
        for new_parent in ["T1691", "T1692", "T1693", "T1694", "T1695"]:
            assert f'data-techid="{new_parent}"' in body, (
                f"v19 matrix should contain new parent {new_parent}"
            )

    def test_matrix_v19_has_subtechniques(self, client):
        r = client.get("/matrix?version=v19")
        assert r.status_code == 200
        body = r.data.decode("utf-8", errors="ignore")
        expected_subs = [
            "T0846.001", "T0846.002", "T0846.003",  # Discovery sub-techs
            "T0843.001", "T0843.002", "T0843.003",  # Program Download sub-techs
            "T0873.001",                            # Project File Infection sub
            "T1691.001", "T1691.002",               # Block OT Message subs
            "T1692.001", "T1692.002",               # Unauthorized Message subs
            "T1693.001", "T1693.002",               # Modify Firmware subs
            "T1694.001", "T1694.002",               # Insecure Credentials subs
            "T1695.001", "T1695.002", "T1695.003",  # Block Communications subs
        ]
        for sub in expected_subs:
            assert f'data-techid="{sub}"' in body, (
                f"v19 matrix should contain sub-technique {sub}"
            )

    def test_matrix_v19_relocated_v18_ids_absent(self, client):
        """v18 IDs that were relocated as sub-techniques should NOT appear
        as standalone tiles in the v19 view."""
        r = client.get("/matrix?version=v19")
        body = r.data.decode("utf-8", errors="ignore")
        # These v18 IDs are relocated entirely — should not have a parent tile
        relocated_v18 = ["T0803", "T0804", "T0805", "T0812",
                         "T0839", "T0855", "T0856", "T0857", "T0891"]
        for v18_id in relocated_v18:
            # Pattern matches data-techid="T0803" but not T0803X or T0803.001
            import re
            pat = rf'data-techid="{re.escape(v18_id)}"'
            assert not re.search(pat, body), (
                f"v19 matrix should NOT have {v18_id} as a standalone tile "
                f"(it was relocated as a sub-technique)"
            )

    def test_matrix_v19_runnable_coverage(self, client):
        """v19 matrix should show our scenarios as runnable on the v19 IDs."""
        r = client.get("/matrix?version=v19")
        body = r.data.decode("utf-8", errors="ignore")
        # Scenarios with technique_v19 annotations should light up the v19 IDs
        # Check a few representative ones
        import re

        def runnable_pat(tid):
            return re.search(
                rf'data-techid="{re.escape(tid)}"\s+data-techname="[^"]*"\s+'
                r'data-runnable="1"', body)
        # We have 10 T0857 -> T1693.001 scenarios, so T1693.001 must be runnable
        assert runnable_pat("T1693.001"), "T1693.001 should be runnable"
        # T1694.002 (Hardcoded Credentials) should be runnable
        assert runnable_pat("T1694.002"), "T1694.002 should be runnable"
        # T0855 was revoked in v19 and replaced by T1692.001 — the new sub-tech
        # must be runnable (scenarios are authored on the old v18 T0855 ID).
        assert runnable_pat("T1692.001"), "T1692.001 (was T0855) should be runnable"
        # T0846 (Remote System Discovery) gained sub-techniques in v19. Scenarios
        # carry technique_v19 annotations tagging the precise sub they exercise,
        # so those sub tiles light up (Port/Broadcast/Multicast Discovery), as
        # does the parent.
        assert runnable_pat("T0846"), "parent T0846 should be runnable"
        assert runnable_pat("T0846.001"), "T0846.001 (Port Scan) should be runnable via annotation"
        assert runnable_pat("T0846.003"), "T0846.003 (Multicast Discovery) should be runnable via annotation"
        # T0843 Program Download granularized into Download All / Online Edit /
        # Program Append — all three are annotated and should light up.
        assert runnable_pat("T0843.001"), "T0843.001 should be runnable via annotation"
        assert runnable_pat("T0843.003"), "T0843.003 should be runnable via annotation"

    def test_matrix_v19_wifi_subtechnique_uncovered(self, client):
        """T1695.003 (Block Communications: Wi-Fi) is an honest out-of-scope gap.

        ICSForge is a network-protocol traffic generator, not an RF tool, so the
        Wi-Fi sub-technique is legitimately not covered. Lock this in so we don't
        accidentally claim coverage we don't have.
        """
        r = client.get("/matrix?version=v19")
        body = r.data.decode("utf-8", errors="ignore")
        import re
        m = re.search(
            r'data-techid="T1695\.003"\s+data-techname="[^"]*"\s+data-runnable="(\d)"',
            body)
        assert m, "T1695.003 tile should exist in the v19 matrix"
        assert m.group(1) == "0", "T1695.003 (Wi-Fi) should NOT be runnable"

    def test_v19_subtechnique_variants_resolve(self, client):
        """Clicking a v19 sub-technique tile must return its scenario variants.

        Covers both crosswalk subs (T1692.001 <- T0855) and annotation subs
        (T0846.001 Port Scan, T0843.002 Online Edit).
        """
        for tid in ("T1692.001", "T0846.001", "T0843.001", "T0873.001"):
            r = client.get(f"/api/technique/variants?technique={tid}")
            assert r.status_code == 200, f"{tid} variants request failed"
            data = r.get_json()
            assert data.get("variants"), f"{tid} should resolve to >=1 variant"

    def test_v19_subtechnique_send_resolves_to_scenario(self, client):
        """Firing a v19 sub-technique tile (with a selected variant) must run.

        Regression for "Technique T1695.001 is not supported for network
        simulation" — the send endpoint must translate crosswalk subs
        (T1695.001 -> T0805) and annotation subs (T0846.001 -> parent T0846)
        back to their v18 scenario keys, and accept either a bare-suffix or a
        full-scenario-name variant value.
        """
        for tid in ("T1695.001", "T1692.001", "T0846.001", "T0843.002", "T0873.001"):
            variants = client.get(f"/api/technique/variants?technique={tid}").get_json()["variants"]
            assert variants, f"{tid} has no variants"
            r = client.post("/api/technique/send", json={
                "technique": tid, "variant": variants[0]["id"], "dst_ip": "127.0.0.1",
            })
            assert r.status_code == 200, (
                f"{tid} send failed: {r.get_json().get('error')}"
            )
            assert r.get_json().get("ok") is True, f"{tid} send not ok"

    def test_technique_send_ambiguous_gives_clear_error(self, client):
        """A technique with multiple variants and none selected returns a clear
        'select one' message, not a misleading 'not supported'."""
        r = client.post("/api/technique/send", json={"technique": "T0855", "dst_ip": "127.0.0.1"})
        assert r.status_code == 400
        err = r.get_json().get("error", "")
        assert "variants" in err and "select" in err.lower(), err
        assert "not supported" not in err

    def test_matrix_invalid_version_falls_back_to_v18(self, client):
        """?version=garbage should fall back to v18, not error."""
        r = client.get("/matrix?version=garbage")
        assert r.status_code == 200
        body = r.data.decode("utf-8", errors="ignore")
        assert "v18" in body


# ═══ Phase 4 semantic audit (v0.64.4) ═══════════════════════════════════

class TestPhase4SemanticAudit:
    """
    Phase 4 audit: every standalone scenario must use protocol verbs
    consistent with its claimed MITRE technique. Catches scenarios that
    are syntactically valid YAML but semantically mis-tagged (e.g., a
    pure-read scenario claiming T0855 Unauthorized Command Message).

    Catalog source:
      icsforge/data/audit_technique_requirements.json — per-technique
        allow_classes / forbid_classes / require_one_of constraints
      icsforge/data/audit_style_classification.json — per (proto, style)
        verb-class assignments

    Both files are bundled with the repo so the audit is reproducible.
    """

    FLOOD_THRESHOLD = 10  # steps with count >= 10 contribute 'flood' verb-class

    def _load_catalogs(self):
        import json
        from pathlib import Path
        repo = Path(__file__).resolve().parent.parent
        with open(repo / "icsforge" / "data" / "audit_technique_requirements.json") as f:
            req = json.load(f)
        with open(repo / "icsforge" / "data" / "audit_style_classification.json") as f:
            cls_raw = json.load(f)
        cls = {tuple(k.split("/", 1)): set(v) for k, v in cls_raw.items()}
        return req, cls

    def _audit_scenario(self, body, req_catalog, class_catalog,
                        override_tech=None):
        """Returns True/False/None (None = no requirements defined)."""
        primary = override_tech or body.get("technique")
        req = req_catalog.get(primary)
        if not req:
            return None
        allow = set(req.get("allow_classes", []))
        require_one = set(req.get("require_one_of", []))
        step_classes = []
        for step in body.get("steps", []):
            p, s = step.get("proto"), step.get("style")
            if p and s:
                cls = set(class_catalog.get((p, s), set()))
                count = step.get("count", 1)
                try:
                    count = int(count) if count is not None else 1
                except (TypeError, ValueError):
                    count = 1
                if count >= self.FLOOD_THRESHOLD:
                    cls.add("flood")
                step_classes.append(cls)
        if not step_classes:
            return None
        has_allowed = any((cls & allow) for cls in step_classes)
        has_required = (not require_one) or any(
            (cls & require_one) for cls in step_classes)
        return has_allowed and has_required

    def test_all_standalone_scenarios_pass_audit(self):
        """No scenario should be flagged as semantically mis-tagged."""
        from pathlib import Path

        import yaml
        repo = Path(__file__).resolve().parent.parent
        with open(repo / "icsforge" / "scenarios" / "scenarios.yml") as f:
            sc = yaml.safe_load(f)["scenarios"]

        req, cls = self._load_catalogs()
        flagged = []
        for name, body in sc.items():
            if name.startswith("CHAIN__"):
                continue
            result = self._audit_scenario(body, req, cls)
            if result is False:
                flagged.append((name, body.get("technique")))

        assert flagged == [], (
            f"Phase 4 audit flagged {len(flagged)} scenarios as semantically "
            f"mis-tagged: {flagged}"
        )

    def test_audit_catches_mistagged_scenario(self):
        """
        Sanity: a deliberately-wrong technique override must fail audit.
        Tagging a read-only scenario as T0855 (Unauthorized Command) should
        be flagged because no step uses write/operate verbs.
        """
        from pathlib import Path

        import yaml
        repo = Path(__file__).resolve().parent.parent
        with open(repo / "icsforge" / "scenarios" / "scenarios.yml") as f:
            sc = yaml.safe_load(f)["scenarios"]
        req, cls = self._load_catalogs()
        # Read-only scenario tagged as a write technique
        body = sc["T0801__monitor_process__modbus_poll"]
        result = self._audit_scenario(body, req, cls, override_tech="T0855")
        assert result is False, (
            "Audit failed to flag a read-only scenario mis-tagged as T0855"
        )

    def test_audit_catches_discovery_as_program_download(self):
        """A discovery scenario tagged as T0843 Program Download should fail."""
        from pathlib import Path

        import yaml
        repo = Path(__file__).resolve().parent.parent
        with open(repo / "icsforge" / "scenarios" / "scenarios.yml") as f:
            sc = yaml.safe_load(f)["scenarios"]
        req, cls = self._load_catalogs()
        body = sc["T0846__remote_sys_discovery__modbus"]
        result = self._audit_scenario(body, req, cls, override_tech="T0843")
        assert result is False, (
            "Audit failed to flag a discovery scenario mis-tagged as T0843"
        )

    def test_audit_catalog_covers_all_used_techniques(self):
        """Every technique referenced in scenarios.yml must have catalog entry."""
        from pathlib import Path

        import yaml
        repo = Path(__file__).resolve().parent.parent
        with open(repo / "icsforge" / "scenarios" / "scenarios.yml") as f:
            sc = yaml.safe_load(f)["scenarios"]
        req, _ = self._load_catalogs()
        used_techs = set()
        for name, body in sc.items():
            if name.startswith("CHAIN__"):
                continue
            t = body.get("technique")
            if t:
                used_techs.add(t)
        missing = used_techs - set(req.keys())
        assert not missing, (
            f"Audit catalog missing entries for techniques: {sorted(missing)}"
        )
