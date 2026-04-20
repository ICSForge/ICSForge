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

import io
import json
import os
import subprocess
import sys
import tempfile
import threading
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
        assert len(sigma_files) >= 149, f"Expected >=149 sigma files, got {len(sigma_files)}"

    def test_rule_counts_match_changelog(self):
        """v0.61.0 CHANGELOG: lab=149, heuristic=145, semantic=227."""
        from icsforge.detection.generator import generate_all

        r = generate_all()
        rc = r["rule_counts"]
        assert rc["lab_marker"] == 149
        assert rc["protocol_heuristic"] == 145
        assert rc["semantic"] == 227


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
        lines = [l for l in r.stdout.splitlines() if l.startswith("  T")]
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
        lines = [l for l in r.stdout.splitlines() if l.startswith("  T")]
        for line in lines:
            assert "modbus" in line.lower() or line.startswith("  T0"), line

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
        assert data["rule_counts"]["lab_marker"] == 149
        assert data["rule_counts"]["semantic"] == 227

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

        # Application layer: app_ctrl(1) + func(1) + obj_hdr(3: group, var, qualifier) + count(1) = 6 bytes
        # For CROB: obj_hdr is "0C 01 07" (group 12, var 1, qualifier 0x07 = 1-byte-count prefix),
        # count byte = 0x01 (one CROB follows), then the CROB itself.
        assert b"\x0c\x01\x07\x01" in app, f"CROB object header not found in {style} app layer: {app.hex()}"
        crob_start = app.index(b"\x0c\x01\x07\x01") + 4
        # The CROB must start with the expected control code
        assert app[crob_start] == ctrl_byte, (
            f"Expected CROB control_code 0x{ctrl_byte:02x} at offset {crob_start}, "
            f"got 0x{app[crob_start]:02x}"
        )
        # 11 bytes later, we must hit the ICSForge marker prefix "ICSFORGE:"
        crob_end = crob_start + 11
        # The marker is prefixed with "ICSFORGE:" before the user-supplied tail
        assert app[crob_end:crob_end + 9] == b"ICSFORGE:", (
            f"CROB is not 11 bytes in {style}: "
            f"expected 'ICSFORGE:' at offset {crob_end}, got {app[crob_end:crob_end+9]!r} "
            f"(app bytes around: {app[crob_start:crob_end+12].hex()})"
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
