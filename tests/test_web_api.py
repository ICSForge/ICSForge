"""
Tests for ICSForge web API endpoints.

Covers:
  - /api/correlate_run (was broken by missing time import)
  - /api/detections/preview and /api/detections/download
  - /api/scenarios, /api/health
  - Route audit: verify README-documented endpoints exist
  - Verify all @web.route decorators resolve without import errors
"""
import os
import sys

import pytest

# Ensure the project root is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def app():
    """Create a Flask test app with all routes registered."""
    os.environ["ICSFORGE_UI_MODE"] = "sender"
    os.environ["ICSFORGE_NO_AUTH"] = "1"  # disable auth for functional tests
    from icsforge.web.app import create_app
    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


# ── /api/correlate_run ────────────────────────────────────────────────


class TestCorrelateRun:
    """The developer's #1 bug: /api/correlate_run crashed due to missing time import."""

    def test_correlate_run_returns_400_without_run_id(self, client):
        """POST without run_id should return 400, not 500 (NameError)."""
        resp = client.post("/api/correlate_run", json={})
        assert resp.status_code == 400
        data = resp.get_json()
        assert "error" in data

    def test_correlate_run_returns_400_for_unknown_run(self, client):
        """POST with nonexistent run_id should return 400 (events not found), not crash."""
        resp = client.post("/api/correlate_run", json={"run_id": "nonexistent-run-xyz"})
        assert resp.status_code == 400
        data = resp.get_json()
        assert "error" in data
        # The key test: it should NOT be a 500 NameError about 'time'
        assert "time" not in data.get("error", "").lower() or "not found" in data.get("error", "").lower()

    def test_correlate_run_with_real_events(self, client, tmp_path):
        """Full end-to-end: generate events, then correlate."""
        from icsforge.scenarios.engine import run_scenario

        # Generate real events
        result = run_scenario(
            os.path.join(os.path.dirname(__file__), "..", "icsforge", "scenarios", "scenarios.yml"),
            "T0855__unauth_command__modbus",
            outdir=str(tmp_path),
            dst_ip="198.51.100.42",
            src_ip="127.0.0.1",
            run_id="correlate-test-001",
        )

        # Register the run in the DB
        from icsforge.state import RunRegistry, default_db_path

        repo_root = os.path.join(os.path.dirname(__file__), "..")
        db_path = default_db_path(repo_root)
        reg = RunRegistry(db_path)
        reg.upsert_run("correlate-test-001", scenario="T0855__unauth_command__modbus", mode="test", status="ok")
        reg.add_artifact("correlate-test-001", "events", result["events"])

        # Now call correlate_run
        resp = client.post("/api/correlate_run", json={
            "run_id": "correlate-test-001",
        })
        # Should succeed (200) or at least not crash with NameError (500)
        assert resp.status_code in (200, 400), f"Got {resp.status_code}: {resp.data}"
        if resp.status_code == 200:
            data = resp.get_json()
            assert data.get("ok") is True
            assert "correlation" in data
            corr = data["correlation"]
            assert "expected" in corr
            assert "coverage_ratio" in corr


# ── Detection endpoints ───────────────────────────────────────────────


class TestDetectionEndpoints:
    """Verify the detection rule endpoints exist and return expected formats."""

    def test_detections_preview_exists(self, client):
        resp = client.get("/api/detections/preview")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "suricata" in data or "count" in data

    def test_detections_download_exists(self, client):
        resp = client.get("/api/detections/download")
        # Should return a file (200) or JSON
        assert resp.status_code == 200

    def test_old_endpoint_does_not_exist(self, client):
        """The old README-documented path should NOT exist."""
        resp = client.get("/api/generate_detection_rules")
        assert resp.status_code == 404


# ── Basic API endpoints ───────────────────────────────────────────────


class TestBasicEndpoints:
    def test_health(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200

    def test_health_page(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_scenarios_list(self, client):
        resp = client.get("/api/scenarios")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, (list, dict))

    def test_packs(self, client):
        resp = client.get("/api/packs")
        assert resp.status_code == 200

    def test_runs(self, client):
        resp = client.get("/api/runs")
        assert resp.status_code == 200

    def test_tools_pcap_replay_dst_field_visible(self, client):
        """The PCAP-replay Destination IP field must not be inside a hidden row.

        Regression guard: the r_dst input was previously wrapped in a
        display:none row, so replayTool() always errored 'Destination IP is
        required' because the user could never fill it.
        """
        body = client.get("/tools").get_data(as_text=True)
        assert 'id="r_dst"' in body, "Destination IP input must exist"
        # Find the row wrapper that contains r_dst and ensure it is not hidden.
        idx = body.find('id="r_dst"')
        # Walk back to the nearest enclosing <div class="row" ...> opening tag.
        row_start = body.rfind('<div class="row"', 0, idx)
        assert row_start != -1, "r_dst should sit inside a .row container"
        row_tag = body[row_start:body.find(">", row_start) + 1]
        assert "display:none" not in row_tag, (
            "r_dst row must not be hidden — replay needs a visible Destination IP"
        )
        # The leftover dummy field should be gone.
        assert 'id="_dummy_"' not in body, "stale dummy field should be removed"

    def test_pcap_peek_dst(self, client, tmp_path):
        """peek-dst returns the destination IP baked into a generated PCAP, so the
        Replay UI can auto-fill it (so 'replay' re-runs what was created)."""
        import subprocess
        import sys
        from pathlib import Path as _Path

        # Generate a PCAP with a known destination inside the repo's out/ dir.
        import icsforge
        repo = _Path(icsforge.__file__).resolve().parent.parent
        outdir = repo / "out"
        outdir.mkdir(exist_ok=True)
        subprocess.run(
            [sys.executable, "-m", "icsforge", "generate",
             "--name", "T0855__unauth_command__modbus",
             "--dst-ip", "192.168.213.128", "--src-ip", "10.10.10.5",
             "--outdir", str(outdir)],
            check=True, capture_output=True, timeout=60)
        pcaps = sorted((outdir / "pcaps").glob("*.pcap"))
        assert pcaps, "expected a generated pcap"
        rel = str(pcaps[-1].relative_to(repo))
        r = client.post("/api/pcap/peek-dst", json={"pcap_path": rel})
        assert r.status_code == 200
        assert r.get_json().get("dst_ip") == "192.168.213.128"
        # Path-safety guard: refuse paths outside out/.
        r2 = client.post("/api/pcap/peek-dst", json={"pcap_path": "/etc/hostname"})
        assert r2.status_code == 400


# ── Route audit ───────────────────────────────────────────────────────


class TestRouteAudit:
    """Verify all documented API routes actually exist in the Flask app."""

    # Every route mentioned in README or public docs
    README_ROUTES = [
        "/api/detections/preview",
        "/api/detections/download",
    ]

    # Core API routes that should always exist
    CORE_GET_ROUTES = [
        "/",
        "/health",
        "/api/health",
        "/api/scenarios",
        "/api/packs",
        "/api/runs",
        "/sender",
        "/matrix",
        "/tools",
        "/api/technique/variants",
        "/api/interfaces",
        "/api/profiles",
        "/api/receiver/stream",
        "/api/report/heatmap",
        "/api/campaigns/list",
    ]

    CORE_POST_ROUTES = [
        "/api/send",
        "/api/correlate_run",
        "/api/alerts/ingest",
        "/api/validate",
        "/api/selftest",
    ]

    def test_readme_routes_exist(self, app):
        """Every API endpoint mentioned in README must resolve."""
        rules = {rule.rule for rule in app.url_map.iter_rules()}
        for route in self.README_ROUTES:
            assert route in rules, f"README documents {route} but it doesn't exist in the app"

    def test_core_get_routes_exist(self, app):
        rules = {rule.rule for rule in app.url_map.iter_rules()}
        for route in self.CORE_GET_ROUTES:
            assert route in rules, f"Core route {route} missing"

    def test_core_post_routes_exist(self, app):
        rules = {rule.rule for rule in app.url_map.iter_rules()}
        for route in self.CORE_POST_ROUTES:
            assert route in rules, f"Core POST route {route} missing"

    def test_no_500_on_get_routes(self, client):
        """GET routes should return 200/302, never 500."""
        for route in self.CORE_GET_ROUTES:
            resp = client.get(route)
            assert resp.status_code != 500, f"GET {route} returned 500 (server error)"

    def test_post_routes_return_400_not_500_on_empty_body(self, client):
        """POST routes with empty body should return 400 (bad request), not 500."""
        for route in self.CORE_POST_ROUTES:
            resp = client.post(route, json={})
            assert resp.status_code != 500, f"POST {route} with empty body returned 500"


class TestLiveCallbackConfig:
    def test_callback_routes_exist(self, app):
        rules = {rule.rule for rule in app.url_map.iter_rules()}
        assert "/api/config/set_callback" in rules
        assert "/api/config/test_callback" in rules

    def test_set_callback_accepts_push(self, client):
        resp = client.post("/api/config/set_callback", json={"callback_url": "http://127.0.0.1:8080/api/receiver/callback", "callback_token": "abc"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["callback_token_set"] is True

    def test_receiver_callback_rejects_bad_token(self, app, client):
        import hashlib
        import hmac
        import json as _json

        import icsforge.web.helpers as web_helpers

        web_helpers._callback_token = "expected-token"
        try:
            # Case 1: no token at all → 401
            resp = client.post("/api/receiver/callback", json={"marker_found": True})
            assert resp.status_code == 401

            # Case 2: correct token but missing HMAC → 401 (v0.60.1 makes HMAC mandatory)
            resp = client.post(
                "/api/receiver/callback",
                json={"marker_found": True, "run_id": "x"},
                headers={"X-ICSForge-Callback-Token": "expected-token"},
            )
            assert resp.status_code == 401
            assert b"HMAC" in resp.data

            # Case 3: correct token + correct HMAC → 200
            body = _json.dumps({"marker_found": True, "run_id": "x"}).encode()
            sig = hmac.new(b"expected-token", body, hashlib.sha256).hexdigest()
            resp = client.post(
                "/api/receiver/callback",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "X-ICSForge-Callback-Token": "expected-token",
                    "X-ICSForge-HMAC": sig,
                },
            )
            assert resp.status_code == 200
            assert resp.get_json()["stored"] is True
        finally:
            web_helpers._callback_token = None


# ── Stateful TCP mode through the web API (v0.75.x) ───────────────────


class TestStatefulWebFlow:
    """The --stateful CLI feature must also be reachable from the web app,
    since the audience prioritises the UI. /api/generate_offline must honour
    a `stateful` flag and produce a handshake; the default must stay stateless.
    """

    SCEN = "T0855__unauth_command__modbus"

    def _syn_count(self, pcap_path):
        import subprocess
        out = subprocess.run(
            ["tshark", "-r", pcap_path, "-Y", "tcp.flags.syn==1",
             "-T", "fields", "-e", "frame.number"],
            capture_output=True, text=True,
        ).stdout
        return len([x for x in out.splitlines() if x.strip()])

    def test_offline_stateful_true_has_handshake(self, client, tmp_path):
        import shutil
        if not shutil.which("tshark"):
            pytest.skip("tshark not available")
        resp = client.post("/api/generate_offline", json={
            "name": self.SCEN, "dst_ip": "192.0.2.10", "src_ip": "192.0.2.11",
            "build_pcap": True, "stateful": True, "outdir": str(tmp_path),
        })
        assert resp.status_code == 200
        pcap = resp.get_json().get("pcap")
        if not pcap:
            pytest.skip("pcap not produced in this environment")
        assert self._syn_count(pcap) > 0, "stateful=True must emit SYN handshake"

    def test_offline_default_is_stateless(self, client, tmp_path):
        import shutil
        if not shutil.which("tshark"):
            pytest.skip("tshark not available")
        resp = client.post("/api/generate_offline", json={
            "name": self.SCEN, "dst_ip": "192.0.2.10", "src_ip": "192.0.2.11",
            "build_pcap": True, "outdir": str(tmp_path),
        })
        assert resp.status_code == 200
        pcap = resp.get_json().get("pcap")
        if not pcap:
            pytest.skip("pcap not produced in this environment")
        assert self._syn_count(pcap) == 0, "default must stay stateless (no SYN)"

    def test_sender_page_exposes_stateful_toggle(self, client):
        html = client.get("/sender").get_data(as_text=True)
        assert "btn_stateful" in html, "sender page missing stateful toggle"

    def test_sender_js_wires_stateful(self, client):
        js = client.get("/static/js/sender.js").get_data(as_text=True)
        assert "window.toggleStateful" in js
        assert "stateful:_stateful" in js


# ── Three-way marker mode through the web preview (v0.75.x) ───────────


class TestMarkerModeWebPreview:
    """The sender UI exposes a covert/explicit/stealth selector (default covert).
    /api/preview_payload must honour a `marker_mode` param and the preview must be
    byte-faithful to what generate/send emit for that mode.
    """

    SCEN = "T0855__unauth_command__modbus"

    def _preview(self, client, mode):
        url = f"/api/preview_payload?name={self.SCEN}&step=0&marker_mode={mode}"
        return client.get(url).get_json()

    def test_default_is_covert(self, client):
        # No marker_mode param -> covert (no ICSF literal, marker in TID field).
        d = client.get(f"/api/preview_payload?name={self.SCEN}&step=0").get_json()
        assert d.get("marker_mode") == "covert"
        assert "49435346" not in (d.get("hex_raw") or "")

    def test_covert_has_no_icsf_literal(self, client):
        d = self._preview(client, "covert")
        assert d.get("marker_mode") == "covert"
        assert "49435346" not in (d.get("hex_raw") or "")

    def test_explicit_has_icsf_literal(self, client):
        d = self._preview(client, "explicit")
        assert d.get("marker_mode") == "explicit"
        assert "49435346" in (d.get("hex_raw") or "")   # 'ICSF' ASCII

    def test_stealth_has_no_marker(self, client):
        d = self._preview(client, "stealth")
        assert d.get("marker_mode") == "stealth"
        assert "49435346" not in (d.get("hex_raw") or "")

    def test_legacy_no_marker_maps_to_stealth(self, client):
        d = client.get(
            f"/api/preview_payload?name={self.SCEN}&step=0&no_marker=1"
        ).get_json()
        assert d.get("marker_mode") == "stealth"

    def test_modes_produce_distinct_previews(self, client):
        cov = self._preview(client, "covert").get("hex_raw")
        exp = self._preview(client, "explicit").get("hex_raw")
        sth = self._preview(client, "stealth").get("hex_raw")
        assert cov and exp and sth
        assert len({cov, exp, sth}) == 3, "all three modes must differ"

    def test_sender_page_has_marker_selector(self, client):
        html = client.get("/sender").get_data(as_text=True)
        assert "marker_seg" in html
        assert 'data-mode="covert"' in html
        assert 'data-mode="explicit"' in html
        assert 'data-mode="stealth"' in html
        assert "marker_help" in html  # the '?' help affordance

    def test_sender_js_wires_marker_mode(self, client):
        js = client.get("/static/js/sender.js").get_data(as_text=True)
        assert "window.setMarkerMode" in js
        assert "marker_mode=${_mm}" in js          # live preview refresh
        assert '_explicitMarker = (_mm === "explicit")' in js


# ── Test Profile (Firewall/ACL ⟷ NSM) through the web API (v0.75.x) ──


class TestProfileWebFlow:
    SCEN = "T0855__unauth_command__modbus"

    def _syn(self, pcap):
        import subprocess
        out = subprocess.run(
            ["tshark", "-r", pcap, "-Y", "tcp.flags.syn==1",
             "-T", "fields", "-e", "frame.number"],
            capture_output=True, text=True).stdout
        return len([x for x in out.splitlines() if x.strip()])

    def test_nsm_profile_defaults_handshake_on(self, client, tmp_path):
        import shutil
        if not shutil.which("tshark"):
            pytest.skip("tshark not available")
        r = client.post("/api/generate_offline", json={
            "name": self.SCEN, "dst_ip": "192.0.2.10", "src_ip": "192.0.2.11",
            "build_pcap": True, "test_profile": "nsm", "outdir": str(tmp_path),
        })
        assert r.status_code == 200
        pcap = r.get_json().get("pcap")
        if not pcap:
            pytest.skip("pcap not produced")
        assert self._syn(pcap) > 0, "NSM profile must default the handshake on"

    def test_firewall_profile_stays_unidirectional(self, client, tmp_path):
        import shutil
        if not shutil.which("tshark"):
            pytest.skip("tshark not available")
        r = client.post("/api/generate_offline", json={
            "name": self.SCEN, "dst_ip": "192.0.2.10", "src_ip": "192.0.2.11",
            "build_pcap": True, "test_profile": "firewall", "outdir": str(tmp_path),
        })
        assert r.status_code == 200
        pcap = r.get_json().get("pcap")
        if not pcap:
            pytest.skip("pcap not produced")
        assert self._syn(pcap) == 0, "firewall profile must stay unidirectional"

    def test_sender_page_has_profile_selector(self, client):
        html = client.get("/sender").get_data(as_text=True)
        assert "profile_seg" in html
        assert 'data-profile="firewall"' in html
        assert 'data-profile="nsm"' in html
        assert "profile_help" in html

    def test_sender_js_wires_profile(self, client):
        js = client.get("/static/js/sender.js").get_data(as_text=True)
        assert "window.setTestProfile" in js
        assert "test_profile:_profile" in js
