"""
Tests for ICSForge web API endpoints.

Covers:
  - /api/correlate_run (was broken by missing time import)
  - /api/detections/preview and /api/detections/download
  - /api/scenarios, /api/health
  - Route audit: verify README-documented endpoints exist
  - Verify all @web.route decorators resolve without import errors
"""
import json
import os
import sys
import tempfile

import pytest


# Ensure the project root is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def app():
    """Create a Flask test app with all routes registered."""
    os.environ["ICSFORGE_UI_MODE"] = "sender"
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
        "/soc",
        "/tools",
        "/api/technique/variants",
        "/api/interfaces",
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
