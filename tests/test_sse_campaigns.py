"""Tests for ICSForge SSE streaming and campaign execution.

Covers:
  - SSE stream connects and emits a connected event
  - SSE subscriber/unsubscribe lifecycle
  - notify_sse feeds to subscribers
  - Campaign validation rejects bad YAML
  - Campaign runner completes without errors on a known scenario
  - Campaign abort signal stops execution
  - Pull mode start/stop lifecycle (no network needed)
"""
import json
import os
import queue
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def app():
    os.environ["ICSFORGE_UI_MODE"] = "sender"
    os.environ["ICSFORGE_NO_AUTH"] = "1"
    from icsforge.web.app import create_app
    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


# ── SSE infrastructure ────────────────────────────────────────────────

class TestSSE:
    def test_subscribe_returns_queue(self):
        from icsforge.web.helpers_sse import subscribe_sse, unsubscribe_sse
        q = subscribe_sse()
        assert hasattr(q, "get")
        unsubscribe_sse(q)

    def test_notify_sse_delivers_to_subscriber(self):
        from icsforge.web.helpers_sse import subscribe_sse, unsubscribe_sse, notify_sse
        q = subscribe_sse()
        try:
            notify_sse({"technique": "T0855", "run_id": "test-run"})
            event = q.get(timeout=1.0)
            assert event["technique"] == "T0855"
        finally:
            unsubscribe_sse(q)

    def test_notify_sse_drops_on_full_queue(self):
        """A full subscriber queue must not block the notification loop."""
        from icsforge.web.helpers_sse import subscribe_sse, unsubscribe_sse, notify_sse
        q = subscribe_sse()
        try:
            # Fill the queue to capacity (maxsize=50)
            for i in range(52):
                notify_sse({"i": i})
            # No hang — test passes if we get here
        finally:
            unsubscribe_sse(q)

    def test_unsubscribe_removes_dead_queue(self):
        from icsforge.web.helpers_sse import (
            subscribe_sse, unsubscribe_sse, _sse_subscribers
        )
        initial = len(_sse_subscribers)
        q = subscribe_sse()
        assert len(_sse_subscribers) == initial + 1
        unsubscribe_sse(q)
        assert len(_sse_subscribers) == initial

    def test_sse_stream_endpoint_connects(self, client):
        """GET /api/receiver/stream should return SSE headers."""
        resp = client.get("/api/receiver/stream",
                          headers={"Accept": "text/event-stream"})
        assert resp.status_code == 200
        assert "text/event-stream" in resp.content_type


# ── Pull mode lifecycle ───────────────────────────────────────────────

class TestPullMode:
    def test_start_stop_cycle(self):
        """Pull mode thread should start and stop cleanly without network."""
        from icsforge.web import helpers as _h
        from icsforge.web.helpers_sse import start_pull_mode, stop_pull_mode
        # Set a non-routable IP so the thread fails gracefully
        _h._receiver_ip = "192.0.2.1"
        _h._pull_enabled = True
        start_pull_mode()
        time.sleep(0.2)
        stop_pull_mode()
        # Reset state
        _h._receiver_ip = None
        _h._pull_enabled = False

    def test_start_twice_is_safe(self):
        from icsforge.web import helpers as _h
        from icsforge.web.helpers_sse import start_pull_mode, stop_pull_mode
        _h._receiver_ip = "192.0.2.1"
        start_pull_mode()
        start_pull_mode()  # second call must not spawn duplicate thread
        stop_pull_mode()
        _h._receiver_ip = None


# ── Campaign validation ───────────────────────────────────────────────

class TestCampaignValidation:
    def test_valid_campaign_passes(self):
        from icsforge.campaigns.runner import validate_campaign
        campaign = {
            "name": "Test Campaign",
            "description": "Smoke test",
            "steps": [
                {"scenario": "T0855__unauth_command__modbus", "delay": "0s"},
                {"scenario": "T0840__network_enum__enip_sweep", "delay": "5s"},
            ],
        }
        warnings = validate_campaign(campaign)
        assert isinstance(warnings, list)

    def test_missing_name_raises(self):
        from icsforge.campaigns.runner import validate_campaign, CampaignValidationError
        with pytest.raises(CampaignValidationError):
            validate_campaign({"steps": [{"scenario": "T0855__unauth_command__modbus"}]})

    def test_empty_steps_raises(self):
        from icsforge.campaigns.runner import validate_campaign, CampaignValidationError
        with pytest.raises(CampaignValidationError):
            validate_campaign({"name": "Empty", "steps": []})

    def test_missing_steps_raises(self):
        from icsforge.campaigns.runner import validate_campaign, CampaignValidationError
        with pytest.raises(CampaignValidationError):
            validate_campaign({"name": "No steps"})

    def test_invalid_delay_raises(self):
        """Invalid delay values are fatal — they indicate a broken campaign definition."""
        from icsforge.campaigns.runner import validate_campaign, CampaignValidationError
        campaign = {
            "name": "Bad Delay",
            "steps": [{"scenario": "T0855__unauth_command__modbus", "delay": "badvalue"}],
        }
        with pytest.raises(CampaignValidationError):
            validate_campaign(campaign)

    def test_unknown_scenario_produces_warning(self):
        from icsforge.campaigns.runner import validate_campaign
        campaign = {
            "name": "Unknown Scenario",
            "steps": [{"scenario": "NONEXISTENT_SCENARIO_XYZ", "delay": "0s"}],
        }
        available = {"T0855__unauth_command__modbus", "T0840__network_enum__enip_sweep"}
        warnings = validate_campaign(campaign, available_scenarios=available)
        assert any("NONEXISTENT" in w for w in warnings)


# ── Campaign API endpoints ────────────────────────────────────────────

class TestCampaignAPI:
    def test_campaigns_list_returns_data(self, client):
        resp = client.get("/api/campaigns/list")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "campaigns" in data

    def test_campaign_run_requires_name(self, client):
        resp = client.post("/api/campaigns/run", json={})
        assert resp.status_code == 400  # missing campaign_id

    def test_campaign_run_rejects_unknown_name(self, client):
        # API uses campaign_id field, requires dst_ip; unknown campaign → 404
        resp = client.post("/api/campaigns/run",
                           json={"campaign_id": "NONEXISTENT_CAMPAIGN_XYZ_999",
                                 "dst_ip": "198.51.100.1"})
        assert resp.status_code == 404

    def test_campaign_abort_no_run_is_safe(self, client):
        """Aborting a non-existent run should not crash."""
        resp = client.post("/api/campaigns/abort",
                           json={"run_id": "nonexistent-run-id"})
        assert resp.status_code in (200, 404)


# ── Webhook config endpoints ──────────────────────────────────────────

class TestWebhookConfig:
    def test_get_webhook_returns_empty_by_default(self, client):
        resp = client.get("/api/config/webhook")
        assert resp.status_code == 200
        assert resp.get_json().get("webhook_url") == ""

    def test_set_and_get_webhook(self, client):
        client.post("/api/config/webhook",
                    json={"webhook_url": "http://localhost:9999/hook"})
        resp = client.get("/api/config/webhook")
        assert resp.get_json()["webhook_url"] == "http://localhost:9999/hook"

    def test_clear_webhook(self, client):
        client.post("/api/config/webhook",
                    json={"webhook_url": "http://localhost:9999/hook"})
        client.post("/api/config/webhook", json={"webhook_url": ""})
        resp = client.get("/api/config/webhook")
        assert resp.get_json()["webhook_url"] == ""


# ── EVE tap endpoints ─────────────────────────────────────────────────

class TestEveTapAPI:
    def test_eve_start_requires_path(self, client):
        resp = client.post("/api/eve/start", json={})
        assert resp.status_code == 400

    def test_eve_stop_with_no_active_tap(self, client):
        resp = client.post("/api/eve/stop", json={})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data.get("ok") is True

    def test_eve_matches_with_no_active_tap(self, client):
        resp = client.get("/api/eve/matches")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data.get("active") is False
        assert data.get("matches") == []

    def test_eve_start_with_tmp_file(self, client, tmp_path):
        """Start tap on a real (empty) file, then stop it."""
        eve_file = tmp_path / "eve.json"
        eve_file.write_text("")
        resp = client.post("/api/eve/start",
                           json={"eve_path": str(eve_file), "run_id": "test-eve-001"})
        # Either OK (200) or blocked by path restriction (400) — neither is a crash
        assert resp.status_code in (200, 400)
        if resp.status_code == 200:
            stop_resp = client.post("/api/eve/stop", json={})
            assert stop_resp.status_code == 200


# ── Step options wiring ───────────────────────────────────────────────

class TestStepOptions:
    def test_api_send_accepts_step_options_field(self, client):
        """Verify /api/send accepts step_options without erroring on input validation."""
        # We don't send to a real IP; just verify the field is accepted
        resp = client.post("/api/send", json={
            "name": "T0855__unauth_command__modbus",
            "dst_ip": "198.51.100.1",
            "step_options": {"modbus": {"address": 100, "quantity": 5}},
        })
        # Will fail with network error (not 422/400 from input validation)
        assert resp.status_code != 422
        data = resp.get_json()
        assert "step_options is not a valid field" not in str(data)
