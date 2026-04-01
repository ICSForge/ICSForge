"""Tests for ICSForge authentication — setup, login, logout, public paths, rate limiting.

Covers:
  - Setup flow (first-run credential creation)
  - Login/logout
  - Protected routes return 401 when unauthenticated
  - Public paths exempt from auth
  - /api/config/set_callback is auth-exempt (regression: was missing in v0.47)
  - Input validation on setup and login
"""
import json
import os
import sys
import tempfile

import pytest


@pytest.fixture(autouse=True)
def reset_rate_limits():
    """Reset rate limiter state before every auth test to prevent cross-test pollution."""
    from icsforge.auth import _reset_rate_limit
    _reset_rate_limit()
    yield
    _reset_rate_limit()


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def auth_app(tmp_path):
    """Flask app with auth ENABLED and a fresh credential file."""
    cred_file = str(tmp_path / "credentials.json")
    os.environ["ICSFORGE_UI_MODE"] = "sender"
    os.environ.pop("ICSFORGE_NO_AUTH", None)
    os.environ["ICSFORGE_CRED_FILE"] = cred_file
    from icsforge.web.app import create_app
    application = create_app()
    application.config["TESTING"] = True
    application.config["SECRET_KEY"] = "test-secret"
    return application


@pytest.fixture
def auth_client(auth_app):
    return auth_app.test_client()


@pytest.fixture
def authed_client(auth_app, tmp_path):
    """Client that has already completed setup and logged in."""
    client = auth_app.test_client()
    # Setup
    client.post("/api/auth/setup", json={"username": "admin", "password": "testpass123"})
    # Login
    client.post("/api/auth/login", json={"username": "admin", "password": "testpass123"})
    return client


# ── Setup flow ────────────────────────────────────────────────────────

class TestAuthSetup:
    def test_setup_creates_credentials(self, auth_client):
        resp = auth_client.post("/api/auth/setup",
                                json={"username": "admin", "password": "secret123"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data.get("ok") is True
        assert data.get("username") == "admin"

    def test_setup_rejects_short_password(self, auth_client):
        resp = auth_client.post("/api/auth/setup",
                                json={"username": "admin", "password": "abc"})
        assert resp.status_code == 400
        assert "error" in resp.get_json()

    def test_setup_rejects_short_username(self, auth_client):
        resp = auth_client.post("/api/auth/setup",
                                json={"username": "a", "password": "secret123"})
        assert resp.status_code == 400

    def test_setup_cannot_run_twice(self, auth_client):
        auth_client.post("/api/auth/setup",
                         json={"username": "admin", "password": "secret123"})
        resp = auth_client.post("/api/auth/setup",
                                json={"username": "admin2", "password": "secret456"})
        assert resp.status_code == 400


# ── Login / logout ────────────────────────────────────────────────────

class TestAuthLogin:
    def test_valid_login(self, auth_client):
        auth_client.post("/api/auth/setup",
                         json={"username": "admin", "password": "secret123"})
        resp = auth_client.post("/api/auth/login",
                                json={"username": "admin", "password": "secret123"})
        assert resp.status_code == 200
        assert resp.get_json().get("ok") is True

    def test_wrong_password_returns_401(self, auth_client):
        auth_client.post("/api/auth/setup",
                         json={"username": "admin", "password": "secret123"})
        resp = auth_client.post("/api/auth/login",
                                json={"username": "admin", "password": "wrongpass"})
        assert resp.status_code == 401

    def test_unknown_user_returns_401(self, auth_client):
        auth_client.post("/api/auth/setup",
                         json={"username": "admin", "password": "secret123"})
        resp = auth_client.post("/api/auth/login",
                                json={"username": "ghost", "password": "secret123"})
        assert resp.status_code == 401

    def test_logout_clears_session(self, authed_client):
        # Should be able to access a protected route before logout
        resp1 = authed_client.get("/api/runs")
        assert resp1.status_code == 200
        # Logout
        authed_client.post("/api/auth/logout")
        # Now a protected route should 401
        resp2 = authed_client.get("/api/runs")
        assert resp2.status_code == 401


# ── Protected routes ──────────────────────────────────────────────────

class TestAuthProtection:
    def test_unauthenticated_api_returns_401(self, auth_client):
        """After setup, un-authed requests to protected APIs get 401."""
        auth_client.post("/api/auth/setup",
                         json={"username": "admin", "password": "secret123"})
        protected = ["/api/runs", "/api/scenarios", "/api/packs"]
        for path in protected:
            resp = auth_client.get(path)
            assert resp.status_code == 401, f"{path} should be 401, got {resp.status_code}"

    def test_authenticated_api_returns_200(self, authed_client):
        resp = authed_client.get("/api/runs")
        assert resp.status_code == 200

    def test_health_is_public(self, auth_client):
        """Health endpoint must be accessible without credentials."""
        auth_client.post("/api/auth/setup",
                         json={"username": "admin", "password": "secret123"})
        resp = auth_client.get("/api/health")
        assert resp.status_code == 200

    def test_receiver_callback_is_public(self, auth_client):
        """Receiver callback must be reachable without auth (cross-host POST)."""
        auth_client.post("/api/auth/setup",
                         json={"username": "admin", "password": "secret123"})
        resp = auth_client.post("/api/receiver/callback",
                                json={"marker_found": False, "run_id": "test"})
        assert resp.status_code != 401

    def test_set_callback_is_public(self, auth_client):
        """Regression: /api/config/set_callback was missing from PUBLIC_PATHS in v0.47."""
        auth_client.post("/api/auth/setup",
                         json={"username": "admin", "password": "secret123"})
        resp = auth_client.post("/api/config/set_callback",
                                json={"callback_url": "http://127.0.0.1:8080/api/receiver/callback"})
        assert resp.status_code != 401, (
            "/api/config/set_callback must be auth-exempt — "
            "sender pushes this before authentication context exists"
        )

    def test_static_files_are_public(self, auth_client):
        """Static assets must be accessible without auth."""
        auth_client.post("/api/auth/setup",
                         json={"username": "admin", "password": "secret123"})
        resp = auth_client.get("/static/css/main.css")
        assert resp.status_code != 401


# ── Rate limiting ─────────────────────────────────────────────────────

class TestAuthRateLimit:
    def test_rate_limit_triggers_after_5_failures(self, auth_client):
        """After 5 failed login attempts from same IP, 429 is returned."""
        auth_client.post("/api/auth/setup",
                         json={"username": "admin", "password": "secret123"})
        # 5 wrong attempts
        for _ in range(5):
            resp = auth_client.post("/api/auth/login",
                                    json={"username": "admin", "password": "wrong"})
            assert resp.status_code == 401
        # 6th attempt should be rate-limited
        resp = auth_client.post("/api/auth/login",
                                json={"username": "admin", "password": "wrong"})
        assert resp.status_code == 429

    def test_correct_login_clears_rate_limit(self, auth_client):
        """Successful login resets the failed attempt counter."""
        auth_client.post("/api/auth/setup",
                         json={"username": "admin", "password": "secret123"})
        # 3 wrong attempts
        for _ in range(3):
            auth_client.post("/api/auth/login",
                             json={"username": "admin", "password": "wrong"})
        # Correct login should succeed
        resp = auth_client.post("/api/auth/login",
                                json={"username": "admin", "password": "secret123"})
        assert resp.status_code == 200
        assert resp.get_json().get("ok") is True
