"""
Markerless attribution tests (v0.64.7).

Closes the IEC-104 / stealth-mode confirmation gap: when a scenario emits
no ICSFORGE_SYNTH marker (because IEC-104 framing forbids trailing bytes,
or because --no-marker was passed), the receiver still attributes traffic
to a run via a pre-announced expectation.
"""
import hashlib
import hmac
import json
import os
import time

import pytest


@pytest.fixture(autouse=True)
def reset_expectations():
    """Each test starts with an empty registry."""
    from icsforge.receiver import receiver as r
    with r._expect_lock:
        r._expectations.clear()
    yield
    with r._expect_lock:
        r._expectations.clear()


@pytest.fixture
def client():
    os.environ["ICSFORGE_NO_AUTH"] = "1"
    from icsforge.web.app import create_app
    return create_app().test_client()


# ── Core registry semantics ──────────────────────────────────────────


class TestExpectationRegistry:

    def test_register_returns_entry(self):
        from icsforge.receiver.receiver import register_expectation
        entry = register_expectation(
            "run_a", scenario="S", technique="T0855",
            steps=2, ttl_sec=60.0, protos=["iec104"],
        )
        assert entry["run_id"] == "run_a"
        assert entry["technique"] == "T0855"
        assert entry["protos"] == ["iec104"]
        assert entry["received"] == 0

    def test_register_with_empty_run_id_is_noop(self):
        from icsforge.receiver.receiver import list_expectations, register_expectation
        result = register_expectation("", scenario="S")
        assert result == {}
        assert list_expectations() == []

    def test_register_replaces_existing_run(self):
        from icsforge.receiver.receiver import list_expectations, register_expectation
        register_expectation("dup", scenario="A", technique="T0801", ttl_sec=60.0)
        register_expectation("dup", scenario="B", technique="T0855", ttl_sec=60.0)
        items = list_expectations()
        assert len(items) == 1
        assert items[0]["scenario"] == "B"
        assert items[0]["technique"] == "T0855"

    def test_clear_expectation(self):
        from icsforge.receiver.receiver import clear_expectation, list_expectations, register_expectation
        register_expectation("to_clear", scenario="S", ttl_sec=60.0)
        assert clear_expectation("to_clear") is True
        assert clear_expectation("to_clear") is False
        assert list_expectations() == []

    def test_expired_entries_pruned_on_list(self):
        from icsforge.receiver.receiver import list_expectations, register_expectation
        # The implementation clamps TTL to >= 1 second, so use 1.0 and sleep just past it
        register_expectation("ephemeral", scenario="S", ttl_sec=1.0)
        time.sleep(1.1)
        assert list_expectations() == []


# ── Marker-vs-expectation precedence ─────────────────────────────────


class TestMarkerPrecedence:

    def test_marker_wins_over_expectation(self):
        from icsforge.protocols.covert_marker import explicit_marker
        from icsforge.receiver.receiver import _parse_marker, register_expectation
        register_expectation("expect_run", scenario="A", technique="T0801",
                             protos=["modbus"])
        # v0.74.0: an explicit compact 'ICSF' marker in the payload is the
        # most-specific path and must win over the expectation fallback. The
        # inline run_id is no longer carried verbatim; the marker yields a
        # run_hash + proto_code, and attribution is 'marker'.
        em = explicit_marker("real_xyz", "modbus")   # 'ICSF' + 'M' + 8 hex
        payload = b"junk" + em
        meta = _parse_marker(payload, proto="modbus")
        assert meta["marker_found"] is True
        assert meta["attributed_via"] == "marker"
        assert meta["proto_code"] == "M"
        assert meta["run_hash"] == em[5:13].decode("ascii")

    def test_no_marker_no_expectation_returns_none(self):
        from icsforge.receiver.receiver import _parse_marker
        meta = _parse_marker(b"random bytes", proto="iec104")
        assert meta["marker_found"] is False
        assert meta["attributed_via"] == "none"

    def test_no_marker_with_expectation_attributes(self):
        from icsforge.receiver.receiver import _parse_marker, register_expectation
        register_expectation(
            "iec104_run_001",
            scenario="T0855__unauth_command__iec104",
            technique="T0855",
            protos=["iec104"],
        )
        # IEC-104 STARTDT_act U-frame — no payload, no marker
        meta = _parse_marker(b"\x68\x04\x07\x00\x00\x00", proto="iec104")
        assert meta["marker_found"] is False
        assert meta["run_id"] == "iec104_run_001"
        assert meta["technique"] == "T0855"
        assert meta["attributed_via"] == "expectation"

    def test_proto_mismatch_does_not_attribute(self):
        from icsforge.receiver.receiver import _parse_marker, register_expectation
        register_expectation("only_iec104", scenario="S", technique="T0855",
                             protos=["iec104"])
        meta = _parse_marker(b"some modbus bytes", proto="modbus")
        assert meta["marker_found"] is False
        assert meta["attributed_via"] == "none"

    def test_no_protos_attribute_any_proto(self):
        """When expectation has protos=None, any proto matches."""
        from icsforge.receiver.receiver import _parse_marker, register_expectation
        register_expectation("any_proto", scenario="S", technique="T0855",
                             protos=None)
        for proto in ("iec104", "modbus", "dnp3", None):
            meta = _parse_marker(b"x", proto=proto)
            assert meta["attributed_via"] == "expectation", f"failed for proto={proto}"
            assert meta["run_id"] == "any_proto"

    def test_received_counter_increments(self):
        from icsforge.receiver.receiver import _parse_marker, list_expectations, register_expectation
        register_expectation("counter_test", scenario="S", technique="T",
                             protos=["iec104"])
        for _ in range(5):
            _parse_marker(b"\x68\x04\x07\x00\x00\x00", proto="iec104")
        items = list_expectations()
        assert len(items) == 1
        assert items[0]["received"] == 5


# ── HTTP endpoints ───────────────────────────────────────────────────


def _signed_post(client, url, body_dict):
    """POST with HMAC signature using the in-memory callback token."""
    import icsforge.web.helpers as _h
    body = json.dumps(body_dict, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if _h._callback_token:
        headers["X-ICSForge-Callback-Token"] = _h._callback_token
        headers["X-ICSForge-HMAC"] = hmac.new(
            _h._callback_token.encode("utf-8"), body, hashlib.sha256
        ).hexdigest()
    return client.post(url, data=body, headers=headers)


class TestExpectationEndpoints:

    def test_post_expect_registers(self, client):
        resp = _signed_post(client, "/api/receiver/expect", {
            "run_id": "http_001",
            "scenario": "T0855__unauth_command__iec104",
            "technique": "T0855",
            "steps": 3,
            "ttl_sec": 60.0,
            "protos": ["iec104"],
        })
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert body["expectation"]["run_id"] == "http_001"
        assert body["expectation"]["technique"] == "T0855"

    def test_post_expect_requires_run_id(self, client):
        resp = _signed_post(client, "/api/receiver/expect", {"scenario": "S"})
        assert resp.status_code == 400

    def test_post_expect_rejects_missing_token(self, client):
        import icsforge.web.helpers as _h
        if not _h._callback_token:
            pytest.skip("no token configured in this env")
        body = json.dumps({"run_id": "x"}).encode("utf-8")
        resp = client.post("/api/receiver/expect", data=body,
                           content_type="application/json")
        assert resp.status_code == 401

    def test_post_expect_rejects_bad_hmac(self, client):
        import icsforge.web.helpers as _h
        if not _h._callback_token:
            pytest.skip("no token configured")
        body = json.dumps({"run_id": "y"}).encode("utf-8")
        resp = client.post("/api/receiver/expect", data=body,
                           content_type="application/json",
                           headers={
                               "X-ICSForge-Callback-Token": _h._callback_token,
                               "X-ICSForge-HMAC": "0" * 64,
                           })
        assert resp.status_code == 401

    def test_get_expectations_lists_active(self, client):
        _signed_post(client, "/api/receiver/expect", {
            "run_id": "list_test", "scenario": "S",
            "technique": "T0855", "ttl_sec": 60.0,
        })
        resp = client.get("/api/receiver/expectations")
        assert resp.status_code == 200
        body = resp.get_json()
        runs = [e["run_id"] for e in body.get("expectations", [])]
        assert "list_test" in runs


# ── Integration: announce_expectation helper ────────────────────────


class TestAnnounceHelper:

    def test_announce_with_no_receiver_configured_returns_empty(self):
        """Helper should be safe-no-op when receiver isn't configured."""
        import icsforge.web.helpers as _h
        from icsforge.web.helpers import announce_expectation
        saved = _h._receiver_ip
        _h._receiver_ip = None
        try:
            result = announce_expectation("test_run", scenario="S")
            assert result == {}
        finally:
            _h._receiver_ip = saved
