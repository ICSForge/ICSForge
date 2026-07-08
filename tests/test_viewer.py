"""
Tests for the alert viewer (port 3000 in the demo stack).

Covers the v0.62.1 fixes:
  - Tailer ingests history from start of file (not seek-to-end)
  - /api/health surfaces actionable diagnostics
  - /api/alerts returns buffered alerts so dashboard backfills on reload
  - Tier classification is correct for lab_marker/heuristic/semantic/unknown
  - Non-alert EVE events are skipped without breaking the parser
"""
import json
import os
import socket
import tempfile
import threading
import time
import wsgiref.simple_server
from urllib.request import urlopen

import pytest


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _start_viewer(eve_path: str):
    """Start a viewer instance pointed at eve_path; return (port, shutdown_fn)."""
    import icsforge.viewer as v
    v.EVE_PATH = eve_path
    v.POLL_INTERVAL = 0.05
    app = v.create_app()
    port = _free_port()
    server = wsgiref.simple_server.make_server("127.0.0.1", port, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return port, server.shutdown


def _get(port: int, path: str) -> dict:
    return json.loads(urlopen(f"http://127.0.0.1:{port}{path}", timeout=5).read())


def _alert(ts: str, sid: int, sig: str, dst_port: int = 502) -> dict:
    return {
        "event_type": "alert",
        "timestamp": ts,
        "src_ip": "192.0.2.11", "src_port": 49152,
        "dest_ip": "192.0.2.10", "dest_port": dst_port,
        "proto": "TCP", "app_proto": "modbus",
        "alert": {"signature_id": sid, "signature": sig},
    }


@pytest.fixture
def eve_with_history():
    """Pre-populated EVE file that exists before the viewer starts."""
    td = tempfile.mkdtemp(prefix="icsforge-viewer-test-")
    path = os.path.join(td, "eve.json")
    lines = [
        {"event_type": "stats", "stats": {}},  # noise — must be skipped
        _alert("2026-01-01T00:00:00.000Z", 5000001,
               "[T0855] ICSForge semantic modbus write_single_register"),
        _alert("2026-01-01T00:00:01.000Z", 5000002,
               "[T0855] ICSForge heuristic modbus"),
        _alert("2026-01-01T00:00:02.000Z", 5000003,
               "[T0855] ICSForge lab_marker modbus T0855_unauth"),
        _alert("2026-01-01T00:00:03.000Z", 5000004,
               "[T0800] ICSForge semantic s7comm cpu_stop", dst_port=102),
        {"event_type": "flow"},  # noise — must be skipped
        _alert("2026-01-01T00:00:04.000Z", 5000005,
               "Suricata default rule"),  # no [Txxxx] -> unknown technique/tier
    ]
    with open(path, "w") as f:
        for line in lines:
            f.write(json.dumps(line) + "\n")
    yield path
    # cleanup deferred to OS tmp


class TestViewerIngestsHistory:
    """v0.62.1: tailer must read existing alerts from the start of file,
    otherwise users running scenarios before opening the dashboard see
    'Waiting for alerts…' forever."""

    def test_buffered_count_matches_alerts_in_file(self, eve_with_history):
        port, shutdown = _start_viewer(eve_with_history)
        try:
            time.sleep(1.0)  # let tailer ingest
            health = _get(port, "/api/health")
            assert health["eve_exists"] is True
            assert health["status"] == "tailing"
            assert health["buffered"] == 5, (
                f"expected 5 alerts buffered (file had 5 alert events), "
                f"got {health['buffered']}; this means the tailer is "
                f"seeking-to-end instead of reading history"
            )
            assert health["lines_read"] == 7
            assert health["lines_skipped_non_alert"] == 2
        finally:
            shutdown()

    def test_api_alerts_returns_history(self, eve_with_history):
        port, shutdown = _start_viewer(eve_with_history)
        try:
            time.sleep(1.0)
            data = _get(port, "/api/alerts?limit=100")
            assert data["count"] == 5
            assert len(data["alerts"]) == 5
        finally:
            shutdown()


class TestViewerTierClassification:
    """v0.62.1: dashboard colour-codes by tier, so misclassification breaks
    the visual signal even when alerts are flowing."""

    def test_all_three_tiers_plus_unknown(self, eve_with_history):
        port, shutdown = _start_viewer(eve_with_history)
        try:
            time.sleep(1.0)
            stats = _get(port, "/api/stats")
            assert stats["by_tier"].get("semantic") == 2
            assert stats["by_tier"].get("heuristic") == 1
            assert stats["by_tier"].get("lab") == 1
            assert stats["by_tier"].get("unknown") == 1
        finally:
            shutdown()

    def test_technique_id_extraction(self, eve_with_history):
        port, shutdown = _start_viewer(eve_with_history)
        try:
            time.sleep(1.0)
            stats = _get(port, "/api/stats")
            assert stats["by_technique"].get("T0855") == 3
            assert stats["by_technique"].get("T0800") == 1
            assert stats["by_technique"].get("unknown") == 1
        finally:
            shutdown()


class TestViewerDiagnostics:
    """v0.62.1: when no alerts show up, /api/health must explain why
    instead of saying 'status: ok' silently."""

    def test_missing_eve_file_health_hint(self):
        # Point at a path that doesn't exist
        td = tempfile.mkdtemp(prefix="icsforge-viewer-missing-")
        bogus = os.path.join(td, "does-not-exist.json")
        port, shutdown = _start_viewer(bogus)
        try:
            time.sleep(1.0)
            health = _get(port, "/api/health")
            assert health["eve_exists"] is False
            assert health["hint"] is not None
            assert "EVE file does not exist" in health["hint"]
        finally:
            shutdown()

    def test_health_reports_lines_read_counter(self, eve_with_history):
        port, shutdown = _start_viewer(eve_with_history)
        try:
            time.sleep(1.0)
            health = _get(port, "/api/health")
            assert "lines_read" in health
            assert "lines_skipped_non_alert" in health
            assert "ingest_history" in health
            assert health["ingest_history"] is True
        finally:
            shutdown()


class TestViewerCli:
    """v0.62.1: `icsforge viewer replay foo.pcap` must exist for users without
    the docker stack."""

    def test_replay_subcommand_parses(self):
        from icsforge.cli import build_parser
        p = build_parser()
        args = p.parse_args(["viewer", "replay", "/tmp/x.pcap"])
        assert args.cmd == "viewer"
        assert args.viewer_cmd == "replay"
        assert args.pcaps == ["/tmp/x.pcap"]
        assert args.func.__name__ == "cmd_viewer_replay"

    def test_default_viewer_still_works(self):
        from icsforge.cli import build_parser
        p = build_parser()
        args = p.parse_args(["viewer"])
        assert args.cmd == "viewer"
        assert args.func.__name__ == "cmd_viewer"

    def test_serve_subcommand(self):
        from icsforge.cli import build_parser
        p = build_parser()
        args = p.parse_args(["viewer", "serve", "--port", "3001"])
        assert args.viewer_cmd == "serve"
        assert args.port == 3001
        assert args.func.__name__ == "cmd_viewer"
