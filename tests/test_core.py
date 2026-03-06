"""Tests for icsforge.core — utilities, PCAP writer, markers, safety checks."""
import os
import struct

import pytest

from icsforge.core import (

    is_allowed_dest,
    now_iso,
    parse_interval,
    write_pcap,
    build_marker,
    marker_prefix,
    generate_run_id,
    is_legacy_run_id,
    event_base,
)
from icsforge.protocols.common import tcp_packet


# ── IP allowlisting ──────────────────────────────────────────────────


class TestIsAllowedDest:
    def test_loopback(self):
        assert is_allowed_dest("127.0.0.1") is True
        assert is_allowed_dest("127.255.255.255") is True

    def test_test_nets(self):
        assert is_allowed_dest("192.0.2.1") is True
        assert is_allowed_dest("198.51.100.42") is True
        assert is_allowed_dest("203.0.113.99") is True

    def test_public_ip_blocked(self):
        assert is_allowed_dest("8.8.8.8") is False
        assert is_allowed_dest("1.1.1.1") is False
        assert is_allowed_dest("192.168.1.1") is False  # RFC1918 not in allowlist

    def test_invalid_ip(self):
        assert is_allowed_dest("not-an-ip") is False
        assert is_allowed_dest("") is False


# ── Interval parsing ─────────────────────────────────────────────────


class TestParseInterval:
    def test_milliseconds(self):
        assert parse_interval("100ms") == pytest.approx(0.1)
        assert parse_interval("500ms") == pytest.approx(0.5)

    def test_seconds(self):
        assert parse_interval("1s") == pytest.approx(1.0)
        assert parse_interval("2.5s") == pytest.approx(2.5)

    def test_minutes(self):
        assert parse_interval("1m") == pytest.approx(60.0)

    def test_hours(self):
        assert parse_interval("1h") == pytest.approx(3600.0)

    def test_zero(self):
        assert parse_interval("0s") == 0.0
        assert parse_interval("0") == 0.0

    def test_invalid(self):
        with pytest.raises(ValueError):
            parse_interval("5x")


# ── PCAP writer ──────────────────────────────────────────────────────


class TestWritePcap:
    def test_writes_valid_pcap(self, tmp_path):
        out = str(tmp_path / "test.pcap")
        pkt = tcp_packet("127.0.0.1", "127.0.0.1", 502, b"\x00\x01\x02\x03")
        n = write_pcap([pkt, pkt, pkt], out)
        assert n == 3
        assert os.path.exists(out)

        # Verify pcap global header
        with open(out, "rb") as f:
            magic = struct.unpack("<I", f.read(4))[0]
            assert magic == 0xA1B2C3D4

    def test_pcap_packet_timing_has_jitter(self, tmp_path):
        """v0.4: timestamps should not be uniformly spaced."""
        out = str(tmp_path / "jitter.pcap")
        pkts = [tcp_packet("127.0.0.1", "127.0.0.1", 502, b"\x00") for _ in range(10)]
        write_pcap(pkts, out)

        # Read timestamps from pcap
        timestamps = []
        with open(out, "rb") as f:
            f.read(24)  # skip global header
            for _ in range(10):
                ph = f.read(16)
                if len(ph) < 16:
                    break
                ts_sec, ts_usec, incl_len, _ = struct.unpack("<IIII", ph)
                timestamps.append(ts_sec + ts_usec / 1_000_000)
                f.read(incl_len)

        # Check that intervals between packets vary (not all identical)
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        unique_intervals = len(set(round(iv, 6) for iv in intervals))
        assert unique_intervals > 1, "PCAP timestamps should have jitter (not uniform spacing)"

    def test_empty_packet_list(self, tmp_path):
        out = str(tmp_path / "empty.pcap")
        n = write_pcap([], out)
        assert n == 0
        assert os.path.exists(out)


# ── Markers ──────────────────────────────────────────────────────────


class TestMarkers:
    def test_build_marker(self):
        m = build_marker("run-123", "T0855", "step1")
        assert m == b"ICSFORGE_SYNTH|run-123|T0855|step1"

    def test_build_marker_none(self):
        m = build_marker(None)
        assert b"offline" in m

    def test_marker_prefix(self):
        assert marker_prefix() == b"ICSFORGE_SYNTH|"


# ── Run ID ───────────────────────────────────────────────────────────


class TestRunId:
    def test_generate_run_id_format(self):
        rid = generate_run_id()
        parts = rid.split("-")
        # YYYY-MM-DD-NATO-NN → 5 parts
        assert len(parts) == 5
        assert len(parts[0]) == 4  # year
        assert len(parts[3]) >= 3  # NATO word

    def test_generate_run_id_unique(self):
        ids = {generate_run_id() for _ in range(20)}
        # With random NATO word + 00-99, collisions very unlikely
        assert len(ids) >= 15

    def test_legacy_run_id(self):
        assert is_legacy_run_id("7df649413e05") is True
        assert is_legacy_run_id("2026-03-05-BRAVO-07") is False
        assert is_legacy_run_id("") is False
        assert is_legacy_run_id(None) is False


# ── Event model ──────────────────────────────────────────────────────


class TestEventBase:
    def test_event_base_fields(self):
        ev = event_base("T0855", "pcap", scenario="test", proto="modbus")
        assert ev["mitre.ics.technique"] == "T0855"
        assert ev["event.source"] == "pcap"
        assert ev["icsforge.synthetic"] is True
        assert ev["icsforge.marker"] == "ICSFORGE_SYNTH"
        assert "@timestamp" in ev

    def test_now_iso(self):
        ts = now_iso()
        assert "T" in ts  # ISO format
        assert "+" in ts or "Z" in ts  # timezone-aware
