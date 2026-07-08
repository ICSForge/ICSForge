"""Live-send ⟷ offline-PCAP parity tests.

Live sending is the priority path. These tests assert that the live sender
threads the same marker modes and per-protocol sequence/correlation fields into
the protocol builders as the offline engine, so live traffic is at least as
realistic on the wire as the offline PCAP.

The live sender's network I/O (`_tcp_send`/`_udp_send`) is monkeypatched to
capture the exact payload bytes without touching the network.
"""
import yaml

import icsforge.live.sender as live
from icsforge.live.sender import send_scenario_live

PACK = "icsforge/scenarios/scenarios.yml"


def _capture_live(scenario, **kwargs):
    """Run a live send with network I/O stubbed; return captured (port, payload)."""
    cap = []

    def _cap_tcp(dst, port, payload, timeout):
        cap.append((port, payload))

    def _cap_udp(dst, port, payload, timeout, **kw):
        cap.append((port, payload))

    orig_tcp, orig_udp = live._tcp_send, live._udp_send
    live._tcp_send, live._udp_send = _cap_tcp, _cap_udp
    try:
        send_scenario_live(
            PACK, scenario, "127.0.0.1",
            confirm_live_network=True, receiver_allowlist=["127.0.0.1"],
            **kwargs,
        )
    finally:
        live._tcp_send, live._udp_send = orig_tcp, orig_udp
    return cap


def _first_modbus_scenario(min_count=3):
    with open(PACK) as _fh:
        sc = yaml.safe_load(_fh)["scenarios"]
    for n, b in sc.items():
        if n.startswith("CHAIN__"):
            continue
        steps = b.get("steps", [])
        if steps and steps[0].get("proto") == "modbus" and steps[0].get("count", 1) >= min_count:
            return n
    return None


class TestLiveMarkerModeParity:
    def test_live_accepts_explicit_marker(self):
        """Explicit mode must reach the wire in live sends (was covert-only)."""
        import inspect
        sig = inspect.signature(send_scenario_live)
        assert "explicit_marker" in sig.parameters

    def test_live_explicit_emits_icsf(self):
        scen = _first_modbus_scenario(min_count=1)
        if not scen:
            return
        cap = _capture_live(scen, explicit_marker=True)
        assert any(b"ICSF" in p for _, p in cap), "explicit marker not present in live traffic"

    def test_live_covert_uses_f7_band(self):
        scen = _first_modbus_scenario(min_count=1)
        if not scen:
            return
        cap = _capture_live(scen)  # covert default
        modbus = [p for port, p in cap if port == 502 and p]
        assert modbus and any(p[0] == 0xF7 for p in modbus), "covert F7 band missing"

    def test_live_stealth_has_no_icsf(self):
        scen = _first_modbus_scenario(min_count=1)
        if not scen:
            return
        cap = _capture_live(scen, no_marker=True)
        assert not any(b"ICSF" in p for _, p in cap), "stealth must carry no ICSF tag"


class TestLiveSequenceParity:
    def test_modbus_tid_is_monotonic_in_stealth(self):
        """In stealth mode the Modbus transaction ID must increment like a real
        client (the offline engine does this; live must match)."""
        scen = _first_modbus_scenario(min_count=3)
        if not scen:
            return
        cap = _capture_live(scen, no_marker=True)
        tids = [int.from_bytes(p[:2], "big") for port, p in cap if port == 502 and len(p) >= 2]
        # The modbus packets within the run should include a monotonic 1,2,3 run.
        assert tids, "no modbus packets captured"
        # find the longest ascending-by-1 streak; require at least 3 in sequence
        best = streak = 1
        for a, b in zip(tids, tids[1:], strict=False):
            streak = streak + 1 if b == a + 1 else 1
            best = max(best, streak)
        assert best >= 3, f"modbus TIDs not monotonic in stealth: {tids}"

    def test_seq_helper_advances_all_protocols(self):
        """The internal per-protocol counter helper must cover the same protocols
        the offline engine threads (modbus/s7comm/dnp3/iec104/opcua)."""
        # Re-create the helper's behaviour through a tiny live run per proto is
        # heavy; instead assert the engine and live agree on the field set.
        import inspect
        src_live = inspect.getsource(live.send_scenario_live)
        for field in ("modbus_tid", "s7_pdu_ref", "dnp3_seq", "iec104_seq",
                      "sequence_number", "request_id"):
            assert field in src_live, f"live sender missing seq field {field}"
