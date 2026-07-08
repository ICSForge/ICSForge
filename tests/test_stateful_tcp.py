"""Tests for the opt-in stateful TCP conversation feature (Phase A).

The default offline model is stateless (single PSH/ACK segments, no handshake).
With stateful=True / --stateful, each TCP step is wrapped in a real conversation:
SYN / SYN-ACK / ACK handshake, per-segment server ACKs, FIN/ACK teardown — so the
pcap survives stream reassembly and exercises stateful IDS engines.
"""
import struct

from icsforge.protocols.common import TCPFlow, tcp_packet, tcp_segment
from icsforge.scenarios.engine import run_scenario


def _parse_tcp(frame: bytes) -> dict:
    """Pull TCP fields out of a raw Ethernet+IP+TCP frame."""
    ip = frame[14:34]
    tcp = frame[34:54]
    sport, dport, seq, ack = struct.unpack(">HHII", tcp[:12])
    flags = tcp[13]
    return {
        "src": ".".join(str(b) for b in ip[12:16]),
        "dst": ".".join(str(b) for b in ip[16:20]),
        "sport": sport, "dport": dport,
        "seq": seq, "ack": ack, "flags": flags,
    }


def _read_pcap_frames(path: str):
    """Yield raw Ethernet frame bytes from a classic .pcap file.

    Deliberately avoids `from scapy.all import rdpcap`, which initialises
    Scapy's full networking stack (route/route6 tables) on import — that init
    raises KeyError('scope') in some containerised Linux environments and is
    entirely unnecessary for reading a local capture. This reader parses the
    pcap global header + per-record headers directly (libpcap format).
    """
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = struct.unpack_from("<I", gh)[0]
        endian = "<" if magic in (0xa1b2c3d4, 0xa1b23c4d) else ">"
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                break
            _, _, incl_len, _ = struct.unpack(f"{endian}IIII", rec)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            yield data


class TestTcpSegment:
    def test_arbitrary_flags(self):
        # SYN
        f = tcp_segment("10.0.0.1", "10.0.0.2", 5000, 502, 100, 0, 0x02)
        assert _parse_tcp(f)["flags"] == 0x02
        # SYN-ACK
        f = tcp_segment("10.0.0.2", "10.0.0.1", 502, 5000, 200, 101, 0x12)
        p = _parse_tcp(f)
        assert p["flags"] == 0x12 and p["ack"] == 101

    def test_tcp_packet_default_unchanged(self):
        """tcp_packet must still emit PSH|ACK with ack=0 (stateless contract)."""
        f = tcp_packet("10.0.0.5", "10.0.0.40", 502, b"\x01\x02\x03",
                       tcp_seq=0x1000, sport=50000)
        p = _parse_tcp(f)
        assert p["flags"] == 0x18      # PSH|ACK
        assert p["ack"] == 0
        assert p["seq"] == 0x1000
        assert p["sport"] == 50000 and p["dport"] == 502


class TestTCPFlow:
    def test_handshake_sequence(self):
        flow = TCPFlow("10.0.0.5", "10.0.0.40", 51000, 502,
                       client_isn=1000, server_isn=9000)
        frames = [_parse_tcp(f) for f in flow.handshake()]
        assert len(frames) == 3
        # SYN from client
        assert frames[0]["flags"] == 0x02
        assert frames[0]["src"] == "10.0.0.5"
        # SYN-ACK from server, acking client ISN+1
        assert frames[1]["flags"] == 0x12
        assert frames[1]["src"] == "10.0.0.40"
        assert frames[1]["ack"] == 1001
        # ACK from client, acking server ISN+1
        assert frames[2]["flags"] == 0x10
        assert frames[2]["ack"] == 9001

    def test_client_data_advances_seq_and_acks(self):
        flow = TCPFlow("10.0.0.5", "10.0.0.40", 51000, 502,
                       client_isn=1000, server_isn=9000)
        flow.handshake()
        seq_before = flow.cseq
        frames = [_parse_tcp(f) for f in flow.client_data(b"ABCDE")]  # 5 bytes
        assert len(frames) == 2
        # client data PSH|ACK
        assert frames[0]["flags"] == 0x18
        assert frames[0]["seq"] == seq_before
        # server bare ACK acking the 5 bytes
        assert frames[1]["flags"] == 0x10
        assert frames[1]["ack"] == seq_before + 5

    def test_teardown_fin(self):
        flow = TCPFlow("10.0.0.5", "10.0.0.40", 51000, 502, client_isn=1000)
        flow.handshake()
        frames = [_parse_tcp(f) for f in flow.teardown()]
        assert len(frames) == 3
        assert frames[0]["flags"] == 0x11   # client FIN|ACK
        assert frames[1]["flags"] == 0x11   # server FIN|ACK
        assert frames[2]["flags"] == 0x10   # client final ACK

    def test_full_conversation_shape(self):
        flow = TCPFlow("10.0.0.5", "10.0.0.40", 51000, 502, client_isn=1000)
        frames = []
        frames += flow.handshake()
        frames += flow.client_data(b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a")
        frames += flow.teardown()
        # 3 (handshake) + 2 (data + ack) + 3 (teardown) = 8
        assert len(frames) == 8


class TestStatefulGeneration:
    SCEN = "T0855__unauth_command__modbus"

    def test_default_is_stateless(self, scenarios_path, tmp_outdir):
        """Without stateful=True there must be no SYN in the pcap."""
        res = run_scenario(scenarios_path, self.SCEN, outdir=tmp_outdir,
                           dst_ip="198.51.100.42", src_ip="127.0.0.1",
                           build_pcap=True)
        if not res.get("pcap"):
            return
        flags = []
        for raw in _read_pcap_frames(res["pcap"]):
            if len(raw) >= 54 and raw[12:14] == b"\x08\x00" and raw[23] == 6:
                flags.append(_parse_tcp(raw)["flags"])
        # stateless: every TCP frame is PSH|ACK, no SYN (0x02) present
        assert flags, "expected some TCP frames"
        assert all(f == 0x18 for f in flags)
        assert not any(f & 0x02 for f in flags)

    def test_stateful_has_handshake_and_teardown(self, scenarios_path, tmp_outdir):
        res = run_scenario(scenarios_path, self.SCEN, outdir=tmp_outdir,
                           dst_ip="198.51.100.42", src_ip="127.0.0.1",
                           build_pcap=True, stateful=True)
        if not res.get("pcap"):
            return
        flags = []
        for raw in _read_pcap_frames(res["pcap"]):
            if len(raw) >= 54 and raw[12:14] == b"\x08\x00" and raw[23] == 6:
                flags.append(_parse_tcp(raw)["flags"])
        # stateful: at least one SYN, one SYN-ACK, and FIN present
        assert any(f == 0x02 for f in flags), "no SYN — handshake missing"
        assert any(f == 0x12 for f in flags), "no SYN-ACK — server side missing"
        assert any(f & 0x01 for f in flags), "no FIN — teardown missing"

    def test_stateful_preserves_covert_marker(self, scenarios_path, tmp_outdir):
        """The covert correlation marker must survive in stateful data segments."""
        res = run_scenario(scenarios_path, self.SCEN, outdir=tmp_outdir,
                           dst_ip="198.51.100.42", src_ip="127.0.0.1",
                           build_pcap=True, stateful=True)
        if not res.get("pcap"):
            return
        # Modbus covert marker -> transaction ID high byte in the F7 band.
        # TCP payload starts after Ethernet(14) + IP(20) + TCP(20) = byte 54.
        band_hits = 0
        for raw in _read_pcap_frames(res["pcap"]):
            if len(raw) >= 54 and raw[12:14] == b"\x08\x00" and raw[23] == 6:
                payload = raw[54:]
                if len(payload) >= 2 and payload[0] == 0xF7:
                    band_hits += 1
        assert band_hits > 0, "covert F7-band marker absent from stateful data segments"
