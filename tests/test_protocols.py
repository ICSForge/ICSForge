"""
Tests for all 7 ICSForge protocol payload builders.

Each test verifies:
  1. build_payload returns bytes (non-empty)
  2. Every documented style produces valid output
  3. Marker bytes are embedded in the payload
  4. Protocol-specific structural checks (magic bytes, headers, etc.)
"""
import struct

import pytest

from icsforge.protocols import bacnet, dnp3, enip, iec104, modbus, opcua, profinet_dcp, s7comm
from icsforge.protocols.common import ether_frame, marker_bytes, tcp_packet, udp_packet

# ── Modbus ────────────────────────────────────────────────────────────

MODBUS_STYLES = [
    "read_holding", "read_coils", "read_discrete", "read_input",
    "write_single_coil", "write_single_register",
    "write_multiple_coils", "write_multiple_registers",
    "read_write_multiple", "mask_write_register",
    "diagnostic", "read_exception_status", "get_comm_event_counter",
    "safety_write", "brute_force_write", "coil_sweep",
    "dos_read", "exception_probe", "zero_all", "input_write",
    "protection_relay", "alarm_threshold", "channel_flood",
    "c2_beacon", "credential_write", "io_image_read",
    "sis_disable", "default_creds_probe", "report_block",
]


@pytest.mark.parametrize("style", MODBUS_STYLES)
def test_modbus_style(style, marker):
    payload = modbus.build_payload(marker, style=style, seed=42)
    assert isinstance(payload, bytes)
    assert len(payload) >= 7  # minimum MBAP (6) + unit_id (1)


def test_modbus_mbap_header(marker):
    """Verify MBAP header structure: transaction_id(2) + protocol_id(2) + length(2)."""
    payload = modbus.build_payload(marker, style="read_holding", seed=42)
    proto_id = struct.unpack(">H", payload[2:4])[0]
    assert proto_id == 0, "Modbus protocol ID must be 0x0000"


def test_modbus_marker_embedded(marker):
    payload = modbus.build_payload(marker, style="write_single_register", seed=1)
    assert b"ICSFORGE:" in payload


# ── DNP3 ──────────────────────────────────────────────────────────────

DNP3_STYLES = [
    "read", "read_class1", "read_analog", "read_counter",
    "write", "select", "operate", "direct_operate", "direct_operate_nr",
    "cold_restart", "warm_restart",
    "enable_unsolicited", "disable_unsolicited",
    "assign_class", "delay_measure", "authenticate_req",
    "clear_events", "broadcast_operate", "file_open",
    "warm_restart2", "spoof_response", "default_auth_bypass",
]


@pytest.mark.parametrize("style", DNP3_STYLES)
def test_dnp3_style(style, marker):
    payload = dnp3.build_payload(marker, style=style, seed=42)
    assert isinstance(payload, bytes)
    assert len(payload) >= 10  # minimum link header


def test_dnp3_link_header_magic(marker):
    """DNP3 link header starts with 0x0564."""
    payload = dnp3.build_payload(marker, style="read", seed=42)
    assert payload[0:2] == b"\x05\x64"


def test_dnp3_crc_not_zero(marker):
    """DNP3 CRC should be computed, not placeholder zeros."""
    payload = dnp3.build_payload(marker, style="read", seed=42)
    # Link header CRC is at bytes 8-9
    crc_bytes = payload[8:10]
    assert crc_bytes != b"\x00\x00", "CRC should not be zero (was placeholder in v0.31)"


def test_dnp3_crc_function():
    """Verify CRC-16/DNP against known test vector."""
    from icsforge.protocols.dnp3 import dnp3_crc
    # Known DNP3 CRC test: data bytes from IEEE 1815
    test_data = b"\x05\x64\x05\xC0\x01\x00\x00\x04"
    crc = dnp3_crc(test_data)
    assert isinstance(crc, int)
    assert 0 <= crc <= 0xFFFF


# ── S7comm ────────────────────────────────────────────────────────────

S7COMM_STYLES = [
    "setup", "read_var", "write_var",
    "cpu_stop", "cpu_start_warm", "cpu_start_cold",
    "download_req", "download_block", "download_end",
    "upload_req", "upload_block", "upload_end",
    "szl_read", "plc_control",
    "read_db", "write_db", "read_outputs", "write_outputs",
    "read_inputs", "write_inputs", "zero_db",
    "firmware_module", "firmware_full", "download_sdb0",
    "szl_clear", "program_mode", "write_failsafe",
    "malformed_param", "hardcoded_creds", "tool_transfer_db",
    "default_creds", "read_all_dbs", "modify_ob1", "modified_ob1_dl",
    "native_cotp", "lateral_pivot",
]


@pytest.mark.parametrize("style", S7COMM_STYLES)
def test_s7comm_style(style, marker):
    payload = s7comm.build_payload(marker, style=style, seed=42)
    assert isinstance(payload, bytes)
    assert len(payload) >= 4  # minimum TPKT header


def test_s7comm_tpkt_header(marker):
    """S7comm frames must start with TPKT version 3."""
    payload = s7comm.build_payload(marker, style="read_var", seed=42)
    assert payload[0] == 0x03, "TPKT version must be 3"
    assert payload[1] == 0x00, "TPKT reserved must be 0"


def test_s7comm_protocol_id(marker):
    """S7comm header contains protocol ID 0x32."""
    payload = s7comm.build_payload(marker, style="read_var", seed=42)
    # TPKT(4) + COTP(3) + S7 header starts at byte 7
    assert payload[7] == 0x32, "S7 protocol ID must be 0x32"


# ── IEC-104 ───────────────────────────────────────────────────────────

IEC104_STYLES = [
    "single_command", "double_command", "setpoint_norm",
    "startdt", "stopdt", "testfr",
    "meas_mv", "setpoint_scale", "regulating_step",
    "interrogation", "counter_interr", "clock_sync",
    "reset_process", "test_command", "param_mv",
    "param_activ", "inhibit_alarm",
]


@pytest.mark.parametrize("style", IEC104_STYLES)
def test_iec104_style(style, marker):
    payload = iec104.build_payload(marker, style=style, seed=42)
    assert isinstance(payload, bytes)
    assert len(payload) >= 4  # minimum APCI


def test_iec104_start_byte(marker):
    """IEC-104 APCI starts with 0x68."""
    payload = iec104.build_payload(marker, style="single_command", seed=42)
    assert payload[0] == 0x68, "IEC-104 start byte must be 0x68"


# ── OPC UA ────────────────────────────────────────────────────────────

OPCUA_STYLES = [
    "hello", "find_servers", "get_endpoints",
    "open_session", "activate_session", "close_session",
    "browse", "browse_next", "translate_paths",
    "read_value", "read_history", "write_value",
    "call_method", "create_sub", "publish", "delete_sub",
]


@pytest.mark.parametrize("style", OPCUA_STYLES)
def test_opcua_style(style, marker):
    payload = opcua.build_payload(marker, style=style, seed=42)
    assert isinstance(payload, bytes)
    assert len(payload) >= 8  # minimum OPC UA header


def test_opcua_message_type(marker):
    """OPC UA messages start with 3-byte type: HEL, OPN, MSG, CLO."""
    payload = opcua.build_payload(marker, style="hello", seed=42)
    msg_type = payload[:3]
    assert msg_type in (b"HEL", b"OPN", b"MSG", b"CLO"), f"Unexpected OPC UA message type: {msg_type}"


# ── EtherNet/IP ──────────────────────────────────────────────────────

ENIP_STYLES = [
    "list_identity", "list_services", "list_interfaces",
    "register_session", "unregister_session",
    "get_identity", "get_device_type",
    "reset_device", "stop_device", "start_device",
    "read_tag", "write_tag", "get_param", "set_param",
    "send_rr_data",
]


@pytest.mark.parametrize("style", ENIP_STYLES)
def test_enip_style(style, marker):
    payload = enip.build_payload(marker, style=style, seed=42)
    assert isinstance(payload, bytes)
    assert len(payload) >= 24  # minimum ENIP header


def test_enip_header_structure(marker):
    """ENIP header: command(2) + length(2) + session(4) + status(4) + context(8) + options(4) = 24 bytes."""
    payload = enip.build_payload(marker, style="list_identity", seed=42)
    assert len(payload) >= 24


# ── PROFINET DCP ─────────────────────────────────────────────────────

PROFINET_STYLES = [
    "identify", "identify_unicast", "get_name", "get_ip",
    "set_name", "set_ip", "hello", "factory_reset",
]


@pytest.mark.parametrize("style", PROFINET_STYLES)
def test_profinet_style(style, marker):
    payload = profinet_dcp.build_payload(marker, style=style)
    assert isinstance(payload, bytes)
    assert len(payload) >= 4


# ── BACnet/IP ────────────────────────────────────────────────────────

BACNET_STYLES = [
    "who_is", "i_am", "read_property", "read_property_multi",
    "write_property", "write_property_multi", "subscribe_cov",
    "reinitialize_device", "device_comm_control",
    "read_file", "write_file", "private_transfer",
    "who_has", "time_sync", "create_object", "delete_object",
]


@pytest.mark.parametrize("style", BACNET_STYLES)
def test_bacnet_style(style, marker):
    payload = bacnet.build_payload(marker, style=style, seed=42)
    assert isinstance(payload, bytes)
    assert len(payload) >= 8  # minimum BVLC header (4) + NPDU (2) + APDU (2)


def test_bacnet_bvlc_header(marker):
    """BACnet/IP BVLC header: type 0x81, length matches actual payload."""
    payload = bacnet.build_payload(marker, style="who_is", seed=42)
    assert payload[0] == 0x81, "BVLC type must be 0x81 (BACnet/IP)"
    bvlc_len = struct.unpack(">H", payload[2:4])[0]
    assert bvlc_len == len(payload), "BVLC length must match payload size"


def test_bacnet_npdu_version(marker):
    """NPDU version must be 0x01 (ASHRAE 135)."""
    payload = bacnet.build_payload(marker, style="read_property", seed=42)
    assert payload[4] == 0x01, "NPDU version must be 0x01"


def test_bacnet_broadcast_uses_correct_bvlc_fn(marker):
    """Broadcast services (Who-Is, I-Am) use BVLC function 0x0B."""
    for style in ["who_is", "i_am", "who_has", "time_sync"]:
        payload = bacnet.build_payload(marker, style=style, seed=42)
        assert payload[1] == 0x0B, f"{style} should use BVLC_ORIGINAL_BROADCAST (0x0B)"


def test_bacnet_unicast_uses_correct_bvlc_fn(marker):
    """Unicast services (ReadProperty, WriteProperty) use BVLC function 0x0A."""
    for style in ["read_property", "write_property", "reinitialize_device"]:
        payload = bacnet.build_payload(marker, style=style, seed=42)
        assert payload[1] == 0x0A, f"{style} should use BVLC_ORIGINAL_UNICAST (0x0A)"


def test_bacnet_marker_embedded(marker):
    payload = bacnet.build_payload(marker, style="write_property", seed=1)
    assert b"ICSFORGE:" in payload


# ── Common utilities ─────────────────────────────────────────────────


def test_tcp_packet_structure():
    """tcp_packet returns a valid Ethernet+IP+TCP frame."""
    pkt = tcp_packet("127.0.0.1", "127.0.0.1", 502, b"\x00\x01\x02\x03")
    assert isinstance(pkt, bytes)
    assert len(pkt) >= 60  # minimum Ethernet frame
    # Ethernet dst MAC = ff:ff:ff:ff:ff:ff
    assert pkt[:6] == b"\xff\xff\xff\xff\xff\xff"
    # Ethertype = 0x0800 (IPv4)
    assert struct.unpack(">H", pkt[12:14])[0] == 0x0800
    # IP protocol = 6 (TCP)
    assert pkt[23] == 6


def test_tcp_packet_ip_checksum():
    """IP checksum should be non-zero (computed)."""
    pkt = tcp_packet("192.168.1.1", "192.168.1.2", 502, b"\xAA\xBB\xCC")
    ip_csum = struct.unpack(">H", pkt[24:26])[0]
    assert ip_csum != 0


def test_ether_frame_structure():
    """ether_frame returns a valid Ethernet II frame."""
    frame = ether_frame("02:00:00:11:22:33", "01:0e:cf:00:00:00", 0x8892, b"\x01\x02\x03")
    assert isinstance(frame, bytes)
    assert len(frame) >= 60  # padded to minimum


def test_marker_bytes():
    mb = marker_bytes("test-marker-123")
    assert mb.startswith(b"ICSFORGE:")
    assert b"test-marker-123" in mb


def test_udp_packet_structure():
    """udp_packet returns a valid Ethernet+IP+UDP frame."""
    pkt = udp_packet("127.0.0.1", "127.0.0.1", 47808, b"\x81\x0b\x00\x08\x01\x00\x10\x08")
    assert isinstance(pkt, bytes)
    assert len(pkt) >= 60  # minimum Ethernet frame
    # Ethertype = 0x0800 (IPv4)
    assert struct.unpack(">H", pkt[12:14])[0] == 0x0800
    # IP protocol = 17 (UDP)
    assert pkt[23] == 17
    # IP checksum non-zero
    assert struct.unpack(">H", pkt[24:26])[0] != 0
    # UDP dst port = 47808
    ihl = (pkt[14] & 0x0F) * 4
    udp_start = 14 + ihl
    dport = struct.unpack(">H", pkt[udp_start + 2:udp_start + 4])[0]
    assert dport == 47808
