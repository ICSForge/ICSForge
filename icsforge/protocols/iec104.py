# ICSForge IEC-60870-5-104 payload builder (Wireshark-friendly APCI/ASDU)
import struct
from .common import marker_bytes

TYPE = {
    "meas": 1,              # M_SP_NA_1 (single-point information)
    "single_command": 45,   # C_SC_NA_1
    "double_command": 46,   # C_DC_NA_1
    "setpoint": 48,         # C_SE_NA_1
    "setpoint_float": 50,   # C_SE_NC_1
}

def build_payload(marker: str, style: str="meas", **kwargs) -> bytes:
    t = TYPE.get(style, 1)
    cot = int(kwargs.get("cot", 3)) & 0xFFFF  # cause of transmission
    ca = int(kwargs.get("ca", 1)) & 0xFFFF    # common address
    ioa = int(kwargs.get("ioa", 1)) & 0xFFFFFF
    mb = marker_bytes(marker)

    # ASDU: type(1) vsq(1) cot(2) ca(2) ioa(3) + data
    vsq = 1
    asdu = struct.pack("<BBH", t, vsq, cot) + struct.pack("<H", ca) + ioa.to_bytes(3,"little")
    if t in (45,46):
        asdu += b"\x01"  # SCO/DCO on
    elif t in (48,50):
        asdu += b"\x10\x00"  # dummy setpoint
    else:
        asdu += b"\x00"  # measurement state
    asdu += mb

    # APCI I-format: start(0x68) len + 4 control bytes
    ctrl = b"\x00\x00\x00\x00"
    apci = b"\x68" + bytes([len(asdu)+4]) + ctrl
    return apci + asdu
