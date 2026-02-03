# ICSForge DNP3 payload builder (Wireshark-friendly-ish for DNP3/TCP)
# Note: This does not implement full DNP3, but uses plausible headers and function mapping.
import random
from .common import marker_bytes

# DNP3 Application Control (AC) + Function Code mapping for simple simulation
FUNC = {
    "confirm": 0x00,
    "read": 0x01,
    "write": 0x02,
    "select": 0x03,
    "operate": 0x04,
    "direct_operate": 0x05,
}

def build_payload(marker: str, style: str="read", **kwargs) -> bytes:
    rnd = random.Random(kwargs.get("seed"))
    func = FUNC.get(style, FUNC["read"])

    # DNP3/TCP often encapsulates DNP3 link frames inside TCP stream.
    # We'll craft a simple link-layer frame: start 0x0564, length, control, dest, src, CRC placeholders.
    dest = int(kwargs.get("dnp3_dest", 1)) & 0xFFFF
    src  = int(kwargs.get("dnp3_src", 1024)) & 0xFFFF

    # Link header (10 bytes): 0x0564 + len + ctrl + dest + src
    start = b"\x05\x64"
    ctrl = b"\xC4"  # DIR=1, PRM=1, FCB/FCV=0, FUNC=4 (USER_DATA) style; approximate
    # Application header: AC + FC
    app_ctrl = bytes([0xC0])  # FIR/FIN set
    app_func = bytes([func])

    # Minimal transport+app payload (no objects): transport=0xC0
    transport = b"\xC0"

    payload = transport + app_ctrl + app_func + marker_bytes(marker)

    # length: link header + payload + CRC blocks; we will include a placeholder CRC (2 bytes) for header and data
    # This is not exact, but improves parser acceptance compared to raw strings.
    length = 5 + 2 + 2 + len(payload) + 2  # rough
    length_b = bytes([max(5, min(255, length))])

    link = start + length_b + ctrl + dest.to_bytes(2,"little") + src.to_bytes(2,"little")

    crc_hdr = b"\x00\x00"
    crc_data = b"\x00\x00"
    return link + crc_hdr + payload + crc_data
