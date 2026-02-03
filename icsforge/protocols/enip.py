# ICSForge EtherNet/IP (CIP encapsulation) payload builder
import struct
from .common import marker_bytes

CMD = {
    "register_session": 0x0065,
    "list_identity": 0x0063,
}

def build_payload(marker: str, style: str="list_identity", **kwargs) -> bytes:
    cmd = CMD.get(style, CMD["list_identity"])
    mb = marker_bytes(marker)
    # Encapsulation header: Command(2), Length(2), Session(4), Status(4), SenderContext(8), Options(4)
    session = int(kwargs.get("session", 0)) & 0xFFFFFFFF
    sender_ctx = b"ICSForge0"  # 8 bytes
    data = b""
    if cmd == 0x0065:
        # RegisterSession payload: protocol version + options
        data = struct.pack("<HH", 1, 0) + mb
    else:
        data = mb
    hdr = struct.pack("<HHII", cmd, len(data), session, 0) + sender_ctx + struct.pack("<I", 0)
    return hdr + data
