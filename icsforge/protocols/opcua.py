# ICSForge OPC UA payload builder (Wireshark-friendly headers)
import struct
from .common import marker_bytes

def _hdr(msg_type: bytes, payload_len: int) -> bytes:
    # OPC UA Secure Conversation Message Header: 3 bytes type + 1 byte chunk + 4 bytes length
    # length includes header itself
    return msg_type + b"F" + struct.pack("<I", payload_len)

def build_payload(marker: str, style: str="hello", **kwargs) -> bytes:
    mb = marker_bytes(marker)
    if style == "hello":
        # HEL message: header + protocol version + recv/send buffer sizes + max msg size + max chunk count + endpoint URL
        endpoint = (kwargs.get("endpoint") or "opc.tcp://127.0.0.1:4840").encode("utf-8")
        body = struct.pack("<I", 0) + struct.pack("<I", 8192)*2 + struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<I", len(endpoint)) + endpoint
        total = 8 + len(body) + len(mb)
        return _hdr(b"HEL", total) + body + mb
    if style == "opn":
        # OPN message: minimal placeholder (not full security), just header + some bytes
        body = b"\x00"*16 + mb
        total = 8 + len(body)
        return _hdr(b"OPN", total) + body
    # MSG
    body = b"\x01"*12 + mb
    total = 8 + len(body)
    return _hdr(b"MSG", total) + body
