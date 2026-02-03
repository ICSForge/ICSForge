# ICSForge S7comm payload builder (TPKT+COTP+S7 header; simplified but Wireshark-friendly)
from .common import marker_bytes

def build_payload(marker: str, style: str="read_var", **kwargs) -> bytes:
    mb = marker_bytes(marker)

    # TPKT header (RFC1006): version 3, reserved 0, length (2 bytes)
    # COTP: minimal Data TPDU
    cotp = b"\x02\xf0\x80"

    # S7 header: Protocol ID 0x32, ROSCTR 0x01(job), reserved 0x0000, PDU ref 0x0001, param len, data len
    # We'll vary parameter based on style.
    if style == "setup":
        params = b"\xf0\x00"  # not real; placeholder
        data = b""
    elif style == "write_var":
        params = b"\x05\x01"  # placeholder
        data = b"\x00\x01"    # placeholder
    else:  # read_var
        params = b"\x04\x01"
        data = b""

    s7 = b"\x32\x01\x00\x00\x00\x01" + len(params).to_bytes(2,"big") + len(data).to_bytes(2,"big") + params + data + mb

    tpkt_len = 4 + len(cotp) + len(s7)
    tpkt = b"\x03\x00" + tpkt_len.to_bytes(2,"big")
    return tpkt + cotp + s7
