# ICSForge Modbus/TCP payload builder (Wireshark-friendly)
import random
from .common import marker_bytes

def _pdu_for_style(style: str, rnd: random.Random, kwargs: dict) -> bytes:
    unit_id = int(kwargs.get("unit_id", rnd.randint(1,247))) & 0xFF
    addr = int(kwargs.get("address", rnd.randint(0, 9999))) & 0xFFFF
    qty  = int(kwargs.get("quantity", rnd.randint(1, 10))) & 0xFFFF
    value = int(kwargs.get("value", rnd.randint(0, 0xFFFF))) & 0xFFFF

    styles = {
        "read_coils": (1, lambda: addr.to_bytes(2,"big")+qty.to_bytes(2,"big")),
        "read_discrete": (2, lambda: addr.to_bytes(2,"big")+qty.to_bytes(2,"big")),
        "read_holding": (3, lambda: addr.to_bytes(2,"big")+qty.to_bytes(2,"big")),
        "read_input": (4, lambda: addr.to_bytes(2,"big")+qty.to_bytes(2,"big")),
        "write_single_coil": (5, lambda: addr.to_bytes(2,"big") + (0xFF00 if (value & 1) else 0x0000).to_bytes(2,"big")),
        "write_single_register": (6, lambda: addr.to_bytes(2,"big")+value.to_bytes(2,"big")),
        "write_multiple_coils": (15, lambda: addr.to_bytes(2,"big")+qty.to_bytes(2,"big") + bytes([(qty+7)//8]) + bytes([0xAA])*((qty+7)//8)),
        "write_multiple_registers": (16, lambda: addr.to_bytes(2,"big")+qty.to_bytes(2,"big") + bytes([qty*2]) + (b"\x00\x01"*qty)),
        "dos_read": (3, lambda: addr.to_bytes(2,"big")+int(kwargs.get("quantity", 120)).to_bytes(2,"big")),
    }
    fc, body = styles.get(style, styles["read_holding"])
    return bytes([unit_id, fc]) + body()

def build_payload(marker: str, style: str="read_holding", **kwargs) -> bytes:
    """Return Modbus/TCP ADU: MBAP(7 bytes) + PDU(unit+fc+data) + marker."""
    rnd = random.Random(kwargs.get("seed"))
    tid = int(kwargs.get("transaction_id", rnd.randint(0, 0xFFFF))) & 0xFFFF
    pid = 0
    pdu = _pdu_for_style(style, rnd, kwargs)
    length = len(pdu)  # includes unit id
    mbap = tid.to_bytes(2,"big") + pid.to_bytes(2,"big") + length.to_bytes(2,"big")
    return mbap + pdu + marker_bytes(marker)
