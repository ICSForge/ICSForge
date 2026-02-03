
from __future__ import annotations
import random, struct
from icsforge.core import MARKER
from .common import ether_frame

def build(src_mac: str | None = None, dst_mac: str | None = None):
    src_mac = src_mac or "02:00:00:%02x:%02x:%02x" % (random.randint(0,255), random.randint(0,255), random.randint(0,255))
    dst_mac = dst_mac or "01:0e:cf:00:00:00"
    frame_id = 0xFEFE
    service_id = 0x05  # Identify
    service_type = 0x00
    xid = random.randint(0, 0xFFFFFFFF)
    response_delay = 0x0000
    dcp_data_len = 0
    dcp = struct.pack(">HBBIHH", frame_id, service_id, service_type, xid, response_delay, dcp_data_len)
    payload = dcp + MARKER
    return ether_frame(src_mac, dst_mac, 0x8892, payload)


def build_payload(run_marker: bytes) -> bytes:
    import random, struct
    frame_id=0xFEFE; service_id=0x05; service_type=0x00
    xid=random.randint(0,0xFFFFFFFF); response_delay=0; dcp_len=0
    dcp = struct.pack(">HBBIHH", frame_id, service_id, service_type, xid, response_delay, dcp_len)
    return dcp + run_marker

