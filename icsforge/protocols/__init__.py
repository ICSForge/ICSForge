from . import bacnet, dnp3, enip, iec104, iec61850, modbus, mqtt, opcua, profinet_dcp, s7comm

__all__ = ["modbus", "dnp3", "s7comm", "iec104", "iec61850", "opcua", "enip", "profinet_dcp", "bacnet", "mqtt"]

# ── Canonical protocol maps (single source of truth) ──────────────────
# TCP payload builders: proto_name -> (default_port, build_payload_fn)
TCP_PROTOS: dict = {
    "modbus":  (502,   modbus.build_payload),
    "dnp3":    (20000, dnp3.build_payload),
    "s7comm":  (102,   s7comm.build_payload),
    "iec104":  (2404,  iec104.build_payload),
    "opcua":   (4840,  opcua.build_payload),
    "enip":    (44818, enip.build_payload),
    "mqtt":    (1883,  mqtt.build_payload),
}

# UDP payload builders
UDP_PROTOS: dict = {
    "bacnet":  (47808, bacnet.build_payload),
}

# L2 protocols (handled specially — not TCP/UDP)
L2_PROTOS: frozenset = frozenset({"profinet_dcp", "iec61850"})
