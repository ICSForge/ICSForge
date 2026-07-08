"""
ICSForge Detection Content Generator

Generates three tiers of detection rules for each scenario:

  Tier 1 — lab_marker:
    Requires ICSFORGE_SYNTH marker in payload. Zero false positives on
    non-ICSForge traffic. Use for precise lab correlation: "did THIS tool
    send this exact packet?" Not useful for detecting a real adversary.

  Tier 2 — protocol_heuristic:
    Matches protocol structure (magic bytes, header fields, port) without
    requiring the marker. Will fire on any traffic matching that protocol
    pattern, including legitimate traffic. Use to validate that your NSM
    CAN see the protocol at all — not whether the specific action was adversary.

  Tier 3 — semantic:
    Matches specific function codes, commands, or service choices at the
    application layer. Low false-positive rate in properly segmented OT
    environments where those function codes should never appear. The closest
    this generator gets to "would catch a real adversary."

Rule files produced:
  icsforge_lab.rules        — Tier 1 (marker-gated, lab use only)
  icsforge_heuristic.rules  — Tier 2 (protocol structure, no marker)
  icsforge_semantic.rules   — Tier 3 (function-code/command level, recommended)

Sigma files produced:
  sigma/<scenario_id>.yml   — One file per scenario, tiered detection blocks
"""

import json
import re
from datetime import date
from pathlib import Path
from typing import Any

from icsforge import __version__

_SPECS_PATH = Path(__file__).parent.parent / "data" / "detection_rules_specs.json"

# ── Tier-1 covert marker detection (v0.74.0) ─────────────────────────────
# The synthetic-traffic marker is no longer an explicit ICSFORGE_SYNTH string
# in the payload. It is woven into genuinely-arbitrary protocol fields whose
# high-order byte is forced into a reserved synthetic band (0xF7) — see
# icsforge/protocols/covert_marker.py. The Tier-1 (Layer-1) Suricata rule is a
# cheap pre-filter that matches that band byte at the field's exact offset.
# It deliberately is NOT zero-FP on its own (~1/256 per packet); the receiver
# performs Layer-2 HMAC verification for the authoritative zero-FP guarantee.
#
# Per-protocol covert-field offset within the L7 (TCP/UDP) payload:
#   modbus  : transaction-ID high byte           @ offset 0
#   s7comm  : PDU-reference high byte             @ offset 11 (TPKT4+COTP3+S7hdr)
#   enip    : Sender Context first byte           @ offset 12 (encap header)
#   opcua   : RequestHandle first byte (MSG body) @ offset 41
#   bacnet  : Invoke ID (confirmed-request APDU)  @ offset 8
# mqtt carries the marker as a compact hex suffix on the client_id string;
# dnp3 uses the explicit 13-byte 'ICSF'+code+hash marker (fits one CRC chunk).
_SYNTH_BAND_HEX = "F7"
_COVERT_OFFSET = {
    "modbus": 0,
    "s7comm": 11,
    "enip": 12,
    "opcua": 41,
    "bacnet": 8,
}
# Explicit-marker mode (and DNP3 always) match the compact 'ICSF' magic.
_MARKER_ICSF_HEX = "49 43 53 46"  # 'ICSF'
_SID_BASE = 9_800_000

# ── Protocol semantic constants ─────────────────────────────────────────────
_PROTO_MAGIC = {
    "modbus": {
        "port": 502, "transport": "tcp",
        "magic": "00 00", "magic_offset": 2, "magic_depth": 4,
        "magic_label": "Modbus/TCP Protocol Identifier (0x0000)",
        "fc_offset": 7, "fc_depth": 8,
        "function_codes": {
            "01": "Read Coils", "02": "Read Discrete Inputs",
            "03": "Read Holding Registers", "04": "Read Input Registers",
            "05": "Write Single Coil", "06": "Write Single Register",
            "0F": "Write Multiple Coils", "10": "Write Multiple Registers",
            "08": "Diagnostics (FC08)", "11": "Report Server ID (FC17)",
            "17": "Read/Write Multiple Registers (FC23)",
            "2B": "Read Device Identification (MEI FC43)",
        },
    },
    "dnp3": {
        "port": 20000, "transport": "tcp",
        "magic": "05 64", "magic_offset": 0, "magic_depth": 2,
        "magic_label": "DNP3 Link-Layer Start Bytes (0x05 0x64)",
        "fc_offset": 12, "fc_depth": 13,
        "function_codes": {
            "01": "Read", "02": "Write", "03": "Select",
            "04": "Operate", "05": "Direct Operate",
            "06": "Direct Operate No Ack",
            "0D": "Cold Restart", "0E": "Warm Restart",
            "13": "Delay Measure", "14": "Record Current Time",
            "28": "Authenticate Request", "81": "Response",
        },
    },
    "s7comm": {
        "port": 102, "transport": "tcp",
        "magic": "03 00", "magic_offset": 0, "magic_depth": 2,
        "magic_label": "TPKT Magic (S7comm/ISO-TSAP)",
        "fc_offset": 8, "fc_depth": 9,
        "function_codes": {
            "01": "Job (Read/Write Variable)",
            "03": "Ack-Data",
            "07": "Userdata (SZL/Diagnostic/Config)",
        },
    },
    "iec104": {
        "port": 2404, "transport": "tcp",
        "magic": "68", "magic_offset": 0, "magic_depth": 1,
        "magic_label": "IEC-104 APCI Start Byte (0x68)",
        "fc_offset": 6, "fc_depth": 7,
        "function_codes": {
            "01": "M_SP_NA_1 Single-point info",
            "03": "M_DP_NA_1 Double-point info",
            "2D": "C_SC_NA_1 Single command",
            "2E": "C_DC_NA_1 Double command",
            "30": "C_SE_NA_1 Setpoint normalised",
            "31": "C_SE_NB_1 Setpoint scaled",
            "32": "C_SE_NC_1 Setpoint float",
            "64": "C_IC_NA_1 Interrogation command",
            "65": "C_CI_NA_1 Counter interrogation",
            "67": "C_CS_NA_1 Clock synchronisation",
            "46": "M_EI_NA_1 End of initialisation",
        },
    },
    "mqtt": {
        "port": 1883, "transport": "tcp",
        "magic": "10", "magic_offset": 0, "magic_depth": 1,
        "magic_label": "MQTT CONNECT Packet (0x10)",
        "fc_offset": 0, "fc_depth": 1,
        "function_codes": {
            "10": "CONNECT", "30": "PUBLISH QoS0",
            "32": "PUBLISH QoS1", "34": "PUBLISH QoS2",
            "82": "SUBSCRIBE", "A2": "UNSUBSCRIBE",
            "C0": "PINGREQ", "E0": "DISCONNECT",
        },
    },
    "bacnet": {
        "port": 47808, "transport": "udp",
        # Magic is just 0x81 (BVLL Type for BACnet/IP) — covers both
        # 81 0A (Original-Unicast-NPDU) and 81 0B (Original-Broadcast-NPDU)
        # which differ only in the BVLC function byte. Using a 1-byte
        # magic match keeps the rules simple while covering both frame
        # types. BACnet/IP traffic on UDP/47808 always starts with 0x81.
        "magic": "81", "magic_offset": 0, "magic_depth": 1,
        "magic_label": "BACnet/IP BVLL Type (0x81)",
        "fc_offset": 7, "fc_depth": 8,
        "function_codes": {
            # Confirmed services (APDU type 0) — these are at byte 9 in real
            # confirmed-request frames; the wider depth=8 window catches them.
            "06": "atomicReadFile",
            "07": "atomicWriteFile",  # also matches who-Has unconfirmed (overlap)
            "0A": "createObject",
            "0B": "deleteObject",
            "0C": "readProperty",
            "0E": "readPropertyMultiple",
            "0F": "writeProperty",
            "10": "writePropertyMultiple",
            "05": "subscribeCOV",
            "11": "deviceCommunicationControl",
            "12": "confirmedPrivateTransfer",
            "14": "reinitializeDevice",
            # Unconfirmed services (APDU type 1) — at byte 7
            "00": "i-Am or timeSync",
            "08": "who-Is",
        },
    },
    "enip": {
        "port": 44818, "transport": "tcp",
        "magic": "63 00", "magic_offset": 0, "magic_depth": 2,
        "magic_label": "EtherNet/IP Encapsulation Command Word",
        "fc_offset": 0, "fc_depth": 2,
        "function_codes": {
            "63 00": "ListIdentity", "64 00": "ListInterfaces",
            "04 00": "ListServices",
            "65 00": "RegisterSession", "66 00": "UnRegisterSession",
            "6f 00": "SendRRData", "70 00": "SendUnitData",
        },
        # CIP service codes carried inside the SendRRData (6f 00) CPF
        # unconnected-data item (b2 00 <len:2> <service>). Matching these
        # gives a true semantic (operation-level) match rather than only the
        # encapsulation command word — a Write (0x4D) is meaningfully different
        # from a Read (0x4C). The service byte sits 4 bytes after the CPF data
        # item marker `b2 00`, matched via content+distance below.
        "cip_services": {
            "4c": "CIP ReadTag (0x4C)",
            "4d": "CIP WriteTag (0x4D)",
            "4e": "CIP ReadModifyWrite (0x4E)",
            "52": "CIP UnconnectedSend (0x52)",
            "53": "CIP MultipleServicePacket (0x53)",
            "01": "CIP GetAttributesAll (0x01)",
            "02": "CIP SetAttributesAll (0x02)",
            "0e": "CIP GetAttributeSingle (0x0E)",
            "10": "CIP SetAttributeSingle (0x10)",
            "05": "CIP Reset (0x05)",
            "06": "CIP Start (0x06)",
            "07": "CIP Stop (0x07)",
            "4b": "CIP ExecutePCCC (0x4B)",
            "54": "CIP ForwardOpen (0x54)",
        },
    },
    "opcua": {
        "port": 4840, "transport": "tcp",
        "magic": "48 45 4C 46", "magic_offset": 0, "magic_depth": 4,
        "magic_label": "OPC UA Hello Message (HELF)",
        "fc_offset": 0, "fc_depth": 4,
        "function_codes": {
            "48 45 4C 46": "Hello",
            "4F 50 4E 46": "OpenSecureChannel",
            "4D 53 47 46": "Message (generic)",
            "43 4C 4F 46": "CloseSecureChannel",
        },
    },
    "iec61850": {
        "port": None, "transport": "l2",
        "magic": None, "magic_offset": None, "magic_depth": None,
        "magic_label": "IEC 61850 GOOSE (L2 EtherType 0x88B8)",
        "fc_offset": None, "fc_depth": None, "function_codes": {},
    },
    "profinet_dcp": {
        "port": None, "transport": "l2",
        "magic": None, "magic_offset": None, "magic_depth": None,
        "magic_label": "PROFINET DCP (L2 EtherType 0x8892)",
        "fc_offset": None, "fc_depth": None, "function_codes": {},
    },
}

# Style → function code mapping per protocol
_STYLE_FC: dict[str, dict[str, str]] = {
    "modbus": {
        "read_coils": "01", "read_discrete": "02",
        "read_holding": "03", "read_input": "04",
        "io_image_read": "03", "read_write_multiple": "17",
        "write_single_coil": "05", "write_single_register": "06",
        "write_multiple_coils": "0F", "write_multiple_registers": "10",
        "input_write": "06", "mask_write_register": "16",
        "brute_force_write": "10", "credential_write": "10",
        "safety_write": "10", "zero_all": "10",
        "diagnostic": "08", "read_exception_status": "07",
        "get_comm_event_counter": "0B",
        "report_block": "11", "default_creds_probe": "03",
        "alarm_threshold": "03", "protection_relay": "10",
        "channel_flood": "03", "coil_sweep": "01",
        "dos_read": "03", "exception_probe": "08",
        "sis_disable": "10", "c2_beacon": "03",
    },
    "dnp3": {
        "read_class_data": "01", "read_class1": "01",
        "read_analog": "01", "read_counter": "01",
        "read": "01", "write": "02",
        "select": "03", "operate": "04",
        "direct_operate": "05", "direct_operate_nr": "06",
        "broadcast_operate": "05",
        "cold_restart": "0D", "warm_restart": "0E",
        "delay_measure": "13", "disable_unsolicited": "15",
        "clear_events": "01", "assign_class": "02",
        "authenticate_req": "28", "default_auth_bypass": "05",
        "file_open": "19", "spoof_response": "81",
        "write_binary_output": "02",
    },
    "s7comm": {
        "read_var": "01", "write_var": "01", "read_db": "01",
        "write_db": "01", "read_inputs": "01", "write_inputs": "01",
        "read_outputs": "01", "write_outputs": "01",
        "read_all_dbs": "01", "write_failsafe": "01", "zero_db": "01",
        "cpu_stop": "01", "cpu_start_cold": "01", "cpu_start_warm": "01",
        "program_mode": "01", "setup": "01",
        "szl_read": "07", "szl_clear": "07",
        "download_req": "01", "download_block": "01", "download_end": "01",
        "download_sdb0": "01", "upload_req": "01",
        "upload_block": "01", "upload_end": "01",
        "firmware_module": "07", "firmware_full": "07",
        "modify_ob1": "01", "modified_ob1_dl": "01",
        "tool_transfer_db": "01", "lateral_pivot": "07",
        "malformed_param": "01", "native_cotp": "01",
        "default_creds": "01", "hardcoded_creds": "01",
    },
    "iec104": {
        "single_command": "2D", "double_command": "2E",
        "regulating_step": "31", "setpoint_scale": "31",
        "setpoint_float": "32", "c_sc_na": "2D", "c_dc_na": "2E",
        "interrogation": "64", "clock_sync": "67",
        "meas_inject": "03", "meas_sp": "01", "meas_mv": "09",
        "param_mv": "70", "param_threshold": "70",
        "inhibit_alarm": "2D", "reset_process": "64",
        "counter_interr": "65", "counter_reset": "66",
        "clock_inject": "67", "block_cmd": "2D", "available": "46",
    },
    "mqtt": {
        "connect": "10", "connect_anonymous": "10", "connect_creds": "10",
        "will_message": "10",
        "publish_qos0": "30", "publish_alarm": "30",
        "publish_command": "30", "publish_config": "30",
        "publish_dos": "30", "publish_setpoint": "30",
        "publish_telemetry": "30",
        "publish_qos1": "32", "publish_firmware": "32",
        "subscribe_all": "82", "subscribe_commands": "82",
        "subscribe_telemetry": "82",
        "unsubscribe": "A2", "pingreq": "C0", "disconnect": "E0",
    },
    "bacnet": {
        # Confirmed services (APDU type 0) — service choice at byte 9 of UDP payload
        "read_property": "0C",            # readProperty
        "read_property_multi": "0E",      # readPropertyMultiple
        "write_property": "0F",            # writeProperty
        "write_property_multi": "10",      # writePropertyMultiple
        "subscribe_cov": "05",             # subscribeCOV (was incorrectly 1A)
        "device_comm_control": "11",       # deviceCommunicationControl (was 1C)
        "reinitialize_device": "14",       # reinitializeDevice (was 12)
        "create_object": "0A",             # createObject
        "delete_object": "0B",             # deleteObject
        "read_file": "06",                 # atomicReadFile (was 07)
        "write_file": "07",                # atomicWriteFile (was 09)
        "private_transfer": "12",          # confirmedPrivateTransfer (was 1A)
        # Unconfirmed services (APDU type 1) — service choice at byte 7 of UDP payload
        # Both byte positions (7 and 9) fall within the existing fc_offset:7
        # depth:8 search window in _PROTO_MAGIC, so a single FC byte match works.
        "who_is": "08",                    # whoIs (was incorrectly 1A)
        "who_has": "07",                   # whoHas (was 1C)
        "i_am": "00",                      # iAm
        "time_sync": "00",                 # timeSynchronization shares iAm shape currently
    },
    "enip": {
        "list_identity": "63 00", "list_services": "04 00",
        "list_interfaces": "64 00",
        "register_session": "65 00", "unregister_session": "66 00",
        "get_identity": "65 00", "get_device_type": "65 00",
        "get_param": "65 00", "set_param": "65 00",
        "read_tag": "6f 00", "write_tag": "6f 00",
        "start_device": "6f 00", "stop_device": "6f 00",
        "reset_device": "6f 00", "reset_safe": "6f 00",
        "firmware_update": "6f 00", "boot_firmware": "6f 00",
        "tool_transfer": "6f 00", "malformed_ucmm": "6f 00",
        "assembly_read": "6f 00", "default_auth": "65 00",
        "c2_beacon": "6f 00", "send_rr_data": "6f 00",
        "multicast_sniff": "63 00",
    },
    "opcua": {
        "hello": "48 45 4C 46", "find_servers": "4F 50 4E 46",
        "get_endpoints": "4F 50 4E 46",
        "open_session": "4D 53 47 46", "activate_session": "4D 53 47 46",
        "close_session": "43 4C 4F 46", "browse": "4D 53 47 46",
        "browse_next": "4D 53 47 46", "read_value": "4D 53 47 46",
        "write_value": "4D 53 47 46", "history_read": "4D 53 47 46",
        "activate_default": "4F 50 4E 46",
        "activate_hardcoded": "4F 50 4E 46",
    },
    "iec61850": {
        # GOOSE styles aren't single-byte distinguishable (same APDU shape).
        # Discriminator is the gocbRef IED-name bytes: "IED1" vs "IED2"
        # encoded as ASCII appearing early in the GOOSE PDU. The Zeek
        # signature emitter will use these as `payload /.../` regex bytes.
        "trip_inject":        "49 45 44 31",  # 'IED1'
        "spoof_measurement":  "49 45 44 31",
        "protection_block":   "49 45 44 31",
        "enumerate_ied":      "49 45 44 31",
        "relay_inject":       "49 45 44 32",  # 'IED2'
    },
}

# ENIP style → CIP service code carried in the SendRRData CPF data item.
# These give Tier-3 a true operation-level match (Read vs Write vs Reset) instead
# of only the encapsulation command word. Values mirror what the ENIP builder
# emits at find(b'\xb2\x00')+4; styles not listed here have no CIP service
# (pure encapsulation commands like ListIdentity/RegisterSession) and fall back
# to the encapsulation-word match.
_STYLE_CIP_SERVICE: dict[str, str] = {
    "get_identity": "01", "get_device_type": "0e", "get_param": "0e",
    "set_param": "10", "read_tag": "4c", "write_tag": "4d",
    "start_device": "06", "stop_device": "07", "reset_device": "05",
    "reset_safe": "05", "boot_firmware": "05", "tool_transfer": "53",
    "malformed_ucmm": "01", "assembly_read": "01", "c2_beacon": "10",
    "send_rr_data": "01",
}

_TRANSPORT = {
    "modbus": "tcp", "dnp3": "tcp", "s7comm": "tcp",
    "iec104": "tcp", "opcua": "tcp", "enip": "tcp",
    "profinet_dcp": "tcp", "mqtt": "tcp", "bacnet": "udp",
    "iec61850": "tcp",
}

_ZEEK_SERVICE = {
    "modbus": "modbus", "dnp3": "dnp3", "s7comm": "iso-tsap",
    "iec104": "iec104", "mqtt": "mqtt", "bacnet": "bacnet",
    "enip": "enip", "opcua": "opc-ua-binary",
}


def _load_specs() -> dict[str, Any]:
    return json.loads(_SPECS_PATH.read_text(encoding="utf-8"))


def _zeek_signature(spec: dict, base_id: int) -> list[str]:
    """Emit Zeek signature-framework rules for L2-only protocols.

    Zeek's signature framework can match L2 traffic via the `eth-proto`
    keyword — something Suricata 7.x cannot do. We emit one or more
    signatures per L2 scenario covering:

    - **EtherType match** — basic protocol-presence detection
    - **Lab-marker match** — payload contains ICSFORGE_SYNTH (Tier 1)
    - **Per-style payload matches** — distinguishing different scenario
      styles by their wire-format signatures (Tier 3 equivalent)

    Returns an empty list for IP-based protocols (Suricata is the right
    tool for those — Zeek emission would just duplicate the work).

    Output format follows Zeek's signature-framework syntax. Users load
    the resulting `icsforge.sig` file via `zeek -r <pcap> icsforge.sig`
    or by adding it to their site-policy via `redef signature_files`.

    Returns:
        List of Zeek signature blocks (each is a multi-line string ready
        to be joined with newlines into a .sig file).
    """
    proto = spec["proto"]
    pm = _PROTO_MAGIC.get(proto, {})
    if pm.get("transport") != "l2":
        return []  # Suricata handles IP-based protocols

    tech = spec["technique"]
    sc_id = spec["id"]
    style_fcs = _STYLE_FC.get(proto, {})

    # EtherType per protocol (canonical IEEE 802.1Q codes)
    ETHERTYPE = {
        "iec61850":     0x88B8,  # GOOSE
        "profinet_dcp": 0x8892,  # PROFINET DCP / context-data
    }
    eth_proto = ETHERTYPE.get(proto)
    if eth_proto is None:
        return []

    rules = []

    def _ascii(s: str) -> str:
        """Replace Unicode dashes etc. with ASCII for Zeek compatibility."""
        return (
            s.replace("\u2013", "-")  # en-dash
             .replace("\u2014", "-")  # em-dash
             .replace("\u2018", "'").replace("\u2019", "'")
             .replace("\u201C", '"').replace("\u201D", '"')
             .encode("ascii", "ignore").decode("ascii")
        )

    # Tier 1 / lab marker — fires when ICSForge marker is present in payload
    sig_id = f"icsforge-{sc_id.lower().replace('__', '-').replace('_', '-')}-lab"
    msg = _ascii(_clean_msg(
        f"ICSForge LAB-MARKER {tech} {spec['tech_name']} "
        f"[{spec['proto_label']}] {spec['title']}"
    ))
    rules.append(
        f"# {sc_id} - Tier 1 (lab marker)\n"
        f"# v0.74.0: covert marker rides in protocol fields (0x{_SYNTH_BAND_HEX} synthetic\n"
        f"# band); in explicit-marker mode the compact 'ICSF' magic appears in payload.\n"
        f"signature {sig_id} {{\n"
        f"    eth-proto == 0x{eth_proto:04X}\n"
        f"    payload /.*ICSF/\n"
        f"    event \"{msg}\"\n"
        f"}}"
    )

    # Tier 2 / heuristic — EtherType match (always fires, like protocol-presence)
    sig_id_h = f"icsforge-{sc_id.lower().replace('__', '-').replace('_', '-')}-heur"
    msg_h = _ascii(_clean_msg(
        f"ICSForge HEURISTIC {tech} {spec['tech_name']} "
        f"[{spec['proto_label']}] {pm.get('magic_label', proto)}"
    ))
    rules.append(
        f"# {sc_id} - Tier 2 (EtherType heuristic)\n"
        f"signature {sig_id_h} {{\n"
        f"    eth-proto == 0x{eth_proto:04X}\n"
        f"    event \"{msg_h}\"\n"
        f"}}"
    )

    # Tier 3 / semantic — per-style frame-id / service-id match
    seen_styles: set[str] = set()
    for style in spec.get("styles", []):
        if style in seen_styles:
            continue
        seen_styles.add(style)
        fc = style_fcs.get(style)
        if not fc:
            continue
        sig_id_s = (
            f"icsforge-{sc_id.lower().replace('__', '-').replace('_', '-')}"
            f"-sem-{style.lower().replace('_', '-')}"
        )
        msg_s = _ascii(_clean_msg(
            f"ICSForge SEMANTIC {tech} {spec['tech_name']} "
            f"[{spec['proto_label']}] {style}"
        ))
        # Build a bytewise payload regex from the FC hex string
        fc_bytes = fc.replace(" ", "").lower()
        payload_re = "".join(f"\\x{fc_bytes[i:i+2]}" for i in range(0, len(fc_bytes), 2))
        rules.append(
            f"# {sc_id} - Tier 3 ({style} semantic)\n"
            f"signature {sig_id_s} {{\n"
            f"    eth-proto == 0x{eth_proto:04X}\n"
            f"    payload /.*{payload_re}/\n"
            f"    event \"{msg_s}\"\n"
            f"}}"
        )
    return rules


def _zeek_header() -> str:
    """File header preamble for the generated icsforge.sig file."""
    return (
        "# ICSForge L2 detection signatures for Zeek\n"
        "#\n"
        "# Auto-generated by `icsforge detections export --zeek`.\n"
        "# Do not edit by hand - re-run the generator instead.\n"
        "#\n"
        "# Coverage: IEC 61850 GOOSE (EtherType 0x88B8) and PROFINET DCP\n"
        "# (EtherType 0x8892). Both are L2-only protocols that Suricata 7.x\n"
        "# cannot match (no rule-protocol for L2 in the detect engine).\n"
        "# Zeek's signature framework supports `eth-proto` and bytewise\n"
        "# `payload` matching, which is exactly what L2 detection needs.\n"
        "#\n"
        "# Deployment:\n"
        "#   1. Copy this file into your Zeek site policy directory.\n"
        "#   2. Either pass it on the CLI:\n"
        "#        zeek -r capture.pcap /path/to/icsforge.sig\n"
        "#      or add to local.zeek:\n"
        "#        redef signature_files += \"icsforge\";\n"
        "#   3. Notices appear in notice.log.\n"
        "#\n"
        f"# Generated: {date.today().isoformat()}\n"
        "#\n"
        "# Tier structure (match Suricata):\n"
        "#   *-lab     Tier 1 - ICSForge marker bytes present (zero FP)\n"
        "#   *-heur    Tier 2 - EtherType match (protocol-presence)\n"
        "#   *-sem-*   Tier 3 - Per-style payload pattern (function code)\n"
        "\n"
    )


def _hex_str(raw: str) -> str:
    clean = raw.replace(" ", "").upper()
    return "|" + " ".join(clean[i:i+2] for i in range(0, len(clean), 2)) + "|"


def _clean_msg(s: str) -> str:
    s = re.sub(r'[();"\'\\]', '', s)
    return s[:120].strip()


def _sigma_id(sc_id: str) -> str:
    return "icsforge-" + sc_id.lower().replace("_", "-")[:60]


# ── Suricata tier builders ─────────────────────────────────────────────────────

def _tier1_marker(spec: dict, sid: int) -> str | None:
    proto = spec["proto"]
    pm = _PROTO_MAGIC.get(proto, {})
    # L2-only protocols (PROFINET DCP, IEC 61850 GOOSE) cannot be matched
    # by Suricata 7.x — Suricata's detect engine requires IP packets.
    # We emit no Suricata rule here; detection for these protocols belongs
    # in Zeek (which has L2 protocol parsers) or custom tooling. The Sigma
    # rules emitted alongside are engine-neutral and can be consumed there.
    if pm.get("transport") == "l2":
        return None
    transport = _TRANSPORT.get(proto, "tcp")
    port = spec["port"] or "any"
    tech = spec["technique"]
    msg = _clean_msg(
        f"ICSForge LAB-MARKER {tech} {spec['tech_name']} "
        f"[{spec['proto_label']}] {spec['title']}"
    )

    # Build the content match for the covert marker (v0.74.0).
    #  * Band protocols: match the 0xF7 synthetic-band byte at the covert
    #    field's exact offset (Layer-1 pre-filter; receiver does Layer-2 HMAC).
    #  * DNP3 (always) and explicit-marker mode: match the 'ICSF' magic.
    #  * MQTT: the marker is a hex suffix on the client_id string; match the
    #    'ICSF' magic only when present (explicit mode), otherwise the band
    #    model doesn't apply and detection relies on Tier-2/registry.
    offset = _COVERT_OFFSET.get(proto)
    if offset is not None:
        # Anchor on the synthetic band byte at the precise field offset.
        content_clause = (
            f'content:"{_hex_str(_SYNTH_BAND_HEX)}"; offset:{offset}; depth:1; '
        )
        marker_note = f"synthetic-band 0x{_SYNTH_BAND_HEX} at offset {offset}"
    elif proto == "dnp3":
        # DNP3 carries the compact explicit 'ICSF' marker inside its payload.
        content_clause = f'content:"{_hex_str(_MARKER_ICSF_HEX.replace(" ", ""))}"; '
        marker_note = "compact ICSF marker (DNP3 in-payload)"
    else:
        # No covert field model for this proto (e.g. MQTT band N/A): match the
        # explicit ICSF marker, which is present in explicit-marker mode.
        content_clause = f'content:"{_hex_str(_MARKER_ICSF_HEX.replace(" ", ""))}"; '
        marker_note = "compact ICSF marker (explicit mode)"

    return (
        f'alert {transport} any any -> any {port} '
        f'(msg:"{msg}"; '
        f'flow:to_server; '
        f'{content_clause}'
        f'classtype:policy-violation; '
        f'sid:{sid}; rev:1; '
        f'metadata:confidence lab_marker, icsforge_tier 1, '
        f'mitre_technique {tech}, icsforge_scenario {spec["id"]}, '
        f'icsforge_marker {marker_note.replace(",", "")}, '
        f'created_at {date.today().isoformat()};)'
    )


def _tier2_heuristic(spec: dict, sid_start: int) -> list[str]:
    """Emit one or more Tier 2 (protocol heuristic) rules.

    Returns a list because protocols whose magic-byte position coincides
    with their function-code position (ENIP, OPC UA, MQTT — see
    `_PROTO_MAGIC[proto]['magic_offset'] == ['fc_offset'] == 0`) need
    one rule per distinct command-byte the scenario produces. Otherwise
    the rule's `content:"|magic|"` would only match the single hardcoded
    magic (e.g. ENIP `63 00` ListIdentity) and miss every scenario whose
    styles use a different command (e.g. RegisterSession `65 00`).

    Pre-v0.66.0 this returned a single rule with the hardcoded magic,
    which caused 31.9% Tier 2 hit rate on ENIP, 25.0% on OPC UA, 34.0%
    on MQTT. This was documented as the v0.66 work item in
    docs/REFERENCE_DETECTION_COVERAGE.md.

    For protocols without magic/FC overlap (Modbus, DNP3, IEC-104,
    S7comm, BACnet) the magic byte is genuinely a protocol marker and
    the single-rule pattern is correct.
    """
    proto = spec["proto"]
    pm = _PROTO_MAGIC.get(proto, {})
    if pm.get("transport") == "l2" or not pm.get("magic"):
        return []
    transport = _TRANSPORT.get(proto, "tcp")
    port = spec["port"] or "any"
    tech = spec["technique"]

    # Determine whether this protocol has magic-FC overlap.
    overlap = (
        pm.get("magic_offset") == pm.get("fc_offset")
        and pm.get("magic_offset") is not None
        and pm.get("function_codes")
    )

    if not overlap:
        # Single-rule classic path — magic alone is sufficient.
        magic_hex = _hex_str(pm["magic"].replace(" ", ""))
        msg = _clean_msg(
            f"ICSForge HEURISTIC {tech} {spec['tech_name']} "
            f"[{spec['proto_label']}] {pm['magic_label']}"
        )
        return [(
            f'alert {transport} any any -> any {port} '
            f'(msg:"{msg}"; '
            f'flow:to_server; '
            f'content:"{magic_hex}"; offset:{pm["magic_offset"]}; depth:{pm["magic_depth"]}; '
            f'classtype:protocol-command-decode; '
            f'sid:{sid_start}; rev:1; '
            f'metadata:confidence protocol_heuristic, icsforge_tier 2, '
            f'mitre_technique {tech}, icsforge_scenario {spec["id"]}, '
            f'created_at {date.today().isoformat()};)'
        )]

    # Overlap path: emit one rule per distinct command-byte the styles produce.
    style_fcs = _STYLE_FC.get(proto, {})
    fcs_seen: set[str] = set()
    rules: list[str] = []

    for style in spec.get("styles", []):
        fc = style_fcs.get(style)
        if not fc:
            continue
        fc_normalized = fc.upper()
        if fc_normalized in fcs_seen:
            continue
        fcs_seen.add(fc_normalized)
        fc_name = pm["function_codes"].get(fc_normalized, f"FC 0x{fc_normalized}")
        fc_hex = _hex_str(fc.replace(" ", ""))
        msg = _clean_msg(
            f"ICSForge HEURISTIC {tech} {spec['tech_name']} "
            f"[{spec['proto_label']}] {fc_name}"
        )
        rules.append(
            f'alert {transport} any any -> any {port} '
            f'(msg:"{msg}"; '
            f'flow:to_server; '
            f'content:"{fc_hex}"; offset:{pm["magic_offset"]}; depth:{pm["magic_depth"]}; '
            f'classtype:protocol-command-decode; '
            f'sid:{sid_start + len(rules)}; rev:1; '
            f'metadata:confidence protocol_heuristic, icsforge_tier 2, '
            f'mitre_technique {tech}, icsforge_scenario {spec["id"]}, '
            f'icsforge_style {style}, '
            f'created_at {date.today().isoformat()};)'
        )

    if not rules:
        # Fallback: scenario has styles but none map to a known FC.
        # Emit one rule using the protocol's default magic (preserves
        # behaviour for any edge case the spec doesn't cover).
        magic_hex = _hex_str(pm["magic"].replace(" ", ""))
        msg = _clean_msg(
            f"ICSForge HEURISTIC {tech} {spec['tech_name']} "
            f"[{spec['proto_label']}] {pm['magic_label']}"
        )
        rules.append(
            f'alert {transport} any any -> any {port} '
            f'(msg:"{msg}"; '
            f'flow:to_server; '
            f'content:"{magic_hex}"; offset:{pm["magic_offset"]}; depth:{pm["magic_depth"]}; '
            f'classtype:protocol-command-decode; '
            f'sid:{sid_start}; rev:1; '
            f'metadata:confidence protocol_heuristic, icsforge_tier 2, '
            f'mitre_technique {tech}, icsforge_scenario {spec["id"]}, '
            f'created_at {date.today().isoformat()};)'
        )
    return rules


def _tier3_semantic(spec: dict, sid_start: int) -> list[str]:
    proto = spec["proto"]
    pm = _PROTO_MAGIC.get(proto, {})
    if pm.get("transport") == "l2" or pm.get("fc_offset") is None:
        return []
    transport = _TRANSPORT.get(proto, "tcp")
    port = spec["port"] or "any"
    tech = spec["technique"]
    style_fcs = _STYLE_FC.get(proto, {})
    rules = []
    seen: set[str] = set()

    # When magic and FC share the same byte position (ENIP, OPC UA, MQTT —
    # the magic IS the function code), emitting both content matches is
    # contradictory ("byte 0 == magic AND byte 0 == FC") and only fires
    # for scenarios whose style equals the hardcoded magic. Skip the
    # redundant magic match for these protocols. Other protocols
    # (Modbus, DNP3, IEC-104, etc.) still need both since magic and FC
    # are at different offsets.
    overlap = (
        pm.get("magic_offset") == pm.get("fc_offset")
        and pm.get("magic_offset") is not None
    )
    magic_hex = _hex_str(pm["magic"].replace(" ", ""))

    for style in spec.get("styles", []):
        # ── ENIP: prefer a true CIP service-code match where the style carries
        # one (Read 0x4C vs Write 0x4D vs Reset 0x05 …). This is the real
        # operation-level semantic match — the CIP service lives in the
        # SendRRData (6f 00) CPF data item: `b2 00 <len:2> <service>`, so we
        # anchor on the data-item marker and test the service byte 2 bytes on.
        if proto == "enip":
            cip = _STYLE_CIP_SERVICE.get(style)
            if cip:
                if f"cip:{cip}" in seen:
                    continue
                seen.add(f"cip:{cip}")
                svc_name = pm.get("cip_services", {}).get(cip, f"CIP service 0x{cip.upper()}")
                msg = _clean_msg(
                    f"ICSForge SEMANTIC {tech} {spec['tech_name']} "
                    f"[{spec['proto_label']}] {svc_name}"
                )
                rules.append(
                    f'alert {transport} any any -> any {port} '
                    f'(msg:"{msg}"; '
                    f'flow:to_server; '
                    f'content:"|6f 00|"; offset:0; depth:2; '
                    f'content:"|b2 00|"; '
                    f'content:"|{cip}|"; distance:2; within:1; '
                    f'classtype:attempted-admin; '
                    f'sid:{sid_start + len(rules)}; rev:1; '
                    f'metadata:confidence semantic, icsforge_tier 3, '
                    f'mitre_technique {tech}, icsforge_scenario {spec["id"]}, '
                    f'icsforge_style {style}, '
                    f'created_at {date.today().isoformat()};)'
                )
                continue
            # else: fall through to the encapsulation-word match below

        fc = style_fcs.get(style)
        if not fc or fc in seen:
            continue
        seen.add(fc)
        fc_name = pm["function_codes"].get(fc.upper(), f"FC 0x{fc.upper()}")
        fc_hex = _hex_str(fc.replace(" ", ""))
        msg = _clean_msg(
            f"ICSForge SEMANTIC {tech} {spec['tech_name']} "
            f"[{spec['proto_label']}] {fc_name}"
        )
        if overlap:
            # Tier 3 for overlap protocols: same content match as Tier 2
            # (the command byte at offset 0 IS the function code), but
            # we add `byte_test` to verify the length field is non-zero.
            # This makes Tier 3 strictly more specific and prevents
            # Suricata's signature group manager from collapsing the two
            # rules at the multi-pattern matcher level.
            #
            # Length-field offset varies by protocol:
            #   ENIP:   bytes 2-3, little-endian
            #   OPC UA: bytes 4-7, little-endian (we test 1 byte at offset 4)
            #   MQTT:   byte 1, single-byte (Variable Byte Integer >= 1)
            length_byte_test = {
                "enip":  "byte_test:2,>,0,2,little; ",
                "opcua": "byte_test:1,>,0,4; ",
                "mqtt":  "byte_test:1,>,0,1; ",
            }.get(proto, "")
            # ENIP discovery/teardown commands (ListIdentity 63 00, ListServices
            # 04 00, ListInterfaces 64 00, UnRegisterSession 66 00) legitimately
            # carry a ZERO-length encapsulation data field, so a "length > 0"
            # byte_test would never fire on them. For those the command word IS
            # the complete semantic, so drop the byte_test and match the word.
            if proto == "enip" and fc.replace(" ", "").lower() in ("6300", "0400", "6400", "6600"):
                length_byte_test = ""
            content_clauses = (
                f'content:"{fc_hex}"; offset:{pm["fc_offset"]}; depth:{pm["fc_depth"]}; '
                f'{length_byte_test}'
            )
        else:
            content_clauses = (
                f'content:"{magic_hex}"; offset:{pm["magic_offset"]}; depth:{pm["magic_depth"]}; '
                f'content:"{fc_hex}"; offset:{pm["fc_offset"]}; depth:{pm["fc_depth"]}; '
            )
        rules.append(
            f'alert {transport} any any -> any {port} '
            f'(msg:"{msg}"; '
            f'flow:to_server; '
            f'{content_clauses}'
            f'classtype:attempted-admin; '
            f'sid:{sid_start + len(rules)}; rev:1; '
            f'metadata:confidence semantic, icsforge_tier 3, '
            f'mitre_technique {tech}, icsforge_scenario {spec["id"]}, '
            f'icsforge_style {style}, '
            f'created_at {date.today().isoformat()};)'
        )
    return rules


# ── Sigma builder ──────────────────────────────────────────────────────────────

def sigma_rule(spec: dict) -> str:
    tech = spec["technique"]
    tech_name = spec["tech_name"]
    sc_id = spec["id"]
    port = spec["port"]
    proto = spec["proto"]
    proto_label = spec["proto_label"]
    title = spec["title"].replace("'", "''")
    today = date.today().isoformat()
    pm = _PROTO_MAGIC.get(proto, {})
    transport = pm.get("transport", "tcp")
    zeek_svc = _ZEEK_SERVICE.get(proto, proto)
    style_fcs = _STYLE_FC.get(proto, {})

    # Build function-code-level detection where possible
    unique_fcs = list({style_fcs.get(s) for s in spec.get("styles", [])
                       if style_fcs.get(s)})
    fc_names = [pm["function_codes"].get(fc.upper(), f"0x{fc.upper()}")
                for fc in unique_fcs]

    # Zeek field varies by protocol
    zeek_fc_field = {
        "modbus": "modbus.func_code",
        "dnp3": "dnp3.app_func_code",
        "mqtt": "mqtt.packet_type_name",
        "bacnet": "bacnet.service_choice",
    }.get(proto)

    if zeek_fc_field and unique_fcs:
        fc_values = "\n".join(f"            - '{fc}'" for fc in unique_fcs)
        semantic_detection = (
            f"    semantic:\n"
            f"        {zeek_fc_field}|contains:\n"
            f"{fc_values}\n"
            f"        # Matches: {', '.join(fc_names)}\n"
            f"    condition_semantic: semantic"
        )
    else:
        semantic_detection = (
            f"    semantic:\n"
            f"        dst_port: {port}\n"
            f"        network.transport: '{transport}'\n"
            f"        # No protocol-specific Zeek field available for {proto};\n"
            f"        # use Suricata tier 3 for function-code-level matching\n"
            f"    condition_semantic: semantic"
        )

    fp_note = (
        f"    - Tier 1 lab_marker: Only fires on ICSForge traffic, zero FP on real traffic\n"
        f"    - Tier 2 protocol_heuristic: Any {proto_label} traffic including legitimate use\n"
        f"    - Tier 3 semantic: Rare/anomalous function codes in {proto_label} — "
        f"tune per environment"
    )

    return (
        f"title: ICSForge {tech} {tech_name} [{proto_label}]\n"
        f"id: {_sigma_id(sc_id)}\n"
        f"status: experimental\n"
        f"description: >\n"
        f"    ICSForge detection scaffold for ATT&CK for ICS {tech} ({tech_name}).\n"
        f"    Scenario: {title}\n"
        f"    Protocol: {proto_label} port {port}.\n"
        f"    Three confidence tiers — choose based on operational context:\n"
        f"      lab_marker (tier 1): zero FP, ICSForge validation only.\n"
        f"      protocol_heuristic (tier 2): protocol visibility check, may FP.\n"
        f"      semantic (tier 3): function-code specific, low FP in segmented OT.\n"
        f"references:\n"
        f"    - https://attack.mitre.org/techniques/ics/{tech}/\n"
        f"    - https://www.icsforge.nl\n"
        f"author: ICSForge v{__version__}\n"
        f"date: {today}\n"
        f"tags:\n"
        f"    - attack.ics.{tech.lower()}\n"
        f"    - icsforge\n"
        f"logsource:\n"
        f"    category: network_traffic\n"
        f"    product: zeek\n"
        f"detection:\n"
        f"    lab_marker:\n"
        f"        # v0.74.0 compact marker; covert mode uses a protocol-field\n"
        f"        # synthetic band (0x{_SYNTH_BAND_HEX}), explicit mode emits 'ICSF' in payload.\n"
        f"        payload|contains: 'ICSF'\n"
        f"    protocol_heuristic:\n"
        f"        dst_port: {port}\n"
        f"        network.transport: '{transport}'\n"
        f"        network.protocol: '{zeek_svc}'\n"
        f"{semantic_detection}\n"
        f"    condition: lab_marker or protocol_heuristic or semantic\n"
        f"falsepositives:\n"
        f"{fp_note}\n"
        f"level: medium\n"
        f"fields:\n"
        f"    - src_ip\n"
        f"    - dst_ip\n"
        f"    - dst_port\n"
        f"    - network.protocol\n"
        f"    - payload\n"
        f"custom:\n"
        f"    confidence_tiers:\n"
        f"        lab_marker: zero-fp-requires-icsforge-marker\n"
        f"        protocol_heuristic: protocol-visibility-may-fp\n"
        f"        semantic: function-code-level-low-fp\n"
        f"    mitre_technique: {tech}\n"
        f"    icsforge_scenario: {sc_id}\n"
        f"    icsforge_proto: {proto}\n"
        f"    icsforge_styles: {spec.get('styles', [])}\n"
        f"    function_codes_matched: {unique_fcs}\n"
    )


# ── Main ───────────────────────────────────────────────────────────────────────

def generate_all(
    technique_filter: list[str] | None = None,
    include_marker: bool = True,
) -> dict[str, Any]:
    specs = _load_specs()
    if technique_filter:
        specs = {k: v for k, v in specs.items()
                 if v.get("technique") in technique_filter}

    header = (
        f"# ICSForge v{__version__} — ATT&CK for ICS Detection Rules\n"
        f"# Generated {date.today().isoformat()}\n"
        f"# {len(specs)} scenarios\n"
        f"#\n"
        f"# Confidence tiers:\n"
        f"#   Tier 1 lab_marker        — ICSFORGE_SYNTH marker required. Zero FP.\n"
        f"#   Tier 2 protocol_heuristic — Protocol magic bytes. FPs on legit traffic.\n"
        f"#   Tier 3 semantic           — Function code/command specific. Low FP.\n"
        f"#\n"
        f"# Recommendation: deploy icsforge_semantic.rules for real-network detection;\n"
        f"#                  use icsforge_lab.rules only during ICSForge runs.\n"
    )

    t1_lines = [header + "# === TIER 1: LAB MARKER ===\n"]
    t2_lines = [header + "# === TIER 2: PROTOCOL HEURISTIC ===\n"]
    t3_lines = [header + "# === TIER 3: SEMANTIC (RECOMMENDED) ===\n"]
    sigma_rules: dict[str, str] = {}
    zeek_signatures: list[str] = []  # L2-only protocols (GOOSE, PROFINET DCP)
    techniques: set[str] = set()
    sid = _SID_BASE
    c1 = c2 = c3 = 0
    cz = 0  # Zeek signature count

    for sc_id, spec in sorted(specs.items()):
        # Tier 1 — emits None for L2-only protocols (Suricata cannot match them)
        r1 = _tier1_marker(spec, sid)
        if r1:
            t1_lines += [f"# {sc_id}", r1, ""]
            sid += 1
            c1 += 1

        # Tier 2 — now returns a list (one or more rules per scenario;
        # ENIP/OPC UA/MQTT need per-command-byte rules, see _tier2_heuristic)
        r2_list = _tier2_heuristic(spec, sid)
        if r2_list:
            t2_lines.append(f"# {sc_id}")
            for r in r2_list:
                t2_lines.append(r)
                sid += 1
                c2 += 1
            t2_lines.append("")

        # Tier 3
        r3_list = _tier3_semantic(spec, sid)
        if r3_list:
            t3_lines.append(f"# {sc_id}")
            for r in r3_list:
                t3_lines.append(r)
                sid += 1
                c3 += 1
            t3_lines.append("")

        # Zeek signatures — emitted for L2-only protocols (returns [] for IP)
        zeek_blocks = _zeek_signature(spec, sid)
        for block in zeek_blocks:
            zeek_signatures.append(block)
            cz += 1

        sigma_rules[sc_id] = sigma_rule(spec)
        techniques.add(spec["technique"])

    return {
        "suricata_lab":        "\n".join(t1_lines),
        "suricata_heuristic":  "\n".join(t2_lines),
        "suricata_semantic":   "\n".join(t3_lines),
        "suricata":            "\n".join(t3_lines),  # legacy compat
        "sigma":               sigma_rules,
        "zeek":                _zeek_header() + "\n\n".join(zeek_signatures) + "\n",
        "count":               len(specs),
        "techniques":          sorted(techniques),
        "rule_counts": {
            "lab_marker":         c1,
            "protocol_heuristic": c2,
            "semantic":           c3,
            "zeek":               cz,
        },
    }


# ── CLI entry: python -m icsforge.detection.generator --outdir /path ─────
def _write_outputs(outdir: str, result: dict[str, Any]) -> None:
    """Write the three Suricata rule files + per-scenario Sigma rules to outdir."""
    import os as _os

    _os.makedirs(outdir, exist_ok=True)
    with open(_os.path.join(outdir, "icsforge_lab.rules"), "w", encoding="utf-8") as f:
        f.write(result["suricata_lab"])
    with open(_os.path.join(outdir, "icsforge_heuristic.rules"), "w", encoding="utf-8") as f:
        f.write(result["suricata_heuristic"])
    with open(_os.path.join(outdir, "icsforge_semantic.rules"), "w", encoding="utf-8") as f:
        f.write(result["suricata_semantic"])

    sigma_dir = _os.path.join(outdir, "sigma")
    _os.makedirs(sigma_dir, exist_ok=True)
    for sc_id, body in result["sigma"].items():
        safe = "".join(c for c in sc_id if c.isalnum() or c in "._-")[:180] or "scenario"
        with open(_os.path.join(sigma_dir, f"{safe}.yml"), "w", encoding="utf-8") as f:
            f.write(body)

    # Zeek signatures for L2-only protocols (GOOSE, PROFINET DCP)
    zeek_content = result.get("zeek", "")
    if zeek_content.strip():
        with open(_os.path.join(outdir, "icsforge.sig"), "w", encoding="utf-8") as f:
            f.write(zeek_content)

    readme = (
        "ICSForge detection content\n"
        "==========================\n\n"
        "Three confidence tiers (recommendation: deploy tier 3 only):\n\n"
        "  icsforge_lab.rules        Tier 1 - requires ICSFORGE_SYNTH marker\n"
        "                            Use only during ICSForge runs.\n"
        "                            Zero false positives.\n\n"
        "  icsforge_heuristic.rules  Tier 2 - protocol magic bytes.\n"
        "                            Fires on ANY legit protocol traffic.\n"
        "                            Use to validate NSM visibility only.\n\n"
        "  icsforge_semantic.rules   Tier 3 - function-code / command-level.\n"
        "                            Recommended for real networks.\n"
        "                            Low FP rate in segmented OT.\n\n"
        "  icsforge.sig              Zeek signatures for L2 protocols.\n"
        "                            Covers IEC 61850 GOOSE (0x88B8) and\n"
        "                            PROFINET DCP (0x8892). Suricata 7.x\n"
        "                            cannot match L2 traffic; Zeek can via\n"
        "                            its signature framework `eth-proto` and\n"
        "                            `payload` keywords.\n\n"
        f"Rule counts:  lab={result['rule_counts']['lab_marker']}  "
        f"heuristic={result['rule_counts']['protocol_heuristic']}  "
        f"semantic={result['rule_counts']['semantic']}  "
        f"zeek={result['rule_counts'].get('zeek', 0)}\n"
        f"Scenarios covered: {result['count']}\n"
        f"Unique techniques: {len(result['techniques'])}\n"
    )
    with open(_os.path.join(outdir, "README.txt"), "w", encoding="utf-8") as f:
        f.write(readme)


def main(argv: list[str] | None = None) -> int:
    import argparse as _argparse

    p = _argparse.ArgumentParser(
        prog="icsforge.detection.generator",
        description="Generate ICSForge Suricata + Sigma detection content.",
    )
    p.add_argument("--outdir", default="out/detections",
                   help="Directory to write rule files (default: out/detections)")
    p.add_argument("--technique", action="append", default=None,
                   help="Filter to one or more technique IDs (e.g. T0855). Repeatable.")
    p.add_argument("--no-marker", action="store_true",
                   help="Omit lab_marker tier (tier 1) from output.")
    p.add_argument("--quiet", action="store_true", help="Suppress progress output.")
    args = p.parse_args(argv)

    result = generate_all(
        technique_filter=args.technique,
        include_marker=not args.no_marker,
    )
    _write_outputs(args.outdir, result)

    if not args.quiet:
        counts = result["rule_counts"]
        print(f"[generator] wrote to {args.outdir}")
        print(f"[generator] lab={counts['lab_marker']} "
              f"heuristic={counts['protocol_heuristic']} "
              f"semantic={counts['semantic']}")
        print(f"[generator] {result['count']} scenarios, "
              f"{len(result['techniques'])} unique techniques")
    return 0


if __name__ == "__main__":
    import sys as _sys
    _sys.exit(main())
