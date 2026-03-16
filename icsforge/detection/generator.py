"""
ICSForge Detection Content Generator

Generates Suricata rules and Sigma rules for each scenario.
Rules are based on:
  1. Destination port (protocol-specific, well-known)
  2. Protocol header bytes (first 8B of payload — consistent per proto)
  3. ICSForge marker prefix (ICSFORGE_SYNTH|) for precise lab validation
  4. ATT&CK technique ID embedded in rule metadata
"""
import json
import re
from datetime import date
from pathlib import Path
from typing import Any

_SPECS_PATH = Path(__file__).parent.parent / "data" / "detection_rules_specs.json"

# Marker prefix as hex bytes for Suricata content match
_MARKER_PREFIX_HEX = "494353464f5247455f53594e54487c"   # ICSFORGE_SYNTH|

_SURICATA_PROTO = {
    "modbus": "tcp", "dnp3": "tcp", "s7comm": "tcp",
    "iec104": "tcp", "opcua": "tcp", "enip":   "tcp",
    "profinet_dcp": "tcp", "mqtt": "tcp", "bacnet": "udp",
}

_SID_BASE = 9_800_000


def _load_specs() -> dict[str, Any]:
    return json.loads(_SPECS_PATH.read_text(encoding="utf-8"))


def _hex_to_suricata(h: str) -> str:
    return "|" + " ".join(h[i:i+2].upper() for i in range(0, len(h), 2)) + "|"


def _suricata_msg(s: str) -> str:
    """Strip characters illegal in Suricata msg field: quotes, parens, semicolons."""
    s = re.sub(r'[();"\'\\]', '', s)
    return s[:120].strip()


def _sigma_id(sc_id: str) -> str:
    return "icsforge-" + sc_id.lower().replace("_", "-")[:60]


def suricata_rule(spec: dict, sid: int, include_marker: bool = True) -> str:
    """Generate a single valid Suricata rule for one scenario."""
    proto      = _SURICATA_PROTO.get(spec["proto"], "tcp")
    port       = spec["port"] or 502
    tech       = spec["technique"]
    tech_name  = _suricata_msg(spec["tech_name"])
    sc_id      = spec["id"]
    # Strip proto_label parens for msg (S7comm ISO-TSAP, not S7comm (ISO-TSAP))
    proto_label = _suricata_msg(spec["proto_label"])
    title       = _suricata_msg(spec["title"])
    header_hex  = spec.get("header_hex", "")

    content_matches = []
    if header_hex:
        content_matches.append(
            f'content:"{_hex_to_suricata(header_hex)}"; depth:8; offset:0;')
    if include_marker:
        content_matches.append(
            f'content:"{_hex_to_suricata(_MARKER_PREFIX_HEX)}";')

    content_str = " ".join(content_matches)
    msg = f"ICSForge {tech} {tech_name} {proto_label} - {title}"

    return (
        f'alert {proto} any any -> any {port} '
        f'(msg:"{msg}"; '
        f'flow:established,to_server; '
        f'{content_str} '
        f'classtype:attempted-admin; '
        f'sid:{sid}; rev:1; '
        f'metadata:mitre_technique {tech}, '
        f'icsforge_scenario {sc_id}, '
        f'created_at {date.today().isoformat()};)'
    )


def sigma_rule(spec: dict, include_marker: bool = True) -> str:
    """Generate a valid Sigma rule (YAML) for one scenario."""
    tech        = spec["technique"]
    tech_name   = spec["tech_name"]
    sc_id       = spec["id"]
    port        = spec["port"]
    proto       = spec["proto"]
    proto_label = spec["proto_label"]
    title       = spec["title"].replace("'", "''")
    today       = date.today().isoformat()

    detection_block = ""
    if include_marker:
        detection_block = (
            "    keywords:\n"
            "        payload|contains: 'ICSFORGE_SYNTH'\n"
            "    condition: keywords"
        )
    else:
        detection_block = (
            f"    selection:\n"
            f"        dst_port: {port}\n"
            f"    condition: selection"
        )

    return (
        f"title: ICSForge {tech} {tech_name} [{proto_label}]\n"
        f"id: {_sigma_id(sc_id)}\n"
        f"status: experimental\n"
        f"description: >\n"
        f"    ICSForge detection for ATT&CK ICS {tech} ({tech_name}).\n"
        f"    Scenario: {title}\n"
        f"    Protocol: {proto_label} (port {port})\n"
        f"references:\n"
        f"    - https://attack.mitre.org/techniques/ics/{tech}/\n"
        f"author: ICSForge v0.42\n"
        f"date: {today}\n"
        f"tags:\n"
        f"    - attack.ics.{tech.lower()}\n"
        f"    - icsforge\n"
        f"logsource:\n"
        f"    category: network_traffic\n"
        f"    product: zeek\n"
        f"detection:\n"
        f"{detection_block}\n"
        f"falsepositives:\n"
        f"    - Legitimate {proto_label} traffic on port {port}\n"
        f"    - Only fires on ICSForge synthetic traffic when marker present\n"
        f"level: medium\n"
        f"fields:\n"
        f"    - src_ip\n"
        f"    - dst_ip\n"
        f"    - dst_port\n"
        f"    - payload\n"
        f"custom:\n"
        f"    mitre_technique: {tech}\n"
        f"    icsforge_scenario: {sc_id}\n"
        f"    icsforge_proto: {proto}\n"
    )


def generate_all(
    technique_filter: list[str] | None = None,
    include_marker: bool = True,
) -> dict[str, Any]:
    specs = _load_specs()
    if technique_filter:
        specs = {k: v for k, v in specs.items()
                 if v.get("technique") in technique_filter}

    suricata_lines = [
        "# ICSForge v0.42 — ATT&CK for ICS Detection Rules",
        f"# Generated {date.today().isoformat()}",
        f"# {len(specs)} rules | SID range {_SID_BASE}–{_SID_BASE+len(specs)-1}",
        "# Usage: suricata -r capture.pcap -S icsforge_ics.rules",
        "",
    ]
    sigma_rules: dict[str, str] = {}
    techniques_covered: set[str] = set()

    for i, (sc_id, spec) in enumerate(sorted(specs.items())):
        sid = _SID_BASE + i
        suricata_lines.append(f"# Scenario: {sc_id}")
        suricata_lines.append(suricata_rule(spec, sid, include_marker))
        suricata_lines.append("")
        sigma_rules[sc_id] = sigma_rule(spec, include_marker)
        techniques_covered.add(spec["technique"])

    return {
        "suricata":   "\n".join(suricata_lines),
        "sigma":      sigma_rules,
        "count":      len(specs),
        "techniques": sorted(techniques_covered),
    }
