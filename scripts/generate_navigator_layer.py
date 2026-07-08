#!/usr/bin/env python3
"""
Generate the MITRE ATT&CK Navigator layer JSON for ICSForge coverage.

Output: docs/icsforge-coverage-layer.json

Run after every release to keep the published Navigator layer in sync
with the scenario library. Reviewers can drag-and-drop the JSON into
https://mitre-attack.github.io/attack-navigator/ to see colour-coded
coverage of MITRE ATT&CK for ICS.

Tier colour scheme:
  green  (10/10 protocols)  — full coverage
  yellow (5-9 protocols)    — strong partial coverage
  orange (1-4 protocols)    — partial coverage
  grey   (0 protocols)      — out of scope (host-only, physical, etc.)
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
SCENARIOS_YML = REPO / "icsforge" / "scenarios" / "scenarios.yml"
OUTPUT = REPO / "docs" / "icsforge-coverage-layer.json"


# Canonical MITRE ATT&CK ICS technique catalog (83 entries).
# Source: https://attack.mitre.org/techniques/ics/  (retrieved 2026-04-29)
MITRE_NAMES = {
    'T0800': 'Activate Firmware Update Mode',
    'T0801': 'Monitor Process State',
    'T0802': 'Automated Collection',
    'T0803': 'Block Command Message',
    'T0804': 'Block Reporting Message',
    'T0805': 'Block Serial COM',
    'T0806': 'Brute Force I/O',
    'T0807': 'Command-Line Interface',
    'T0809': 'Data Destruction',
    'T0811': 'Data from Information Repositories',
    'T0812': 'Default Credentials',
    'T0813': 'Denial of Control',
    'T0814': 'Denial of Service',
    'T0815': 'Denial of View',
    'T0816': 'Device Restart/Shutdown',
    'T0817': 'Drive-by Compromise',
    'T0819': 'Exploit Public-Facing Application',
    'T0820': 'Exploitation for Evasion',
    'T0821': 'Modify Controller Tasking',
    'T0822': 'External Remote Services',
    'T0823': 'Graphical User Interface',
    'T0826': 'Loss of Availability',
    'T0827': 'Loss of Control',
    'T0828': 'Loss of Productivity and Revenue',
    'T0829': 'Loss of View',
    'T0830': 'Adversary-in-the-Middle',
    'T0831': 'Manipulation of Control',
    'T0832': 'Manipulation of View',
    'T0834': 'Native API',
    'T0835': 'Manipulate I/O Image',
    'T0836': 'Modify Parameter',
    'T0837': 'Loss of Protection',
    'T0838': 'Modify Alarm Settings',
    'T0839': 'Module Firmware',
    'T0840': 'Network Connection Enumeration',
    'T0842': 'Network Sniffing',
    'T0843': 'Program Download',
    'T0845': 'Program Upload',
    'T0846': 'Remote System Discovery',
    'T0847': 'Replication Through Removable Media',
    'T0848': 'Rogue Master',
    'T0849': 'Masquerading',
    'T0851': 'Rootkit',
    'T0852': 'Screen Capture',
    'T0853': 'Scripting',
    'T0855': 'Unauthorized Command Message',
    'T0856': 'Spoof Reporting Message',
    'T0857': 'System Firmware',
    'T0858': 'Change Operating Mode',
    'T0859': 'Valid Accounts',
    'T0860': 'Wireless Compromise',
    'T0861': 'Point & Tag Identification',
    'T0862': 'Supply Chain Compromise',
    'T0863': 'User Execution',
    'T0864': 'Transient Cyber Asset',
    'T0865': 'Spearphishing Attachment',
    'T0866': 'Exploitation of Remote Services',
    'T0867': 'Lateral Tool Transfer',
    'T0868': 'Detect Operating Mode',
    'T0869': 'Standard Application Layer Protocol',
    'T0871': 'Execution through API',
    'T0872': 'Indicator Removal on Host',
    'T0873': 'Project File Infection',
    'T0874': 'Hooking',
    'T0877': 'I/O Image',
    'T0878': 'Alarm Suppression',
    'T0879': 'Damage to Property',
    'T0880': 'Loss of Safety',
    'T0881': 'Service Stop',
    'T0882': 'Theft of Operational Information',
    'T0883': 'Internet Accessible Device',
    'T0884': 'Connection Proxy',
    'T0885': 'Commonly Used Port',
    'T0886': 'Remote Services',
    'T0887': 'Wireless Sniffing',
    'T0888': 'Remote System Information Discovery',
    'T0889': 'Modify Program',
    'T0890': 'Exploitation for Privilege Escalation',
    'T0891': 'Hardcoded Credentials',
    'T0892': 'Change Credential',
    'T0893': 'Data from Local System',
    'T0894': 'System Binary Proxy Execution',
    'T0895': 'Autorun Image',
}

PROTO_LABEL = {
    'modbus': 'Modbus/TCP', 'dnp3': 'DNP3', 'iec104': 'IEC-104',
    's7comm': 'S7comm', 'enip': 'EtherNet/IP', 'opcua': 'OPC UA',
    'mqtt': 'MQTT', 'bacnet': 'BACnet/IP',
    'profinet_dcp': 'PROFINET DCP', 'iec61850': 'IEC 61850 GOOSE',
}


def get_version() -> str:
    sys.path.insert(0, str(REPO))
    try:
        from icsforge import __version__  # type: ignore
        return __version__
    except ImportError:
        return "unknown"


def main() -> int:
    with open(SCENARIOS_YML) as f:
        sc = yaml.safe_load(f)["scenarios"]

    proto_for: dict[str, set[str]] = defaultdict(set)
    scenarios_for: dict[str, set[str]] = defaultdict(set)
    for sc_name, body in sc.items():
        for step in body.get("steps", []):
            tech = step.get("technique")
            proto = step.get("proto")
            if tech and proto:
                proto_for[tech].add(proto)
                scenarios_for[tech].add(sc_name)

    techniques = []
    for tech in sorted(MITRE_NAMES):
        if tech in proto_for:
            n_protos = len(proto_for[tech])
            n_scenarios = len(scenarios_for[tech])
            if n_protos == 10:
                color, score = "#2ecc40", 100
            elif n_protos >= 5:
                color, score = "#ffdc00", 75
            else:
                color, score = "#ff851b", 50
            proto_names = sorted(
                PROTO_LABEL[p] for p in proto_for[tech] if p in PROTO_LABEL
            )
            comment = (
                f"ICSForge: {n_scenarios} scenario(s), "
                f"{n_protos}/10 protocols: {', '.join(proto_names)}"
            )
            techniques.append({
                "techniqueID": tech,
                "score": score,
                "color": color,
                "comment": comment,
                "enabled": True,
                "metadata": [
                    {"name": "Protocols", "value": f"{n_protos}/10"},
                    {"name": "Scenarios", "value": str(n_scenarios)},
                ],
                "showSubtechniques": False,
            })
        else:
            techniques.append({
                "techniqueID": tech,
                "score": 0,
                "color": "#aaaaaa",
                "comment": "ICSForge: not covered (out of scope or precursor)",
                "enabled": False,
                "showSubtechniques": False,
            })

    version = get_version()
    n_covered = sum(1 for t in techniques if t["score"] >= 50)
    n_total = len(techniques)
    pct = 100 * n_covered / n_total

    layer = {
        "name": f"ICSForge {version} — MITRE ATT&CK ICS Coverage",
        "versions": {
            "attack": "18",
            "navigator": "5.1.0",
            "layer": "4.5",
        },
        "domain": "ics-attack",
        "description": (
            f"ICSForge v{version} coverage of MITRE ATT&CK for ICS. "
            f"Covers {n_covered} of {n_total} techniques ({pct:.1f}%). "
            f"Color: green=10/10 protocols, yellow=5-9, orange=1-4, grey=out of scope. "
            f"See https://github.com/ICSForge/ICSForge for details."
        ),
        "filters": {
            "platforms": [
                "Windows", "Linux", "Embedded", "Field Controller/RTU/PLC/IED",
                "Safety Instrumented System/Protection Relay", "Control Server",
                "Data Historian", "Engineering Workstation",
                "Human-Machine Interface", "Input/Output Server",
            ],
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ff851b", "#ffdc00", "#2ecc40"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "10/10 protocols", "color": "#2ecc40"},
            {"label": "5-9 protocols",   "color": "#ffdc00"},
            {"label": "1-4 protocols",   "color": "#ff851b"},
            {"label": "Not covered",     "color": "#aaaaaa"},
        ],
        "metadata": [
            {"name": "ICSForge version", "value": version},
            {"name": "Total scenarios", "value": str(len(sc))},
            {"name": "Distinct techniques", "value": str(len(proto_for))},
            {"name": "MITRE coverage", "value": f"{pct:.1f}%"},
            {"name": "Source", "value": "https://github.com/ICSForge/ICSForge"},
        ],
        "showTacticRowBackground": False,
        "selectVisibleTechniques": False,
        "selectSubtechniquesWithParent": False,
    }

    OUTPUT.write_text(json.dumps(layer, indent=2))
    print(f"Wrote: {OUTPUT.relative_to(REPO)}")
    print(f"  Version: {version}")
    print(f"  Covered: {n_covered}/{n_total} techniques ({pct:.1f}%)")
    print(f"  Green (10/10):  {sum(1 for t in techniques if t['score'] == 100)}")
    print(f"  Yellow (5-9):   {sum(1 for t in techniques if t['score'] == 75)}")
    print(f"  Orange (1-4):   {sum(1 for t in techniques if t['score'] == 50)}")
    print(f"  Grey (none):    {sum(1 for t in techniques if t['score'] == 0)}")
    print()
    print("Drag-and-drop the JSON at https://mitre-attack.github.io/attack-navigator/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
