"""
ICSForge Alert-to-Technique Mapping

Maps IDS/SIEM alert signatures to MITRE ATT&CK for ICS technique IDs.
Patterns cover:
  - Suricata ET ICS/SCADA rule naming conventions
  - Snort ICS rule patterns
  - Protocol-specific indicators (Modbus, DNP3, S7comm, IEC-104, OPC UA, ENIP, BACnet, PROFINET, MQTT)
  - Generic OT/ICS alert patterns from common NSM/IDS platforms
  - MITRE ATT&CK for ICS technique names appearing in alert metadata

v0.41: Expanded from 13 to 70+ rules covering all 8 protocols.
"""

import re
from typing import Any

# ── Pattern → Technique mapping rules ────────────────────────────────
# Each tuple: (compiled_regex, technique_id)
# Regex is matched against the alert signature/msg/message field.

RULES = [
    # ── T0840 Network Connection Enumeration ──────────────────────────
    (re.compile(r"(scan|sweep|enumerat|probe|discover)", re.I), "T0840"),
    (re.compile(r"(who.is|list.identity|list.services|identify.all)", re.I), "T0840"),
    (re.compile(r"ET SCADA.*(scan|discover|enumerat)", re.I), "T0840"),
    (re.compile(r"ENIP.*list.?identity", re.I), "T0840"),
    (re.compile(r"BACnet.*who.?is", re.I), "T0840"),
    (re.compile(r"profinet.*dcp.*identify", re.I), "T0840"),

    # ── T0888 Remote System Information Discovery ─────────────────────
    (re.compile(r"(device.?info|fingerprint|system.?info|SZL|read.?device.?id)", re.I), "T0888"),
    (re.compile(r"(get.?attribute|identity.?object|product.?info)", re.I), "T0888"),
    (re.compile(r"S7.*(SZL|SSL|system.?status)", re.I), "T0888"),
    (re.compile(r"OPC.?UA.*(find.?server|get.?endpoint)", re.I), "T0888"),
    (re.compile(r"ENIP.*(get.?identity|get.?attribute)", re.I), "T0888"),
    (re.compile(r"BACnet.*read.?property.*(device|vendor|model|firmware)", re.I), "T0888"),

    # ── T0861 Point & Tag Identification ──────────────────────────────
    (re.compile(r"(tag|point|object).*?(enumerat|browse|discover|who.?has)", re.I), "T0861"),
    (re.compile(r"OPC.?UA.*(browse|translate.?path)", re.I), "T0861"),
    (re.compile(r"BACnet.*who.?has", re.I), "T0861"),
    (re.compile(r"modbus.*(register|coil).*sweep", re.I), "T0861"),

    # ── T0841 Network Service Scanning ────────────────────────────────
    (re.compile(r"(port.?scan|service.?scan|nmap|masscan)", re.I), "T0841"),
    (re.compile(r"(sequential|rapid).*(read|request|query)", re.I), "T0841"),
    (re.compile(r"modbus.*coil.*sweep", re.I), "T0841"),

    # ── T0855 Unauthorized Command Message ────────────────────────────
    (re.compile(r"unauthorized.*(write|command|operate|control)", re.I), "T0855"),
    (re.compile(r"modbus.*(write|fc0[56f]|fc1[056])", re.I), "T0855"),
    (re.compile(r"dnp3.*(operate|direct.?operate|select.?before)", re.I), "T0855"),
    (re.compile(r"iec.?104.*(command|C_SC|C_DC|C_SE)", re.I), "T0855"),
    (re.compile(r"s7.*(write.?var|write.?output)", re.I), "T0855"),
    (re.compile(r"OPC.?UA.*write.?(value|node)", re.I), "T0855"),
    (re.compile(r"ENIP.*(write.?tag|set.?attribute)", re.I), "T0855"),
    (re.compile(r"BACnet.*write.?property", re.I), "T0855"),
    (re.compile(r"ET SCADA.*(write|command|operate)", re.I), "T0855"),

    # ── T0831 Manipulation of Control ─────────────────────────────────
    (re.compile(r"(setpoint|manipulat).*(control|process)", re.I), "T0831"),
    (re.compile(r"(control.?loop|feedback).*(change|modif|alter)", re.I), "T0831"),
    (re.compile(r"dnp3.*select.?before.?operate", re.I), "T0831"),

    # ── T0836 Modify Parameter ────────────────────────────────────────
    (re.compile(r"(parameter|config|setting).*(modif|change|alter|write)", re.I), "T0836"),
    (re.compile(r"modbus.*(mask.?write|fc16|fc22)", re.I), "T0836"),
    (re.compile(r"iec.?104.*(param|P_ME|P_AC)", re.I), "T0836"),
    (re.compile(r"BACnet.*write.?property.?multiple", re.I), "T0836"),

    # ── T0832 Manipulation of View ────────────────────────────────────
    (re.compile(r"(manipulat).*(view|display|hmi|dashboard)", re.I), "T0832"),
    (re.compile(r"(spoof|inject).*(measurement|sensor|reading)", re.I), "T0832"),

    # ── T0848 Rogue Master Device ─────────────────────────────────────
    (re.compile(r"(rogue|new|unknown|unexpected).*(master|client|controller)", re.I), "T0848"),
    (re.compile(r"(unauthorized|unauthenticated).*(source|origin|address)", re.I), "T0848"),

    # ── T0801 Monitor Process State ───────────────────────────────────
    (re.compile(r"(monitor|poll|read).*(process|state|value|analog|sensor)", re.I), "T0801"),
    (re.compile(r"modbus.*read.*(holding|input|register)", re.I), "T0801"),
    (re.compile(r"OPC.?UA.*read.?value", re.I), "T0801"),
    (re.compile(r"BACnet.*read.?property", re.I), "T0801"),

    # ── T0802 Automated Collection ────────────────────────────────────
    (re.compile(r"(automated|bulk|mass).*(collect|read|poll|harvest)", re.I), "T0802"),
    (re.compile(r"(subscribe|COV|change.?of.?value)", re.I), "T0802"),
    (re.compile(r"OPC.?UA.*(subscribe|publish|create.?subscription)", re.I), "T0802"),

    # ── T0882 Theft of Operational Information ────────────────────────
    (re.compile(r"(theft|exfil|steal).*(operational|data|config)", re.I), "T0882"),
    (re.compile(r"(read.?file|download.?config|extract.?data)", re.I), "T0882"),
    (re.compile(r"OPC.?UA.*history.?read", re.I), "T0882"),
    (re.compile(r"S7.*read.?db", re.I), "T0882"),
    (re.compile(r"BACnet.*atomic.?read.?file", re.I), "T0882"),

    # ── T0814 Denial of Service ───────────────────────────────────────
    (re.compile(r"(dos|flood|rate.?anomaly|burst|saturat)", re.I), "T0814"),
    (re.compile(r"(excessive|abnormal).*(request|traffic|packet)", re.I), "T0814"),

    # ── T0813 Denial of Control ───────────────────────────────────────
    (re.compile(r"(denial|block).*(control|command)", re.I), "T0813"),
    (re.compile(r"s7.*(cpu.?stop|plc.?stop)", re.I), "T0813"),
    (re.compile(r"ENIP.*(stop.?device|inhibit)", re.I), "T0813"),
    (re.compile(r"BACnet.*device.?communication.?control", re.I), "T0813"),

    # ── T0815 Denial of View ──────────────────────────────────────────
    (re.compile(r"(loss.?of.?view|telemetry.?gap|reporting.?missing|no.?data)", re.I), "T0815"),
    (re.compile(r"dnp3.*disable.?unsolicited", re.I), "T0815"),
    (re.compile(r"OPC.?UA.*delete.?subscription", re.I), "T0815"),

    # ── T0816 Device Restart ──────────────────────────────────────────
    (re.compile(r"(restart|reboot|reinitialize|cold.?start|warm.?start)", re.I), "T0816"),
    (re.compile(r"dnp3.*(cold|warm).?restart", re.I), "T0816"),
    (re.compile(r"ENIP.*reset.?device", re.I), "T0816"),
    (re.compile(r"BACnet.*reinitialize", re.I), "T0816"),
    (re.compile(r"profinet.*factory.?reset", re.I), "T0816"),

    # ── T0843 Program Download ────────────────────────────────────────
    (re.compile(r"(program|firmware|logic).*(download|upload|transfer)", re.I), "T0843"),
    (re.compile(r"s7.*(download|upload).*(block|program|OB)", re.I), "T0843"),
    (re.compile(r"BACnet.*atomic.?write.?file", re.I), "T0843"),

    # ── T0845 Program Upload ──────────────────────────────────────────
    (re.compile(r"s7.*upload.*(request|block)", re.I), "T0845"),
    (re.compile(r"(upload|extract).*(program|logic|ladder)", re.I), "T0845"),

    # ── T0849 Masquerading ────────────────────────────────────────────
    (re.compile(r"(spoof|fake|masquerad|impersonat)", re.I), "T0849"),
    (re.compile(r"BACnet.*(fake|spoof).*i.?am", re.I), "T0849"),
    (re.compile(r"profinet.*(set.?name|set.?ip)", re.I), "T0849"),
    (re.compile(r"iec.?104.*clock.?sync", re.I), "T0849"),

    # ── T0856 Spoof Reporting Message ─────────────────────────────────
    (re.compile(r"(spoof|false|inject).*(report|response|measurement)", re.I), "T0856"),
    (re.compile(r"dnp3.*unsolicited.*(spoof|inject|false)", re.I), "T0856"),

    # ── T0869 Standard Application Layer Protocol ─────────────────────
    (re.compile(r"(covert|c2|beacon|command.?and.?control).*protocol", re.I), "T0869"),
    (re.compile(r"BACnet.*private.?transfer", re.I), "T0869"),

    # ── T0876 Loss of Safety ──────────────────────────────────────────
    (re.compile(r"(safety|SIS|SIF|trip).*(disable|bypass|inhibit|loss)", re.I), "T0876"),
    (re.compile(r"(failsafe|fail.?safe).*(write|modif|zero)", re.I), "T0876"),

    # ── T0838 Modify Alarm Settings ───────────────────────────────────
    (re.compile(r"(alarm|alert|threshold).*(modif|change|suppress|disable)", re.I), "T0838"),

    # ── T0889 Modify Program ──────────────────────────────────────────
    (re.compile(r"(modify|alter|inject).*(program|logic|code|OB1)", re.I), "T0889"),
    (re.compile(r"BACnet.*create.?object", re.I), "T0889"),

    # ── T0809 Data Destruction ────────────────────────────────────────
    (re.compile(r"(destroy|wipe|zero|erase|delete).*(data|register|block|object)", re.I), "T0809"),
    (re.compile(r"BACnet.*delete.?object", re.I), "T0809"),

    # ── T0858 Change Operating Mode / Credentials ─────────────────────
    (re.compile(r"(change|switch).*(mode|operating|credential|password)", re.I), "T0858"),
    (re.compile(r"dnp3.*authenticate", re.I), "T0858"),

    # ── T0812 Default Credentials ─────────────────────────────────────
    (re.compile(r"(default|blank|factory).*(credential|password|auth)", re.I), "T0812"),

    # ── T0866 Exploitation of Remote Services ─────────────────────────
    (re.compile(r"(exploit|overflow|malform|corrupt).*(service|packet|frame)", re.I), "T0866"),

    # ── T0872 Indicator Removal on Host ───────────────────────────────
    (re.compile(r"(clear|delete|purge).*(log|event|diagnostic|audit)", re.I), "T0872"),

    # ── MQTT-specific ICS rules ──────────────────────────────────────
    (re.compile(r"MQTT.*(connect|CONNECT|unauthorized.?client)", re.I), "T0822"),
    (re.compile(r"MQTT.*(publish|PUBLISH).*(command|actuator|write|setpoint)", re.I), "T0855"),
    (re.compile(r"MQTT.*(publish|PUBLISH).*(config|parameter|tuning|pid)", re.I), "T0836"),
    (re.compile(r"MQTT.*(publish|PUBLISH).*(firmware|update|flash)", re.I), "T0843"),
    (re.compile(r"MQTT.*(publish|PUBLISH).*(alarm|safety|trip|suppress)", re.I), "T0838"),
    (re.compile(r"MQTT.*(subscribe|SUBSCRIBE).*(wildcard|#|\+)", re.I), "T0802"),
    (re.compile(r"MQTT.*(subscribe|SUBSCRIBE).*(sensor|telemetry|monitor)", re.I), "T0801"),
    (re.compile(r"MQTT.*(disconnect|flood|dos|oversize)", re.I), "T0814"),
    (re.compile(r"MQTT.*(brute|credential|default|anonymous)", re.I), "T0812"),
    (re.compile(r"MQTT.*(will|testament|last.?will)", re.I), "T0856"),
    (re.compile(r"MQTT.*(retain|persistent.?message)", re.I), "T0831"),

    # ── Generic ICSForge marker detection ─────────────────────────────
    (re.compile(r"ICSFORGE", re.I), "T0855"),  # ICSForge marker in traffic = synthetic test
]


def map_alert_to_techniques(alert: dict[str, Any]) -> set[str]:
    """Map an alert dict to a set of MITRE ATT&CK for ICS technique IDs.

    Checks the ``signature``, ``msg``, or ``message`` field against all rules.
    Also checks ``alert.signature`` for Suricata EVE JSON format and
    ``note`` for Zeek Notice log format.
    """
    # Extract signature from multiple common alert formats
    candidates = [
        alert.get("signature") or "",
        alert.get("msg") or "",
        alert.get("message") or "",
    ]
    # Suricata EVE JSON nested format
    if isinstance(alert.get("alert"), dict):
        candidates.append(alert["alert"].get("signature") or "")
        candidates.append(alert["alert"].get("category") or "")
    # Zeek Notice log
    candidates.append(alert.get("note") or "")
    candidates.append(alert.get("sub") or "")

    sig = " ".join(c for c in candidates if c)

    techs: set[str] = set()
    if not sig:
        return techs
    for rx, tid in RULES:
        if rx.search(sig):
            techs.add(tid)
    return techs


def correlate_run(
    expected_techniques: list[str],
    alerts: list[dict[str, Any]],
) -> dict[str, Any]:
    """Correlate expected techniques against observed alerts.

    Returns a dict with expected/observed/gaps/coverage_ratio/evidence.
    """
    observed: set[str] = set()
    evidence: dict[str, list[dict[str, Any]]] = {}
    for a in alerts:
        techs = map_alert_to_techniques(a)
        for t in techs:
            observed.add(t)
            evidence.setdefault(t, []).append({
                "ts": a.get("ts") or a.get("timestamp"),
                "signature": a.get("signature") or a.get("msg") or a.get("message"),
                "severity": a.get("severity"),
                "src_ip": a.get("src_ip"),
                "dst_ip": a.get("dst_ip"),
            })
    exp = [t for t in expected_techniques if t]
    obs = sorted(observed & set(exp))
    gaps = sorted(set(exp) - set(obs))
    return {
        "expected": sorted(set(exp)),
        "observed": obs,
        "gaps": gaps,
        "coverage_ratio": round(len(obs) / max(1, len(set(exp))), 2),
        "evidence": evidence,
    }
