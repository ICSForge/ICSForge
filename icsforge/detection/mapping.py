from __future__ import annotations
import re
from typing import Dict, Any, List, Set

RULES = [
    (re.compile(r"unauthorized.*(write|operate|control)", re.I), "T0855"),
    (re.compile(r"modbus.*write", re.I), "T0855"),
    (re.compile(r"dnp3.*(operate|direct operate)", re.I), "T0855"),
    (re.compile(r"iec\s*104.*control|iec104.*control", re.I), "T0855"),
    (re.compile(r"s7.*(write|stop|start)", re.I), "T0855"),
    (re.compile(r"(rogue|new).*(master|client)", re.I), "T0848"),
    (re.compile(r"unexpected.*(master|client)", re.I), "T0848"),
    (re.compile(r"(scan|sweep|enumerat|probe)", re.I), "T0840"),
    (re.compile(r"(tag|point).*?(enumerat|browse)", re.I), "T0861"),
    (re.compile(r"(dos|flood|rate anomaly|burst)", re.I), "T0814"),
    (re.compile(r"(loss of view|telemetry gap|reporting missing|no data)", re.I), "T0815"),
    (re.compile(r"(setpoint|manipulat).*(control|process)", re.I), "T0831"),
    (re.compile(r"(manipulat).*(view|hmi)", re.I), "T0832"),
]

def map_alert_to_techniques(alert: Dict[str, Any]) -> Set[str]:
    sig = (alert.get("signature") or alert.get("msg") or alert.get("message") or "")
    techs: Set[str] = set()
    for rx, tid in RULES:
        if sig and rx.search(sig):
            techs.add(tid)
    return techs

def correlate_run(expected_techniques: List[str], alerts: List[Dict[str,Any]]) -> Dict[str, Any]:
    observed: Set[str] = set()
    evidence: Dict[str, List[Dict[str,Any]]] = {}
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
        "coverage_ratio": round(len(obs)/max(1,len(set(exp))), 2),
        "evidence": evidence,
    }
