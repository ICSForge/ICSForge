from __future__ import annotations
import json
from collections import defaultdict

def _load_jsonl(path: str):
    with open(path,"r",encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line: continue
            try: yield json.loads(line)
            except Exception: continue

def build_network_validation_report(events_jsonl: str, receipts_jsonl: str, alerts_jsonl: str|None=None, out_path: str|None=None):
    events=list(_load_jsonl(events_jsonl))
    receipts=list(_load_jsonl(receipts_jsonl))
    alerts=list(_load_jsonl(alerts_jsonl)) if alerts_jsonl else []

    expected_by_run=defaultdict(set)
    for e in events:
        run=e.get("run_id") or e.get("icsforge.run_id")
        tech=e.get("mitre.ics.technique")
        if run and tech: expected_by_run[run].add(tech)

    received_by_run=defaultdict(list)
    for r in receipts:
        run=r.get("run_id")
        if run: received_by_run[run].append(r)

    observed_by_run=defaultdict(set)
    for a in alerts:
        run=a.get("run_id") or a.get("icsforge.run_id")
        tech=a.get("mitre.ics.technique")
        if run and tech: observed_by_run[run].add(tech)

    runs=sorted(set(list(expected_by_run.keys())+list(received_by_run.keys())+list(observed_by_run.keys())))
    report={"runs":[], "summary":{}}
    for run in runs:
        exp=sorted(expected_by_run.get(run,set()))
        rec=received_by_run.get(run,[])
        rec_tech=sorted(set([x.get("technique") for x in rec if x.get("technique")]))
        item={"run_id":run,
              "expected_techniques":exp,
              "received_packets":len(rec),
              "received_techniques_from_marker":rec_tech,
              "delivery_ratio": (1.0 if len(rec)>0 else 0.0)}
        if alerts_jsonl:
            obs=sorted(observed_by_run.get(run,set()))
            item["observed_techniques"]=obs
            item["coverage_ratio"]=round(len(set(obs)&set(exp))/max(1,len(exp)),2)
        report["runs"].append(item)
    report["summary"]={"runs":len(runs), "total_received_packets":sum(x["received_packets"] for x in report["runs"])}
    if out_path:
        with open(out_path,"w",encoding="utf-8") as f: json.dump(report,f,indent=2)
    return report
