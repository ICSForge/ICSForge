import json
def validate(events_path, alerts_path):
    ev=set(); al=set()
    with open(events_path,"r",encoding="utf-8") as f:
        for l in f:
            try: ev.add(json.loads(l).get("mitre.ics.technique"))
            except: pass
    with open(alerts_path,"r",encoding="utf-8") as f:
        for l in f:
            try: al.add(json.loads(l).get("mitre.ics.technique"))
            except: pass
    cov = ev & al
    return {"expected":sorted(t for t in ev if t),
            "observed":sorted(t for t in cov if t),
            "coverage_ratio":round(len(cov)/max(1,len(ev)),2)}
