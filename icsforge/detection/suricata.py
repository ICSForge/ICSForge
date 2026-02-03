import json
def validate_suricata(eve_json_path, techniques):
    hits=[]
    with open(eve_json_path,"r",encoding="utf-8") as f:
        for l in f:
            try:
                j=json.loads(l)
                if j.get("event_type")=="alert":
                    sig=j.get("alert",{}).get("signature","")
                    for t in techniques:
                        if t in sig: hits.append(t)
            except: pass
    return {"matched":sorted(set(hits)),"count":len(hits)}
