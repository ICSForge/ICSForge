def validate_zeek(notice_log_path, techniques):
    hits=[]
    with open(notice_log_path,"r",encoding="utf-8") as f:
        for l in f:
            for t in techniques:
                if t in l: hits.append(t)
    return {"matched":sorted(set(hits)),"count":len(hits)}
