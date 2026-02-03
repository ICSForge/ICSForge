import json
def coverage_report(result,out_path):
    with open(out_path,"w",encoding="utf-8") as f:
        json.dump(result,f,indent=2)
    return out_path
