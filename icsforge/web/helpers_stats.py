"""ICSForge web helpers — receipt statistics and timeline binning."""
from datetime import datetime


def _bin_receipts(items: list[dict], bins: int = 40) -> list[dict]:
    ts = []
    for r in items:
        t = r.get("@timestamp")
        if not t:
            continue
        try:
            dt = datetime.fromisoformat(t.replace("Z", "+00:00"))
            ts.append(dt.timestamp())
        except (ValueError, TypeError):
            continue
    if len(ts) < 2:
        step = max(1, len(items) // bins)
        out = []
        for i in range(0, len(items), step):
            out.append({"i": len(out), "count": len(items[i:i + step])})
        return out[:bins]
    tmin, tmax = min(ts), max(ts)
    span = max(1.0, tmax - tmin)
    out = [{"i": i, "count": 0} for i in range(bins)]
    for t in ts:
        idx = int((t - tmin) / span * (bins - 1))
        out[idx]["count"] += 1
    return out


def _stats_from_receipts(items: list[dict]) -> dict:
    runs: set = set()
    techs: set = set()
    protos: set = set()
    for r in items:
        if r.get("run_id"):
            runs.add(r["run_id"])
        if r.get("technique"):
            techs.add(r["technique"])
        if r.get("receiver.proto"):
            protos.add(r["receiver.proto"])
    return {
        "total": len(items),
        "runs": len(runs),
        "techniques": len(techs),
        "protocols": len(protos),
    }
