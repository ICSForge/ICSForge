import json
import os
from collections import defaultdict
from icsforge.log import get_logger

log = get_logger(__name__)


def _load_jsonl(path: str):
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def build_network_validation_report(
    events_jsonl: str,
    receipts_jsonl: str,
    alerts_jsonl: str | None = None,
    out_path: str | None = None,
):
    events = list(_load_jsonl(events_jsonl))
    receipts = list(_load_jsonl(receipts_jsonl))
    alerts = list(_load_jsonl(alerts_jsonl)) if alerts_jsonl else []

    # Validate inputs and warn loudly about quality issues
    _warnings: list[str] = []
    if not events:
        msg = (
            f"Events file is empty: {events_jsonl}. "
            "Ground-truth techniques will be missing — report will lack expected_techniques. "
            "For live sends, run 'icsforge send' with --also-build-pcap to generate ground truth."
        )
        log.warning(msg)
        _warnings.append(msg)
    if not receipts:
        msg = f"Receipts file is empty: {receipts_jsonl}. Delivery ratios will be zero."
        log.warning(msg)
        _warnings.append(msg)

    expected_by_run = defaultdict(set)
    for e in events:
        run = e.get("run_id") or e.get("icsforge.run_id")
        tech = e.get("mitre.ics.technique")
        if run and tech:
            expected_by_run[run].add(tech)

    received_by_run = defaultdict(list)
    for r in receipts:
        run = r.get("run_id")
        if run:
            received_by_run[run].append(r)

    observed_by_run = defaultdict(set)
    for a in alerts:
        run = a.get("run_id") or a.get("icsforge.run_id")
        tech = a.get("mitre.ics.technique")
        if run and tech:
            observed_by_run[run].add(tech)

    runs = sorted(set(expected_by_run) | set(received_by_run) | set(observed_by_run))
    report = {"runs": [], "summary": {}}
    for run in runs:
        exp = sorted(expected_by_run.get(run, set()))
        rec = received_by_run.get(run, [])
        rec_tech = sorted({x.get("technique") for x in rec if x.get("technique")})
        item = {
            "run_id": run,
            "expected_techniques": exp,
            "received_packets": len(rec),
            "received_techniques_from_marker": rec_tech,
            "delivery_ratio": (1.0 if len(rec) > 0 else 0.0),
        }
        if alerts_jsonl:
            obs = sorted(observed_by_run.get(run, set()))
            item["observed_techniques"] = obs
            item["coverage_ratio"] = round(len(set(obs) & set(exp)) / max(1, len(exp)), 2)
        report["runs"].append(item)

    if _warnings:
        report["warnings"] = _warnings
    report["summary"] = {
        "runs": len(runs),
        "total_received_packets": sum(x["received_packets"] for x in report["runs"]),
    }
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
    return report
