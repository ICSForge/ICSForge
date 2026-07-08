import json
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
        # Test profile + expected alert are recorded on receipts (from the
        # expectation the sender announced). Take the first non-empty value.
        _profile = next((x.get("test_profile") for x in rec if x.get("test_profile")), "")
        _exp_alert = next((x.get("expected_alert") for x in rec if x.get("expected_alert")), "")
        delivered = sorted({x.get("technique") for x in rec if x.get("technique")} & set(exp))
        item = {
            "run_id": run,
            "test_profile": _profile or "firewall",
            "expected_techniques": exp,
            "expected_alert": _exp_alert,
            "received_packets": len(rec),
            "received_techniques_from_marker": rec_tech,
            # Delivery ratio: fraction of expected techniques confirmed by markers.
            # A technique is "delivered" if at least one receipt carries its ID.
            "delivered_techniques": delivered,
            "delivery_ratio": (
                round(len({x.get("technique") for x in rec if x.get("technique")} & set(exp)) / len(exp), 3)
                if exp else (1.0 if len(rec) > 0 else 0.0)
            ),
        }
        # Profile-aware interpretation so the report reads correctly per intent.
        delivered_any = len(rec) > 0
        if (_profile or "firewall") == "nsm":
            if alerts_jsonl:
                obs = set(observed_by_run.get(run, set()))
                fired = bool(obs & set(exp)) if exp else bool(obs)
                item["interpretation"] = (
                    "NSM: traffic witnessed at the sink and the sensor raised the "
                    "expected alert." if (delivered_any and fired) else
                    "NSM: traffic witnessed at the sink but NO matching sensor alert "
                    "— possible detection gap." if (delivered_any and not fired) else
                    "NSM: traffic did not reach the sink — check the path/run."
                )
            else:
                item["interpretation"] = (
                    "NSM: traffic witnessed at the sink (provide --alerts to confirm "
                    "the sensor fired)." if delivered_any else
                    "NSM: traffic did not reach the sink — check the path/run."
                )
        else:  # firewall / ACL
            item["interpretation"] = (
                "Firewall/ACL: traffic TRAVERSED the boundary and reached the sink "
                "— a rule allowed it; investigate the policy that permitted these "
                "protocols." if delivered_any else
                "Firewall/ACL: no traffic reached the sink — the boundary blocked it "
                "(expected for a correctly-segmented path)."
            )
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
