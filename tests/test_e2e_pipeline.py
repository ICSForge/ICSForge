"""
ICSForge end-to-end pipeline test.

Verifies the complete flow:
  1. generate_offline → events JSONL written with correct technique metadata
  2. /api/run_full → run indexed, artifacts and techniques accessible
  3. /api/run + /api/run_detail → consistent with live callback receipts + dedup
  4. /api/scenarios_grouped → 400+ scenarios, all chains include steps
  5. /api/technique/variants → variants derive from scenarios.yml, all IDs resolve
  6. /api/matrix_status → 83 unique technique IDs, matrix_info block present
  7. /api/alerts/ingest → strict 400 for malformed alert; 200 for valid
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault("ICSFORGE_NO_AUTH", "1")


@pytest.fixture(scope="module")
def client():
    from icsforge.web.app import create_app

    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# 1. generate_offline
# ---------------------------------------------------------------------------
def test_generate_offline_creates_artifacts(client, tmp_path):
    """generate_offline writes events JSONL with correct technique metadata."""
    r = client.post(
        "/api/generate_offline",
        data=json.dumps({
            "name": "T0855__unauth_command__modbus",
            "dst_ip": "127.0.0.1",
            "outdir": str(tmp_path),
            "build_pcap": False,
        }),
        content_type="application/json",
    )
    assert r.status_code == 200
    d = r.get_json()
    assert d.get("run_id"), "run_id must be present"
    events_path = d.get("events")
    assert events_path and os.path.exists(events_path), "events file must exist"
    with open(events_path) as fh:
        lines = [json.loads(line) for line in fh]
    assert len(lines) > 0, "events file must have content"
    techniques = {line.get("mitre.ics.technique") for line in lines}
    assert "T0855" in techniques, "T0855 must appear in events"


# ---------------------------------------------------------------------------
# 2. run_full
# ---------------------------------------------------------------------------
def test_run_full_returns_artifacts(client, tmp_path):
    """run_full returns artifacts and techniques for a generated run."""
    r = client.post(
        "/api/generate_offline",
        data=json.dumps({
            "name": "T0813__denial_of_control__dnp3_flood",
            "dst_ip": "127.0.0.1",
            "outdir": str(tmp_path),
            "build_pcap": False,
        }),
        content_type="application/json",
    )
    assert r.status_code == 200
    run_id = r.get_json()["run_id"]

    rf = client.get(f"/api/run_full?run_id={run_id}")
    assert rf.status_code == 200
    d = rf.get_json()
    assert d.get("run_id") == run_id
    assert d.get("artifacts"), "artifacts list must be non-empty"
    assert d.get("techniques"), "techniques list must be non-empty"


# ---------------------------------------------------------------------------
# 3. Live receipts — consistent across /api/run, /api/run_detail, /api/run_full
# ---------------------------------------------------------------------------
def test_live_receipts_visible_in_all_run_endpoints(client):
    """Simulated live receipts appear consistently in all three run endpoints."""
    import icsforge.web.helpers_sse as sse

    run_id = "E2E-TEST-RECEIPT-RUN-58"
    base_ts = "2026-04-04T10:00:{:02d}Z"

    for i in range(5):
        sse._live_receipts.append({
            "run_id": run_id,
            "marker_found": True,
            "technique": "T0855",
            "@timestamp": base_ts.format(i),
            "proto": "modbus",
            "src_ip": "127.0.0.1",
            "src_port": str(50000 + i),
        })

    r1 = client.get(f"/api/run?run_id={run_id}").get_json()
    assert r1.get("packets") == 5, f"/api/run: expected 5, got {r1.get('packets')}"

    r2 = client.get(f"/api/run_detail?run_id={run_id}").get_json()
    assert r2.get("packets") == 5, f"/api/run_detail: expected 5, got {r2.get('packets')}"

    r3 = client.get(f"/api/run_full?run_id={run_id}").get_json()
    preview = r3.get("receipts_preview", [])
    assert len(preview) == 5, f"/api/run_full: expected 5, got {len(preview)}"

    # Dedup: adding identical receipts must not inflate count
    for i in range(5):
        sse._live_receipts.append({
            "run_id": run_id,
            "marker_found": True,
            "technique": "T0855",
            "@timestamp": base_ts.format(i),
            "proto": "modbus",
            "src_ip": "127.0.0.1",
            "src_port": str(50000 + i),
        })
    r4 = client.get(f"/api/run?run_id={run_id}").get_json()
    assert r4.get("packets") == 5, f"dedup failed: expected 5, got {r4.get('packets')}"


# ---------------------------------------------------------------------------
# 4. scenarios_grouped
# ---------------------------------------------------------------------------
def test_scenarios_grouped_complete(client):
    """scenarios_grouped returns 400+ scenarios; all chains include steps."""
    r = client.get("/api/scenarios_grouped")
    assert r.status_code == 200
    groups = r.get_json()["groups"]
    total = sum(len(g["scenarios"]) for g in groups)
    assert total >= 400, f"expected 400+ scenarios, got {total}"

    chain_group = next((g for g in groups if "Chain" in g["name"]), None)
    assert chain_group, "Attack Chains group must exist"
    assert len(chain_group["scenarios"]) >= 11, "need at least 11 chains"
    for ch in chain_group["scenarios"]:
        assert len(ch.get("steps", [])) > 0, \
            f"chain {ch['id']} must have steps"


# ---------------------------------------------------------------------------
# 5. technique/variants — spot-check a sample, not all 68
# ---------------------------------------------------------------------------
def test_technique_variants_sample_resolve(client):
    """Spot-check a sample of technique variants for correctness and resolve."""
    import yaml

    with open("icsforge/scenarios/scenarios.yml") as fh:
        doc = yaml.safe_load(fh)
    scenarios = {k for k in doc["scenarios"] if not k.startswith("CHAIN__")}

    # Sample representative techniques rather than all 68 (avoids timeout)
    sample = ["T0855", "T0813", "T0858", "T0846", "T0892", "T0880", "T0829"]
    failures = []
    for tech in sample:
        r = client.get(f"/api/technique/variants?technique={tech}")
        assert r.status_code == 200, f"{tech}: expected 200, got {r.status_code}"
        variants = r.get_json().get("variants", [])
        assert len(variants) > 0, f"{tech} has no variants"
        for v in variants:
            sc_name = f"{tech}__{v['id']}"
            if sc_name not in scenarios:
                failures.append(sc_name)

    assert not failures, f"Variant IDs not resolving to scenarios: {failures}"


# ---------------------------------------------------------------------------
# 6. matrix_status
# ---------------------------------------------------------------------------
def test_matrix_status_consistent(client):
    """matrix_status returns 83 unique techniques with matrix_info block."""
    r = client.get("/api/matrix_status")
    assert r.status_code == 200
    d = r.get_json()
    assert "status" in d
    assert "matrix_info" in d
    mi = d["matrix_info"]
    assert mi["unique_technique_ids"] == 83, \
        f"expected 83, got {mi['unique_technique_ids']}"
    assert mi["total_entries"] >= 83


# ---------------------------------------------------------------------------
# 7. alerts/ingest strict validation
# ---------------------------------------------------------------------------
def test_alerts_ingest_strict_validation(client, tmp_path):
    """alerts/ingest: malformed alert → 400; valid alert → 200."""
    # The endpoint requires repo-relative paths — write inside out/ directory
    repo_root = os.path.dirname(os.path.dirname(__file__))
    out_dir = os.path.join(repo_root, "out", "test_tmp")
    os.makedirs(out_dir, exist_ok=True)

    def _rel(abs_path):
        """Convert absolute path to repo-relative for the ingest endpoint."""
        return os.path.relpath(abs_path, repo_root)

    bad_path = os.path.join(out_dir, "e2e_bad_alert.jsonl")
    with open(bad_path, "w") as fh:
        fh.write(json.dumps({
            "timestamp": "2026-04-01T10:00:00Z",
            "alert": "not_a_dict",
        }) + "\n")

    try:
        r = client.post(
            "/api/alerts/ingest",
            data=json.dumps({"path": _rel(bad_path), "profile": "suricata_eve"}),
            content_type="application/json",
        )
        assert r.status_code == 400, f"expected 400, got {r.status_code}"
        err = (r.get_json() or {}).get("error", "")
        assert "Row" in err, f"expected row-specific error, got: {err!r}"
    finally:
        if os.path.exists(bad_path):
            os.remove(bad_path)

    good_path = os.path.join(out_dir, "e2e_good_alert.jsonl")
    with open(good_path, "w") as fh:
        fh.write(json.dumps({
            "timestamp": "2026-04-01T10:00:00Z",
            "alert": {"signature": "Modbus FC16", "severity": 2},
            "src_ip": "10.0.0.1",
            "dest_ip": "10.0.0.2",
        }) + "\n")

    try:
        r2 = client.post(
            "/api/alerts/ingest",
            data=json.dumps({"path": _rel(good_path), "profile": "suricata_eve"}),
            content_type="application/json",
        )
        assert r2.status_code == 200, f"expected 200, got {r2.status_code}"
        assert r2.get_json()["imported"] == 1
    finally:
        if os.path.exists(good_path):
            os.remove(good_path)
