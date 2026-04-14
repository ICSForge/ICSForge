"""ICSForge detections blueprint — tiered Suricata/Sigma rule preview and download."""
import io
import zipfile
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, send_file

from icsforge import __version__
from icsforge.detection.generator import generate_all

bp = Blueprint("bp_detections", __name__)


@bp.route("/api/detections/preview")
def api_detections_preview():
    """Return metadata and rule counts for all three tiers."""
    try:
        r = generate_all()
        return jsonify({
            "count":      r["count"],
            "techniques": r["techniques"],
            "rule_counts": r["rule_counts"],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route("/api/detections/download")
def api_detections_download():
    """
    Download three-tier detection rules as a zip:
      icsforge_lab.rules        -- Tier 1: ICSFORGE_SYNTH marker (zero FP)
      icsforge_heuristic.rules  -- Tier 2: protocol magic bytes (may FP)
      icsforge_semantic.rules   -- Tier 3: function-code/command (low FP)
      sigma/                    -- Sigma YAML per scenario, all three tiers
      README.txt                -- Usage guide with tier explanations
    """
    technique_filter = request.args.getlist("technique") or None
    try:
        r = generate_all(technique_filter=technique_filter)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    rc = r["rule_counts"]
    readme = (
        f"ICSForge v{__version__} Detection Rules\n"
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
        f"Scenarios: {r['count']} | Techniques: {len(r['techniques'])}\n\n"
        "=== CONFIDENCE TIERS ===\n\n"
        f"Tier 1 icsforge_lab.rules ({rc['lab_marker']} rules)\n"
        "  Requires ICSFORGE_SYNTH marker. Zero FP. ICSForge correlation only.\n"
        "  Not useful for detecting real adversaries.\n\n"
        f"Tier 2 icsforge_heuristic.rules ({rc['protocol_heuristic']} rules)\n"
        "  Protocol magic bytes. Fires on any matching protocol traffic.\n"
        "  Use to verify NSM visibility. Will FP on legitimate OT traffic.\n\n"
        f"Tier 3 icsforge_semantic.rules ({rc['semantic']} rules)  <- RECOMMENDED\n"
        "  Specific function codes / commands at application layer.\n"
        "  Low FP in segmented OT where those codes should be absent.\n"
        "  Closest to firing on a real adversary doing the same thing.\n\n"
        "=== SURICATA ===\n\n"
        "  suricata -r capture.pcap -S icsforge_semantic.rules -l /tmp/\n\n"
        "=== SIGMA ===\n\n"
        "  sigma convert -t splunk sigma/<scenario>.yml\n"
        "  Each file has all three tiers; choose condition: lab_marker / \n"
        "  protocol_heuristic / semantic\n\n"
        "=== TECHNIQUES COVERED ===\n\n"
        + "\n".join("  " + t for t in r["techniques"])
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("icsforge_lab.rules",       r["suricata_lab"])
        zf.writestr("icsforge_heuristic.rules", r["suricata_heuristic"])
        zf.writestr("icsforge_semantic.rules",  r["suricata_semantic"])
        zf.writestr("README.txt", readme)
        for sc_id, sigma_text in r["sigma"].items():
            zf.writestr(f"sigma/{sc_id}.yml", sigma_text)
    buf.seek(0)
    fname = f"icsforge_detection_rules_v{__version__}.zip"
    return send_file(buf, mimetype="application/zip",
                     as_attachment=True, download_name=fname)
