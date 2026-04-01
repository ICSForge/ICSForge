"""ICSForge detections blueprint — Suricata/Sigma rule preview and download."""
import io
import zipfile

from datetime import datetime, timezone

import os
from flask import Blueprint, jsonify, request, send_file

from icsforge import __version__
from icsforge.web.helpers import log
from icsforge.detection.generator import generate_all

bp = Blueprint("bp_detections", __name__)


# ── Detections preview
@bp.route("/api/detections/preview")
def api_detections_preview():
    """Return metadata about available detection rules."""
    try:
        r = generate_all()
        return jsonify({"count": r["count"], "techniques": r["techniques"]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500




# ── Detections download
@bp.route("/api/detections/download")
def api_detections_download():
    """
    Download all detection rules as a zip containing:
      - icsforge_ics.rules   (Suricata)
      - sigma/               (one YAML per scenario)
      - README.txt
    """
    technique_filter = request.args.getlist("technique") or None
    include_marker   = request.args.get("marker", "1") != "0"

    try:
        r = generate_all(technique_filter=technique_filter,
                         include_marker=include_marker)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    readme = f"""ICSForge v{__version__} Detection Rules
Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
Techniques: {len(r['techniques'])} | Rules: {r['count']}

FILES
  icsforge_ics.rules   — Suricata rules (SID range 9800000–9800{r['count']-1:03d})
  sigma/               — Sigma rules (one YAML per scenario)

SURICATA USAGE
  suricata -r your_capture.pcap -S icsforge_ics.rules -l /tmp/logs/

SIGMA USAGE
  sigma convert -t splunk sigma/T0812__default_creds__s7comm_blank_auth.yml

NOTE
  Rules match the ICSForge marker bytes (ICSFORGE_SYNTH|) to fire ONLY
  on synthetic traffic. Remove the marker content match for production
  use against real OT traffic (download with ?marker=0).

ATT&CK for ICS techniques covered:
  {chr(10).join('  ' + t for t in r['techniques'])}
"""

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("icsforge_ics.rules", r["suricata"])
        zf.writestr("README.txt", readme)
        for sc_id, sigma_text in r["sigma"].items():
            zf.writestr(f"sigma/{sc_id}.yml", sigma_text)
    buf.seek(0)

    fname = f"icsforge_detection_rules_v{__version__}.zip"
    return send_file(buf, mimetype="application/zip",
                            as_attachment=True, download_name=fname)

