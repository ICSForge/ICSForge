"""ICSForge scenarios blueprint — scenario listing, preview, send, offline generation."""
import os
import random as _rnd
import re as _re
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from pathlib import Path as _P

import yaml
from flask import Blueprint, jsonify, request

from icsforge.web.helpers import (
    MATRIX_SINGLETON_PACK,
    _append_run_index,
    _canonical_scenarios_path,
    _list_packs,
    _list_profiles,
    _load_matrix,
    _load_yaml,
    _registry,
    log,
    run_scenario,
    send_scenario_live,
)

bp = Blueprint("bp_scenarios", __name__)


# ── Scenario listing
@bp.route("/api/scenarios")
def api_scenarios():
    real = _canonical_scenarios_path()
    if not os.path.exists(real):
        return jsonify({'scenarios': []})
    doc = _load_yaml(real)
    sc = sorted((doc.get("scenarios") or {}).keys())
    return jsonify({"scenarios": sc})




# ── Scenario preview
@bp.route("/api/preview")
def api_preview():
    name = request.args.get('name')
    real = _canonical_scenarios_path()
    if not os.path.exists(real):
        return jsonify({'error':'Scenario pack not found'}), 404
    doc = _load_yaml(real)
    scenarios = (doc.get("scenarios") or {})
    aliases = (doc.get("aliases") or {})
    if name not in scenarios and name in aliases:
        name = aliases[name]
    sc = scenarios.get(name)
    if not sc:
        return jsonify({"error": "Scenario not found"})
    steps = sc.get("steps") or []
    techs = sorted(set([s.get("technique") for s in steps if s.get("technique")]))
    slim = [{
        "type": s.get("type"),
        "proto": s.get("proto"),
        "technique": s.get("technique"),
        "style": s.get("style", "auto"),
        "count": s.get("count", 1),
        "interval": s.get("interval", "0s"),
        "message": s.get("message", ""),
    } for s in steps]
    return jsonify({
        "name": name,
        "title": sc.get("title", name),
        "description": sc.get("description", ""),
        "steps": slim,
        "techniques": techs,
        "is_chain": name.startswith("CHAIN__"),
    })




# ── Payload hex preview
@bp.route("/api/preview_payload")
def api_preview_payload():
    """Return hex dump of actual PDU bytes for a scenario step."""
    name = request.args.get('name')
    step_idx = int(request.args.get('step', 0))
    real = _canonical_scenarios_path()
    if not os.path.exists(real):
        return jsonify({'error': 'Scenario pack not found'}), 404
    doc = _load_yaml(real)
    scenarios = doc.get("scenarios") or {}
    aliases = doc.get("aliases") or {}
    if name not in scenarios and name in aliases:
        name = aliases[name]
    sc = scenarios.get(name)
    if not sc:
        return jsonify({"error": "Scenario not found"}), 404
    steps = [s for s in (sc.get("steps") or []) if s.get("proto") and s.get("type") in ("packet", "pcap")]
    if not steps:
        return jsonify({"error": "No packet steps in scenario"}), 400
    step_idx = max(0, min(step_idx, len(steps) - 1))
    step = steps[step_idx]
    proto = step.get("proto")
    style = step.get("style", "auto")
    tech = step.get("technique", "")
    marker = f"ICSFORGE:PREVIEW:{name[:20]}:{tech}:"
    try:
        from icsforge.protocols import bacnet, dnp3, enip, iec104, iec61850, modbus, mqtt, opcua, profinet_dcp, s7comm
        builders = {
            "modbus": modbus.build_payload,
            "dnp3": dnp3.build_payload,
            "s7comm": s7comm.build_payload,
            "iec104": iec104.build_payload,
            "opcua": opcua.build_payload,
            "enip": enip.build_payload,
            "profinet_dcp": profinet_dcp.build_payload,
            "mqtt": mqtt.build_payload,
            "bacnet": bacnet.build_payload,
            "iec61850": iec61850.build_payload,
        }
        ports = {"modbus": 502, "dnp3": 20000, "s7comm": 102, "iec104": 2404,
                 "opcua": 4840, "enip": 44818, "profinet_dcp": 0,
                 "mqtt": 1883, "bacnet": 47808, "iec61850": 0}
        # bacnet is UDP — note this in the display
        udp_protos = {"bacnet"}
        l2_protos = {"profinet_dcp", "iec61850"}
        if proto not in builders:
            return jsonify({"error": f"Unknown proto: {proto}"}), 400
        # L2/raw-frame protos and UDP protos expect bytes marker
        marker_b = marker.encode() if proto in ("profinet_dcp", "iec61850", "bacnet") else marker
        data = builders[proto](marker_b, style=style)
        width = 16
        lines = []
        for i in range(0, len(data), width):
            chunk = data[i:i+width]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:04x}  {hex_part:<{width*3}}  {ascii_part}")
        return jsonify({
            "proto": proto,
            "style": style,
            "technique": tech,
            "port": ports.get(proto, 0),
            "transport": "L2/Ethernet" if proto in l2_protos else ("UDP" if proto in udp_protos else "TCP"),
            "length": len(data),
            "step_index": step_idx,
            "step_count": len(steps),
            "hexdump": "\n".join(lines),
            "hex_raw": data.hex(),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500




# ── Scenarios grouped
@bp.route("/api/scenarios_grouped")
def api_scenarios_grouped():
    """Return scenarios grouped by tactic, with metadata for UI rendering."""
    real = _canonical_scenarios_path()
    if not os.path.exists(real):
        return jsonify({"groups": []}), 404
    doc = _load_yaml(real)
    scenarios = doc.get("scenarios") or {}
    mat = _load_matrix()
    tid_tactic = {}
    tid_name = {}
    for tac in mat.get("tactics", []):
        for tech in tac.get("techniques", []):
            tid = tech.get("id", "")
            tid_tactic[tid] = tac.get("name", "Other")
            tid_name[tid] = tech.get("name", "")
    groups = {}
    for sc_name, sc in scenarios.items():
        steps = sc.get("steps") or []
        techs = sorted(set(s.get("technique") for s in steps if s.get("technique")))
        protos = sorted(set(s.get("proto") for s in steps if s.get("proto")))
        if sc_name.startswith("CHAIN__"):
            group = "\u26d3 Attack Chains"
        elif techs:
            group = tid_tactic.get(techs[0], "Other")
        else:
            group = "Other"
        groups.setdefault(group, [])
        entry = {
            "id": sc_name,
            "title": sc.get("title", sc_name),
            "techniques": techs,
            "tech_names": [tid_name.get(t, t) for t in techs],
            "protocols": protos,
            "is_chain": sc_name.startswith("CHAIN__"),
            "step_count": len(steps),
        }
        # Include full steps for chain scenarios so the campaign page
        # can render the step-by-step progress view
        if sc_name.startswith("CHAIN__"):
            entry["steps"] = steps
        groups[group].append(entry)
    order = ["\u26d3 Attack Chains",
             "Initial Access", "Execution", "Persistence", "Privilege Escalation",
             "Evasion", "Discovery", "Lateral Movement", "Collection",
             "Command and Control",
             "Inhibit Response Function", "Impair Process Control",
             "Impact", "Other"]
    sorted_groups = []
    seen = set()
    for g in order:
        if g in groups:
            sorted_groups.append({"name": g, "scenarios": sorted(groups[g], key=lambda x: x["id"])})
            seen.add(g)
    for g, items in groups.items():
        if g not in seen:
            sorted_groups.append({"name": g, "scenarios": sorted(items, key=lambda x: x["id"])})
    return jsonify({"groups": sorted_groups})




# ── Send scenario (live)
@bp.route("/api/send", methods=["POST"])
def api_send():
    if os.environ.get('ICSFORGE_UI_MODE','sender').strip().lower() == 'receiver':
        return jsonify({'ok': False, 'error': 'send disabled in receiver mode'}), 403
    data = request.get_json(force=True) or {}
    pack = _canonical_scenarios_path()
    name = data.get("name")
    dst_ip = (data.get("dst_ip") or "").strip()
    src_ip = (data.get("src_ip") or "127.0.0.1").strip()
    outdir = (data.get("outdir") or "out").strip()
    allowlist = (data.get("allowlist") or "").strip()
    timeout = float(data.get("timeout") or 2.0)
    also_build_pcap = bool(data.get("also_build_pcap"))
    iface = (data.get("iface") or "").strip() or None
    step_options = data.get("step_options") or None  # {proto: {key: val}}
    no_marker = bool(data.get("no_marker"))
    if not name:
        return jsonify({"error": "Scenario name missing"}), 400
    if not dst_ip:
        return jsonify({"error": "Destination IP missing"}), 400

    allow = [x.strip() for x in allowlist.split(",") if x.strip()] or [dst_ip]

    try:
        res = send_scenario_live(
            scenario_file=pack,
            scenario_name=name,
            dst_ip=dst_ip,
            iface=iface,
            confirm_live_network=True,
            receiver_allowlist=allow,
            timeout=timeout,
            step_options=step_options,
            no_marker=no_marker,
        )

        # Create ground-truth artifacts (events jsonl + optional pcap)
        gt = run_scenario(
            pack,
            name,
            outdir,
            dst_ip=dst_ip,
            src_ip=src_ip,
            run_id=res["run_id"],
            build_pcap=also_build_pcap,
            no_marker=no_marker,
        )

        # Index run for SOC Mode (legacy JSONL + enterprise DB)
        try:
            reg = _registry()
            reg.upsert_run(res["run_id"], scenario=name, pack=pack, dst_ip=dst_ip, src_ip=src_ip, iface=iface, mode="live", status="ok", meta={"sent": res.get("sent")})
            reg.add_artifact(res["run_id"], "events", gt.get("events"))
            if gt.get("pcap"):
                reg.add_artifact(res["run_id"], "pcap", gt.get("pcap"))
        except (OSError, ValueError) as exc:
            log.debug("Registry upsert failed for %s: %s", res["run_id"], exc)

        # Index run for SOC Mode
        entry = {
            "run_id": res["run_id"],
            "scenario": name,
            "pack": pack,
            "events": gt.get("events"),
            "pcap": gt.get("pcap"),
            "ts": datetime.now(timezone.utc).isoformat() + "Z",
        }
        with suppress(OSError, ValueError):
            _append_run_index(entry)

        return jsonify(
            {
                "run_id": res["run_id"],
                "sent": res["sent"],
                "events": gt.get("events"),
                "pcap": gt.get("pcap"),
                "warnings": res.get("warnings", []),
            }
        )
    except (OSError, ValueError) as exc:
        log.error("Send scenario failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── Packs
@bp.route("/api/packs")
def api_packs():
    return jsonify(_list_packs())




# ── Technique variants
@bp.route("/api/technique/variants")
def api_technique_variants():
    """Return all scenario variants for a technique, derived live from scenarios.yml."""
    technique = (request.args.get("technique") or "").strip()
    if not technique:
        return jsonify({"error": "technique required"}), 400
    try:
        pack_path = _canonical_scenarios_path()
        doc = _load_yaml(pack_path) or {}
        scenarios = doc.get("scenarios") or {}
        prefix = technique + "__"
        variants = []
        for name, sc in sorted(scenarios.items()):
            # Skip chain/campaign scenarios — they cover multiple techniques
            if name.startswith("CHAIN__"):
                continue
            # Match scenarios whose top-level technique == requested technique
            if sc.get("technique") != technique:
                continue
            # Derive variant id: strip the "T0XXX__" prefix from scenario name
            var_id = name[len(prefix):] if name.startswith(prefix) else name
            # Derive proto: first proto seen in steps
            protos = list({s.get("proto") for s in sc.get("steps", []) if s.get("proto")})
            proto = protos[0] if len(protos) == 1 else ("+".join(sorted(protos)) if protos else "")
            variants.append({
                "id":    var_id,
                "label": sc.get("title") or name,
                "proto": proto,
                "protocols": sorted(set(protos)),
                "notes": (sc.get("description") or "")[:200],
            })
        return jsonify({"technique": technique, "variants": variants})
    except Exception as e:
        return jsonify({"error": f"variants load failed: {e}"}), 500




# ── Technique send
@bp.route("/api/technique/send", methods=["POST"])
def api_technique_send():
    data = request.get_json(force=True) or {}
    technique = (data.get("technique") or "").strip()
    variant = (data.get("variant") or "").strip()
    dst_ip = (data.get("dst_ip") or "").strip()
    also_build_pcap = bool(data.get("also_build_pcap"))
    no_marker = bool(data.get("no_marker"))
    timeout = float(data.get("timeout") or 2.0)
    allowlist = (data.get("allowlist") or "").strip()
    iface = (data.get("iface") or "").strip() or None
    outdir = (data.get("outdir") or "out").strip()
    src_ip = (data.get("src_ip") or "127.0.0.1").strip()
    iface = (data.get("iface") or "").strip() or None
    src_ip = (data.get("src_ip") or "127.0.0.1").strip()
    no_marker = bool(data.get("no_marker"))

    if not technique:
        return jsonify({"error": "technique required"}), 400
    if not dst_ip:
        return jsonify({"error": "dst_ip required"}), 400

    scenario_name = technique if not variant else f"{technique}__{variant}"

    try:
        pack = yaml.safe_load(Path(MATRIX_SINGLETON_PACK).read_text(encoding="utf-8")) or {}
        if scenario_name not in (pack.get("scenarios") or {}):
            if scenario_name != technique and technique in (pack.get("scenarios") or {}):
                scenario_name = technique
            else:
                return jsonify({"error": f"Technique {technique} is not supported for network simulation in this build."}), 400
    except Exception:
        return jsonify({"error": "Matrix scenario pack missing"}), 500

    try:
        res = send_scenario_live(
            scenario_file=MATRIX_SINGLETON_PACK,
            scenario_name=scenario_name,
            dst_ip=dst_ip,
            iface=iface,
            confirm_live_network=True,
            receiver_allowlist=([x.strip() for x in allowlist.split(',') if x.strip()] or [dst_ip]),
            timeout=timeout,
            no_marker=no_marker,
        )

        gt = run_scenario(
            MATRIX_SINGLETON_PACK,
            scenario_name,
            outdir=outdir,
            dst_ip=dst_ip,
            src_ip=src_ip,
            run_id=res["run_id"],
            build_pcap=also_build_pcap,
            no_marker=no_marker,
        )

        entry = {
            "run_id": res["run_id"],
            "scenario": scenario_name,
            "pack": MATRIX_SINGLETON_PACK,
            "events": gt.get("events"),
            "pcap": gt.get("pcap"),
            "ts": datetime.now(timezone.utc).isoformat() + "Z",
        }
        # Register in SQLite (same pattern as api_send) so /api/runs shows matrix runs
        try:
            reg = _registry()
            reg.upsert_run(res["run_id"], scenario=scenario_name, pack=MATRIX_SINGLETON_PACK,
                           dst_ip=dst_ip, src_ip=src_ip, iface=iface, mode="live", status="ok",
                           meta={"sent": res.get("sent")})
            reg.add_artifact(res["run_id"], "events", gt.get("events"))
            if gt.get("pcap"):
                reg.add_artifact(res["run_id"], "pcap", gt.get("pcap"))
        except (OSError, ValueError, Exception) as exc:
            log.debug("Registry upsert failed for matrix run %s: %s", res["run_id"], exc)
        with suppress(OSError, ValueError):
            _append_run_index(entry)

        return jsonify({"ok": True, "run_id": res["run_id"], "sent": res.get("sent"), "events": gt.get("events"), "pcap": gt.get("pcap")})
    except Exception as e:
        return jsonify({"error": str(e)}), 500




# ── Generate offline PCAP
@bp.route("/api/generate_offline", methods=["POST"])
def api_generate_offline():
    data = request.get_json(force=True) or {}
    pack = _canonical_scenarios_path()
    name = (data.get("name") or "").strip()
    outdir = (data.get("outdir") or "out").strip()
    dst_ip = (data.get("dst_ip") or "198.51.100.42").strip()
    src_ip = (data.get("src_ip") or "127.0.0.1").strip()
    build_pcap = bool(data.get("build_pcap"))
    run_id = (data.get("run_id") or "").strip() or None
    no_marker = bool(data.get("no_marker"))
    if not name:
        return jsonify({"error": "Scenario name missing"}), 400

    # Always generate a meaningful run_id — unique name for every offline artifact
    if not run_id:
        _NATO_W = ["ALPHA","BRAVO","CHARLIE","DELTA","ECHO","FOXTROT","GOLF","HOTEL",
                   "INDIA","JULIET","KILO","LIMA","MIKE","NOVEMBER","OSCAR","PAPA",
                   "QUEBEC","ROMEO","SIERRA","TANGO","UNIFORM","VICTOR","WHISKEY",
                   "XRAY","YANKEE","ZULU"]
        _date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        _word = _rnd.choice(_NATO_W)
        _parts = name.split("__")[:2]
        run_id = "__".join(_parts) + f"__{_date}__{_word}"

    try:
        gt = run_scenario(pack, name, outdir, dst_ip=dst_ip, src_ip=src_ip,
                          run_id=run_id, build_pcap=build_pcap, skip_intervals=True,
                          no_marker=no_marker)
        final_run_id = gt.get("run_id") or run_id
        entry = {"run_id": final_run_id, "scenario": name, "pack": pack,
                 "events": gt.get("events"), "pcap": gt.get("pcap"),
                 "ts": datetime.now(timezone.utc).isoformat()+"Z"}
        # Register in SQLite so /api/runs and matrix overlay include offline runs
        try:
            reg = _registry()
            reg.upsert_run(final_run_id, scenario=name, pack=pack,
                           dst_ip=dst_ip, src_ip=src_ip, iface=None,
                           mode="offline", status="ok", meta={})
            if gt.get("events"):
                reg.add_artifact(final_run_id, "events", gt["events"])
            if gt.get("pcap"):
                reg.add_artifact(final_run_id, "pcap", gt["pcap"])
        except Exception:
            pass
        with suppress(OSError, ValueError):
            _append_run_index(entry)
        return jsonify({"ok": True, "run_id": final_run_id,
                        "events": gt.get("events"), "pcap": gt.get("pcap")})
    except Exception as e:
        return jsonify({"error": str(e)}), 500





# ── Industry profiles
@bp.route("/api/profiles")
def api_profiles():
    """List available industry profiles with their protocol/technique filters."""

    profiles = []
    for pf in _list_profiles():
        try:
            doc = yaml.safe_load(Path(pf).read_text(encoding="utf-8")) or {}
            profiles.append({
                "sector": doc.get("sector", Path(pf).stem),
                "description": doc.get("description", ""),
                "protocols": doc.get("protocols", []),
                "priority_techniques": doc.get("priority_techniques", []),
                "typical_assets": doc.get("typical_assets", []),
            })
        except Exception:
            continue
    return jsonify({"profiles": profiles})


# ── Scenario parameters schema
@bp.route("/api/scenario/params")
def api_scenario_params():
    """Return configurable parameters for a scenario's protocol."""
    proto = (request.args.get("proto") or "").strip()
    PROTO_PARAMS = {
        "modbus": [
            {"name": "register", "label": "Register address", "type": "number", "default": 0, "help": "Modbus holding register (0-65535)"},
            {"name": "unit_id", "label": "Unit ID", "type": "number", "default": 1, "help": "Modbus slave unit ID (1-247)"},
            {"name": "value", "label": "Write value", "type": "number", "default": 0, "help": "Value to write to register"},
        ],
        "iec61850": [
            {"name": "ied_ref",    "label": "IED Reference",   "type": "text",   "default": "IED1LD0/LLN0", "help": "Logical node reference (e.g. IED1LD0/LLN0)"},
            {"name": "gcb_suffix", "label": "GCB Suffix",       "type": "text",   "default": "GCB01",        "help": "GOOSE control block suffix"},
            {"name": "appid",      "label": "APPID (hex)",      "type": "text",   "default": "0x0004",       "help": "Application identifier (0x0000-0x3FFF)"},
            {"name": "st_num",     "label": "stNum override",   "type": "number", "default": "",             "help": "State number (blank = random high value for attack)"},
            {"name": "voltage",    "label": "Voltage (V)",      "type": "number", "default": "0.0",          "help": "Spoofed voltage for spoof_measurement style"},
        ],
        "opcua": [
            {"name": "node_id", "label": "OPC UA Node ID", "type": "text", "default": "1001", "help": "Node identifier (numeric, e.g. 1001, or ns=2;i=1001)"},
            {"name": "value", "label": "Write value", "type": "text", "default": "42.0", "help": "Value to write"},
        ],
        "mqtt": [
            {"name": "topic", "label": "MQTT topic", "type": "text", "default": "factory/plc01/control/valve-01", "help": "Publish/subscribe topic path"},
            {"name": "value", "label": "Payload", "type": "text", "default": '{"command":"open"}', "help": "MQTT message payload (JSON)"},
        ],
        "s7comm": [
            {"name": "db_number", "label": "DB number", "type": "number", "default": 1, "help": "S7 data block number"},
            {"name": "byte_offset", "label": "Byte offset", "type": "number", "default": 0, "help": "Offset within data block"},
        ],
        "dnp3": [
            {"name": "point_index", "label": "Point index", "type": "number", "default": 0, "help": "DNP3 binary/analog output point index"},
        ],
        "iec104": [
            {"name": "ioa", "label": "IOA (Info Object Address)", "type": "number", "default": 1, "help": "Information object address"},
        ],
        "bacnet": [
            {"name": "object_id", "label": "Object ID", "type": "number", "default": 1, "help": "BACnet object instance number"},
            {"name": "property_id", "label": "Property ID", "type": "number", "default": 85, "help": "BACnet property identifier (85=present-value)"},
        ],
        "enip": [
            {"name": "slot", "label": "Slot number", "type": "number", "default": 0, "help": "CIP route slot"},
        ],
    }
    params = PROTO_PARAMS.get(proto, [])
    return jsonify({"proto": proto, "params": params})

@bp.route("/api/pcap/upload", methods=["POST"])
def api_pcap_upload():
    """Accept a PCAP file upload and save it to out/pcaps/uploads/."""
    rr = str(Path(__file__).resolve().parents[2])
    upload_dir = os.path.join(rr, "out", "pcaps", "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "No file provided"}), 400
    safe_name = _re.sub(r"[^\w.\-]", "_", _P(f.filename).name)
    if not safe_name.endswith(".pcap") and not safe_name.endswith(".pcapng"):
        safe_name += ".pcap"
    dest = os.path.join(upload_dir, safe_name)
    stem, ext = os.path.splitext(safe_name)
    idx = 1
    while os.path.exists(dest):
        dest = os.path.join(upload_dir, f"{stem}_{idx}{ext}")
        idx += 1
    f.save(dest)
    return jsonify({"ok": True, "path": dest, "filename": os.path.basename(dest)})

