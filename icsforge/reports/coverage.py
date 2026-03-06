"""
ICSForge v0.30 Coverage Report Generator
"""
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import json


_MATRIX_PATH = Path(__file__).parent.parent / "data" / "ics_attack_matrix.json"

STATUS_COLORS = {
    "detected": ("#10b981", "Detected"),
    "executed": ("#f59e0b", "Executed / Not Detected"),
    "gap":      ("#ef4444", "Gap Found (blind spot)"),
    "none":     ("#1e293b", "Not Tested"),
}


def _load_matrix() -> dict:
    return json.loads(_MATRIX_PATH.read_text(encoding="utf-8"))


def generate_report(
    run_id: str | None,
    scenario_name: str | None,
    executed_techniques: list[str],
    detected_techniques: list[str],
    gap_techniques: list[str],
    protocol_gaps: list[dict] | None = None,
    meta: dict[str, Any] | None = None,
) -> str:
    mat      = _load_matrix()
    meta     = meta or {}
    now_str  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    run_ref  = run_id or "—"
    protocol_gaps = protocol_gaps or []

    # Assessment date — from meta if provided, else today
    assess_date = meta.get("assess_date", "") or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    executed_set = set(executed_techniques)
    detected_set = set(detected_techniques)
    gap_set      = set(gap_techniques)

    def tech_status(tid: str) -> str:
        if tid in detected_set: return "detected"
        if tid in gap_set:      return "gap"
        if tid in executed_set: return "executed"
        return "none"

    total_matrix = sum(len(t["techniques"]) for t in mat["tactics"])
    total_exec   = len(executed_set)
    total_det    = len(detected_set)
    total_gap    = len(gap_set)
    pct_exec     = int(100 * total_exec / total_matrix) if total_matrix else 0
    pct_det      = int(100 * total_det  / total_exec)   if total_exec   else 0

    # Matrix tiles
    tactic_cols = ""
    for tac in mat["tactics"]:
        tiles = ""
        for tech in tac["techniques"]:
            tid   = tech["id"]
            tname = tech["name"]
            st    = tech_status(tid)
            color, label = STATUS_COLORS[st]
            tiles += (
                f'<div class="tile st-{st}" title="{tid}: {tname} [{label}]">'
                f'<div class="tid">{tid}</div>'
                f'<div class="tname">{tname}</div>'
                f'</div>'
            )
        tactic_cols += (
            f'<div class="tac-col">'
            f'<div class="tac-head">{tac["name"]}</div>'
            f'<div class="tac-body">{tiles}</div>'
            f'</div>'
        )

    # Technique detail table — only non-"none" rows
    rows = ""
    for tac in mat["tactics"]:
        for tech in tac["techniques"]:
            tid = tech["id"]
            st  = tech_status(tid)
            if st == "none": continue
            color, st_label = STATUS_COLORS[st]
            rows += (
                f'<tr>'
                f'<td><code>{tid}</code></td>'
                f'<td>{tech["name"]}</td>'
                f'<td>{tac["name"]}</td>'
                f'<td><span class="badge" style="background:{color}20;color:{color};border:1px solid {color}40">'
                f'{st_label}</span></td>'
                f'</tr>'
            )

    # Protocol gaps table
    proto_section = ""
    if protocol_gaps:
        pg_rows = "".join(
            f'<tr>'
            f'<td><code>{pg.get("protocol","")}</code></td>'
            f'<td>{pg.get("gap_type","")}</td>'
            f'<td style="color:#94a3b8">{pg.get("note","")}</td>'
            f'</tr>'
            for pg in protocol_gaps
        )
        proto_section = f"""
<h2>Protocol Coverage Gaps</h2>
<p style="color:#94a3b8;margin-bottom:12px;max-width:720px">
  The following protocols were flagged as having coverage gaps — not firewalled,
  not monitored, or lacking detection rules. These represent architectural blind spots
  independent of technique coverage.
</p>
<table>
<thead><tr><th>Protocol</th><th>Gap Type</th><th>Notes</th></tr></thead>
<tbody>{pg_rows}</tbody>
</table>
"""

    # Executive summary
    gap_verdict = ""
    if total_exec > 0:
        if pct_det < 50:
            gap_verdict = (
                '<br><br><strong style="color:#ef4444">⚠ Critical: detection rate below 50%.</strong> '
                'Immediate NSM/IDS tuning is recommended before next assessment.'
            )
        elif pct_det >= 80:
            gap_verdict = (
                '<br><br><strong style="color:#10b981">✓ Strong detection posture.</strong> '
                'Over 80% of tested techniques were detected. Focus on expanding matrix coverage.'
            )

    proto_gap_note = (
        f'<br>Additionally, <strong style="color:#ef4444">{len(protocol_gaps)}</strong> '
        f'protocol-level coverage gap(s) were identified — see Protocol Coverage Gaps section.'
    ) if protocol_gaps else ""

    num_cols = len(mat["tactics"])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ICSForge Coverage Report — {assess_date}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Courier New',monospace;background:#0a0f1a;color:#e2e8f0;font-size:13px;line-height:1.5;padding:32px}}
h1{{font-size:26px;font-weight:900;letter-spacing:-.02em;color:#fff;margin-bottom:4px}}
h2{{font-size:14px;font-weight:700;color:#f59e0b;margin:28px 0 12px;text-transform:uppercase;letter-spacing:.08em}}
.meta{{color:#64748b;font-size:11px;margin-bottom:24px;line-height:1.8}}
.meta strong{{color:#94a3b8}}
.kpi-row{{display:flex;gap:14px;margin-bottom:28px;flex-wrap:wrap}}
.kpi{{background:#111827;border:1px solid #1e293b;border-top:2px solid #f59e0b;border-radius:10px;padding:14px 20px;min-width:130px}}
.kpi .v{{font-size:28px;font-weight:900;color:#f59e0b;line-height:1}}
.kpi .l{{font-size:10px;color:#64748b;margin-top:4px;text-transform:uppercase;letter-spacing:.05em}}
.kpi.green .v{{color:#10b981}} .kpi.green{{border-top-color:#10b981}}
.kpi.red   .v{{color:#ef4444}} .kpi.red{{border-top-color:#ef4444}}
.kpi.blue  .v{{color:#38bdf8}} .kpi.blue{{border-top-color:#38bdf8}}
.matrix{{display:grid;grid-template-columns:repeat({num_cols},minmax(0,1fr));gap:3px;margin-bottom:28px;overflow-x:auto;padding-bottom:8px}}
.tac-col{{background:#111827;border:1px solid #1e293b;border-radius:6px;overflow:hidden;min-width:85px}}
.tac-head{{background:#1e293b;padding:5px 7px;font-size:8.5px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#94a3b8;border-bottom:2px solid #f59e0b}}
.tac-body{{padding:3px;display:flex;flex-direction:column;gap:2px}}
.tile{{padding:3px 5px;border-radius:3px;border:1px solid transparent;min-height:32px}}
.tile .tid{{font-size:7px;font-weight:700;color:#64748b;line-height:1}}
.tile .tname{{font-size:8px;font-weight:500;line-height:1.2;margin-top:1px}}
.st-detected{{background:rgba(16,185,129,.15);border-color:rgba(16,185,129,.45);}}
.st-detected .tid{{color:#10b981}} .st-detected .tname{{color:#6ee7b7}}
.st-executed{{background:rgba(245,158,11,.12);border-color:rgba(245,158,11,.4);}}
.st-executed .tid{{color:#f59e0b}} .st-executed .tname{{color:#fcd34d}}
.st-gap{{background:rgba(239,68,68,.12);border-color:rgba(239,68,68,.4);}}
.st-gap .tid{{color:#ef4444}} .st-gap .tname{{color:#fca5a5}}
.st-none{{background:#0f172a;border-color:#1e293b;opacity:.35}}
.legend{{display:flex;gap:14px;margin-bottom:16px;flex-wrap:wrap}}
.leg-item{{display:flex;align-items:center;gap:5px;font-size:11px;color:#94a3b8}}
.leg-dot{{width:10px;height:10px;border-radius:2px;flex-shrink:0}}
table{{width:100%;border-collapse:collapse;margin-bottom:24px}}
th{{text-align:left;padding:7px 12px;background:#111827;color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid #1e293b}}
td{{padding:7px 12px;border-bottom:1px solid #0f172a;font-size:12px}}
tr:hover td{{background:#111827}}
code{{font-family:'Courier New',monospace;font-size:11px;color:#f59e0b}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700}}
.footer{{margin-top:32px;padding-top:14px;border-top:1px solid #1e293b;color:#334155;font-size:10px;text-align:center}}
@media print{{body{{background:#fff;color:#000;padding:20px}}
  .kpi,.tac-col{{border-color:#ccc}} .kpi .v,.h2{{color:#000}}
  .st-detected{{background:#d1fae5!important}} .st-gap{{background:#fee2e2!important}}
  .st-executed{{background:#fef3c7!important}} .st-none{{opacity:.2}}}}
</style>
</head>
<body>
<h1>ICSForge Coverage Report</h1>
<div class="meta">
  <strong>Assessment Date:</strong> {assess_date} &nbsp;·&nbsp;
  <strong>Generated:</strong> {now_str}<br>
  <strong>Run ID:</strong> {run_ref} &nbsp;·&nbsp;
  {f'<strong>Scenario:</strong> {scenario_name} &nbsp;·&nbsp;' if scenario_name else ''}
  <strong>Matrix:</strong> ATT&amp;CK for ICS v{mat.get("x_mitre_version","?")}<br>
  <strong>Organization:</strong> {meta.get("org","—")} &nbsp;·&nbsp;
  <strong>Analyst:</strong> {meta.get("analyst","—")}
  {f'<br><strong>Notes:</strong> {meta.get("notes","")}' if meta.get("notes") else ""}
</div>

<div class="kpi-row">
  <div class="kpi blue"><div class="v">{total_matrix}</div><div class="l">Matrix Techniques</div></div>
  <div class="kpi"><div class="v">{total_exec}</div><div class="l">Executed</div></div>
  <div class="kpi green"><div class="v">{total_det}</div><div class="l">Detected</div></div>
  <div class="kpi red"><div class="v">{total_gap}</div><div class="l">Gaps Found</div></div>
  <div class="kpi"><div class="v">{pct_exec}%</div><div class="l">Matrix Coverage</div></div>
  <div class="kpi {'green' if pct_det>=80 else 'red' if pct_det<50 else ''}">
    <div class="v">{pct_det}%</div><div class="l">Detection Rate</div></div>
  {f'<div class="kpi red"><div class="v">{len(protocol_gaps)}</div><div class="l">Protocol Gaps</div></div>' if protocol_gaps else ''}
</div>

<h2>ATT&amp;CK for ICS Heatmap</h2>
<div class="legend">
  <div class="leg-item"><div class="leg-dot" style="background:#10b981"></div>Detected</div>
  <div class="leg-item"><div class="leg-dot" style="background:#f59e0b"></div>Executed / Not Detected</div>
  <div class="leg-item"><div class="leg-dot" style="background:#ef4444"></div>Gap Found (blind spot)</div>
  <div class="leg-item"><div class="leg-dot" style="background:#1e293b;opacity:.5"></div>Not Tested</div>
</div>
<div class="matrix">{tactic_cols}</div>

<h2>Technique Detail</h2>
<table>
<thead><tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Status</th></tr></thead>
<tbody>{rows}</tbody>
</table>

{proto_section}

<h2>Executive Summary</h2>
<p style="color:#94a3b8;line-height:1.8;max-width:820px">
  Assessment date: <strong style="color:#e2e8f0">{assess_date}</strong>.
  ICSForge executed <strong style="color:#f59e0b">{total_exec}</strong> of
  <strong style="color:#38bdf8">{total_matrix}</strong> ATT&amp;CK for ICS techniques
  ({pct_exec}% matrix coverage).
  The detection stack identified <strong style="color:#10b981">{total_det}</strong> ({pct_det}% detection rate),
  leaving <strong style="color:#ef4444">{total_gap}</strong> gap(s) confirmed as blind spots.
  {proto_gap_note}
  {gap_verdict}
</p>

<div class="footer">
  ICSForge v0.30 · OT/ICS Cybersecurity Coverage Validation Framework · GPLv3<br>
  Generated using synthetic traffic. All packets were safe-by-design with no destructive payloads.
</div>
</body>
</html>"""
    return html
