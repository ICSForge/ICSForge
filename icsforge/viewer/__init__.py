"""
ICSForge Alert Viewer — tiny Flask service for live Suricata alert display.

Reads Suricata EVE JSON from the shared /var/log/suricata volume, parses
alerts, maps each to the ICSForge ATT&CK for ICS technique (encoded in the
rule msg as "[T0xxx]"), and exposes:

    GET  /            — live dashboard (vanilla HTML + SSE)
    GET  /events      — Server-Sent Events stream of new alerts
    GET  /api/alerts  — most recent N alerts as JSON
    GET  /api/stats   — counts per technique and per tier
    GET  /api/health  — liveness check

Zero external dependencies beyond Flask. No database. Rolling in-memory
buffer of the most recent 500 alerts. Restart-safe.

Rule msg conventions honoured:
    "[T0xxx] ICSForge semantic <proto> <fc_name>"     -> tier=semantic
    "[T0xxx] ICSForge heuristic <proto>"              -> tier=heuristic
    "[T0xxx] ICSForge lab_marker <proto> <scenario>"  -> tier=lab
"""
from __future__ import annotations

import json
import os
import queue
import re
import threading
import time
from collections import Counter, deque
from pathlib import Path

from flask import Flask, Response, jsonify, render_template_string, request

EVE_PATH = os.environ.get("ICSFORGE_EVE_PATH", "/var/log/suricata/eve.json")
MAX_ALERTS = int(os.environ.get("ICSFORGE_VIEWER_BUFFER", "500"))
POLL_INTERVAL = float(os.environ.get("ICSFORGE_VIEWER_POLL", "0.5"))

# ── Tier detection from rule message ─────────────────────────────────────
_TIER_RE = re.compile(r"ICSForge\s+(lab_marker|heuristic|semantic)\b", re.IGNORECASE)
_TECH_RE = re.compile(r"\[(T\d{4})\]")


def _classify(msg: str) -> tuple[str, str]:
    """Return (technique, tier) extracted from a Suricata alert msg."""
    tech_m = _TECH_RE.search(msg or "")
    tier_m = _TIER_RE.search(msg or "")
    technique = tech_m.group(1) if tech_m else "unknown"
    tier = tier_m.group(1).lower() if tier_m else "unknown"
    if tier == "lab_marker":
        tier = "lab"
    return technique, tier


# ── Tail thread — single source of truth ─────────────────────────────────
class EveTailer:
    def __init__(self, path: str, buffer_size: int):
        self.path = path
        self.buffer: deque[dict] = deque(maxlen=buffer_size)
        self.stats_tech: Counter = Counter()
        self.stats_tier: Counter = Counter()
        self.subscribers: list[queue.Queue] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="eve-tailer", daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=100)
        with self._lock:
            self.subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue):
        with self._lock:
            try:
                self.subscribers.remove(q)
            except ValueError:
                pass

    def _publish(self, record: dict):
        with self._lock:
            self.buffer.append(record)
            self.stats_tech[record["technique"]] += 1
            self.stats_tier[record["tier"]] += 1
            dead = []
            for q in self.subscribers:
                try:
                    q.put_nowait(record)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                try:
                    self.subscribers.remove(q)
                except ValueError:
                    pass

    def _parse_line(self, line: str) -> dict | None:
        try:
            doc = json.loads(line)
        except json.JSONDecodeError:
            return None
        if doc.get("event_type") != "alert":
            return None
        alert = doc.get("alert", {}) or {}
        msg = alert.get("signature", "")
        technique, tier = _classify(msg)
        return {
            "ts": doc.get("timestamp", ""),
            "src_ip": doc.get("src_ip"),
            "src_port": doc.get("src_port"),
            "dst_ip": doc.get("dest_ip"),
            "dst_port": doc.get("dest_port"),
            "proto": doc.get("proto"),
            "app_proto": doc.get("app_proto"),
            "signature": msg,
            "sid": alert.get("signature_id"),
            "severity": alert.get("severity"),
            "category": alert.get("category"),
            "technique": technique,
            "tier": tier,
        }

    def _open_and_seek_end(self):
        # Wait for the file to exist; seek to end so we only see new alerts.
        while not self._stop.is_set():
            if os.path.exists(self.path):
                try:
                    f = open(self.path, encoding="utf-8", errors="replace")
                    f.seek(0, os.SEEK_END)
                    return f
                except OSError:
                    pass
            time.sleep(1)
        return None

    def _run(self):
        f = self._open_and_seek_end()
        if f is None:
            return
        inode = None
        try:
            inode = os.fstat(f.fileno()).st_ino
        except OSError:
            pass

        while not self._stop.is_set():
            line = f.readline()
            if line:
                rec = self._parse_line(line)
                if rec is not None:
                    self._publish(rec)
                continue

            # Detect rotation: inode change => reopen
            time.sleep(POLL_INTERVAL)
            try:
                cur = os.stat(self.path).st_ino
                if inode is not None and cur != inode:
                    try:
                        f.close()
                    except OSError:
                        pass
                    f = open(self.path, encoding="utf-8", errors="replace")
                    inode = cur
            except OSError:
                continue


# ── Flask app ────────────────────────────────────────────────────────────
def create_app() -> Flask:
    app = Flask(__name__)
    tailer = EveTailer(EVE_PATH, MAX_ALERTS)
    tailer.start()
    app.config["_TAILER"] = tailer

    @app.route("/")
    def index():
        return render_template_string(_DASHBOARD_HTML)

    @app.route("/api/alerts")
    def api_alerts():
        limit = int(request.args.get("limit", 100))
        with tailer._lock:  # readonly snapshot
            data = list(tailer.buffer)[-limit:]
        return jsonify({"count": len(data), "alerts": data})

    @app.route("/api/stats")
    def api_stats():
        with tailer._lock:
            tech = dict(tailer.stats_tech)
            tier = dict(tailer.stats_tier)
            total = sum(tech.values())
        return jsonify({
            "total_alerts": total,
            "by_technique": tech,
            "by_tier": tier,
            "buffer_path": EVE_PATH,
        })

    @app.route("/api/health")
    def api_health():
        return jsonify({
            "status": "ok",
            "eve_path": EVE_PATH,
            "eve_exists": os.path.exists(EVE_PATH),
            "subscribers": len(tailer.subscribers),
            "buffered": len(tailer.buffer),
        })

    @app.route("/events")
    def events():
        def stream():
            q = tailer.subscribe()
            try:
                # Send a hello event so the browser knows the stream is open.
                yield f"event: hello\ndata: {json.dumps({'ts': time.time()})}\n\n"
                # Replay the last 20 alerts on reconnect so the panel is populated.
                with tailer._lock:
                    replay = list(tailer.buffer)[-20:]
                for rec in replay:
                    yield f"event: alert\ndata: {json.dumps(rec)}\n\n"
                # Then block on new alerts.
                while True:
                    try:
                        rec = q.get(timeout=15)
                        yield f"event: alert\ndata: {json.dumps(rec)}\n\n"
                    except queue.Empty:
                        # Heartbeat to keep middleware from closing the pipe.
                        yield ": keepalive\n\n"
            finally:
                tailer.unsubscribe(q)

        headers = {
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        }
        return Response(stream(), mimetype="text/event-stream", headers=headers)

    return app


# ── Dashboard HTML (inline to keep this single-file) ─────────────────────
_DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ICSForge — Live Detection Feed</title>
<style>
  :root {
    --bg: #0b0d12;
    --panel: #151924;
    --panel-alt: #1c2130;
    --text: #e6e9f0;
    --muted: #7a8196;
    --border: #252b3d;
    --lab: #5fb3ff;
    --heuristic: #ffb347;
    --semantic: #5eff9b;
    --unknown: #888;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    background: var(--bg); color: var(--text);
  }
  header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px 22px; border-bottom: 1px solid var(--border);
    background: var(--panel);
  }
  header h1 { margin: 0; font-size: 18px; font-weight: 600; letter-spacing: 0.3px; }
  header .status {
    display: flex; gap: 18px; font-size: 13px; color: var(--muted);
  }
  header .status b { color: var(--text); }
  .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--semantic); margin-right: 6px; }
  .dot.off { background: #555; }

  main {
    display: grid; grid-template-columns: 320px 1fr; gap: 0;
    height: calc(100vh - 53px);
  }
  aside {
    background: var(--panel); border-right: 1px solid var(--border);
    padding: 18px; overflow-y: auto;
  }
  aside h2 { font-size: 12px; text-transform: uppercase; letter-spacing: 1.1px; color: var(--muted); margin: 0 0 10px; }
  .tier-row {
    display: flex; justify-content: space-between; align-items: center;
    padding: 8px 10px; border-radius: 6px; margin-bottom: 6px;
    background: var(--panel-alt);
  }
  .tier-row .label { display: flex; align-items: center; gap: 8px; font-size: 13px; }
  .tier-row .swatch { width: 10px; height: 10px; border-radius: 2px; }
  .tier-row .count { font-variant-numeric: tabular-nums; font-weight: 600; }
  .tech-list { margin-top: 18px; }
  .tech-row {
    display: flex; justify-content: space-between; align-items: center;
    padding: 6px 10px; font-size: 13px;
  }
  .tech-row .tid { color: var(--text); font-family: "SF Mono", Menlo, monospace; }
  .tech-row .tc  { color: var(--muted); font-variant-numeric: tabular-nums; }

  section.feed { overflow-y: auto; padding: 18px; }
  .empty { color: var(--muted); padding: 40px 10px; text-align: center; }
  .alert {
    display: grid; grid-template-columns: 120px 60px 1fr auto; gap: 14px;
    padding: 10px 14px; border-left: 3px solid var(--unknown);
    background: var(--panel); border-radius: 6px; margin-bottom: 6px;
    animation: slide 240ms ease;
  }
  .alert.lab       { border-left-color: var(--lab); }
  .alert.heuristic { border-left-color: var(--heuristic); }
  .alert.semantic  { border-left-color: var(--semantic); }
  .alert .ts   { color: var(--muted); font-family: "SF Mono", Menlo, monospace; font-size: 12px; }
  .alert .tid  { font-family: "SF Mono", Menlo, monospace; font-size: 12px; color: var(--text); font-weight: 600; }
  .alert .msg  { font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .alert .tier { font-size: 11px; padding: 2px 8px; border-radius: 10px; text-transform: uppercase; letter-spacing: 0.6px; }
  .alert.lab       .tier { color: var(--lab); background: rgba(95,179,255,0.12); }
  .alert.heuristic .tier { color: var(--heuristic); background: rgba(255,179,71,0.12); }
  .alert.semantic  .tier { color: var(--semantic); background: rgba(94,255,155,0.12); }
  .alert.unknown   .tier { color: var(--unknown); background: rgba(136,136,136,0.12); }

  @keyframes slide {
    from { opacity: 0; transform: translateY(-6px); }
    to   { opacity: 1; transform: translateY(0); }
  }
</style>
</head>
<body>
<header>
  <h1>ICSForge — Live Detection Feed</h1>
  <div class="status">
    <span><span class="dot" id="conn-dot"></span><b id="conn-label">connecting…</b></span>
    <span>Total alerts: <b id="total">0</b></span>
    <span>Buffer: <b id="buffer">0</b></span>
  </div>
</header>
<main>
  <aside>
    <h2>Detection tiers</h2>
    <div id="tiers"></div>
    <h2 class="tech-list">Techniques seen</h2>
    <div id="techniques"></div>
  </aside>
  <section class="feed" id="feed">
    <div class="empty" id="empty">
      Waiting for Suricata alerts…<br><br>
      Run a campaign on the sender (:8080) and alerts will appear here live.
    </div>
  </section>
</main>
<script>
  const feed = document.getElementById('feed');
  const empty = document.getElementById('empty');
  const tiersEl = document.getElementById('tiers');
  const techEl = document.getElementById('techniques');
  const totalEl = document.getElementById('total');
  const bufferEl = document.getElementById('buffer');
  const connDot = document.getElementById('conn-dot');
  const connLabel = document.getElementById('conn-label');

  const tierOrder = ['semantic', 'heuristic', 'lab', 'unknown'];
  const tierLabel = { semantic: 'Semantic (FC-level)', heuristic: 'Heuristic (protocol)', lab: 'Lab (marker)', unknown: 'Unknown' };
  const counts = { tech: {}, tier: {} };

  function renderAside() {
    tiersEl.innerHTML = tierOrder.map(t => {
      const c = counts.tier[t] || 0;
      return `<div class="tier-row">
        <span class="label"><span class="swatch" style="background: var(--${t})"></span>${tierLabel[t]}</span>
        <span class="count">${c}</span>
      </div>`;
    }).join('');
    const tech = Object.entries(counts.tech).sort((a, b) => b[1] - a[1]).slice(0, 40);
    techEl.innerHTML = tech.length === 0
      ? '<div class="tech-row"><span class="tid">—</span><span class="tc">0</span></div>'
      : tech.map(([t, c]) => `<div class="tech-row"><span class="tid">${t}</span><span class="tc">${c}</span></div>`).join('');
  }

  function appendAlert(a) {
    if (empty.parentNode) empty.remove();
    counts.tech[a.technique] = (counts.tech[a.technique] || 0) + 1;
    counts.tier[a.tier] = (counts.tier[a.tier] || 0) + 1;
    totalEl.textContent = Object.values(counts.tier).reduce((a, b) => a + b, 0);
    bufferEl.textContent = feed.children.length + 1;

    const el = document.createElement('div');
    el.className = `alert ${a.tier}`;
    const ts = (a.ts || '').replace('T', ' ').split('.')[0];
    el.innerHTML = `
      <span class="ts">${ts}</span>
      <span class="tid">${a.technique}</span>
      <span class="msg" title="${(a.signature || '').replace(/"/g, '&quot;')}">${a.signature || ''}</span>
      <span class="tier">${a.tier}</span>
    `;
    feed.insertBefore(el, feed.firstChild);
    // Cap DOM at 120 rows; aside stats still count the full history.
    while (feed.children.length > 120) feed.removeChild(feed.lastChild);
    renderAside();
  }

  function connect() {
    const es = new EventSource('/events');
    es.addEventListener('hello', () => {
      connDot.classList.remove('off'); connLabel.textContent = 'live';
    });
    es.addEventListener('alert', (ev) => appendAlert(JSON.parse(ev.data)));
    es.onerror = () => {
      connDot.classList.add('off'); connLabel.textContent = 'reconnecting…';
      es.close(); setTimeout(connect, 2000);
    };
  }
  connect();
  renderAside();
</script>
</body>
</html>
"""


def main():
    global EVE_PATH
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=3000)
    p.add_argument("--eve-path", default=EVE_PATH)
    args = p.parse_args()
    EVE_PATH = args.eve_path
    app = create_app()
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
