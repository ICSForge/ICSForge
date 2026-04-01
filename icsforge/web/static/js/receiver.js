const PROTO_C = {modbus:"#f59e0b",s7comm:"#2563eb",iec104:"#10b981",dnp3:"#7c3aed",opcua:"#0ea5e9",enip:"#ef4444",profinet_dcp:"#ea580c",bacnet:"#8b5cf6",mqtt:"#06b6d4"};

function $(id){ return document.getElementById(id); }

async function loadCallbackConfig(){
  try {
    const data = await window.fetchJSON("/api/config/network");
    if(data.sender_callback_url) $("cb_url").value = data.sender_callback_url;
    if(data.callback_token) $("cb_token").value = data.callback_token;
  } catch(e){}
}

async function saveCallbackConfig(){
  const sender_callback_url = $("cb_url").value.trim();
  const callback_token = $("cb_token").value.trim();
  const status = $("cb_status");
  status.textContent = "Saving…";
  status.style.color = "var(--muted)";
  try {
    await window.fetchJSON("/api/config/network", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({sender_callback_url, callback_token})
    });
    status.textContent = sender_callback_url ? "Saved" : "Callback cleared";
    status.style.color = "var(--good)";
    window.toast("Callback saved", sender_callback_url || "Receiver callback disabled", "ok");
  } catch(e) {
    status.textContent = "Save failed";
    status.style.color = "var(--err, #ef4444)";
    window.toast("Error", String(e), "error");
  }
}

async function testCallback(){
  const status = $("cb_status");
  status.textContent = "Testing…";
  status.style.color = "var(--muted)";
  try {
    const data = await window.fetchJSON("/api/config/test_callback", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:"{}"
    });
    status.textContent = `OK ${data.status} · ${data.response_ms}ms`;
    status.style.color = "var(--good)";
    window.toast("Callback OK", `${data.callback_url} responded in ${data.response_ms}ms`, "ok");
  } catch(e) {
    status.textContent = "Test failed";
    status.style.color = "var(--err, #ef4444)";
    window.toast("Callback failed", String(e), "error");
  }
}

function protoBadge(p){
  const c=PROTO_C[p]||"#475569";
  return `<span style="display:inline-block;padding:2px 6px;border-radius:999px;font-size:9px;font-weight:700;background:${c};color:${c==='#f59e0b'?'#000':'#fff'};font-family:var(--mono)">${p||"?"}</span>`;
}
function techBadge(t){
  if(!t) return '<span class="badge" style="font-size:9px">—</span>';
  return `<span class="badge brand" style="font-size:9px">${t}</span>`;
}

// NATO-style run IDs: YYYY-MM-DD-WORD-NN  |  Legacy: 12 hex chars
function isLegacyRunId(id){
  return id && /^[0-9a-f]{12}$/.test(id);
}
function runIdBadge(id){
  if(!id) return '—';
  if(isLegacyRunId(id)){
    return `<span class="mono" style="font-size:9px;color:var(--muted);opacity:.7"
      title="Legacy run ID">${id.slice(0,12)}</span>`;
  }
  // NATO format: show date muted, word bold, number normal
  const parts = id.split('-');  // ['2026','03','05','BRAVO','07']
  if(parts.length === 5){
    const date = parts.slice(0,3).join('-');
    const word = parts[3];
    const num  = parts[4];
    return `<span style="cursor:pointer" onclick="loadRun('${id}')">` +
      `<span class="mono" style="font-size:9px;color:var(--muted)">${date} </span>` +
      `<span class="mono" style="font-size:10px;font-weight:700;color:var(--brand2)">${word}</span>` +
      `<span class="mono" style="font-size:9px;color:var(--fg)">-${num}</span>` +
      `</span>`;
  }
  return `<a class="mono" style="color:var(--brand2);font-size:10px;cursor:pointer"
    onclick="loadRun('${id}')">${id.slice(0,20)}</a>`;
}

async function reloadReceipts(){
  const qs = new URLSearchParams();
  const rv=$("f_run").value.trim(), tv=$("f_tech").value.trim(), pv=$("f_proto").value.trim();
  if(rv) qs.set("run_id",rv); if(tv) qs.set("technique",tv); if(pv) qs.set("proto",pv);
  const data = await window.fetchJSON("/api/receipts?"+qs.toString());
  const tb = document.querySelector("#receipts_tbl tbody");
  tb.innerHTML = "";
  for(const r of (data.items||[])){
    const ts = (r["@timestamp"]||"").replace("T"," ").slice(0,19);
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono" style="font-size:10px;white-space:nowrap">${ts}</td>
      <td>${protoBadge(r["receiver.proto"])}</td>
      <td class="mono" style="font-size:10px">${r["receiver.l2"] ? (r.src_mac||"L2") : ((r.src_ip||"")+":"+(r.src_port||""))}</td>
      <td>${techBadge(r.technique)}</td>
      <td>${runIdBadge(r.run_id)}</td>
      <td class="mono" style="font-size:10px">${r.bytes||0}</td>`;
    tb.appendChild(tr);
  }
}

async function loadRun(run_id){
  const data = await window.fetchJSON("/api/run_detail?run_id="+encodeURIComponent(run_id));
  const p = document.getElementById("run_panel");
  if(!data.run_id){ p.innerHTML="<span style='color:var(--muted)'>Run not found.</span>"; return; }
  const techs = (data.techniques||[]).map(t=>`<span class="badge brand" style="font-size:10px">${t}</span>`).join(" ");
  if(data.bins){ drawSparkline(document.getElementById("spark_run"), (data.bins||[]).map((b,i)=>[i,b.count])); }
  const legacyNote = isLegacyRunId(data.run_id)
    ? `<span class="badge" style="font-size:9px;opacity:.6;margin-left:6px">legacy id</span>` : '';
  p.innerHTML = `
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:10px">
      <div>
        <div class="mono" style="font-size:15px;font-weight:700;color:var(--brand2)">${data.run_id}${legacyNote}</div>
        <div class="small" style="margin-top:4px">Packets: <b>${data.packets}</b></div>
        <div class="small">First: ${(data.first_seen||"—").replace("T"," ").slice(0,19)}</div>
        <div class="small">Last:  ${(data.last_seen||"—").replace("T"," ").slice(0,19)}</div>
      </div>
      <span class="badge good">DELIVERED</span>
    </div>
    <div class="hr"></div>
    <div class="small" style="margin-bottom:6px">Techniques observed:</div>
    <div class="pillrow">${techs || "<span class='badge'>none</span>"}</div>
    <div class="hr"></div>
    <div class="small" style="color:var(--muted)">Evidence stored in receipts.jsonl with correlation marker.</div>`;
}

async function resetReceipts(){
  if(!confirm('Archive current receipts.jsonl and reset all counters?\n\nYour data is not deleted — it is saved as receipts_TIMESTAMP.jsonl in the same folder.')) return;
  const btn = $("reset_btn");
  btn.disabled = true; btn.textContent = "Resetting…";
  try {
    const res = await fetch("/api/receiver/reset", {method:"POST"});
    const d   = await res.json();
    if(d.error){ alert("Reset failed: "+d.error); return; }
    const msg = d.archived
      ? `Archived ${d.lines} packets → ${d.archived}`
      : "Nothing to reset (0 packets).";
    window.toast("Reset complete", msg, "ok");
    reloadReceipts();
    reloadOverview();
  } finally {
    btn.disabled = false; btn.textContent = "⟳ Reset";
  }
}

async function reloadOverview(){
  const data = await window.fetchJSON("/api/receiver/overview");
  if(!data) return;
  $("k_total").textContent = data.total ?? 0;
  $("k_runs").textContent  = data.runs  ?? 0;
  $("k_tech").textContent  = (data.top_techniques||[]).length;
  $("k_proto").textContent = (data.top_protocols||[]).length;
  // L2 listener status banner
  const banner = $("l2_banner");
  if(banner){
    if(data.l2_active){
      banner.style.display = "";
      banner.style.background = "rgba(16,185,129,.1)";
      banner.style.border = "1px solid rgba(16,185,129,.3)";
      banner.style.color = "#10b981";
      banner.textContent = "⬡ PROFINET L2 listener active on interface: " + data.l2_iface;
    } else {
      banner.style.display = "";
      banner.style.background = "rgba(239,68,68,.08)";
      banner.style.border = "1px solid rgba(239,68,68,.25)";
      banner.style.color = "#ef4444";
      banner.textContent = "⚠ PROFINET L2 listener not running. Start receiver with --l2-iface eth0 to capture PROFINET DCP frames.";
    }
  }
  const lbl = $("live_label");
  if(lbl) lbl.textContent = `Last: ${(data.last_ts||"—").replace("T"," ").slice(0,19)}`;
  const dot = $("live_dot");
  if(dot) dot.classList.remove("off");
}

loadCallbackConfig();
reloadReceipts();
reloadOverview();
setInterval(()=>{ reloadReceipts(); reloadOverview(); }, 2000);

/* ── Live SSE toast feed (v0.48) ────────────────────────────── */
let _rxSse = null;
let _rxLastToastTs = 0;
const _TOAST_THROTTLE_MS = 800; // max one toast per 800ms during burst

function _startReceiverSSE(){
  if(_rxSse) return;
  try {
    _rxSse = new EventSource("/api/receiver/stream");
    _rxSse.onmessage = function(ev){
      try {
        const d = JSON.parse(ev.data);
        if(d.type === "connected") return;
        const tech  = d.technique || "";
        const proto = d["receiver.proto"] || d.proto || "";
        const now = Date.now();
        // Throttle: skip toast if another fired too recently
        if(now - _rxLastToastTs < _TOAST_THROTTLE_MS) return;
        _rxLastToastTs = now;
        const label = [tech, proto].filter(Boolean).join(" · ") || "packet";
        window.toast("Received", label, "ok");
      } catch(e){}
    };
    _rxSse.onerror = function(){
      _rxSse.close();
      _rxSse = null;
      // Fall back to polling-only (already running above)
    };
  } catch(e){ /* SSE not supported — polling continues */ }
}
_startReceiverSSE();
