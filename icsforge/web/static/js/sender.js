(function(){
const $ = id => document.getElementById(id);
const API = window.fetchJSON;

/* ── State ──────────────────────────────────────────────────── */
let allGroups    = [];
let selectedName = null;
let previewData  = null;
let hexStepIdx   = 0;
let feedPollTimer = null;
let prevTotal    = null;

/* ── Protocol colours ───────────────────────────────────────── */
const PROTO_C = {modbus:"#f59e0b",s7comm:"#2563eb",iec104:"#10b981",iec61850:"#16a34a",dnp3:"#7c3aed",opcua:"#0ea5e9",enip:"#ef4444",profinet_dcp:"#ea580c",bacnet:"#8b5cf6",mqtt:"#06b6d4"};
function protoBadge(p){const c=PROTO_C[p]||"#475569";return `<span class="proto-badge" style="background:${c};${c==='#f59e0b'?'color:#000':''}">${p}</span>`;}
function protoDot(p){const c=PROTO_C[p]||"#888";return `<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:${c}" title="${p}"></span>`;}

/* ── Log ────────────────────────────────────────────────────── */
function logln(msg, cls=""){
  const el = $("run_log"), s = document.createElement("span");
  if(cls) s.className = cls;
  s.textContent = msg + "\n";
  el.appendChild(s); el.scrollTop = el.scrollHeight;
}

/* ── Load groups ────────────────────────────────────────────── */
async function loadGroups(){
  const data = await API("/api/scenarios_grouped");
  allGroups = data.groups || [];
  renderChainCards();
  renderScenarioList("");
}

/* ── Chain cards ────────────────────────────────────────────── */
const CHAIN_META = {
  CHAIN__industroyer2__power_grid:   {icon:"⚡",label:"Industroyer2",sub:"Ukraine 2022 · IEC-104 + S7comm"},
  CHAIN__triton__safety_system:      {icon:"☢",label:"SIS Targeting (TRITON-inspired)",sub:"Modbus+S7comm surrogate · SIS disable pattern"},
  CHAIN__stuxnet__siemens_plc:       {icon:"⚙",label:"Stuxnet-style",sub:"Siemens PLC · Program manipulation"},
  CHAIN__water_treatment_tampering:  {icon:"💧",label:"Water Treatment",sub:"Oldsmar-style · Setpoint tampering"},
  CHAIN__industrial_espionage__opcua:{icon:"🕵",label:"OPC UA Espionage",sub:"Silent exfil via OPC UA sessions"},
  CHAIN__enip_manufacturing_attack:  {icon:"🏭",label:"EtherNet/IP MFG",sub:"Allen-Bradley · CIP manipulation"},
};
function renderChainCards(){
  const grid = $("chains_grid");
  const chains = (allGroups.find(g=>g.name.includes("Attack Chains"))||{}).scenarios||[];
  if(!chains.length){grid.innerHTML='<div class="small">No chains found.</div>';return;}
  // Split: named chains (in CHAIN_META) first row, generic chains second row
  const named   = chains.filter(sc => sc.id in CHAIN_META);
  const generic = chains.filter(sc => !(sc.id in CHAIN_META));
  function renderCard(sc){
    const m = CHAIN_META[sc.id]||{icon:"⛓",label:sc.title,sub:sc.protocols.join(" · ")};
    const pills = sc.techniques.slice(0,4).map(t=>`<span class="chain-pill">${t}</span>`).join("");
    return `<div class="chain-card" onclick="selectScenario('${sc.id}')">
      <div class="chain-name">${m.icon} ${m.label}</div>
      <div class="chain-sub">${m.sub}</div>
      <div class="chain-pills">${pills}</div>
    </div>`;
  }
  let html = named.map(renderCard).join("");
  if(generic.length){
    html += `<div style="width:100%;font-size:10px;color:var(--muted);margin:6px 0 2px;letter-spacing:.04em">MULTI-PROTOCOL CHAINS</div>`;
    html += generic.map(renderCard).join("");
  }
  grid.innerHTML = html;
}

/* ── Scenario list ──────────────────────────────────────────── */
function renderScenarioList(filter){
  const f = filter.toLowerCase().trim();
  let html = "", total = 0;
  for(const group of allGroups){
    let items = group.scenarios.filter(sc =>
      !f || [sc.id, sc.title, ...sc.techniques, ...sc.protocols].some(s=>(s||"").toLowerCase().includes(f))
    );
    // Filter by active industry profile
    if(activeProfile){
      const profProtos = new Set(activeProfile.protocols || []);
      const profTechs = new Set(activeProfile.priority_techniques || []);
      items = items.filter(sc =>
        sc.protocols.some(p => profProtos.has(p)) ||
        sc.techniques.some(t => profTechs.has(t))
      );
    }
    if(!items.length) continue;
    html += `<div class="sc-group-head">${group.name}${activeProfile ? ' · '+activeProfile.sector.replace(/_/g,' ') : ''}</div>`;
    for(const sc of items){
      const active = sc.id === selectedName ? " active" : "";
      const dots = sc.protocols.map(p=>protoDot(p)).join("");
      const nameStr = sc.title.length > 50 ? sc.title.slice(0,48)+"…" : sc.title;
      html += `<div class="sc-item${active}" onclick="selectScenario('${sc.id}')">
        <span>${nameStr}</span>
        <span class="sc-protos">${dots}</span>
      </div>`;
      total++;
    }
  }
  if(!total) html = '<div class="sc-item" style="cursor:default;color:var(--muted)">No matches.</div>';
  $("sc_list").innerHTML = html;
}

$("sc_search").addEventListener("input", e => renderScenarioList(e.target.value));

/* ── Select scenario ────────────────────────────────────────── */
async function selectScenario(name){
  selectedName = name; hexStepIdx = 0;
  renderScenarioList($("sc_search").value);
  const data = await API("/api/preview?name="+encodeURIComponent(name));
  previewData = data;
  if(data.error){$("sc_desc").textContent = data.error; return;}
  $("sc_desc").textContent = data.description || data.title || name;
  const steps = data.steps || [];
  const totalPkts = steps.reduce((a,s)=>a+(s.count||1),0);
  const protos = [...new Set(steps.map(s=>s.proto).filter(Boolean))];
  $("step_summary").innerHTML =
    `<span>${steps.length} steps · ${totalPkts} total packets</span> ` +
    protos.map(p=>protoBadge(p)).join(" ");
  $("preview_steps").innerHTML = steps.map(s=>{
    const badge = s.proto ? protoBadge(s.proto) : "";
    const tech = s.technique ? `<span class="badge" style="font-size:9px">${s.technique}</span>` : "";
    const style = s.style && s.style!=="auto" ? `<span class="muted" style="font-size:10px">${s.style}</span>` : "";
    const cnt = s.count > 1 ? `<span class="muted" style="font-size:10px">×${s.count}</span>` : "";
    const intv = s.interval && s.interval!=="0s" ? `<span class="muted" style="font-size:10px">${s.interval}</span>` : "";
    return `<div style="display:flex;align-items:center;gap:6px;padding:5px 8px;border-radius:8px;background:var(--panel2);border:1px solid var(--border)">${badge}${tech}${style}${cnt}${intv}</div>`;
  }).join("");
  renderStepPlan(steps, null);
  await loadHexDump(name, 0);
  // Load protocol-specific parameters
  if(protos.length > 0) loadProtoParams(protos[0]);
  else $("proto_params").innerHTML = "";
}

/* ── Step plan ──────────────────────────────────────────────── */
function renderStepPlan(steps, statuses){
  if(!steps||!steps.length){$("step_plan").innerHTML="";return;}
  $("step_plan").innerHTML = steps.map((s,i)=>{
    const st = statuses ? statuses[i] : "pending";
    const icon = {ok:"✓",err:"✗",sending:"…",pending:"·"}[st]||"·";
    const badge = s.proto ? protoBadge(s.proto) : "";
    const tech  = s.technique ? `<span class="badge" style="font-size:9px">${s.technique}</span>` : "";
    const style = s.style && s.style!=="auto" ? `<span class="muted">${s.style}</span>` : "";
    const cnt   = s.count>1 ? `<span class="muted">×${s.count}</span>` : "";
    return `<div class="step-row st-${st}" id="sr_${i}">
      <span class="step-icon">${icon}</span>${badge}${tech}${style}${cnt}
    </div>`;
  }).join("");
}
function setStepSt(i, st){
  const el = document.getElementById(`sr_${i}`);
  if(!el) return;
  el.className = `step-row st-${st}`;
  const ic = el.querySelector(".step-icon");
  if(ic) ic.textContent = {ok:"✓",err:"✗",sending:"…",pending:"·"}[st]||"·";
}

/* ── Hex dump ───────────────────────────────────────────────── */
function escHtml(s){return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")}
async function loadHexDump(name, stepIdx){
  $("hex_dump").innerHTML = '<span style="color:#475569">Loading…</span>';
  $("hex_meta").innerHTML = "";
  $("hex_nav").style.display = "none";
  const _mm = (document.getElementById("marker_mode") && document.getElementById("marker_mode").value) || "covert";
  const data = await API(`/api/preview_payload?name=${encodeURIComponent(name)}&step=${stepIdx}&marker_mode=${_mm}&_=${Date.now()}`);
  if(data.error){$("hex_dump").innerHTML=`<span style="color:var(--bad)">${escHtml(data.error)}</span>`;return;}
  const lines = (data.hexdump||"").split("\n").map(line=>{
    const m = line.match(/^([0-9a-f]{4})  ([ 0-9a-f]{47})  (.+)$/);
    if(!m) return escHtml(line);
    return `<span style="color:#7c3aed">${m[1]}</span>  <span style="color:#a5f3fc">${m[2]}</span>  <span style="color:#6ee7b7">${escHtml(m[3])}</span>`;
  });
  $("hex_dump").innerHTML = lines.join("\n");
  $("hex_meta").innerHTML = [
    `${protoBadge(data.proto)}`,
    `<span class="small">style: <b>${data.style}</b></span>`,
    `<span class="small">${data.transport||"TCP"}${data.port ? " <b>:"+data.port+"</b>" : ""}</span>`,
    `<span class="small"><b>${data.length}</b> bytes</span>`,
    `<span class="badge">${data.technique}</span>`,
  ].join("");
  if(data.step_count > 1){
    $("hex_nav").style.display = "flex";
    $("hex_step_label").textContent = `Step ${data.step_index+1} / ${data.step_count}`;
    hexStepIdx = data.step_index;
  }
}
async function hexStep(delta){
  if(!selectedName) return;
  hexStepIdx = Math.max(0, hexStepIdx + delta);
  await loadHexDump(selectedName, hexStepIdx);
}
window.hexStep = hexStep;


/* ── Timeline state ─────────────────────────────────────────── */
let tlSteps = [];          // [{proto, technique, style, count}]
let tlStatuses = [];       // 'pending'|'sending'|'delivered'|'confirmed'|'err'
let tlRunId = null;
let tlConfirmedTechs = new Set();
let tlStartTime = null;
let tlElapsedTimer = null;

function tlRender(){
  const el = $("timeline_steps");
  if(!el) return;
  el.innerHTML = tlSteps.map((s,i)=>{
    const st = tlStatuses[i] || "pending";
    const tech = s.technique ? `<span class="tl-tech">${s.technique}</span>` : "";
    const proto = s.proto ? `<span class="badge cyan" style="font-size:9px">${s.proto}</span>` : "";
    const label = `<span style="font-family:var(--mono);font-size:10px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${s.style||s.proto||"step"}</span>`;
    const confirmed = st==="confirmed" ? `<span class="tl-confirmed-badge">confirmed</span>` : "";
    const count = s.count>1 ? `<span style="font-size:9px;color:var(--muted)">×${s.count}</span>` : "";
    return `<div class="tl-step tls-${st}" id="tls_${i}">
      <div class="tl-dot"></div>${proto}${label}${tech}${count}${confirmed}
    </div>`;
  }).join("");
  // Progress bar
  const done = tlStatuses.filter(s=>s==="confirmed"||s==="delivered"||s==="ok").length;
  const pct = tlSteps.length ? Math.round(done/tlSteps.length*100) : 0;
  const bar = $("tl_progress_bar");
  if(bar) bar.style.width = pct+"%";
  // Summary
  const confirmed = tlStatuses.filter(s=>s==="confirmed").length;
  // A confirmed step was necessarily also delivered — include it in the delivered count.
  const delivered = tlStatuses.filter(s=>s==="delivered"||s==="ok"||s==="confirmed").length;
  const summary = $("tl_summary");
  if(summary) summary.textContent = `${delivered} delivered · ${confirmed} confirmed by receiver`;
}

function tlConfirmStep(technique, run_id){
  // A temp run_id is set at tlStart before the real one arrives from the server.
  // Accept confirmation receipts regardless of run_id while we still have a temp ID,
  // matching on technique alone. Once the real run_id is set we require an exact match.
  const isTempId = tlRunId && tlRunId.includes("_") && /\d{10,}/.test(tlRunId);
  if(!tlRunId) return;
  if(!isTempId && run_id !== tlRunId) return;
  let matched = false;
  for(let i=0; i<tlSteps.length; i++){
    if(tlSteps[i].technique === technique && tlStatuses[i] !== "confirmed"){
      tlStatuses[i] = "confirmed";
      matched = true;
      const el = document.getElementById("tls_"+i);
      if(el) el.scrollIntoView({block:"nearest",behavior:"smooth"});
      break;
    }
  }
  if(matched) tlRender();
}

function tlStart(steps, run_id, offline){
  // Show stealth badge in timeline header when active
  const stealthBadge = document.getElementById("tl_stealth_badge");
  const stealthActive = !!(document.getElementById("stealth_mode") && document.getElementById("stealth_mode").checked);
  if(stealthBadge) stealthBadge.style.display = stealthActive ? "inline" : "none";
  tlSteps = steps;
  tlStatuses = steps.map(()=>"pending");
  tlRunId = run_id;
  tlConfirmedTechs.clear();
  tlStartTime = Date.now();
  clearInterval(tlElapsedTimer);
  if(!offline){
    tlElapsedTimer = setInterval(()=>{
      const el = $("tl_elapsed");
      if(el) el.textContent = ((Date.now()-tlStartTime)/1000).toFixed(1)+"s";
    }, 100);
  }
  // Show timeline card
  const card = $("timeline_card");
  if(card){ card.style.display=""; card.scrollIntoView({behavior:"smooth",block:"nearest"}); }
  const rid = $("tl_run_id");
  if(rid) rid.textContent = run_id ? run_id.slice(0,20) : "";
  tlRender();
}

function tlMarkSending(idx){
  if(tlStatuses[idx]==="pending") tlStatuses[idx]="sending";
  tlRender();
}

function tlMarkDelivered(){
  // Mark remaining steps as delivered. Skip already-confirmed steps — confirmed is a
  // stronger state than delivered (receiver verified receipt), never downgrade it.
  for(let i=0;i<tlStatuses.length;i++){
    if(tlStatuses[i]==="sending"||tlStatuses[i]==="pending") tlStatuses[i]="delivered";
  }
  clearInterval(tlElapsedTimer);
  tlRender();
}

function tlMarkError(){
  for(let i=0;i<tlStatuses.length;i++){
    if(tlStatuses[i]==="pending"||tlStatuses[i]==="sending") tlStatuses[i]="err";
  }
  clearInterval(tlElapsedTimer);
  tlRender();
}

/* ── Run scenario ───────────────────────────────────────────── */
async function doSend(offline=false){
  if(!offline && !$("confirm").checked){logln("[BLOCKED] Check the safety confirmation checkbox.","log-err");return;}
  if(!selectedName){logln("[ERROR] No scenario selected.","log-err");return;}
  const dst_ip = $("dst_ip").value.trim();
  if(!dst_ip && !offline){logln("[ERROR] Destination IP required.","log-err");return;}
  const steps = (previewData&&previewData.steps)||[];
  const statuses = steps.map(()=>"pending");
  renderStepPlan(steps, statuses);
  const endpoint = offline ? "/api/generate_offline" : "/api/send";
  // Collect protocol param overrides from the params form
  function _collectStepOptions(){
    const opts = {};
    document.querySelectorAll("[id^='param_']").forEach(el => {
      const proto = (previewData&&previewData.steps||[]).find(s=>s.proto)?.proto;
      if(!proto) return;
      opts[proto] = opts[proto] || {};
      const key = el.id.replace("param_","");
      const val = el.type === "number" ? (parseFloat(el.value)||0) : el.value;
      if(el.value !== "") opts[proto][key] = val;
    });
    return Object.keys(opts).length ? opts : null;
  }
  const stepOptions = _collectStepOptions();
  const _stateful = !!($("stateful_mode") && $("stateful_mode").checked);
  const _mm = ($("marker_mode") && $("marker_mode").value) || "covert";
  const _noMarker = (_mm === "stealth");
  const _explicitMarker = (_mm === "explicit");
  const _profile = ($("test_profile") && $("test_profile").value) || "firewall";
  const payload = offline
    ? {name:selectedName, dst_ip:dst_ip||$("cfg_receiver_ip").value.trim()||"198.51.100.99", src_ip:$("src_ip").value.trim(), build_pcap:true, no_marker:_noMarker, explicit_marker:_explicitMarker, stateful:_stateful, test_profile:_profile}
    : {name:selectedName, dst_ip, src_ip:$("src_ip").value.trim(), iface:$("iface").value.trim(),
       timeout:parseFloat($("timeout").value)||2.0, also_build_pcap:$("pcap").checked,
       no_marker:_noMarker, explicit_marker:_explicitMarker,
       stateful:_stateful, test_profile:_profile,
       ...(stepOptions ? {step_options: stepOptions} : {})};
  logln(`[${offline?"OFFLINE":"LIVE"}] ${selectedName} → ${dst_ip||"(offline)"}`, "log-info");
  // Launch timeline
  const tempRunId = selectedName+"_"+Date.now();
  tlStart(steps, tempRunId, offline);
  // Animate steps sending in sequence
  let ai = 0;
  const stepDelay = Math.max(120, Math.min(400, 2000/Math.max(steps.length,1)));
  const anim = setInterval(()=>{
    if(ai < steps.length){ tlMarkSending(ai); statuses[ai]="sending"; renderStepPlan(steps,statuses); ai++; }
  }, stepDelay);
  try {
    const data = await API(endpoint, {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
    clearInterval(anim);
    if(data.error){
      statuses.fill("err"); renderStepPlan(steps,statuses);
      tlMarkError();
      logln("[ERROR] "+data.error,"log-err"); window.toast("Error",data.error,"err");
      (function(){
        const bar=document.getElementById("last_run_bar");
        const icon=document.getElementById("last_run_icon");
        const text=document.getElementById("last_run_text");
        const ts=document.getElementById("last_run_ts");
        if(!bar) return;
        bar.style.display="flex"; icon.textContent="❌";
        text.textContent=data.error.substring(0,80);
        ts.textContent=new Date().toLocaleTimeString();
      })();
      return;
    }
    statuses.fill("ok"); renderStepPlan(steps,statuses);
    // Update timeline runId to the real one from server so SSE can match
    if(data.run_id) tlRunId = data.run_id;
    tlMarkDelivered();
    logln(`[OK] run_id=${data.run_id}  sent=${data.sent||"—"}`,"log-ok");
    // Update last-run status bar
    (function(){
      const bar = document.getElementById("last_run_bar");
      const icon = document.getElementById("last_run_icon");
      const text = document.getElementById("last_run_text");
      const ts   = document.getElementById("last_run_ts");
      if(!bar) return;
      bar.style.display = "flex";
      icon.textContent = "✅";
      const name = (payload.name||"").replace(/^.*?__/,"").replace(/__/g," · ");
      text.textContent = `${name} — ${data.sent||0} packets sent`;
      ts.textContent = new Date().toLocaleTimeString();
    })();
    if(data.pcap){
      logln(`  pcap   → ${data.pcap}`,"log-info");
      // Trigger browser download for offline PCAP generation
      if(offline){
        const a = document.createElement('a');
        a.href = '/download?path=' + encodeURIComponent(data.pcap);
        a.download = data.pcap.split('/').pop();
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.toast('PCAP ready', a.download, 'ok');
      }
    }
    if(data.events) logln(`  events → ${data.events}`,"log-info");
    if(data.warnings && data.warnings.length){
      data.warnings.forEach(w => logln(`  ⚠ ${w}`, "log-warn"));
      if(data.warnings.some(w => w.includes('profinet_dcp') && w.includes('iface'))){
        window.toast("PROFINET skipped","No interface specified. Set the Interface (L2) field to e.g. eth0.","warn");
      }
    }
    if(!offline) window.toast("Scenario fired", `${selectedName} · ${data.sent||"—"} packets`, "ok");
    // Stealth mode: confirm techniques via TCP ACK evidence (no receiver marker needed)
    if(data.confirmed_techniques && data.confirmed_techniques.length > 0){
      data.confirmed_techniques.forEach(tech => tlConfirmStep(tech, data.run_id));
    }
    setTimeout(loadHistory, 800);
    startFeedPoll();
    // If EVE tap is armed, notify it of the run_id
    if(data.run_id) tlRunId = data.run_id;
    startEveTapPoll(data.run_id);
  } catch(e){
    clearInterval(anim); statuses.fill("err"); renderStepPlan(steps,statuses);
    tlMarkError();
    logln("[EXCEPTION] "+e,"log-err");
  }
}

$("btn_send").addEventListener("click",   e=>{e.preventDefault();doSend(false);});
$("btn_offline").addEventListener("click", e=>{e.preventDefault();doSend(true);});
$("btn_clear").addEventListener("click",   e=>{e.preventDefault();$("run_log").innerHTML="";});

/* ── Safety confirm toggle ────────────────────────────────── */
window.toggleConfirm = function(){
  const cb  = $("confirm");
  const btn = $("confirm_btn");
  const ico = $("confirm_icon");
  cb.checked = !cb.checked;
  if(cb.checked){
    btn.style.borderColor = "var(--good)";
    btn.style.background  = "rgba(16,185,129,.1)";
    btn.style.color       = "var(--good)";
    ico.textContent       = "✓";
  } else {
    btn.style.borderColor = "var(--border)";
    btn.style.background  = "var(--panel2)";
    btn.style.color       = "var(--muted)";
    ico.textContent       = "○";
  }
};

/* ── Live Receiver Feed — SSE real-time stream ─────────────── */
let sseSource = null;
let ssePacketCount = 0;
let sseTechniques = new Map();
let sseProtocols = new Set();
let sseRuns = new Set();

function startFeedPoll(){
  // Try SSE first, fall back to polling
  if(sseSource) return;
  try {
    sseSource = new EventSource("/api/receiver/stream");
    $("live_dot").classList.remove("off");

    sseSource.onmessage = function(ev){
      try {
        const d = JSON.parse(ev.data);
        if(d.type === "connected") return;
        // Live receipt arrived
        ssePacketCount++;
        if(d.technique) sseTechniques.set(d.technique, (sseTechniques.get(d.technique)||0)+1);
        if(d["receiver.proto"]) sseProtocols.add(d["receiver.proto"]);
        if(d.run_id) sseRuns.add(d.run_id);
        // Update KPIs
        $("fk_pkts").textContent = ssePacketCount;
        $("fk_runs").textContent = sseRuns.size;
        $("fk_tech").textContent = sseTechniques.size;
        $("fk_proto").textContent = sseProtocols.size;
        // Flash green on new packet
        $("fk_pkts").style.color = "var(--good)";
        setTimeout(()=>{ $("fk_pkts").style.color=""; }, 600);
        // Update techniques pill row
        const techs = [...sseTechniques.entries()].sort((a,b)=>b[1]-a[1]).slice(0,8);
        $("feed_techs").innerHTML = techs.map(([t,n])=>`<span class="badge brand">${t} <span style="color:var(--muted)">${n}</span></span>`).join("");
        // Confirm matching timeline step
        if(d.technique && d.run_id) tlConfirmStep(d.technique, d.run_id);
      } catch(e){}
    };

    sseSource.onerror = function(){
      // SSE failed, fall back to polling
      sseSource.close();
      sseSource = null;
      if(!feedPollTimer){
        feedPollTimer = setInterval(pollFeed, 2000);
        pollFeed();
      }
    };
  } catch(e){
    // EventSource not supported, use polling
    if(!feedPollTimer){
      feedPollTimer = setInterval(pollFeed, 2000);
      pollFeed();
    }
  }
}
async function pollFeed(){
  try {
    const data = await API("/api/receiver/overview");
    if(!data || data.error) return;
    const pkts = data.total ?? 0;
    $("fk_pkts").textContent  = pkts;
    $("fk_runs").textContent  = data.top_protocols ? data.top_protocols.length : "—";
    $("fk_tech").textContent  = data.unique_techniques ?? (data.top_techniques ? data.top_techniques.length : "—");
    $("fk_proto").textContent = data.unique_protocols  ?? (data.top_protocols  ? data.top_protocols.length  : "—");
    // Techniques pill row
    const techs = (data.top_techniques||[]).slice(0,8);
    $("feed_techs").innerHTML = techs.map(([t,n])=>`<span class="badge brand">${t} <span style="color:var(--muted)">${n}</span></span>`).join("");
    // Flash if new packets
    if(prevTotal !== null && pkts > prevTotal){
      $("fk_pkts").style.color = "var(--good)";
      setTimeout(()=>{ $("fk_pkts").style.color=""; }, 600);
    }
    prevTotal = pkts;
  } catch(e){/* receiver may be offline, silent fail */}
}

/* ── Run History (v0.23) ────────────────────────────────────── */
async function loadHistory(){
  const data = await API("/api/runs");
  const runs = (data.runs||[]).slice(0,10);
  const el = $("history_list");
  if(!runs.length){el.innerHTML='<div class="history-item" style="cursor:default;color:var(--muted)">No runs yet.</div>';return;}
  el.innerHTML = runs.map(r=>{
    const name = r.scenario || r.run_id || "—";
    const ts   = (r.ts||"").replace("T"," ").slice(0,19);
    const sc   = name.length > 32 ? name.slice(0,30)+"…" : name;
    return `<div class="history-item" onclick="inspectRun('${r.run_id}','${sc}')">
      <span class="hi-name">${sc}</span>
      <span class="hi-ts">${ts}</span>
    </div>`;
  }).join("");
}

/* ── Run management panel ────────────────────────────────────── */
let _inspectedRunId = null;

function inspectRun(run_id, label){
  _inspectedRunId = run_id;
  // Show the run panel
  let panel = $("run_mgmt_panel");
  if(!panel) return;
  panel.style.display = "";
  $("rmp_run_id").textContent = run_id.slice(0,22);
  $("rmp_title_input").value  = label;
  $("rmp_tags_input").value   = "";
  $("rmp_status").textContent = "";
  // Copy to clipboard
  if(navigator.clipboard) navigator.clipboard.writeText(run_id).catch(()=>{});
  panel.scrollIntoView({behavior:"smooth", block:"nearest"});
}

window.rmpValidate = async function(){
  if(!_inspectedRunId) return;
  $("rmp_status").textContent = "Validating…";
  const r = await API("/api/validate", {method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({run_id: _inspectedRunId})});
  if(r.ok){
    const pct = r.report ? Math.round((r.report.delivered_ratio||0)*100) : "—";
    $("rmp_status").textContent = `Validated — ${pct}% delivered`;
    window.toast("Validation complete", `Run ${_inspectedRunId.slice(0,12)}`, "ok");
  } else {
    $("rmp_status").textContent = "Error: " + (r.error||"validation failed");
  }
};

window.rmpCorrelate = async function(){
  if(!_inspectedRunId) return;
  $("rmp_status").textContent = "Correlating…";
  const r = await API("/api/correlate_run", {method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({run_id: _inspectedRunId})});
  if(r.ok){
    const corr = r.correlation || {};
    const pct = Math.round((corr.coverage_ratio||0)*100);
    $("rmp_status").textContent = `Correlated — ${pct}% detected, ${(corr.gaps||[]).length} gaps`;
    window.toast("Correlation done", `${pct}% detected`, "ok");
  } else {
    $("rmp_status").textContent = "Error: " + (r.error||"correlation failed");
  }
};

window.rmpExport = async function(){
  if(!_inspectedRunId) return;
  $("rmp_status").textContent = "Exporting…";
  const r = await API("/api/run/export_bundle?run_id="+encodeURIComponent(_inspectedRunId));
  if(r.ok){
    window.location = r.download_url;
    $("rmp_status").textContent = "Bundle downloaded";
  } else {
    $("rmp_status").textContent = "Error: " + (r.error||"export failed");
  }
};

window.rmpRename = async function(){
  if(!_inspectedRunId) return;
  const title = ($("rmp_title_input")||{}).value?.trim();
  if(!title) return;
  const r = await API("/api/run/rename", {method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({run_id: _inspectedRunId, title})});
  if(r.ok){
    $("rmp_status").textContent = "Renamed";
    window.toast("Run renamed", title, "ok");
    setTimeout(loadHistory, 400);
  } else {
    $("rmp_status").textContent = "Error: " + (r.error||"rename failed");
  }
};

window.rmpTag = async function(){
  if(!_inspectedRunId) return;
  const raw = ($("rmp_tags_input")||{}).value?.trim() || "";
  const tags = raw ? raw.split(",").map(t=>t.trim()).filter(Boolean) : [];
  const r = await API("/api/run/tag", {method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({run_id: _inspectedRunId, tags})});
  if(r.ok){
    $("rmp_status").textContent = "Tags saved: " + (tags.join(", ") || "(cleared)");
    window.toast("Tags updated", tags.join(", ") || "cleared", "ok");
  } else {
    $("rmp_status").textContent = "Error: " + (r.error||"tag failed");
  }
};

window.selectScenario = selectScenario;
window.loadHistory    = loadHistory;

/* ── Industry Profiles ─────────────────────────────────────── */
let allProfiles = [];
let activeProfile = null;

async function loadProfiles(){
  try {
    const data = await API("/api/profiles");
    allProfiles = data.profiles || [];
    const sel = $("profile_select");
    sel.innerHTML = '<option value="">All sectors</option>';
    for(const p of allProfiles){
      const label = p.sector.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase());
      sel.innerHTML += `<option value="${p.sector}">${label} (${p.protocols.length} protocols)</option>`;
    }
  } catch(e){}
}
function applyProfile(){
  const sector = $("profile_select").value;
  activeProfile = allProfiles.find(p=>p.sector===sector) || null;
  renderScenarioList($("sc_search").value);
}
window.applyProfile = applyProfile;

/* ── Protocol Parameters ───────────────────────────────────── */
async function loadProtoParams(proto){
  const el = $("proto_params");
  if(!proto){ el.innerHTML = ""; return; }
  try {
    const data = await API("/api/scenario/params?proto="+encodeURIComponent(proto));
    const params = data.params || [];
    if(!params.length){ el.innerHTML = ""; return; }
    el.innerHTML = '<div style="margin-bottom:6px"><span style="font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);font-weight:700">Protocol Parameters (' + proto + ')</span></div>' +
      '<div class="row" style="gap:8px">' +
      params.map(p =>
        `<div class="field" style="max-width:180px"><label>${p.label}</label>` +
        `<input id="param_${p.name}" type="${p.type||'text'}" value="${p.default||''}" placeholder="${p.help||''}" title="${p.help||''}"></div>`
      ).join('') + '</div>';
  } catch(e){ el.innerHTML = ""; }
}

/* ── Boot ───────────────────────────────────────────────────── */
document.addEventListener("DOMContentLoaded", async ()=>{
  await loadNetworkConfig();
  await loadProfiles();
  await loadGroups();
  const first = (allGroups.find(g=>!g.name.includes("Chain"))||allGroups[0]);
  if(first && first.scenarios && first.scenarios[0]) selectScenario(first.scenarios[0].id);
  loadHistory();
  startFeedPoll();
  loadWebhookConfig();
});

/* ── Network Config ────────────────────────────────────────── */
async function loadNetworkConfig(){
  try {
    const data = await API("/api/config/network");
    if(data.sender_ip){
      $("cfg_sender_ip").value = data.sender_ip;
      $("src_ip").value = data.sender_ip;
    }
    if(data.receiver_ip){
      $("cfg_receiver_ip").value = data.receiver_ip;
      $("dst_ip").value = data.receiver_ip;
      $("net_status").textContent = "Receiver: " + data.receiver_ip;
      $("net_status").style.color = "var(--good)";
    }
    if(data.receiver_port){
      $("cfg_receiver_port").value = data.receiver_port;
    }
    if(data.sender_callback_url){
      $("cfg_sender_callback_url").value = data.sender_callback_url;
    }
    if(data.callback_token){
      $("cfg_callback_token").value = data.callback_token;
    }
    const _pull = !!data.pull_enabled;
    $("cfg_pull_mode").checked = _pull;
    // Sync toggle button visual state
    const _pb = $("btn_pull_mode"), _pi = $("pull_mode_icon");
    if(_pb && _pi){
      if(_pull){ _pb.style.borderColor="var(--brand2,#00d4ff)"; _pb.style.background="rgba(0,212,255,.1)"; _pb.style.color="var(--brand2,#00d4ff)"; _pi.textContent="●"; }
      else { _pb.style.borderColor=""; _pb.style.background=""; _pb.style.color=""; _pi.textContent="○"; }
    }
    if(data.pull_enabled && data.receiver_ip){
      $("net_status").textContent = "Pull mode: polling " + data.receiver_ip;
      $("net_status").style.color = "var(--brand2, #00d4ff)";
    }
  } catch(e){}
}

async function saveNetworkConfig(){
  const sender_ip   = $("cfg_sender_ip").value.trim();
  const receiver_ip = $("cfg_receiver_ip").value.trim();
  const receiver_port = parseInt($("cfg_receiver_port").value) || 9090;
  const sender_callback_url = $("cfg_sender_callback_url").value.trim();
  const callback_token = $("cfg_callback_token").value.trim();
  const pull_enabled = $("cfg_pull_mode").checked;
  // Mirror to scenario fields immediately — do not wait for API roundtrip
  if(sender_ip)   $("src_ip").value = sender_ip;
  if(receiver_ip) $("dst_ip").value = receiver_ip;
  $("net_status").textContent = "Saving…";
  $("net_status").style.color = "var(--muted)";
  try {
    // Save combined config (includes pull_mode flag)
    await API("/api/config/network", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({sender_ip, receiver_ip, receiver_port, sender_callback_url, callback_token, pull_enabled})
    });
    // Prefill scenario fields
    if(sender_ip)   $("src_ip").value = sender_ip;
    if(receiver_ip) $("dst_ip").value = receiver_ip;
    // Handle connection mode
    if(pull_enabled && receiver_ip){
      $("net_status").textContent = "✓ Pull mode — polling " + receiver_ip + ":" + receiver_port;
      $("net_status").style.color = "var(--brand2, #00d4ff)";
      window.toast("Pull mode active", `Polling ${receiver_ip}:${receiver_port} for receipts`, "ok");
    } else if(receiver_ip){
      // Try push callback to receiver
      const data = await API("/api/config/receiver_ip", {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({receiver_ip, receiver_port, sender_callback_url, callback_token})
      });
      if(data.callback_configured){
        $("net_status").textContent = "✓ Connected — callback active";
        $("net_status").style.color = "var(--good)";
        window.toast("Receiver linked", `${receiver_ip}:${receiver_port} — live callbacks active`, "ok");
      } else {
        $("net_status").textContent = "✓ IP saved — enable Pull mode if sender has no reachable callback URL";
        $("net_status").style.color = "var(--warn, #f59e0b)";
        window.toast("IP saved", data.push_error || `Receiver not reachable for callback setup — enable Pull mode if sender has no public callback address.`, "warn");
      }
    } else {
      $("net_status").textContent = "Sender IP saved";
      $("net_status").style.color = "var(--muted)";
    }
  } catch(e){
    $("net_status").textContent = "Error: " + e;
    $("net_status").style.color = "var(--err, #ef4444)";
  }
}
window.saveNetworkConfig = saveNetworkConfig;

// Export IIFE-private names needed by post-IIFE EVE tap and webhook code
window._senderAPI = API;
window._senderLog = logln;
window._senderTlConfirm = tlConfirmStep;
window._senderGetTlRunId = () => tlRunId;
window._sender$ = $;

// ── Marker mode (covert / explicit / stealth) — INSIDE IIFE so selectedName
//    and loadHexDump are in scope. Default is covert. Changing the mode updates
//    the segmented control, syncs the legacy stealth_mode checkbox (used by the
//    timeline badge + confirmation path), and immediately refreshes the live
//    preview for the selected scenario/step. ────────────────────────────────
const _MARKER_INFO = {
  covert: {
    label: "Covert",
    accent: "var(--brand2)", tint: "rgba(0,212,255,.10)",
    desc: "Default. Correlation marker woven into an existing protocol field " +
          "(e.g. Modbus transaction ID, S7 PDU reference) — zero added bytes, " +
          "no ASCII signature. Realistic traffic an IDS can't cheat on; the " +
          "receiver still correlates it back to this run.",
  },
  explicit: {
    label: "Explicit",
    accent: "var(--brand)", tint: "rgba(240,165,0,.10)",
    desc: "Embeds a literal 13-byte 'ICSF' tag in the payload. Visible in " +
          "Wireshark and matchable by a single content rule — useful for " +
          "offline PCAP detection without a receiver. Obviously synthetic, " +
          "so not for stealth/realism testing.",
  },
  stealth: {
    label: "Stealth",
    accent: "var(--bad)", tint: "rgba(255,59,92,.10)",
    desc: "No marker at all — traffic is bit-for-bit like a real device. " +
          "Use to test whether detections fire on the attack itself, not on " +
          "any watermark. Correlation then relies on the receiver expectation " +
          "registry / timing rather than the packet.",
  },
};

window.setMarkerMode = function(mode) {
  if (!_MARKER_INFO[mode]) mode = "covert";
  const hidden = document.getElementById("marker_mode");
  if (hidden) hidden.value = mode;
  // Keep the legacy stealth checkbox in sync (timeline badge + confirm logic).
  const cb = document.getElementById("stealth_mode");
  if (cb) cb.checked = (mode === "stealth");
  // Paint the segmented control.
  const seg = document.getElementById("marker_seg");
  if (seg) {
    seg.querySelectorAll("button[data-mode]").forEach(b => {
      const info = _MARKER_INFO[b.dataset.mode];
      const on = (b.dataset.mode === mode);
      b.style.background = on ? info.tint : "transparent";
      b.style.color      = on ? info.accent : "var(--muted)";
      b.setAttribute("aria-checked", on ? "true" : "false");
    });
    seg.style.borderColor = _MARKER_INFO[mode].accent;
  }
  // Description + help tooltip.
  const desc = document.getElementById("marker_desc");
  if (desc) desc.textContent = _MARKER_INFO[mode].desc;
  const help = document.getElementById("marker_help");
  if (help) {
    help.title =
      "Covert (default): marker hidden in a protocol field, no added bytes.\n" +
      "Explicit: literal 'ICSF' tag in payload, matchable offline without a receiver.\n" +
      "Stealth: no marker — realistic traffic; correlation via the receiver registry.";
  }
  // Live preview must reflect the new mode immediately.
  if (selectedName) loadHexDump(selectedName, hexStepIdx || 0);
};

// ── Stateful TCP toggle — mirrors stealth; uses the accent (info) colour ──
function _paintStateful(on) {
  const cb  = document.getElementById("stateful_mode");
  const btn = document.getElementById("btn_stateful");
  const ico = document.getElementById("stateful_icon");
  if (!cb || !btn || !ico) return;
  cb.checked = !!on;
  if (cb.checked) {
    btn.style.borderColor = "var(--brand2)";
    btn.style.background  = "rgba(0,212,255,.08)";
    btn.style.color       = "var(--brand2)";
    ico.textContent = "●";
  } else {
    btn.style.borderColor = "var(--border)";
    btn.style.background  = "var(--panel2)";
    btn.style.color       = "var(--muted)";
    ico.textContent = "○";
  }
}
window.toggleStateful = function() {
  const cb = document.getElementById("stateful_mode");
  if (!cb) return;
  _paintStateful(!cb.checked);
};

// ── Test profile (Firewall/ACL ⟷ NSM) — sets safe defaults + how results are
//    framed. NEVER fabricates device responses; the receiver stays a safe sink.
//    Firewall (default): unidirectional, arrival is the signal. NSM: path
//    assumed open, defaults the Stateful TCP toggle on so stream sensors engage,
//    and the receiver pairs the witnessed receipt with the expected technique.
const _PROFILE_INFO = {
  firewall: {
    accent: "var(--brand)", tint: "rgba(240,165,0,.10)",
    desc: "Boundary / ACL test. Sender sits in IT or another OT zone; the " +
          "receiver is a safe sinkhole. Unidirectional by design — arrival of " +
          "any of the 10 protocols means a rule allowed it (a forward-path " +
          "finding). No return traffic is assumed; a permitted forward flow " +
          "does not imply the reverse is open.",
    stateful: false,
  },
  nsm: {
    accent: "var(--brand2)", tint: "rgba(0,212,255,.10)",
    desc: "Sensor test. The path is assumed open; the question is whether the " +
          "NSM alarms on the behaviour. Completes the TCP handshake (Stateful " +
          "TCP defaulted on) so stream-tracking sensors engage, and the " +
          "receiver pairs each witnessed scenario with its expected ATT&CK " +
          "technique for diffing against what the sensor fired.",
    stateful: true,
  },
};
window.setTestProfile = function(profile) {
  if (!_PROFILE_INFO[profile]) profile = "firewall";
  const hidden = document.getElementById("test_profile");
  if (hidden) hidden.value = profile;
  const seg = document.getElementById("profile_seg");
  if (seg) {
    seg.querySelectorAll("button[data-profile]").forEach(b => {
      const info = _PROFILE_INFO[b.dataset.profile];
      const on = (b.dataset.profile === profile);
      b.style.background = on ? info.tint : "transparent";
      b.style.color      = on ? info.accent : "var(--muted)";
      b.setAttribute("aria-checked", on ? "true" : "false");
    });
    seg.style.borderColor = _PROFILE_INFO[profile].accent;
  }
  const desc = document.getElementById("profile_desc");
  if (desc) desc.textContent = _PROFILE_INFO[profile].desc;
  const help = document.getElementById("profile_help");
  if (help) {
    help.title =
      "Firewall / ACL (default): unidirectional boundary test; arrival means a rule allowed it.\n" +
      "NSM: path assumed open; completes the handshake so stream sensors engage and pairs witnessed traffic with the expected technique.\n" +
      "Neither fabricates device responses — the receiver is a safe sinkhole.";
  }
  // Apply the profile's transport default to the Stateful toggle.
  _paintStateful(_PROFILE_INFO[profile].stateful);
};

// Initialise controls on load (covert marker, firewall profile).
try { window.setMarkerMode("covert"); } catch (e) {}
try { window.setTestProfile("firewall"); } catch (e) {}

})();

/* ── EVE tap live poll (v0.49) ──────────────────────────────── */
let _evePollTimer = null;
let _eveRunId = null;
let _eveConfirmedTechs = new Set();

function startEveTapPoll(run_id){
  _eveRunId = run_id;
  if(_evePollTimer) clearInterval(_evePollTimer);
  _evePollTimer = setInterval(async ()=>{
    try {
      const d = await window._senderAPI("/api/eve/matches");
      if(!d.active){ clearInterval(_evePollTimer); _evePollTimer = null; return; }
      for(const m of (d.matches||[])){
        if(m.technique && !_eveConfirmedTechs.has(m.technique)){
          _eveConfirmedTechs.add(m.technique);
          window._senderTlConfirm(m.technique, _eveRunId);
          window._senderLog(`[EVE] ${m.technique} — ${(m.signature||"").slice(0,60)}`, "log-ok");
        }
      }
    } catch(e){}
  }, 1500);
}

/* ── Webhook config panel (v0.49) ───────────────────────────── */
async function loadWebhookConfig(){
  try {
    const d = await window._senderAPI("/api/config/webhook");
    const el = window._sender$("cfg_webhook_url");
    if(el && d.webhook_url) el.value = d.webhook_url;
  } catch(e){}
}

window.saveWebhookConfig = async function(){
  const url = (window._sender$("cfg_webhook_url")||{}).value?.trim()||"";
  const r = await window._senderAPI("/api/config/webhook", {method:"POST",
    headers:{"Content-Type":"application/json"}, body:JSON.stringify({webhook_url:url})});
  if(r.ok) window.toast("Webhook saved", url || "Webhook disabled", "ok");
  else window.toast("Error", r.error||"save failed", "err");
};

window.testWebhook = async function(){
  const r = await window._senderAPI("/api/config/test_webhook", {method:"POST",
    headers:{"Content-Type":"application/json"}, body:JSON.stringify({})});
  if(r.ok) window.toast("Webhook OK", "Test event delivered", "ok");
  else window.toast("Webhook failed", r.error||"unreachable", "err");
};

/* ── EVE tap arm/disarm (v0.49) ─────────────────────────────── */
window.armEveTap = async function(){
  const path = (window._sender$("cfg_eve_path")||{}).value?.trim()||"";
  if(!path){ window.toast("EVE path required","Enter path to eve.json","err"); return; }
  const run_id = (window._senderGetTlRunId && window._senderGetTlRunId())||null;
  const r = await window._senderAPI("/api/eve/start", {method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({eve_path:path, run_id})});
  if(r.ok) window.toast("EVE tap armed", `Watching ${path}`, "ok");
  else window.toast("EVE tap failed", r.error||"error", "err");
};

window.disarmEveTap = async function(){
  const r = await window._senderAPI("/api/eve/stop", {method:"POST",
    headers:{"Content-Type":"application/json"}, body:JSON.stringify({})});
  const count = r.matches?.length||0;
  window.toast("EVE tap stopped", `${count} detection${count===1?"":"s"} matched`, "ok");
};

// ── Collapsible secondary cards ─────────────────────────────────────────────
window.toggleCard = function(bodyId, heading) {
  const body = document.getElementById(bodyId);
  if (!body) return;
  const collapsed = body.style.display === "none";
  body.style.display = collapsed ? "" : "none";
  // Update the chevron in the heading
  if (heading) {
    heading.textContent = heading.textContent.replace(/^[▾▸] /, (collapsed ? "▾ " : "▸ "));
  }
};

// Secondary cards remain visible by default
