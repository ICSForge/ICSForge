(function(){
  const root = document.documentElement;
  const saved = localStorage.getItem("icsforge_theme") || "light";
  root.dataset.theme = saved;
  window.setTheme = function(t){
    root.dataset.theme = t;
    localStorage.setItem("icsforge_theme", t);
  }
  window.toggleTheme = function(){
    const cur = root.dataset.theme || "light";
    setTheme(cur === "dark" ? "light" : "dark");
  }
})();

window.toast = function(title, msg){
  let el = document.getElementById("toast");
  if(!el){
    el = document.createElement("div");
    el.id="toast";
    el.className="toast";
    el.innerHTML = '<div class="t"></div><div class="m"></div>';
    document.body.appendChild(el);
  }
  el.querySelector(".t").textContent = title;
  el.querySelector(".m").textContent = msg || "";
  el.classList.add("show");
  setTimeout(()=>el.classList.remove("show"), 2800);
}

window.drawSparkline = function(canvas, points){
  if(!canvas || !points || points.length < 2) return;
  const ctx = canvas.getContext("2d");
  const w = canvas.width, h = canvas.height;
  ctx.clearRect(0,0,w,h);
  const stroke = getComputedStyle(document.documentElement).getPropertyValue("--brand").trim() || "#2563eb";
  ctx.strokeStyle = stroke;
  ctx.lineWidth = 2;
  const xs = points.map(p=>p[0]);
  const ys = points.map(p=>p[1]);
  const xmin=Math.min(...xs), xmax=Math.max(...xs);
  const ymin=Math.min(...ys), ymax=Math.max(...ys);
  const dx = (xmax-xmin) || 1;
  const dy = (ymax-ymin) || 1;
  ctx.beginPath();
  for(let i=0;i<points.length;i++){
    const x = (points[i][0]-xmin)/dx * (w-8) + 4;
    const y = h-4 - (points[i][1]-ymin)/dy * (h-8);
    if(i===0) ctx.moveTo(x,y); else ctx.lineTo(x,y);
  }
  ctx.stroke();
}


// --- Common helpers used by templates ---
window.fetchJSON = async function(url, opts){
  const res = await fetch(url, opts || {});
  let data = null;
  try { data = await res.json(); } catch(e) { data = { error: "Invalid JSON response" }; }
  if(!res.ok && data && !data.error){
    data.error = "HTTP " + res.status;
  }
  return data;
};

window.postJSON = async function(url, body){
  return await window.fetchJSON(url, {
    method: "POST",
    headers: { "Content-Type":"application/json" },
    body: JSON.stringify(body || {})
  });
};
