/* ICSForge main.js — dark default, shared helpers */
(function(){
  const root = document.documentElement;
  // Default: dark
  const saved = localStorage.getItem("icsforge_theme") || "dark";
  root.dataset.theme = saved;
  window.setTheme = function(t){
    root.dataset.theme = t;
    localStorage.setItem("icsforge_theme", t);
  };
  window.toggleTheme = function(){
    const cur = root.dataset.theme || "dark";
    setTheme(cur === "dark" ? "light" : "dark");
  };
})();

window.toast = function(title, msg, variant){
  let el = document.getElementById("toast");
  if(!el){
    el = document.createElement("div");
    el.id = "toast"; el.className = "toast";
    el.innerHTML = '<div class="t"></div><div class="m"></div>';
    document.body.appendChild(el);
  }
  el.querySelector(".t").textContent = title;
  el.querySelector(".m").textContent = msg || "";
  el.style.borderLeftColor = variant === "err" ? "var(--bad)" : variant === "ok" ? "var(--good)" : "var(--brand)";
  el.classList.remove("show");
  void el.offsetWidth; // force reflow for re-animation
  el.classList.add("show");
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove("show"), 3000);
};

window.drawSparkline = function(canvas, points){
  if(!canvas || !points || points.length < 2) return;
  const ctx = canvas.getContext("2d");
  const w = canvas.width, h = canvas.height;
  ctx.clearRect(0,0,w,h);
  const stroke = getComputedStyle(document.documentElement).getPropertyValue("--brand2").trim() || "#22d3ee";
  ctx.strokeStyle = stroke;
  ctx.lineWidth = 1.5;
  const ys = points.map(p => p[1]);
  const ymin = Math.min(...ys), ymax = Math.max(...ys);
  const dy = (ymax - ymin) || 1;
  const dx = points.length - 1;
  ctx.beginPath();
  for(let i = 0; i < points.length; i++){
    const x = (i / dx) * (w - 8) + 4;
    const y = h - 4 - ((points[i][1] - ymin) / dy) * (h - 8);
    if(i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  }
  ctx.stroke();
};

// Read CSRF token from meta tag (set by Flask session)
window._csrfToken = () => {
  const m = document.querySelector('meta[name="csrf-token"]');
  return m ? m.getAttribute('content') : '';
};

window.fetchJSON = async function(url, opts){
  // Inject CSRF token on all state-mutating requests
  if (opts && opts.method && opts.method !== 'GET' && opts.method !== 'HEAD') {
    opts.headers = opts.headers || {};
    if (typeof opts.headers === 'object' && !(opts.headers instanceof Headers)) {
      opts.headers['X-CSRF-Token'] = window._csrfToken();
    }
  }
  const res = await fetch(url, opts || {});
  let data = null;
  try { data = await res.json(); } catch(e) { data = { error: "Invalid JSON" }; }
  if(!res.ok && data && !data.error) data.error = "HTTP " + res.status;
  return data;
};

window.postJSON = async function(url, body){
  return await window.fetchJSON(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {})
  });
};
