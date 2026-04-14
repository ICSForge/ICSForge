"""ICSForge Authentication — setup, login, session-based access control."""

import collections as _collections
import hashlib
import json
import os
import secrets
import time as _time

from flask import jsonify, redirect, request, session

from icsforge.log import get_logger

log = get_logger(__name__)


# ── Simple in-memory rate limiter (per IP, for auth endpoints) ─────────
_LOGIN_ATTEMPTS: dict = _collections.defaultdict(list)  # ip -> [timestamps]
_MAX_ATTEMPTS = 5
_WINDOW_SECONDS = 60
_LOCKOUT_SECONDS = 300


def _check_rate_limit(ip: str) -> bool:
    """Return True if the IP is allowed to attempt login, False if locked out."""
    now = _time.time()
    attempts = _LOGIN_ATTEMPTS[ip]
    # Drop attempts outside the window
    _LOGIN_ATTEMPTS[ip] = [t for t in attempts if now - t < _LOCKOUT_SECONDS]
    recent = [t for t in _LOGIN_ATTEMPTS[ip] if now - t < _WINDOW_SECONDS]
    return len(recent) < _MAX_ATTEMPTS


def _record_failed_attempt(ip: str) -> int:
    """Record a failed login attempt. Returns remaining attempts before lockout."""
    _LOGIN_ATTEMPTS[ip].append(_time.time())
    recent = [t for t in _LOGIN_ATTEMPTS[ip] if _time.time() - t < _WINDOW_SECONDS]
    return max(0, _MAX_ATTEMPTS - len(recent))

_CRED_FILE = None

PUBLIC_PATHS = {
    "/login", "/setup", "/health",
    "/api/auth/login", "/api/auth/setup", "/api/health",
    "/api/receiver/callback",
    "/api/config/set_callback",
}
PUBLIC_PREFIXES = ("/static/",)


def _cred_path():
    if _CRED_FILE:
        return _CRED_FILE
    # Store inside the project's out/ directory.
    # Each installation has its own credentials — they are scoped to the
    # project folder, so installing a new version means a fresh setup.
    # The release script and .gitignore exclude out/.credentials.json from
    # tarballs and commits.
    here = os.path.dirname(os.path.abspath(__file__))   # icsforge/
    project_root = os.path.dirname(here)                 # project root
    return os.path.join(project_root, "out", ".credentials.json")


def _hash_password(pw: str) -> str:
    """Hash a password with scrypt (N=2^14, r=8, p=1) — memory-hard KDF."""
    salt = os.urandom(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return f"scrypt:{salt.hex()}:{h.hex()}"


def _verify_password(pw: str, stored: str) -> bool:
    """Verify a password against a stored hash. Supports scrypt and legacy sha256."""
    if stored.startswith("scrypt:"):
        _, salt_hex, expected_hex = stored.split(":", 2)
        salt = bytes.fromhex(salt_hex)
        actual = hashlib.scrypt(pw.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
        return secrets.compare_digest(actual, bytes.fromhex(expected_hex))
    if stored.startswith("sha256:"):
        # Legacy: verify then re-hash with scrypt on next write
        _, salt, expected = stored.split(":", 2)
        actual = hashlib.sha256((salt + pw).encode()).hexdigest()
        return secrets.compare_digest(actual, expected)
    return False


def credentials_exist():
    p = _cred_path()
    if not os.path.exists(p):
        return False
    try:
        with open(p) as f:
            data = json.load(f)
        return bool(data.get("username") and data.get("password_hash"))
    except Exception:
        return False


def create_credentials(username, password):
    if credentials_exist():
        return {"error": "Credentials already configured"}
    p = _cred_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    data = {"username": username, "password_hash": _hash_password(password)}
    with open(p, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(p, 0o600)
    log.info("Credentials created for user %s", username)

    # Auto-generate and persist a callback token on first setup.
    # This ensures receipt integrity is enforced by default without
    # requiring manual token configuration.
    token = secrets.token_urlsafe(24)
    try:
        from icsforge.web import helpers as _wh
        _wh._callback_token = token
        _wh._save_persisted_config()
        log.info("Callback token auto-generated and persisted")
    except Exception as exc:
        log.warning("Could not persist auto-generated callback token: %s", exc)

    return {"ok": True, "username": username, "callback_token": token}



def _reset_rate_limit(ip: str | None = None) -> None:
    """Reset rate limit counters. Pass ip to reset one address, or None to clear all.
    Intended for testing only — called from test fixtures to prevent state leakage.
    """
    if ip is None:
        _LOGIN_ATTEMPTS.clear()
    else:
        _LOGIN_ATTEMPTS.pop(ip, None)


def verify_login(username, password):
    p = _cred_path()
    if not os.path.exists(p):
        return False
    try:
        with open(p) as f:
            data = json.load(f)
        stored_user = data.get("username") or ""
        # Use compare_digest to avoid username timing oracle
        if not secrets.compare_digest(stored_user.encode(), username.encode()):
            # Still run password hash to avoid timing difference between
            # "wrong username" and "wrong password" — consume similar time
            _verify_password(password, data.get("password_hash", ""))
            return False
        return _verify_password(password, data.get("password_hash", ""))
    except Exception:
        return False


def _is_api_path(path):
    """Return True if this is an API path that should get JSON errors, not redirects."""
    return path.startswith("/api/")


# ── Auth page templates (minimal, self-contained) ────────────

_SETUP_HTML = """<!doctype html>
<html><head><title>ICSForge Setup</title>
<style>
body{font-family:system-ui;background:#04080e;color:#d4dce8;display:flex;
  justify-content:center;align-items:center;min-height:100vh;margin:0}
.card{background:#0a1018;border:1px solid #1a2538;border-radius:12px;
  padding:40px;width:380px;box-shadow:0 20px 50px rgba(0,0,0,.5)}
h1{margin:0 0 8px;font-size:22px;color:#f0a500;font-family:sans-serif}
p{color:#566882;margin:0 0 24px;font-size:13px}
label{display:block;margin-bottom:4px;font-size:12px;color:#566882;
  text-transform:uppercase;letter-spacing:.08em}
input{width:100%;padding:10px 12px;margin-bottom:14px;background:#04080e;
  border:1px solid #1a2538;border-radius:8px;color:#d4dce8;font-size:14px;
  box-sizing:border-box}
input:focus{outline:none;border-color:#f0a500}
button{width:100%;padding:12px;background:rgba(240,165,0,.15);color:#f0a500;
  border:1px solid rgba(240,165,0,.3);border-radius:8px;font-size:14px;
  font-weight:600;cursor:pointer}
button:hover{background:rgba(240,165,0,.25)}
.err{color:#ff3b5c;font-size:13px;margin-bottom:12px;display:none}
</style></head>
<body><div class=card>
<h1>ICSForge Setup</h1>
<p>Create admin credentials for the web interface.<br><span style="font-size:11px;color:#566882">Credentials stored in <code style="color:#8499b5">out/.credentials.json</code> inside this installation folder.</span></p>
<div class=err id=err></div>
<form id=f>
  <label>Username</label><input id=u required>
  <label>Password</label><input type=password id=p required minlength=6>
  <label>Confirm Password</label><input type=password id=p2 required minlength=6>
  <button type=submit>Create Account</button>
</form></div>
<script>
document.getElementById('f').onsubmit=async e=>{
  e.preventDefault();
  const err=document.getElementById('err'),
        u=document.getElementById('u').value,
        p=document.getElementById('p').value,
        p2=document.getElementById('p2').value;
  if(p!==p2){err.textContent='Passwords do not match';err.style.display='block';return}
  const r=await fetch('/api/auth/setup',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username:u,password:p})});
  const d=await r.json();
  if(d.ok) window.location='/login';
  else{err.textContent=d.error;err.style.display='block'}
};
</script></body></html>"""

_LOGIN_HTML = """<!doctype html>
<html><head><title>ICSForge Login</title>
<style>
body{font-family:system-ui;background:#04080e;color:#d4dce8;display:flex;
  justify-content:center;align-items:center;min-height:100vh;margin:0}
.card{background:#0a1018;border:1px solid #1a2538;border-radius:12px;
  padding:40px;width:380px;box-shadow:0 20px 50px rgba(0,0,0,.5)}
h1{margin:0 0 8px;font-size:22px;color:#f0a500;font-family:sans-serif}
p{color:#566882;margin:0 0 24px;font-size:13px}
label{display:block;margin-bottom:4px;font-size:12px;color:#566882;
  text-transform:uppercase;letter-spacing:.08em}
input{width:100%;padding:10px 12px;margin-bottom:14px;background:#04080e;
  border:1px solid #1a2538;border-radius:8px;color:#d4dce8;font-size:14px;
  box-sizing:border-box}
input:focus{outline:none;border-color:#f0a500}
button{width:100%;padding:12px;background:rgba(240,165,0,.15);color:#f0a500;
  border:1px solid rgba(240,165,0,.3);border-radius:8px;font-size:14px;
  font-weight:600;cursor:pointer}
button:hover{background:rgba(240,165,0,.25)}
.err{color:#ff3b5c;font-size:13px;margin-bottom:12px;display:none}
</style></head>
<body><div class=card>
<h1>ICSForge</h1>
<p>Sign in to access the dashboard.</p>
<div class=err id=err></div>
<form id=f>
  <label>Username</label><input id=u required>
  <label>Password</label><input type=password id=p required>
  <button type=submit>Sign In</button>
</form></div>
<script>
document.getElementById('f').onsubmit=async e=>{
  e.preventDefault();
  const err=document.getElementById('err'),
        u=document.getElementById('u').value,
        p=document.getElementById('p').value;
  const r=await fetch('/api/auth/login',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username:u,password:p})});
  const d=await r.json();
  if(d.ok) window.location='/';
  else{err.textContent=d.error;err.style.display='block'}
};
</script></body></html>"""


def init_auth(app):
    """Wire authentication into a Flask app."""
    global _CRED_FILE
    # Allow env override; otherwise use project-local path (set via _cred_path())
    env_override = os.environ.get("ICSFORGE_CRED_FILE", "").strip()
    if env_override:
        _CRED_FILE = env_override
    # If no override, _cred_path() already resolves to out/.credentials.json

    if os.environ.get("ICSFORGE_NO_AUTH", "").strip().lower() in ("1", "true", "yes"):
        log.warning("Authentication DISABLED via ICSFORGE_NO_AUTH")
        return

    @app.before_request
    def _check_auth():
        path = request.path
        # Public paths — no auth needed
        if path in PUBLIC_PATHS:
            return None
        for pfx in PUBLIC_PREFIXES:
            if path.startswith(pfx):
                return None
        # Authenticated sessions pass through
        if session.get("authenticated"):
            return None
        # No credentials configured yet → setup required
        if not credentials_exist():
            if _is_api_path(path):
                return jsonify({"error": "Setup required", "setup_url": "/setup"}), 401
            return redirect("/setup")
        # Not authenticated
        if _is_api_path(path):
            return jsonify({"error": "Authentication required"}), 401
        return redirect("/login")

    @app.route("/setup")
    def setup_page():
        if credentials_exist():
            return redirect("/login")
        return _SETUP_HTML

    @app.route("/api/auth/setup", methods=["POST"])
    def api_auth_setup():
        if credentials_exist():
            return jsonify({"error": "Already configured"}), 400
        data = request.get_json(force=True) or {}
        un = (data.get("username") or "").strip()
        pw = data.get("password") or ""
        if not un or len(un) < 2:
            return jsonify({"error": "Username min 2 chars"}), 400
        if len(pw) < 6:
            return jsonify({"error": "Password min 6 chars"}), 400
        r = create_credentials(un, pw)
        if r.get("ok"):
            return jsonify(r)
        return jsonify(r), 400

    @app.route("/login")
    def login_page():
        if not credentials_exist():
            return redirect("/setup")
        return _LOGIN_HTML

    @app.route("/api/auth/login", methods=["POST"])
    def api_auth_login():
        ip = request.remote_addr or "unknown"
        if not _check_rate_limit(ip):
            return jsonify({"error": "Too many failed attempts. Try again later."}), 429
        data = request.get_json(force=True) or {}
        un = (data.get("username") or "").strip()
        pw = data.get("password") or ""
        if verify_login(un, pw):
            session["authenticated"] = True
            session["username"] = un
            # Reset failed attempts on success
            _LOGIN_ATTEMPTS.pop(ip, None)
            return jsonify({"ok": True, "username": un})
        remaining = _record_failed_attempt(ip)
        msg = "Invalid credentials"
        if remaining == 0:
            msg = f"Too many failed attempts. Locked out for {_LOCKOUT_SECONDS // 60} minutes."
        elif remaining <= 2:
            msg = f"Invalid credentials ({remaining} attempt{'s' if remaining != 1 else ''} remaining)"
        return jsonify({"error": msg}), 401

    @app.route("/api/auth/logout", methods=["POST"])
    def api_auth_logout():
        session.clear()
        return jsonify({"ok": True})
