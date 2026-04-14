"""ICSForge web — shared helpers, state, and utilities.

Sub-modules:
  helpers_io    — file I/O: JSONL, YAML, run index
  helpers_stats — receipt statistics and timeline binning
  helpers_sse   — SSE push and pull-mode polling

This module re-exports everything so existing imports remain unchanged.
"""
import json
import os
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

from icsforge import __version__
from icsforge.live.sender import send_scenario_live
from icsforge.log import get_logger
from icsforge.reports.network_validation import build_network_validation_report
from icsforge.scenarios.engine import run_scenario
from icsforge.state import RunRegistry, default_db_path

# Re-exports from sub-modules
from icsforge.web.helpers_io import (
    _append_run_index,
    _load_run_index,
    _load_yaml,
    _read_json_lines,
    _read_jsonl_tail,
    _repo_root,
    _run_index_path,
    _save_run_index,
    _update_run_entry,
)
from icsforge.web.helpers_sse import (
    _live_receipts,
    notify_sse,
    start_pull_mode,
    stop_pull_mode,
    subscribe_sse,
    unsubscribe_sse,
)
from icsforge.web.helpers_stats import _bin_receipts, _stats_from_receipts

log = get_logger(__name__)

__all__ = [
    "__version__",
    "send_scenario_live",
    "build_network_validation_report",
    "run_scenario",
    "RunRegistry",
    "default_db_path",
    "_repo_root",
    "_load_yaml",
    "_read_jsonl_tail",
    "_read_json_lines",
    "_run_index_path",
    "_load_run_index",
    "_append_run_index",
    "_save_run_index",
    "_update_run_entry",
    "_bin_receipts",
    "_stats_from_receipts",
    "_live_receipts",
    "notify_sse",
    "subscribe_sse",
    "unsubscribe_sse",
    "start_pull_mode",
    "stop_pull_mode",
]

# ATT&CK for ICS matrix data paths (bundled)
MATRIX_JSON_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "ics_attack_matrix.json")
MATRIX_SINGLETON_PACK = os.path.join(os.path.dirname(__file__), "..", "scenarios", "scenarios.yml")


def _load_matrix() -> dict:
    try:
        return json.loads(Path(MATRIX_JSON_PATH).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"tactics": [], "x_mitre_version": "?"}


def _registry():
    rr = _repo_root()
    return RunRegistry(default_db_path(rr))


def _artifact_rel(repo_root: str, path: str) -> str:
    if not path:
        return ""
    p = os.path.realpath(path if os.path.isabs(path) else os.path.join(repo_root, path))
    rr = os.path.realpath(repo_root)
    if p.startswith(rr):
        return os.path.relpath(p, rr)
    return path


def _is_safe_private_ip(ip: str) -> bool:
    """
    Allow RFC1918, loopback, link-local, RFC 5737 test nets, and any ranges
    in ICSFORGE_ALLOWED_NETS (comma-separated CIDRs for non-standard internal ranges).
    Block public/global IPs not in any of the above.
    """
    try:
        import ipaddress, os
        a = ipaddress.ip_address(ip)
        if a.is_loopback or a.is_private or a.is_link_local:
            return True
        # RFC 5737 test nets
        if any(a in ipaddress.ip_network(net) for net in [
            "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"
        ]):
            return True
        # User-defined additional networks: env var + persisted web config
        extra_cidrs = []
        env_nets = os.environ.get("ICSFORGE_ALLOWED_NETS", "").strip()
        if env_nets:
            extra_cidrs.extend(c.strip() for c in env_nets.split(",") if c.strip())
        extra_cidrs.extend(_allowed_nets)  # from web UI / persisted config
        for cidr in extra_cidrs:
            try:
                if a in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                pass
        return False
    except ValueError:
        return False


def _resolve_pack(pack: str) -> str | None:
    if not pack:
        return None
    rr = os.path.realpath(_repo_root())
    cand = os.path.realpath(pack)
    if os.path.exists(cand) and cand.startswith(rr):
        return cand
    cand = os.path.realpath(os.path.join(rr, pack.lstrip("/")))
    if os.path.exists(cand) and cand.startswith(rr):
        return cand
    return None


def _canonical_scenarios_path() -> str:
    return str(Path(_repo_root()) / "icsforge" / "scenarios" / "scenarios.yml")


def _tech_name(tid: str) -> str:
    try:
        mat = _load_matrix()
        for tac in mat.get("tactics", []):
            for tech in tac.get("techniques", []):
                if tech.get("id") == tid:
                    return tech.get("name") or tid
    except (OSError, ValueError):
        pass
    return tid


def _default_receipts_path() -> str:
    return os.path.join(_repo_root(), "receiver_out", "receipts.jsonl")


def _list_packs() -> list[str]:
    rr = _repo_root()
    candidates = [
        os.path.join(rr, "icsforge", "scenarios", "scenarios.yml"),
        os.path.join(rr, "catalog", "scenarios.yml"),
    ]
    return [p for p in candidates if os.path.exists(p)]


def _default_pack() -> str | None:
    return _canonical_scenarios_path()


def _list_profiles() -> list[str]:
    rr = _repo_root()
    pdir = os.path.join(rr, "icsforge", "profiles")
    if not os.path.isdir(pdir):
        return []
    return sorted([str(Path(pdir, f)) for f in os.listdir(pdir) if f.endswith(".yml")])


def _alerts_path(run_id: str) -> str:
    return os.path.join(_repo_root(), "out", "alerts", f"{run_id}.jsonl")


def _validation_path(run_id: str) -> str:
    return os.path.join(_repo_root(), "out", "validation", f"{run_id}.json")


def _export_path(run_id: str) -> str:
    return os.path.join(_repo_root(), "out", "exports", f"{run_id}.html")


def _supported_techniques() -> set:
    techs: set = set()
    for pack_path in _list_packs():
        doc = _load_yaml(pack_path) or {}
        for sc in (doc.get("scenarios") or {}).values():
            for step in (sc.get("steps") or []):
                tid = step.get("technique")
                if tid:
                    techs.add(tid)
    return techs


# ── Persisted network config ───────────────────────────────────────────
_receiver_ip: str | None = None
_sender_ip: str | None = None
_receiver_port: int = 9090
_sender_callback_url: str | None = None
_callback_token: str | None = None
_pull_enabled: bool = False
_allowed_nets: list[str] = []  # extra CIDRs for non-RFC1918 internal ranges
_webhook_allow_public: bool = False   # allow webhook POSTs to public internet URLs
_replay_allow_public: bool = False    # allow PCAP replay to public IPs

_CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".icsforge", "web_config.json")


def _load_persisted_config() -> None:
    global _receiver_ip, _sender_ip, _receiver_port, _sender_callback_url, _callback_token, _pull_enabled, _allowed_nets, _webhook_allow_public, _replay_allow_public
    if not os.path.exists(_CONFIG_PATH):
        return
    try:
        with open(_CONFIG_PATH) as f:
            cfg = json.load(f)
        _sender_ip = cfg.get("sender_ip") or None
        _receiver_ip = cfg.get("receiver_ip") or None
        _receiver_port = int(cfg.get("receiver_port", 9090))
        _sender_callback_url = cfg.get("sender_callback_url") or None
        _callback_token = cfg.get("callback_token") or None
        _pull_enabled = bool(cfg.get("pull_enabled", False))
        _allowed_nets = [c.strip() for c in cfg.get("allowed_nets", []) if isinstance(c, str) and c.strip()]
        _webhook_allow_public = bool(cfg.get("webhook_allow_public", False))
        _replay_allow_public  = bool(cfg.get("replay_allow_public",  False))
    except (OSError, json.JSONDecodeError, ValueError):
        pass


def _save_persisted_config() -> None:
    os.makedirs(os.path.dirname(_CONFIG_PATH), exist_ok=True)
    with open(_CONFIG_PATH, "w") as f:
        json.dump({
            "sender_ip": _sender_ip or "",
            "receiver_ip": _receiver_ip or "",
            "receiver_port": _receiver_port,
            "sender_callback_url": _sender_callback_url or "",
            "callback_token": _callback_token or "",
            "pull_enabled": _pull_enabled,
            "allowed_nets": _allowed_nets,
            "webhook_allow_public": _webhook_allow_public,
            "replay_allow_public":  _replay_allow_public,
        }, f, indent=2)


def _build_sender_callback_url(req) -> str:
    if _sender_callback_url:
        return _sender_callback_url
    if _sender_ip:
        return f"http://{_sender_ip}:8080/api/receiver/callback"
    sender_host = req.host.split(":")[0]
    sender_port = req.host.split(":")[-1] if ":" in req.host else "8080"
    return f"http://{sender_host}:{sender_port}/api/receiver/callback"


def _callback_headers() -> dict:
    headers = {"Content-Type": "application/json"}
    if _callback_token:
        headers["X-ICSForge-Callback-Token"] = _callback_token
    return headers


# Load persisted config at module import time
_load_persisted_config()

# ── Webhook config (v0.49) ────────────────────────────────────────────
_webhook_url: str | None = None
_webhook_events: set = {"run_complete", "gap_detected", "campaign_complete"}


def set_webhook_url(url: str | None) -> None:
    global _webhook_url
    _webhook_url = (url or "").strip() or None


def get_webhook_url() -> str | None:
    return _webhook_url


def _is_safe_webhook_url(url: str) -> bool:
    """Validate webhook URL: must be http/https and not a public IP unless ICSFORGE_WEBHOOK_ALLOW_PUBLIC is set."""
    import urllib.parse as _up, ipaddress as _ip
    try:
        p = _up.urlparse(url)
        if p.scheme not in ("http", "https"):
            return False
        host = p.hostname or ""
        # Allow if public webhooks explicitly enabled via persisted UI config
        if _webhook_allow_public:
            return bool(host)
        # Otherwise restrict to private/loopback/link-local
        try:
            a = _ip.ip_address(host)
            return a.is_loopback or a.is_private or a.is_link_local
        except ValueError:
            # Hostname — allow non-public FQDNs (localhost, internal hostnames)
            # Block obvious public patterns
            return host == "localhost" or "." not in host or host.endswith(".local")
    except Exception:
        return False


def fire_webhook(event_type: str, payload: dict) -> bool:
    """POST payload to configured webhook URL. Returns True on success."""
    if not _webhook_url or event_type not in _webhook_events:
        return False
    if not _is_safe_webhook_url(_webhook_url):
        log.warning("Webhook URL blocked (public/unsafe): %s — enable 'Allow public webhook URLs' in Tools → Send Policy", _webhook_url)
        return False
    body = json.dumps({
        "event": event_type,
        "ts": datetime.now(timezone.utc).isoformat() + "Z",
        **payload,
    }).encode("utf-8")
    try:
        req = urllib.request.Request(
            _webhook_url,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": f"ICSForge/{__version__}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5):
            pass
        log.info("Webhook fired: %s → %s", event_type, _webhook_url)
        return True
    except (OSError, ValueError) as exc:
        log.warning("Webhook delivery failed (%s): %s", event_type, exc)
        return False
