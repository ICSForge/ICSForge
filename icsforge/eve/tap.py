"""ICSForge EVE tap — tail Suricata EVE JSON log in real time.

Watches an EVE JSON file (inotify on Linux, stat-polling fallback) during
a scenario run. Correlates alert signatures against known technique mappings
and notifies the SSE bus so the sender UI can update the ATT&CK matrix live.

Usage (from a blueprint or background thread):
    tap = EveTap("/var/log/suricata/eve.json", run_id="2026-03-27-ALPHA-01")
    tap.start()
    # ... scenario runs ...
    results = tap.stop()   # returns list of matched {technique, signature, ts}
"""
import json
import os
import re
import threading
from collections.abc import Callable
from datetime import datetime, timezone

from icsforge.log import get_logger

log = get_logger(__name__)

# Poll interval when inotify is unavailable (seconds)
_POLL_INTERVAL = 0.5

# Minimum alert event_type to follow
_ALERT_EVENT_TYPES = {"alert"}


def _has_inotify() -> bool:
    try:
        import select
        return hasattr(select, "epoll")  # Linux
    except ImportError:
        return False


class EveTap:
    """Tail a Suricata EVE JSON log and emit matched detections via callback."""

    def __init__(
        self,
        eve_path: str,
        run_id: str | None = None,
        on_match: Callable[[dict], None] | None = None,
        technique_map: dict | None = None,
    ):
        self.eve_path = eve_path
        self.run_id = run_id
        self.on_match = on_match  # called with {technique, signature, ts, src_ip, dst_ip, sid}
        self._technique_map = technique_map or {}  # SID/signature → technique mapping
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._matches: list[dict] = []
        self._lock = threading.Lock()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name=f"icsforge-eve-{self.run_id or 'tap'}"
        )
        self._thread.start()
        log.info("EVE tap started on %s (run_id=%s)", self.eve_path, self.run_id)

    def stop(self, timeout: float = 3.0) -> list[dict]:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)
        log.info("EVE tap stopped — %d matches", len(self._matches))
        with self._lock:
            return list(self._matches)

    def get_matches(self) -> list[dict]:
        with self._lock:
            return list(self._matches)

    def _run(self) -> None:
        # Seek to end of file before we start so we don't replay history
        try:
            offset = os.path.getsize(self.eve_path) if os.path.exists(self.eve_path) else 0
        except OSError:
            offset = 0

        while not self._stop_event.is_set():
            try:
                if not os.path.exists(self.eve_path):
                    self._stop_event.wait(_POLL_INTERVAL)
                    continue
                with open(self.eve_path, encoding="utf-8", errors="replace") as f:
                    f.seek(offset)
                    while not self._stop_event.is_set():
                        line = f.readline()
                        if not line:
                            # No new data — sleep and retry
                            self._stop_event.wait(_POLL_INTERVAL)
                            # Re-check file (rotation detection)
                            try:
                                new_size = os.path.getsize(self.eve_path)
                                if new_size < offset:
                                    # File was rotated/truncated
                                    log.debug("EVE file rotated, resetting offset")
                                    offset = 0
                                    break
                            except OSError:
                                break
                            continue
                        offset = f.tell()
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            event = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if event.get("event_type") not in _ALERT_EVENT_TYPES:
                            continue
                        self._process_alert(event)
            except OSError as exc:
                log.debug("EVE tap file error: %s — retrying", exc)
                self._stop_event.wait(_POLL_INTERVAL * 4)

    def _process_alert(self, event: dict) -> None:
        alert = event.get("alert") or {}
        signature = alert.get("signature") or ""
        sid = alert.get("signature_id")
        ts = event.get("timestamp") or datetime.now(timezone.utc).isoformat()

        # Try to map to a technique
        technique = None
        if sid and sid in self._technique_map:
            technique = self._technique_map[sid]
        if not technique and signature:
            # Scan technique_map for signature substring matches
            sig_lower = signature.lower()
            for key, val in self._technique_map.items():
                if isinstance(key, str) and key.lower() in sig_lower:
                    technique = val
                    break
        # Also try extracting T0XXX directly from signature
        if not technique and "T0" in signature:
            m = re.search(r"T0\d{3}", signature)
            if m:
                technique = m.group(0)

        if not technique:
            return  # skip unrecognised alerts

        match = {
            "technique": technique,
            "signature": signature,
            "sid": sid,
            "ts": ts,
            "src_ip": event.get("src_ip"),
            "dst_ip": event.get("dest_ip") or event.get("dst_ip"),
            "proto": event.get("proto") or event.get("app_proto"),
            "run_id": self.run_id,
        }
        with self._lock:
            self._matches.append(match)
        log.debug("EVE match: %s → %s", technique, signature[:60])
        if self.on_match:
            try:
                self.on_match(match)
            except Exception as exc:  # noqa: BLE001 — callback errors must not crash the tap
                log.debug("EVE tap on_match callback raised: %s", exc)


def build_technique_map_from_rules(rules_text: str) -> dict:
    """Parse a Suricata rules file and build {sid: technique_id} map.

    Recognises the ICSForge metadata format:
        metadata: mitre_technique T0855, icsforge_scenario ...
    and also any msg field containing T0XXX.
    """
    mapping: dict = {}
    for line in rules_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Extract SID
        sid_m = re.search(r"\bsid:(\d+)", line)
        if not sid_m:
            continue
        sid = int(sid_m.group(1))
        # Try metadata field first
        meta_m = re.search(r"mitre_technique\s+(T0\d{3})", line)
        if meta_m:
            mapping[sid] = meta_m.group(1)
            continue
        # Fall back to msg field
        msg_m = re.search(r'msg:"[^"]*?(T0\d{3})', line)
        if msg_m:
            mapping[sid] = msg_m.group(1)
    return mapping
