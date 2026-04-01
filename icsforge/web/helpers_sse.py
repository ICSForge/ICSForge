import queue
"""ICSForge web helpers — SSE push and pull-mode polling."""
import collections
import json
import threading
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from icsforge.log import get_logger

log = get_logger(__name__)

_live_receipts: collections.deque = collections.deque(maxlen=500)
_sse_subscribers: list = []
_sse_lock = threading.Lock()


def notify_sse(event_data: dict) -> None:
    """Push event to all SSE subscribers."""
    with _sse_lock:
        dead = []
        for q in _sse_subscribers:
            try:
                q.put_nowait(event_data)
            except Exception:  # queue.Full or similar
                dead.append(q)
        for q in dead:
            _sse_subscribers.remove(q)


def subscribe_sse():
    """Return a queue that will receive SSE events."""
    q: queue.Queue = queue.Queue(maxsize=50)
    with _sse_lock:
        _sse_subscribers.append(q)
    return q


def unsubscribe_sse(q) -> None:
    """Remove a subscriber queue."""
    with _sse_lock:
        if q in _sse_subscribers:
            _sse_subscribers.remove(q)


# ── Pull-mode state ────────────────────────────────────────────────────
_pull_thread: threading.Thread | None = None
_pull_stop = threading.Event()
_pull_last_ts = ""




def _pull_worker() -> None:
    """Background thread: polls receiver /api/receipts and feeds into SSE."""
    global _pull_last_ts

    # Import lazily to avoid circular deps
    from icsforge.web import helpers as _h

    log.info("Pull-mode started: polling receiver at %s:%s", _h._receiver_ip, _h._receiver_port)
    while not _pull_stop.is_set():
        if not _h._receiver_ip:
            _pull_stop.wait(5)
            continue
        url = f"http://{_h._receiver_ip}:{_h._receiver_port}/api/receipts?limit=50"
        if _pull_last_ts:
            url += f"&since={urllib.parse.quote(_pull_last_ts)}"
        try:
            req = urllib.request.Request(url, method="GET")
            resp = urllib.request.urlopen(req, timeout=5)
            data = json.loads(resp.read().decode("utf-8"))
            for item in data.get("items", []):
                ts = item.get("@timestamp", "")
                if ts > _pull_last_ts:
                    _pull_last_ts = ts
                if item.get("marker_found"):
                    item["_received_at"] = datetime.now(timezone.utc).isoformat()
                    item["_source"] = "pull"
                    _live_receipts.append(item)
                    notify_sse(item)
        except (OSError, ValueError):
            pass  # receiver unreachable, retry next interval
        _pull_stop.wait(2)
    log.info("Pull-mode stopped")


def start_pull_mode() -> None:
    global _pull_thread
    if _pull_thread and _pull_thread.is_alive():
        return
    _pull_stop.clear()
    _pull_thread = threading.Thread(target=_pull_worker, daemon=True, name="icsforge-pull")
    _pull_thread.start()


def stop_pull_mode() -> None:
    _pull_stop.set()
    if _pull_thread:
        _pull_thread.join(timeout=3)
