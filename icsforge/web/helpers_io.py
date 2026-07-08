"""ICSForge web helpers — file I/O utilities (JSONL, YAML, run index)."""
import json
import os
import threading
from pathlib import Path

import yaml

# Use libyaml's C loader when available — 8× faster than pure-Python
# safe_load on our scenarios.yml (170ms vs 1400ms locally). Falls back
# transparently if libyaml isn't installed.
try:
    _SafeLoader = yaml.CSafeLoader  # type: ignore[attr-defined]
except AttributeError:
    _SafeLoader = yaml.SafeLoader

# In-process cache: path -> (mtime_ns, parsed_dict). The mtime check
# means we re-parse only when the file actually changes on disk;
# subsequent web requests serve from memory (microsecond latency).
_yaml_cache: dict[str, tuple[int, dict]] = {}
_yaml_cache_lock = threading.Lock()


def _repo_root() -> str:
    return str(Path(__file__).resolve().parents[2])


def _load_yaml(path: str) -> dict:
    """Load a YAML file with mtime-keyed in-process cache.

    Web routes that hit scenarios.yml were paying ~1.4s of pure-Python YAML
    parsing on every request. With this cache, the first request takes that
    hit; subsequent requests serve from memory in microseconds, and the cache
    invalidates automatically when the file is edited.
    """
    try:
        st = os.stat(path)
    except OSError:
        # File doesn't exist or can't be stat'd — fall through to open(),
        # which will raise the appropriate exception.
        with open(path, encoding="utf-8") as f:
            return yaml.load(f, Loader=_SafeLoader) or {}

    cache_key = os.path.abspath(path)
    mtime_ns = st.st_mtime_ns
    with _yaml_cache_lock:
        cached = _yaml_cache.get(cache_key)
        if cached and cached[0] == mtime_ns:
            return cached[1]
    # Cache miss or stale — parse outside the lock so concurrent readers
    # don't block each other on the parse.
    with open(path, encoding="utf-8") as f:
        doc = yaml.load(f, Loader=_SafeLoader) or {}
    with _yaml_cache_lock:
        _yaml_cache[cache_key] = (mtime_ns, doc)
    return doc


def _read_jsonl_tail(path: str, limit: int = 250) -> list[dict]:
    if not os.path.exists(path):
        return []
    items = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except (json.JSONDecodeError, ValueError):
                continue
    return items[-limit:]


def _read_json_lines(path: str) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except (json.JSONDecodeError, ValueError):
                continue
    return rows


def _run_index_path() -> str:
    return os.path.join(_repo_root(), "out", "run_index.json")


def _load_run_index() -> list[dict]:
    p = _run_index_path()
    if not os.path.exists(p):
        return []
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []


def _append_run_index(entry: dict) -> None:
    os.makedirs(os.path.dirname(_run_index_path()), exist_ok=True)
    items = _load_run_index()
    items.insert(0, entry)
    Path(_run_index_path()).write_text(json.dumps(items[:100], indent=2), encoding="utf-8")


def _save_run_index(items: list[dict]) -> None:
    os.makedirs(os.path.dirname(_run_index_path()), exist_ok=True)
    Path(_run_index_path()).write_text(json.dumps(items[:200], indent=2), encoding="utf-8")


def _update_run_entry(run_id: str, fn) -> bool:
    items = _load_run_index()
    changed = False
    for it in items:
        if it.get("run_id") == run_id:
            fn(it)
            changed = True
            break
    if changed:
        _save_run_index(items)
    return changed
