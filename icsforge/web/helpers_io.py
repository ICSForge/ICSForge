"""ICSForge web helpers — file I/O utilities (JSONL, YAML, run index)."""
import json
import os
from pathlib import Path

import yaml


def _repo_root() -> str:
    return str(Path(__file__).resolve().parents[2])


def _load_yaml(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


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
