from __future__ import annotations
import os, json, sqlite3, hashlib, zipfile
from typing import Any, Dict, List, Tuple
from datetime import datetime

def default_db_path(repo_root: str) -> str:
    out_dir = os.path.join(repo_root, "out")
    os.makedirs(out_dir, exist_ok=True)
    return os.path.join(out_dir, "runs.db")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS runs(
  run_id TEXT PRIMARY KEY,
  created_ts TEXT,
  scenario TEXT,
  pack TEXT,
  profile TEXT,
  dst_ip TEXT,
  src_ip TEXT,
  iface TEXT,
  mode TEXT,
  status TEXT,
  notes TEXT,
  meta_json TEXT
);
CREATE TABLE IF NOT EXISTS artifacts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT,
  kind TEXT,
  path TEXT,
  sha256 TEXT,
  bytes INTEGER,
  created_ts TEXT,
  FOREIGN KEY(run_id) REFERENCES runs(run_id)
);
"""

def _sha256_file(path: str) -> Tuple[str,int]:
    h=hashlib.sha256()
    n=0
    with open(path,"rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n

class RunRegistry:
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._init()

    def _conn(self):
        return sqlite3.connect(self.db_path)

    def _init(self):
        with self._conn() as c:
            c.executescript(SCHEMA_SQL)

    def upsert_run(self, run_id: str, **fields):
        created_ts = fields.pop("created_ts", None) or datetime.utcnow().isoformat()+"Z"
        meta = fields.pop("meta", None) or {}
        meta_json = json.dumps(meta, separators=(",",":"))
        with self._conn() as c:
            c.execute("""
                INSERT INTO runs(run_id, created_ts, scenario, pack, profile, dst_ip, src_ip, iface, mode, status, notes, meta_json)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(run_id) DO UPDATE SET
                  scenario=excluded.scenario,
                  pack=excluded.pack,
                  profile=excluded.profile,
                  dst_ip=excluded.dst_ip,
                  src_ip=excluded.src_ip,
                  iface=excluded.iface,
                  mode=excluded.mode,
                  status=excluded.status,
                  notes=excluded.notes,
                  meta_json=excluded.meta_json
            """, (
                run_id, created_ts,
                fields.get("scenario"), fields.get("pack"), fields.get("profile"),
                fields.get("dst_ip"), fields.get("src_ip"), fields.get("iface"),
                fields.get("mode"), fields.get("status"), fields.get("notes"),
                meta_json
            ))

    def add_artifact(self, run_id: str, kind: str, path: str):
        if not path:
            return
        sha=""
        size=0
        try:
            if os.path.exists(path) and os.path.isfile(path):
                sha,size = _sha256_file(path)
        except Exception:
            sha=""
            size=0
        with self._conn() as c:
            c.execute("""INSERT INTO artifacts(run_id,kind,path,sha256,bytes,created_ts)
                         VALUES(?,?,?,?,?,?)""", (
                run_id, kind, path, sha, size, datetime.utcnow().isoformat()+"Z"
            ))

    def list_runs(self, limit: int = 50):
        with self._conn() as c:
            rows = c.execute("""SELECT run_id, created_ts, scenario, pack, dst_ip, mode, status FROM runs
                                 ORDER BY created_ts DESC LIMIT ?""", (limit,)).fetchall()
        return [{"run_id":r[0],"ts":r[1],"scenario":r[2],"pack":r[3],"dst_ip":r[4],"mode":r[5],"status":r[6]} for r in rows]

    def get_run(self, run_id: str):
        with self._conn() as c:
            r = c.execute("""SELECT run_id, created_ts, scenario, pack, profile, dst_ip, src_ip, iface, mode, status, notes, meta_json
                              FROM runs WHERE run_id=?""", (run_id,)).fetchone()
            if not r:
                return {}
            arts = c.execute("""SELECT kind, path, sha256, bytes, created_ts FROM artifacts WHERE run_id=? ORDER BY id""", (run_id,)).fetchall()
        try:
            meta = json.loads(r[11] or "{}")
        except Exception:
            meta = {}
        return {
            "run_id": r[0], "ts": r[1], "scenario": r[2], "pack": r[3], "profile": r[4],
            "dst_ip": r[5], "src_ip": r[6], "iface": r[7], "mode": r[8], "status": r[9], "notes": r[10],
            "meta": meta,
            "artifacts": [{"kind":a[0],"path":a[1],"sha256":a[2],"bytes":a[3],"ts":a[4]} for a in arts]
        }

    def export_bundle(self, run_id: str, repo_root: str) -> str:
        run = self.get_run(run_id)
        if not run:
            raise ValueError("run_id not found")
        out_dir = os.path.join(repo_root, "out", "bundles")
        os.makedirs(out_dir, exist_ok=True)
        bundle_path = os.path.join(out_dir, f"bundle_{run_id}.zip")
        rr = os.path.realpath(repo_root)
        with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("run.json", json.dumps(run, indent=2))
            for a in run.get("artifacts", []):
                p = a.get("path")
                if not p:
                    continue
                ap = os.path.realpath(p if os.path.isabs(p) else os.path.join(rr, p))
                if not ap.startswith(rr):
                    continue
                if os.path.exists(ap) and os.path.isfile(ap):
                    arc = os.path.relpath(ap, rr)
                    z.write(ap, arcname=arc)
        self.add_artifact(run_id, "bundle", bundle_path)
        return bundle_path
