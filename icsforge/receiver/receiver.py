from __future__ import annotations
import os, json, socket, threading, hashlib, time
from datetime import datetime, timezone
import yaml
from icsforge.core import marker_prefix

def _now():
    return datetime.now(timezone.utc).isoformat()

def _ensure_dir(p: str):
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)

def _parse_marker(payload: bytes) -> dict:
    pref = marker_prefix()
    i = payload.find(pref)
    if i < 0:
        return {"marker_found": False}
    tail = payload[i:]
    parts = tail.split(b"|", 3)
    run_id = parts[1].decode("utf-8","ignore") if len(parts)>1 else ""
    tech = parts[2].decode("utf-8","ignore") if len(parts)>2 else ""
    step = parts[3].decode("utf-8","ignore") if len(parts)>3 else ""
    return {"marker_found": True, "run_id": run_id, "technique": tech, "step": step}

def _write_receipt(path: str, ev: dict):
    _ensure_dir(path)
    with open(path,"a",encoding="utf-8") as f:
        f.write(json.dumps(ev, ensure_ascii=False) + "\n")

def _handle(conn: socket.socket, addr, proto: str, port: int, receipts_path: str, max_payload: int):
    try:
        data = conn.recv(max_payload)
        if not data:
            return
        meta = _parse_marker(data)
        ev = {
            "@timestamp": _now(),
            "receiver.proto": proto,
            "receiver.port": port,
            "src_ip": addr[0],
            "src_port": addr[1],
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            **meta,
        }
        _write_receipt(receipts_path, ev)
    finally:
        try: conn.close()
        except Exception: pass

def _server(bind_ip: str, port: int, proto: str, receipts_path: str, max_payload: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_ip, port))
    s.listen(200)
    print(f"[ICSForge Receiver] {proto} listening on {bind_ip}:{port}")
    while True:
        c,a = s.accept()
        threading.Thread(target=_handle, args=(c,a,proto,port,receipts_path,max_payload), daemon=True).start()

def main():
    import argparse
    ap = argparse.ArgumentParser(prog="icsforge-receiver")
    ap.add_argument("--web", action="store_true", default=True, help="Enable Receiver Web UI (read-only)")
    ap.add_argument("--web-host", default="0.0.0.0")
    ap.add_argument("--web-port", type=int, default=8080)
    # Compatibility aliases (launcher uses --host/--port)
    ap.add_argument("--host", dest="web_host", help="Alias for --web-host (also used as --bind if --bind not set)")
    ap.add_argument("--port", dest="web_port", type=int, help="Alias for --web-port")
    ap.add_argument("--no-web", action="store_true", help="Disable Receiver Web UI")
    ap.add_argument("--config", default=os.path.join(os.path.dirname(__file__), "config.yml"))
    ap.add_argument("--bind", default="0.0.0.0")
    args = ap.parse_args()

    # If --host/--port aliases were used, argparse populated web_host/web_port.
    # For convenience, treat --host as --bind when bind is default.
    if getattr(args, 'web_host', None) and args.bind == '0.0.0.0':
        # Only override when user did not specify --bind explicitly
        args.bind = args.web_host

    cfg = yaml.safe_load(open(args.config,"r",encoding="utf-8")) or {}
    listen = cfg.get("listen") or {}
    receipts_path = (cfg.get("log") or {}).get("receipts","./receiver_out/receipts.jsonl")
    max_payload = int((cfg.get("safety") or {}).get("max_payload", 8192))

    for proto, port in listen.items():
        threading.Thread(target=_server, args=(args.bind, int(port), proto, receipts_path, max_payload), daemon=True).start()

    print("[ICSForge Receiver] receipts:", receipts_path)
    # Web UI (read-only) runs alongside receiver by default
    enable_web = (not args.no_web) and args.web
    if enable_web:
        try:
            from threading import Thread
            from icsforge.web.app import main as web_main

            def _run_web():
                os.environ['ICSFORGE_UI_MODE'] = 'receiver'
                import sys
                sys.argv = ["icsforge-web", "--host", args.web_host, "--port", str(args.web_port)]
                web_main()

            Thread(target=_run_web, daemon=True).start()
            print(f"[ICSForge Receiver] Web UI: http://{args.web_host}:{args.web_port}")
        except Exception as e:
            print("[ICSForge Receiver] Web UI failed to start:", e)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[ICSForge Receiver] stopped.")

if __name__ == "__main__":
    main()
