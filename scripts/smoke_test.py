#!/usr/bin/env python3
"""ICSForge pre-release smoke test.

Starts a test Flask app and hits every major API endpoint.
Any 500 is a hard failure. Run before cutting a release.

Usage:
    python scripts/smoke_test.py
    python scripts/smoke_test.py --verbose
"""
import argparse
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["ICSFORGE_UI_MODE"] = "sender"
os.environ["ICSFORGE_NO_AUTH"] = "1"

from icsforge.web.app import create_app  # noqa: E402

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
SKIP = "\033[33mSKIP\033[0m"



def check_engine_signature():
    """Verify run_scenario has skip_intervals param — prevents 25s pcap delay in live send."""
    import ast
    src = open(os.path.join(os.path.dirname(__file__), "..", "icsforge", "scenarios", "engine.py")).read()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "run_scenario":
            params = [a.arg for a in node.args.args] + [a.arg for a in node.args.kwonlyargs]
            defaults = node.args.defaults
            kw_defaults = node.args.kw_defaults
            has_param = "skip_intervals" in params
            if has_param:
                print(f"  {PASS}  run_scenario has skip_intervals parameter")
                return True
            else:
                print(f"  {FAIL}  run_scenario missing skip_intervals — live send PCAP will be slow/missing")
                return False
    print(f"  {FAIL}  run_scenario function not found")
    return False


def check_launcher():
    """Verify main() uses create_app() not a partial app — the v0.50.0 regression."""
    import ast
    src = open(os.path.join(os.path.dirname(__file__), "..", "icsforge", "web", "app.py")).read()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "main":
            calls = [n.func.id for n in ast.walk(node)
                     if isinstance(n, ast.Call) and isinstance(getattr(n, "func", None), ast.Name)]
            uses_factory = "create_app" in calls
            builds_flask = "Flask" in calls
            if uses_factory and not builds_flask:
                print(f"  {PASS}  main() uses create_app() — launcher is correct")
                return True
            else:
                print(f"  {FAIL}  main() does NOT use create_app() — API routes will be missing in production!")
                return False
    print(f"  {FAIL}  main() function not found in app.py")
    return False

def run_smoke(verbose: bool = False) -> int:
    app = create_app()
    app.config["TESTING"] = True
    failures = 0
    total = 0

    # Verify the launcher path and engine signature
    if not check_launcher():
        return 1
    if not check_engine_signature():
        return 1

    with tempfile.TemporaryDirectory() as tmpdir:
        eve_file = os.path.join(tmpdir, "eve.json")
        open(eve_file, "w").close()

        # (method, path, body, expected_not_500, description)
        checks = [
            # Health & config
            ("GET",  "/api/health",              None,                        True,  "health"),
            ("GET",  "/api/config/network",      None,                        True,  "config network GET"),
            ("POST", "/api/config/network",      {"sender_ip": "127.0.0.1"},  True,  "config network POST"),
            ("GET",  "/api/config/webhook",      None,                        True,  "webhook config GET"),
            ("GET",  "/api/interfaces",          None,                        True,  "interfaces"),

            # Scenarios & packs
            ("GET",  "/api/scenarios",           None,                        True,  "scenarios list"),
            ("GET",  "/api/scenarios_grouped",   None,                        True,  "scenarios grouped"),
            ("GET",  "/api/packs",               None,                        True,  "packs list"),
            ("GET",  "/api/profiles",            None,                        True,  "profiles list"),
            ("GET",  "/api/preview?name=T0855__unauth_command__modbus", None, True, "scenario preview"),
            ("GET",  "/api/preview_payload?name=T0855__unauth_command__modbus&step=0", None, True, "payload preview"),
            ("GET",  "/api/scenario/params?proto=modbus", None,               True,  "scenario params"),

            # Receiver
            ("GET",  "/api/receiver/overview",   None,                        True,  "receiver overview"),
            ("GET",  "/api/receipts",            None,                        True,  "receipts list"),
            ("POST", "/api/receiver/callback",   {"marker_found": False},     True,  "receiver callback"),

            # Detections — the three that were broken in v0.49.2
            ("GET",  "/api/detections/preview",  None,                        True,  "detections preview"),
            ("GET",  "/api/detections/download", None,                        True,  "detections download ★"),

            # Reports — the three that were broken in v0.49.2
            ("POST", "/api/report/generate",
                {"executed_techniques": ["T0855"], "detected_techniques": [], "gap_techniques": []},
                True, "report generate"),
            ("POST", "/api/report/download",
                {"executed_techniques": ["T0855"], "detected_techniques": [], "gap_techniques": []},
                True, "report download ★"),
            ("GET",  "/api/report/heatmap?format=json", None,                 True,  "report heatmap ★"),

            # Runs
            ("GET",  "/api/runs",                None,                        True,  "runs list"),
            ("GET",  "/api/matrix_status",       None,                        True,  "matrix status"),

            # Campaigns
            ("GET",  "/api/campaigns/list",      None,                        True,  "campaigns list"),
            ("POST", "/api/campaigns/run",
                {"campaign_id": "NONEXISTENT_XYZ", "dst_ip": "198.51.100.1"},
                True, "campaign run 404 (not 500)"),

            # EVE tap
            ("POST", "/api/eve/start",           {"eve_path": eve_file},      True,  "eve start"),
            ("GET",  "/api/eve/matches",         None,                        True,  "eve matches"),
            ("POST", "/api/eve/stop",            {},                          True,  "eve stop"),

            # Page routes
            ("GET",  "/",                        None,                        True,  "index page"),
            ("GET",  "/sender",                  None,                        True,  "sender page"),
            ("GET",  "/receiver",                None,                        True,  "receiver page"),
            ("GET",  "/matrix",                  None,                        True,  "matrix page"),
            ("GET",  "/campaigns",               None,                        True,  "campaigns page"),
            ("GET",  "/report",                  None,                        True,  "report page"),
            ("GET",  "/health",                  None,                        True,  "health page"),
            ("GET",  "/tools",                   None,                        True,  "tools page"),
        ]

        with app.test_client() as c:
            for method, path, body, should_not_500, desc in checks:
                total += 1
                try:
                    if method == "GET":
                        r = c.get(path)
                    else:
                        r = c.post(path, json=body,
                                   headers={"Content-Type": "application/json"})
                    ok = r.status_code != 500
                    if ok:
                        tag = PASS
                    else:
                        tag = FAIL
                        failures += 1
                    if verbose or not ok:
                        print(f"  {tag}  {method:4} {path:<45} → {r.status_code}  ({desc})")
                    elif not verbose:
                        print(".", end="", flush=True)
                except Exception as exc:
                    failures += 1
                    print(f"  {FAIL}  {method:4} {path:<45} → EXCEPTION: {exc}  ({desc})")

    if not verbose:
        print()
    print()
    print(f"Smoke test: {total - failures}/{total} passed", end="  ")
    if failures == 0:
        print(f"{PASS} — no 500s detected")
    else:
        print(f"{FAIL} — {failures} endpoint(s) returned 500")
    return failures


def main():
    ap = argparse.ArgumentParser(description="ICSForge pre-release smoke test")
    ap.add_argument("--verbose", "-v", action="store_true", help="Show all results")
    args = ap.parse_args()
    sys.exit(run_smoke(args.verbose))


if __name__ == "__main__":
    main()
