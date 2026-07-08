"""Test that README technique-coverage figures match what scripts/v19_coverage.py
computes. This catches the kind of drift caught manually in v0.68.1
(README claimed 65/79 standalone when actual was 73/79, drifting across
4 releases since v0.64.1).

The canonical numbers live in scripts/v19_coverage.py — that's the source
of truth. README and docs MUST match what the script outputs.
"""
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "v19_coverage.py"


def test_v19_coverage_script_runs():
    """The script itself must produce output without error."""
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, (
        f"v19_coverage.py crashed:\n"
        f"  stdout: {result.stdout}\n"
        f"  stderr: {result.stderr}"
    )
    # Sanity: contains the expected headings
    assert "v18 standalone:" in result.stdout
    assert "v19 standalone:" in result.stdout
    assert "v19 sub-techniques:" in result.stdout


def test_readme_matches_canonical_v19_coverage():
    """README.md must contain the canonical v19 coverage figures.

    If this fails:
    1. Run `scripts/v19_coverage.py` to see the current canonical numbers.
    2. Update README.md and docs/MITRE_V19_CROSSWALK.md to match.
    3. Re-run tests.

    The script is the source of truth; README is the consumer.
    """
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--check"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, (
        f"README.md technique-coverage figures have drifted from canonical "
        f"(scripts/v19_coverage.py).\n"
        f"  stdout: {result.stdout}\n"
        f"  stderr: {result.stderr}\n"
        f"Fix: update README.md to match scripts/v19_coverage.py output."
    )


def test_v19_json_output_parses():
    """The --json mode must produce parseable JSON with expected keys."""
    import json
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--json"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert "v18" in data
    assert "v19_standalone" in data
    assert "v19_subs" in data
    assert "v19_combined" in data
    # Sanity: counts are sensible
    assert data["v18"]["total"] == 83
    assert data["v19_standalone"]["total"] == 79
    assert data["v19_subs"]["total"] == 18
    assert data["v19_combined"]["total"] == 97
    # Coverage in [0, 100]
    for key in ["v18", "v19_standalone", "v19_subs", "v19_combined"]:
        pct = data[key]["pct"]
        assert 0 <= pct <= 100, f"{key} pct out of range: {pct}"
