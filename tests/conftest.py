"""Shared test fixtures for ICSForge test suite."""
import os

import pytest


@pytest.fixture
def tmp_outdir(tmp_path):
    """Temporary output directory."""
    d = tmp_path / "out"
    d.mkdir()
    return str(d)


@pytest.fixture
def scenarios_path():
    """Path to the bundled scenarios.yml."""
    p = os.path.join(os.path.dirname(__file__), "..", "icsforge", "scenarios", "scenarios.yml")
    p = os.path.abspath(p)
    if os.path.exists(p):
        return p
    pytest.skip("scenarios.yml not found")


@pytest.fixture
def marker():
    """Standard test marker string."""
    return "test-run-42|T0855|step1:modbus"
