# Contributing to ICSForge

Thank you for your interest in contributing to ICSForge! This guide will help you get started.

## Development Setup

```bash
git clone https://github.com/ICSforge/ICSforge.git
cd ICSforge
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=icsforge --cov-report=term-missing

# Run specific test file
pytest tests/test_protocols.py -v

# Run with debug output
pytest -v -s --log-cli-level=DEBUG
```

## Code Style

We use [ruff](https://docs.astral.sh/ruff/) for linting. Run before committing:

```bash
ruff check icsforge/ tests/
ruff format icsforge/ tests/
```

## Adding a New Protocol

1. Create `icsforge/protocols/your_protocol.py` with a `build_payload(marker, style, **kwargs)` function
2. Register it in `icsforge/scenarios/engine.py` → `PROTO_PAYLOADS` and `icsforge/live/sender.py` → `TCP_PROTOS`
3. Add scenarios to `icsforge/scenarios/scenarios.yml`
4. Add tests in `tests/test_protocols.py`
5. Update the ATT&CK matrix data if new techniques are covered

## Adding a New Scenario

Scenarios follow the naming convention: `T0XXX__technique_name__protocol__variant`

```yaml
T0855__unauth_command__modbus_fc16:
  title: "T0855 — Modbus FC16 bulk write"
  description: "..."
  tactic: Impair Process Control
  technique: T0855
  steps:
    - type: pcap
      proto: modbus
      technique: T0855
      style: write_multiple_registers
      count: 10
      interval: 0.1s
```

## Reporting Security Issues

If you find a security vulnerability, please report it responsibly via GitHub Security Advisories rather than opening a public issue.

## Pull Request Process

1. Fork the repository and create a feature branch
2. Add tests for any new functionality
3. Ensure all tests pass: `pytest`
4. Ensure code passes lint: `ruff check`
5. Update CHANGELOG.md with your changes
6. Submit a PR against the `develop` branch

## License

By contributing, you agree that your contributions will be licensed under the GPLv3 license.
