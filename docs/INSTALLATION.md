# ICSForge — Installation Guide

This guide covers a **traditional installation** of ICSForge from source on Linux
(and notes for macOS). It does not use Docker. By the end you will have the
`icsforge` CLI, the **web UI** (`icsforge-web`), and the **receiver**
(`icsforge-receiver`) installed and running.

ICSForge is an OT/ICS security-control validation tool: it generates realistic
ICS protocol traffic (Modbus, DNP3, S7comm, IEC-104, IEC-61850/GOOSE, PROFINET-DCP,
OPC UA, EtherNet/IP, BACnet, MQTT) mapped to MITRE ATT&CK for ICS, so you can test
firewalls, ACLs, and network security monitoring sensors.

---

## 1. Requirements

**Python:** 3.10 or newer (3.12 / 3.13 recommended).

**Operating system:** Linux is the primary target (Ubuntu 22.04/24.04, Debian 12,
RHEL/Rocky 9 all work). macOS works for offline PCAP generation and the web UI;
live Layer-2 capture (GOOSE / PROFINET-DCP) is Linux-only.

**Privileges:** none required for offline PCAP generation or the web UI. Live
sending and live L2 capture need raw-socket capability (root, or a granted
capability — see §6).

**Core Python dependencies** (installed automatically): `flask>=3.0`,
`pyyaml>=6.0`, `requests>=2.31`, `psutil>=5.9`.

**Optional Python extras:**
- `replay` → `scapy>=2.5` — richer packet replay/inspection.
- `dev` → `pytest`, `pytest-cov`, `pytest-timeout`, `ruff` — for running the test
  suite and linting.
- `kafka` → `kafka-python` — only if you stream events to Kafka.

**Optional system tools** (not required to install, but useful for the validation
workflow): `tshark`/`wireshark` (inspect generated PCAPs), `suricata` and/or
`zeek` (run the bundled detection rules against PCAPs).

---

## 2. Get the source

You will have received ICSForge either as a release tarball or via Git.

**From a release tarball:**

```bash
tar -xzf ICSForge_v<version>.tar.gz
cd ICSForge-v<version>
```

**From Git:**

```bash
git clone https://github.com/ICSForge/ICSForge.git
cd ICSForge
```

> Releases ship as `.tar.gz` (not `.zip`) to preserve the executable bit on
> `bin/icsforge`.

---

## 3. Create a virtual environment (recommended)

A virtual environment keeps ICSForge's dependencies isolated from the system
Python. This is the recommended approach on any machine you also use for other work.

```bash
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate         # Windows PowerShell
```

Your shell prompt should now show `(.venv)`. Everything below runs inside it.

> **Prefer not to use a venv?** On Debian/Ubuntu the system Python is "externally
> managed", so a global install needs `pip install --break-system-packages ...`.
> A virtual environment avoids that flag entirely and is strongly recommended.

---

## 4. Install ICSForge

From the project root (the directory containing `pyproject.toml`):

```bash
# Core install
pip install -e .

# Recommended: include packet-replay support
pip install -e ".[replay]"

# Everything, including the test/lint toolchain
pip install -e ".[replay,dev]"
```

The `-e` (editable) install is recommended so the scenario library and templates
are served directly from the source tree.

This installs three commands:

| Command | Purpose |
|---|---|
| `icsforge` | Main CLI (generate, send, net-validate, selftest, scenarios, …) |
| `icsforge-web` | The web application (Sender / Receiver / Report UI) |
| `icsforge-receiver` | The standalone safe-sinkhole receiver |

---

## 5. Verify the installation

```bash
icsforge --version
# → ICSForge <version>   (e.g. 0.76.1)
```

Run the built-in self-test, which generates traffic and confirms the core
pipeline end-to-end:

```bash
icsforge selftest --live
```

You should see a series of `[PASS]` lines (receiver reachable, packets received,
correlation run-id). If those pass, the install is healthy.

Optionally, run the test suite (requires the `dev` extra):

```bash
pytest -q
```

---

## 6. Optional: system tools and live-traffic privileges

**Inspect generated PCAPs and run detections** (Linux example):

```bash
sudo apt-get install -y tshark suricata        # Debian/Ubuntu
# RHEL/Rocky: sudo dnf install wireshark-cli suricata
```

**Offline generation needs no privileges.** Live sending and live L2 capture send
raw frames and therefore need raw-socket access. Two options:

```bash
# Option A — run the specific command with sudo (simplest)
sudo $(which icsforge) send ...

# Option B — grant the Python interpreter the capability once (no sudo per-run)
sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f $(which python3))"
```

> Granting capabilities to the interpreter affects every script it runs; on a
> shared machine, prefer Option A or a dedicated venv interpreter.

---

## 7. First launch of the web app

The web UI is the primary interface. Launch it with:

```bash
icsforge-web --host 0.0.0.0 --port 8080
# equivalent: python -m icsforge.web --host 0.0.0.0 --port 8080
```

- Default host is `127.0.0.1`, default port is `8080`.
- Use `--host 0.0.0.0` only if you need to reach the UI from another machine on a
  trusted network; otherwise leave it on localhost.

Open `http://<host>:8080/` in a browser. On first run you will be redirected to a
**Setup** page to create an administrator account, then to **Login**. Credentials
are stored per-install in the project folder, so a brand-new install always starts
with a fresh setup step.

> **Dev/lab shortcut:** `icsforge-web --no-auth` disables authentication entirely.
> Use only on an isolated lab machine — never on anything reachable by others.

The receiver (the safe sinkhole that confirms what arrived) is launched separately
— see the **User Manual** for the full sender + receiver workflow.

---

## 8. Configuration & data locations

- **Per-install state** (credentials, callback token, web config) lives in the
  project folder under `out/` and is **not** shared between installs. Installing a
  new version starts fresh.
- **Global state** that should survive upgrades lives in `~/.icsforge/`.
- **Generated artifacts** (PCAPs, event logs) are written to the output directory
  you choose (default `out/`).

Useful environment variables:

| Variable | Effect |
|---|---|
| `ICSFORGE_NO_AUTH=1` | Disable web authentication (lab only) |
| `ICSFORGE_UI_MODE` | `sender` (default), `receiver`, or `report` — selects the UI mode |
| `ICSFORGE_SECRET_KEY` | Fix the Flask session key (otherwise persisted/auto-generated) |
| `ICSFORGE_SECURE_COOKIES=1` | Set the Secure flag on session cookies (use behind HTTPS) |

---

## 9. Upgrading

1. Stop the running web app and receiver.
2. Extract the new tarball (or `git pull`) into a fresh directory.
3. Re-create/activate the venv and `pip install -e ".[replay]"` again.
4. Run `icsforge --version` and `icsforge selftest --live` to confirm.

Because per-install credentials live in the project folder, a new directory means
a fresh Setup step on first web launch. Anything you want to persist across
upgrades should live in `~/.icsforge/`.

---

## 10. Uninstall

```bash
pip uninstall icsforge
# then remove the source directory and, if desired, ~/.icsforge/
```

---

## Troubleshooting

**`icsforge: command not found`** — the venv isn't active, or the install didn't
complete. Re-run `source .venv/bin/activate` and `pip install -e .`.

**`externally-managed-environment` error from pip** — you're installing into the
system Python without a venv. Either create a venv (§3) or add
`--break-system-packages` to the `pip install` command.

**Web UI starts but the browser can't connect** — check the host/port and any
local firewall. If you launched with the default `127.0.0.1`, the UI is only
reachable from the same machine; use `--host 0.0.0.0` for remote access on a
trusted network.

**Live send fails with a permission error** — raw sockets need privilege; see §6.
Offline generation (the default workflow) never needs this.

**Self-test fails** — run `icsforge selftest --live --log-level DEBUG` to see which
stage failed, and confirm no other process is using the receiver's port.
