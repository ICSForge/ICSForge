# ICSForge Installation Guide

## Quick Install

```bash
git clone https://github.com/ICSforge/ICSforge.git
cd ICSforge
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .
chmod +x icsforge.sh
```

Installs into a local `.venv` to avoid system Python conflicts (Kali, Ubuntu, etc.).

## System Requirements

- Python 3.10+
- `python3-venv` (or equivalent)
- Linux or macOS
- `sudo` / `root` for live traffic sends and L2 raw sockets

## Run

```bash
# Sender dashboard (port 8080)
sudo ./icsforge.sh web

# Receiver (port 9090)
sudo ./icsforge.sh receiver

# L2 capture for PROFINET DCP + IEC 61850 GOOSE
sudo ./icsforge.sh receiver --l2-iface eth0
```

## Docker

```bash
docker compose up
# Sender UI:   http://localhost:8080
# Receiver UI: http://localhost:9090
```

## Auth

First launch prompts for an admin account. Credentials stored with scrypt KDF.

```bash
# Disable auth for local lab development only
ICSFORGE_NO_AUTH=1 python -m icsforge.web
```

## Non-RFC1918 Internal Networks

If your OT network uses public IP ranges internally (e.g. `130.75.0.0/24`), set the `ICSFORGE_ALLOWED_NETS` environment variable:

```bash
export ICSFORGE_ALLOWED_NETS="130.75.0.0/24"
sudo ./icsforge.sh web
```

Multiple ranges are comma-separated:

```bash
export ICSFORGE_ALLOWED_NETS="130.75.0.0/24,195.10.20.0/24"
```

RFC 1918 ranges (`10.x`, `172.16-31.x`, `192.168.x`), loopback, and link-local are always allowed without any configuration. Only non-standard ranges need this setting.

## Layer-2 Requirements (PROFINET DCP, IEC 61850 GOOSE)

Both protocols require raw sockets — Linux only, root or `CAP_NET_RAW`:

```bash
# Sender: set Interface (L2) field in the UI, or pass via CLI
# Receiver: must be started with --l2-iface
sudo ./icsforge.sh receiver --l2-iface eth0
```

Sender and receiver must be on the same Ethernet segment (L2 multicast does not cross routers).
