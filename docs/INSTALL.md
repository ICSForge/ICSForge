# INSTALLATION GUIDE (INSTALL.md)

This guide covers installation on Kali/Linux/macOS.

## Quick install (recommended)

```bash
chmod +x icsforge.sh bin/icsforge
./icsforge.sh install
```

ICSForge installs into a **local virtual environment** (`.venv`) to avoid system Python issues (e.g., Kali “externally-managed-environment”).

## System prerequisites

- Python 3.10+ (Kali ships newer; works)
- `python3-venv` (or equivalent) to create venv
- `tcpdump` (optional, if you want packet capture outside of generated PCAP artifacts)
- **sudo/root privileges** are recommended for:
  - live packet sending on real interfaces
  - binding to privileged ports (standard ICS ports)

### Kali note: “externally-managed-environment”
If pip complains about system-wide installation, **do not use system pip**.
Use:

```bash
./icsforge.sh install
```

It creates and uses `.venv` automatically.

## Docker (receiver appliance, optional)
A receiver container example is under `docker/`:
- `docker/Dockerfile.receiver`
- `docker/docker-compose.receiver.yml`

## Verify installation

```bash
./icsforge.sh selftest
```

## Next steps
- Read `docs/HOWTO.md` for web/cli usage
- Read `docs/PHASE.md` for the latest phase notes
