# ICSForge — Current Phase Notes (Latest)

This is the **single** up-to-date phase document for the repository.

## What ICSForge is
ICSForge is a safe OT/ICS telemetry lab that can:
- run **ATT&CK for ICS** aligned scenarios (live traffic + optional PCAP artifact)
- generate **offline PCAPs** for replay/testing
- optionally run a **Receiver** to validate delivery across the network
- provide a web UI for Sender / Receiver roles, plus an ATT&CK matrix view

## Current highlights
- **Sender vs Receiver UI separation**
  - Sender web (`./icsforge.sh web`) shows Sender/SOC/Matrix/Tools
  - Receiver web (`./icsforge.sh receiver`) shows Receiver/Matrix/Tools
- **Realistic protocol defaults**
  - Uses standard ports (e.g., Modbus 502, DNP3 20000, S7comm 102, IEC104 2404, ENIP 44818, OPC UA 4840)
- **Scenario catalog**
  - 120+ scenarios with consistent IDs and technique prefixes
  - Technique variants supported (protocol alternatives where applicable)
- **PCAP artifact workflow**
  - Sender can optionally “also build offline PCAP” while doing live send
  - Tools can build offline PCAP bundles for replay
  - Sender UI includes a **Download PCAP** button after a run (when a PCAP was created)

## Known limitations (transparent)
- SOC Mode currently needs **your NSM/IDS exports** (e.g., Suricata EVE JSON, Zeek logs, vendor exports) to evaluate detection.
- Some ATT&CK for ICS techniques are **not network-runnable** by design (host/physical actions). Matrix marks these accordingly.

## Files of record
- `docs/INSTALL.md` — installation and prerequisites
- `docs/HOWTO.md` — usage, CLI/UI, receiver validation, PCAP flows
- `docs/LIVE_SOC_DEMO_FLOW.md` — suggested live demo walkthrough
