
[//]: [![CI](https://github.com/ICSforge/ICSforge/actions/workflows/ci.yml/badge.svg)](https://github.com/ICSforge/ICSforge/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](https://github.com/ICSforge/ICSforge/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-green.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Version](https://img.shields.io/badge/version-0.57.5-orange.svg)](https://github.com/ICSforge/ICSforge/releases)

**ICSForge™** is an open-source **OT/ICS security coverage validation platform** designed to help defenders, SOC teams, and OT security engineers validate detection, visibility, and readiness against real-world industrial attack techniques.

ICSForge focuses on what can actually be observed on the network and generates realistic OT traffic and PCAPs in **10 industrial protocols (Modbus/TCP, DNP3, S7comm, IEC-104, OPC UA, EtherNet/IP, BACnet/IP, MQTT, GOOSE, PROFINET DCP)** which are aligned with **72 out of 83 unique techniques in MITRE ATT&CK for ICS (v18)** - without exploiting real systems or causing unsafe process impact - to help asset owners and defenders assessing the quality of existing security countermeasures such as firewalls, OT NSM sensors and ACLs and identifying hidden gaps.

ICSForge is developed with a **safe-by-design** approach, operating within a **Sender-Receiver architecture** and interacting only with the designated sender and receiver, without touching other OT devices.

> Most ICS security tools promise coverage - ICSForge lets you **prove it**.
---

## Key Numbers (v0.57.5)

| Metric | Value |
|---|---|
| **Protocols** | 10 industrial protocols (Modbus/TCP, DNP3, S7comm, IEC-104, OPC UA, EtherNet/IP, BACnet/IP, MQTT, GOOSE, PROFINET DCP)|
| **Runnable Scenarios** | 434 standalone + 11 named attack chains |
| **ATT&CK for ICS Techniques Implemented** | 69 unique technique IDs in scenario steps |
| **ATT&CK for ICS Matrix** | 83 unique technique IDs (94 total entries — 11 appear in multiple tactics) |
| **ATT&CK for ICS Matrix Coverage** | 83% (69 out of 83 technique) |
| **Techniques at Full Coverage** | 18 techniques covered across all 10 protocols |
| **Detection Rules** | Auto-generated Suricata + Sigma rules per scenario |

---

## Architecture

```
┌───────────────────────┐                  ┌──────────────────────┐
│   ICSForge Sender     │  TCP/ UDP / L2   │  ICSForge Receiver   │
│                       │ ─>─>─>─>─>─>─>─> │                      │
│ • Scenario engine     │                  │ • Traffic sink       │
│ • 10 protocol builders│                  │ • Marker correlation │
│ • PCAP generation     │                  │ • Receipt logging    │
│ • Campaign playbooks  │   <── callback   │ • Coverage matrix    │
│ • Web UI (:8080)      │                  │ • Web UI (:9090)     │
└───────────────────────┘                  └──────────────────────┘
           │                                          │
           ▼                                          ▼
     ┌───────────┐                            ┌──────────────┐
     │  ATT&CK   │                            │ Correlation  │
     │  Matrix   │                            │    & Gap     │
     │  Overlay  │                            │  Visibility  │
     └───────────┘                            └──────────────┘
```

**How correlation works:** Every generated packet embeds an on-wire correlation marker (`ICSFORGE_SYNTH|run_id|technique|step`). When the receiver detects it, it posts a receipt back to the sender. If the receipt arrives, the packet traversed the wire. If your IDS fires on it, your detection works. Run both to prove **Executed → Delivered → Detected**.

**Stealth mode** (`--no-marker` / toggle in UI): generates bit-for-bit realistic traffic with no ICSForge tags in payloads. Confirmation switches to TCP ACK delivery. Use for IDS/NGFW validation where the marker would betray the test.

---

## Quick Start

### Install

```bash
git clone https://github.com/ICSforge/ICSforge.git
cd ICSforge
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .
chmod +x icsforge.sh
```

### Web UI

```bash
sudo ./icsforge.sh web        				# Sender dashboard on :8080
sudo ./icsforge.sh receiver   				# Receiver dashboard on :9090
sudo ./icsforge.sh receiver --l2-iface eth0 # Receiver with Profinet Listener
```

### Or with Docker

```bash
docker compose up
# Sender UI:   http://localhost:8080
# Receiver UI: http://localhost:9090
```

### Authentication

On first launch, ICSForge prompts you to create an admin account. All subsequent access requires login.

```bash
# Disable auth for local/lab development only
ICSFORGE_NO_AUTH=1 python -m icsforge.web
```

Credentials are stored in `~/.icsforge/credentials.json` (SHA-256 + salt, file mode 0600).

**Always-public endpoints** (no auth required): `/api/health` (monitoring), `/api/receiver/callback` (receiver→sender receipts), `/api/config/set_callback` (sender→receiver registration). When `callback_token` is configured, the callback endpoint also requires `X-ICSForge-Callback-Token`.

## Network Configuration: Receiver IP vs Destination IP

ICSForge uses two related but distinct IP concepts in the sender UI:

**Receiver IP (Network Settings panel)** — the IP of the machine running `icsforge receiver`. Setting this via Network Settings saves the address to persistent config and attempts to register a callback URL with the receiver so it can push receipts back to the sender automatically.

**Destination IP (Configuration panel)** — the IP written into generated packet headers as the target address. Auto-populated from Receiver IP when you click Save & Connect, but can be overridden independently. For example: if testing against a real PLC you may want `dst_ip` = the PLC's IP while the receiver runs on a different monitoring host.

**Sync modes:**

| Mode | How it works | When to use |
|---|---|---|
| **Callback (default)** | Receiver POSTs receipt to sender when marker detected | Sender has a reachable callback address |
| **Pull mode** | Sender polls receiver for receipts | Sender is behind NAT or has no public address |
| **SSE** | Browser receives real-time events via Server-Sent Events | Campaigns page — live step-by-step progress |

```bash
# Set receiver IP via CLI
icsforge-receiver --callback-url http://sender-ip:8080/api/receiver/callback

# Or via API
curl -X POST http://localhost:8080/api/config/network \
  -H 'Content-Type: application/json' \
  -d '{"receiver_ip": "192.168.1.50", "receiver_port": 9090}'
```

ICSForge can be run from **command line interface** as well;

### CLI — generate a PCAP offline

```bash
icsforge generate --name T0855__unauth_command__modbus --outdir out/
# → out/pcaps/T0855__unauth_command__<date>__<word>.pcap
#   out/events/T0855__unauth_command__<date>__<word>.jsonl
```

### CLI — send live traffic

```bash
# Terminal 1: start receiver
python -m icsforge.receiver --no-web --bind 127.0.0.1

# Terminal 2: send traffic
icsforge send --name T0855__unauth_command__modbus \
  --dst-ip 127.0.0.1 --confirm-live-network

# With stealth mode (no correlation markers in payloads)
icsforge send --name T0855__unauth_command__modbus \
  --dst-ip 127.0.0.1 --confirm-live-network --no-marker
```

---
## Protocol Coverage

| Protocol | Port | Styles | Techniques (of 69) |
|---|---|---|---|
| S7comm (Siemens) | TCP/102 | 36 | 54/69 |
| EtherNet/IP (Allen-Bradley) | TCP/44818 | 23 | 52/69 |
| DNP3 | TCP/20000 | 22 | 48/69 |
| Modbus/TCP | TCP/502 | 29 | 43/69 |
| OPC UA | TCP/4840 | 30 | 42/69 |
| IEC-104 | TCP/2404 | 24 | 41/69 |
| BACnet/IP | UDP/47808 | 16 | 38/69 |
| MQTT | TCP/1883 | 16 | 33/69 |
| IEC 61850 GOOSE | L2/EtherType 0x88B8 | 5 | 27/69 |
| PROFINET DCP | L2/EtherType 0x8892 | 8 | 25/69 |

**IEC 61850 GOOSE** and **PROFINET DCP** are Layer 2 protocols — they require a raw socket interface (`--l2-iface eth0`) for live sends. PCAP and offline generation work without a network interface.

### Techniques at Full Coverage (10/10 protocols)

T0813, T0826, T0829, T0831, T0832, T0836, T0838, T0840, T0846, T0848, T0855, T0856, T0858, T0877, T0878, T0882, T0888, T0889 — **18 techniques** fully covered across all 10 protocols. 

---

## Scenarios

Scenarios are defined in `icsforge/scenarios/scenarios.yml`.

**Naming convention:** `T08XX__<description>__<protocol>[_variant]`

**Types:**

| Type | Count | Description |
|---|---|---|
| Standalone scenarios | 423 | Single-technique, single-protocol runs |
| Named attack chains | 11 | Multi-step sequences modelling real campaigns |

**Named attack chains** include:
- **Industroyer2** — Ukraine 2022 power grid attack (IEC-104 + S7comm)
- **Triton / TRISIS** — Safety system targeting (SIS) modelling the 2017 Saudi petrochemical incident
- **Stuxnet-style** — Siemens PLC programme manipulation
- **Water Treatment** — Oldsmar-style setpoint tampering (Modbus + IEC-104)
- **OPC UA Espionage** — Silent data exfiltration via OPC UA sessions
- **EtherNet/IP Manufacturing** — Allen-Bradley CIP manipulation
- **AitM + Sensor Spoof** — Adversary-in-the-Middle combined with DNP3 measurement injection
- **Firmware Persistence** — S7comm firmware implant and persistence
- **Full ICS Kill Chain** — Recon to impact (S7comm + Modbus)
- **Loss of Availability** — Multi-protocol concurrent DoS (DNP3 + IEC-104 + Modbus)
- **Default Creds → Impact** — Lateral pivot to programme modification

---

## What Techniques Are Covered

ICSForge implements 69 of 83 ATT&CK for ICS techniques at the network-observable level. The remaining 14 are correctly classified as host-only or require physical access — they are documented in `icsforge/data/technique_support.json` with explicit rationale.

**ATT&CK matrix counts explained:**
- 83 unique technique IDs in the matrix
- 94 total matrix entries — 11 techniques appear under multiple tactics (e.g. T0856 Spoof Reporting Message appears under both Evasion and Impair Process Control, which is correct ATT&CK for ICS design)
- The `/api/matrix_status` response includes a `matrix_info` block that makes this distinction explicit

---

## Web UI Pages

| Page | URL | Purpose |
|---|---|---|
| **Home** | `/` | KPIs, top techniques by protocol coverage, scenario browser |
| **Sender** | `/sender` | Launch scenarios and chains; configure network; view live receipts |
| **ATT&CK Matrix** | `/matrix` | Interactive coverage overlay; click any runnable tile to fire traffic |
| **Campaigns** | `/campaigns` | Multi-step campaign playbooks and named attack chains with SSE progress |
| **Report** | `/report` | Coverage report generation and download; correlation gap analysis |
| **Tools** | `/tools` | Offline PCAP generation, alerts ingestion, detection rule download |

---

## Key API Endpoints

### Run lifecycle

| Endpoint | Method | Description |
|---|---|---|
| `/api/send` | POST | Send a named scenario or chain live |
| `/api/generate_offline` | POST | Generate events + PCAP offline (no live traffic) |
| `/api/runs` | GET | List recent runs from SQLite registry |
| `/api/run` | GET | Receipt count + techniques for a run (`?run_id=`) |
| `/api/run_detail` | GET | Full receipt histogram for a run (`?run_id=`) |
| `/api/run_full` | GET | Complete run detail: artifacts, receipts, techniques (`?run_id=`) |

All three run-detail endpoints (`/api/run`, `/api/run_detail`, `/api/run_full`) merge both receipt sources — the JSONL file written by the standalone receiver process and the in-memory callback receipts — using a stable content-based deduplication key.

### Scenarios and matrix

| Endpoint | Method | Description |
|---|---|---|
| `/api/scenarios` | GET | All scenario names |
| `/api/scenarios_grouped` | GET | Scenarios grouped by ATT&CK tactic (add `?include_steps=0` for lean payload) |
| `/api/technique/variants` | GET | All runnable variants for a technique (`?technique=T0855`) |
| `/api/matrix_status` | GET | Per-technique coverage status + `matrix_info` counts |

### Configuration

| Endpoint | Method | Description |
|---|---|---|
| `/api/config/network` | GET/POST | Sender/receiver IPs, ports, callback URL, pull mode |
| `/api/config/receiver_ip` | POST | Set receiver IP and attempt callback registration |
| `/api/receiver/live` | GET | In-memory live receipts (last 500) |
| `/api/receiver/callback` | POST | Receipt ingest from receiver (used by receiver process) |

### Detection and reporting

| Endpoint | Method | Description |
|---|---|---|
| `/api/detections/download` | GET | Download Suricata + Sigma rules |
| `/api/report/generate` | POST | Generate coverage report for a run |
| `/api/report/download` | POST | Download generated report |
| `/api/alerts/ingest` | POST | Import Suricata EVE JSONL for correlation (`{"path": "...", "profile": "suricata_eve"}`) |

Note: `/api/alerts/ingest` requires the `path` to be inside the repo directory and returns `400` with a row-specific error message for malformed `alert` fields.

---

## Detection Content

ICSForge auto-generates detection rules directly from its scenario catalog:

```bash
# Via Web UI: Tools → Generate Detection Rules
# Preview:  GET  /api/detections/preview
# Download: GET  /api/detections/download
```

Output formats: **Suricata rules** (`.rules`) matching ICSForge correlation markers, and **Sigma rules** (`.yml`) for SIEM integration.

---

## Stealth Mode

Standard mode embeds `ICSFORGE_SYNTH|run_id|technique|step` bytes in every packet payload for precise end-to-end correlation. Stealth mode removes all markers:

```bash
# CLI
icsforge send --name T0855__unauth_command__modbus \
  --dst-ip 192.168.1.50 --confirm-live-network --no-marker

# Web UI: toggle "Stealth" before clicking Send
```

In stealth mode:
- **PCAP:** contains zero ICSForge-identifying bytes — bit-for-bit identical to real device traffic
- **Events JSONL:** `icsforge.marker` is `null`; `icsforge.synthetic: true` is preserved (accurate ground-truth metadata)
- **Delivery confirmation:** switches from marker detection to TCP ACK

Use stealth mode for IDS/NGFW validation exercises where the marker would trivially identify the test traffic.

---

## Development

```bash
pip install -e ".[dev]"
pytest                          # run tests
pytest -q tests/test_e2e_pipeline.py -p no:cov  # E2E pipeline tests
ruff check icsforge/ tests/     # lint (should be clean)
python scripts/smoke_test.py    # 35/35 quick sanity check
```

### Testing

```
tests/
├── test_web_api.py         — API endpoint tests (19 tests)
├── test_auth.py            — Auth flow and rate limiting
├── test_sse_campaigns.py   — Campaign SSE streaming
└── test_e2e_pipeline.py    — End-to-end pipeline integration
```

---

## What ICSForge Is Not

- Not an exploitation framework — it does not exploit vulnerabilities
- Not a PLC hacking tool — it does not modify real device state
- Not a malware platform — it generates synthetic traffic only
- Not a process-impact simulator — safe-by-design for OT environments

ICSForge is **defender-first**, **safe by design** and **honest about what each technique requires**, and explicit about which techniques cannot be simulated over the network.

---

## Protocol Notes

**Layer 2 protocols (IEC 61850 GOOSE, PROFINET DCP)** require a raw network interface for live traffic:
```bash
python -m icsforge.receiver --l2-iface eth0  # receiver side
icsforge send --name T0855__unauth_command__iec61850 \
  --dst-ip ff:ff:ff:ff:ff:ff --iface eth0 --confirm-live-network
```
Offline PCAP generation (`icsforge generate`) works without an interface.

**MQTT** requires a broker at the destination IP (default port 1883). ICSForge generates all MQTT traffic types including connect, publish, subscribe, will messages, and disconnect.

**OPC UA** scenarios run against a standard OPC UA server endpoint on TCP/4840.

---

## Screenshots

### Authentication Setup
![Authentication Setup](screenshots/auth.png)

### Sender Landing Page - Dark Theme
![Sender Landing Dark](screenshots/sender_home_dark.png)

### Sender Landing Page - Light Theme
![Sender Landing Light](screenshots/sender_home.png)

### Sender Dashboard
![Sender Dashboard](screenshots/sender.png)

### Campaigns Dashboard
![Campaigns Dashboard](screenshots/campaigns.png)

### ATT&CK for ICS Matrix
![ATT&CK Matrix](screenshots/attack_matrix.png)

### Coverage Report
![Coverage Report](screenshots/coverage_report.png)

### Tools for Offline Generation and PCAP Replay
![Tools](screenshots/tools.png)

### Receiver - Live Traffic View
![Receiver Live View](screenshots/receiver.png)

### Receiver - ATT&CK for ICS Matrix - Light Theme
![Receiver ATT&CK for ICS Matrix](screenshots/attack_matrix_receiver.png)

### Receiver - ATT&CK for ICS Matrix - Dark Theme
![Receiver ATT&CK for ICS Matrix Dark](screenshots/attack_matrix_receiver_dark.png)

---

## License

GPLv3 - see [LICENSE](LICENSE)

---

*ICSForge™ • OT/ICS Cybersecurity Coverage Validation Platform • [icsforge.nl](https://www.icsforge.nl)*
