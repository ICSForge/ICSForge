# ICSForge — Features Guide

This guide covers the parts of ICSForge beyond the core Sender workflow and
detection content (which are in `USER_MANUAL.md`): the offline PCAP generator,
the ATT&CK Matrix view, Campaigns, the Receiver console, the Tools page, and the
artifacts ICSForge produces. It complements `CLI_REFERENCE.md` (exhaustive flag
reference) and `USER_MANUAL.md` (the primary web walkthrough).

---

## 1. The scenario library

Everything ICSForge does starts from its scenario library: 600+ scenarios plus
named multi-step attack chains, spanning 10 protocols (Modbus, DNP3, S7comm,
IEC-104, IEC-61850/GOOSE, PROFINET-DCP, OPC UA, EtherNet/IP, BACnet, MQTT) and
mapped to MITRE ATT&CK for ICS.

Each scenario carries a **confidence label** for its ATT&CK mapping:

- **HIGH** — the traffic is a faithful realization of the technique; trust it.
- **MEDIUM** — a reasonable representation; sanity-check against your environment.
- **LOW** — a hint/approximation; treat as indicative.

Browse the library from the CLI:

```bash
icsforge scenarios list --proto modbus
icsforge scenarios list --technique T0855
icsforge scenarios list --search "stop cpu"
```

Scenario names follow the pattern `T<id>__<short_label>__<protocol>` (e.g.
`T0855__unauth_command__modbus`). The scenario file format is documented in
`SCENARIO_SCHEMA.md`.

---

## 2. The offline PCAP generator

The offline generator is the **zero-risk** path: it builds a ground-truth event
log and a PCAP without putting anything on the network. Use it to rehearse a
scenario, feed an offline analyzer, or produce a capture for a detection-rule
test.

### From the web app

Two routes:

- **Sender page → ⬇ PCAP Only** — generates the capture for the selected scenario
  with the current run options (marker mode, stateful, test profile) but sends
  nothing.
- **Tools page → Offline Generate** — a dedicated panel: pick a scenario, set an
  output directory, optionally enable Build PCAP, and click **Generate**.

### From the CLI

```bash
icsforge generate --name T0855__unauth_command__modbus --dst-ip 10.20.30.40
```

### What it produces

Under your output directory (default `out/`):

- `events/<run_id>.jsonl` — the **ground-truth event log** (always written).
- `pcaps/<run_id>.pcap` — the **packet capture** (when a marker/packets exist).

The PCAP is built to **survive independent dissection** — open it in Wireshark and
the protocol fields decode correctly. The exact bytes depend on your options:

- **Marker mode** — covert (marker hidden in a protocol field, zero added bytes),
  explicit (literal `ICSF` tag), or stealth (no marker). See `USER_MANUAL.md` §4.2.
- **`--stateful`** — wraps each TCP step in a full handshake + teardown so the
  capture survives stream reassembly (otherwise the default is a single PSH/ACK
  segment per packet — lighter, ideal for pure content-rule testing).
- **Test profile** — `nsm` turns `--stateful` on by default; `firewall` keeps it
  unidirectional.

> **Live vs offline parity:** the live send path threads exactly the same marker
> modes and per-protocol sequence fields as the offline generator, so a live send
> puts byte-identical payloads on the wire (plus a real OS handshake). Whatever you
> verify in an offline PCAP holds for the live send.

---

## 3. The ATT&CK Matrix view

The **Matrix** page (`/matrix`) is the ATT&CK-for-ICS coverage view — a heatmap of
which techniques ICSForge can exercise, colour-coded by how many protocols cover
each technique.

What you can do there:

- **See coverage at a glance** — each tile is a technique; colour indicates protocol
  breadth (green = many protocols, down to grey = out of scope).
- **Inspect a technique** — click a tile to see its scenarios, the protocols that
  realize it, and whether it's *runnable* (network-observable traffic) or a
  *precursor* (a step that sets up an attack but isn't itself a distinct packet).
- **Send technique traffic directly** — from a technique you can launch a send
  (Destination IP, Source IP, interface, timeout, optional Build PCAP), the same
  gated live-send path as the Sender page.

The matrix is also exportable as a **MITRE ATT&CK Navigator layer**
(`docs/icsforge-coverage-layer.json`) — drag-and-drop it into the Navigator
(`mitre-attack.github.io/attack-navigator`) to overlay ICSForge coverage on the
official matrix. Regenerate it with `python3 scripts/generate_navigator_layer.py`.

---

## 4. Campaigns

A **campaign** is a curated bundle of scenarios run as one playbook — for example a
sector-specific set, or a multi-technique kill-chain. Use campaigns when you want
to exercise a coherent group of techniques in one go rather than firing scenarios
individually.

### From the web app

The **Campaigns** page (`/campaigns`) lets you pick an **Industry Profile** (or
"all sectors"), set the Destination IP, and run — with **live progress**, a
per-step **Steps OK** count, and an **Event Stream** as the campaign executes.

### From the CLI

```bash
icsforge campaign list                       # see available campaigns
icsforge campaign validate                   # check the campaign definitions
icsforge campaign run --id water_treatment \
  --dst-ip 10.20.30.40 --confirm-live-network
```

Named attack chains in the library (e.g. `CHAIN__industroyer_crashoverride__2016_grid`,
`CHAIN__triton__safety_system`, `CHAIN__stuxnet__siemens_plc`,
`CHAIN__water_treatment_tampering`, `CHAIN__industroyer2__power_grid`) string
multiple techniques into a realistic sequence; campaigns are the way to run those
end to end. Confirmed campaign IDs include `full_ics_kill_chain`, `stuxnet_ttps`,
`safety_system_attack`, `industroyer2`, and `water_treatment` — list them with
`icsforge campaign list`.

---

## 5. The Receiver console

The Receiver is the **safe sinkhole** — it witnesses arriving traffic and reports
it back, and it is *never* a simulated device (it sends no protocol responses), so
it is safe to target. Run it at the destination of your test.

```bash
icsforge-receiver --web --web-host 0.0.0.0 --web-port 9090
```

The Receiver web console (`/receiver`, default port **9090**) shows:

- **What arrived** — receipts per run, with the attributed technique/scenario and
  how it was attributed (covert marker, explicit tag, or expectation registry).
- **Test-profile framing** — receipts carry the test profile and expected technique
  so the Report can frame them correctly.

**Attribution paths** (how the receiver knows what it saw):

1. **Explicit marker** — the literal `ICSF` tag is in the payload.
2. **Covert marker** — the marker value is read from the protocol field it hides in.
3. **Expectation registry** — for stealth runs (no marker) or markerless protocols
   like IEC-104, the sender pre-announces an expectation and the receiver attributes
   matching-protocol traffic to it.

**Callback:** the receiver can POST a live receipt back to the sender
(`--callback-url`, with `--callback-token` for auth). This travels over HTTP on a
path **separate** from the ICS traffic under test — run it over your management
network. If that path is blocked, the receiver still records receipts locally.

---

## 6. The Tools page

The **Tools** page (`/tools`) collects operational utilities:

- **Health** — environment/health check (interfaces, output dir, dependencies).
- **Interfaces** — list and refresh the network interfaces available for sending.
- **Offline Generate** — the offline PCAP generator panel (see §2).
- **PCAP Replay** — upload a PCAP and replay it to a destination IP.
- **Alerts Ingest** — feed your sensor's alerts (Suricata EVE JSON, or Generic
  pass-through) into the witnessed-vs-expected report to complete the NSM
  detection-gap diff. The path must be **relative to the project root** (e.g.
  `out/alerts/suricata_eve.json`); absolute paths are rejected for safety.
- **Coverage Heatmap** — a quick coverage visualization.

---

## 7. Artifacts & output formats

ICSForge writes everything under your chosen output directory (default `out/`).

### Ground-truth events JSONL

One JSON object per line. Key fields:

- `@timestamp` — ISO-8601 time.
- `icsforge.synthetic: true` — always present; marks this as test traffic.
- `icsforge.marker` — the correlation marker, or `null` in stealth mode.
- `mitre.ics.technique` — the ATT&CK technique ID.
- `run_id` — correlates events ↔ receipts ↔ alerts.

This is the **ground truth** for validation: it records exactly what ICSForge
intended to send, independent of what crossed the network.

### PCAP

Standard libpcap format, openable in Wireshark/tshark. Protocol fields decode
correctly under independent dissection. Sequence fields and markers reflect the
chosen mode (see §2).

### Detection rules

`icsforge detections export` produces `icsforge_lab.rules`,
`icsforge_heuristic.rules`, `icsforge_semantic.rules`, and per-scenario Sigma YAML.
See `USER_MANUAL.md` §7.

### Validation report

`icsforge net-validate` (or the Report page) correlates events, receipts, and
alerts into a per-run report framed by test profile. See `USER_MANUAL.md` §8.

---

## 8. Configuration & state locations

- **Per-install state** (credentials, callback token, web config) → the project
  folder under `out/`; not shared between installs.
- **Global state** that survives upgrades → `~/.icsforge/`.
- **Generated artifacts** → your `--outdir` (default `out/`).

Relevant environment variables (`ICSFORGE_NO_AUTH`, `ICSFORGE_UI_MODE`,
`ICSFORGE_SECRET_KEY`, `ICSFORGE_SECURE_COOKIES`) are documented in
`INSTALLATION.md` §8.

---

## 9. Where to go next

- **`USER_MANUAL.md`** — the primary web-app walkthrough (Sender, run options,
  workflows, detection content, reviewing results).
- **`CLI_REFERENCE.md`** — every command and flag.
- **`INSTALLATION.md`** — traditional (non-Docker) install.
- **`SCENARIO_SCHEMA.md`** — the scenario file format, if you want to author your own.
- **`SIEM_INTEGRATION.md`** — wiring alerts into a SIEM.
