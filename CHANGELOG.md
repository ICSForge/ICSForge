# ICSForge Changelog

## v0.21 (2025 — Black Hat / DEF CON build)

### Protocol Engine — full rewrite of all 7 protocol builders

**Modbus/TCP** (`modbus.py`): 9 → 18 styles
- Added FC01 read_coils, FC02 read_discrete, FC04 read_input
- Added FC05 write_single_coil, FC06 write_single_register, FC15 write_multiple_coils
- Added FC22 mask_write_register (bit-level parameter manipulation — T0836)
- Added FC23 read_write_multiple (simultaneous read+write — T0832)
- Added FC07 read_exception_status, FC08 diagnostic, FC11 get_comm_event_counter (T0882)
- Added safety_write (FC16 to register 60000+ zone — T0829/T0876 Triton pattern)
- Added brute_force_write (sequential address sweep — T0806)
- Added coil_sweep (address sweep — T0841)
- Added dos_read (FC03 max 125 registers — T0814)
- Added exception_probe (illegal address fingerprinting — T0820)
- Proper MBAP header construction throughout

**DNP3** (`dnp3.py`): 5 → 16 styles
- Full link+transport+application layer framing with real CRC placeholders
- Real CROB (Control Relay Output Block) objects in select/operate/direct_operate
- Added cold_restart (FC0D), warm_restart (FC0E) — T0816
- Added enable_unsolicited (FC14), disable_unsolicited (FC15) — T0815/T0856
- Added assign_class (FC16) — T0841
- Added delay_measure (FC17) — T0841 timing probe
- Added direct_operate_nr (FC06) — no-ack evasion variant
- Added authenticate_req (FC32) — T0858
- Added read_class1 (Class 1 event data), read_analog, read_counter

**S7comm** (`s7comm.py`): 3 → 18 styles
- Proper TPKT (RFC1006) + COTP + S7comm header structure
- Added cpu_stop (FC29 — T0813/T0881), cpu_start_warm, cpu_start_cold (FC28 — T0816)
- Added download_req, download_block, download_end (FC1A/1B/1C — T0821/T0843)
- Added upload_req, upload_block, upload_end (FC1D/1E/1F — T0845)
- Added szl_read (ROSCTR_USERDATA SZL — T0882/T0888 System Status List)
- Added plc_control (FC28 — T0875)
- Added read_db, write_db (Data Block access — T0882/T0836)
- Added read_outputs, write_outputs (AREA_OUTPUTS — T0801/T0876)
- Area codes: DB (0x84), Inputs (0x81), Outputs (0x82), Flags (0x83)

**IEC-60870-5-104** (`iec104.py`): 5 → 18 styles
- U-format APCI: startdt, stopdt, testfr (distinct from I-format data frames)
- Added meas_mv (M_ME_NC_1 short float — T0801)
- Added setpoint_scale (C_SE_NB_1 — T0836), regulating_step (C_RC_NA_1 — T0831)
- Added interrogation (C_IC_NA_1 — T0841/T0882)
- Added counter_interr (C_CI_NA_1 — T0882)
- Added clock_sync (C_CS_NA_1 with 7-byte timestamp — T0849 time injection)
- Added reset_process (C_RP_NA_1 — T0816)
- Added test_command (C_TS_NA_1 — T0841)
- Added param_mv (P_ME_NA_1 — T0836), param_activ (P_AC_NA_1 — T0878)
- Added inhibit_alarm (P_AC_NA_1 with deactivation COT — T0878)
- Proper I-format APCI with send/recv sequence numbers

**OPC UA** (`opcua.py`): 3 → 16 styles
- Real service NodeIds used throughout (GetEndpoints=428, Browse=527, Read=631, Write=673, etc.)
- Added get_endpoints, find_servers (T0888 discovery)
- Added open_session (OPN with CreateSessionRequest — T0822)
- Added activate_session (ActivateSession with identity token — T0859)
- Added close_session (CLO message — T0826)
- Added browse, browse_next, translate_paths (BrowseRequest — T0861)
- Added read_value (ReadRequest — T0801), read_history (HistoryReadRequest — T0879)
- Added write_value (WriteRequest — T0831/T0836/T0855)
- Added call_method (CallRequest — T0871)
- Added create_sub (CreateSubscriptionRequest — T0802), publish (T0801)
- Added delete_sub (DeleteSubscriptionsRequest — T0815)

**EtherNet/IP / CIP** (`enip.py`): 2 → 15 styles
- Real CIP path encoding (EPATH) for class/instance/attribute addressing
- Added list_services (T0841), list_interfaces (T0840)
- Added get_identity (CIP GetAttributeAll on Identity object — T0888)
- Added get_device_type (CIP GetAttributeSingle attr 2 — T0868)
- Added reset_device (CIP Reset service — T0816)
- Added stop_device (CIP Stop — T0813/T0881), start_device (CIP Start — T0875)
- Added read_tag (FC 0x4C with EPATH tag name — T0801/T0882)
- Added write_tag (FC 0x4D with REAL value — T0831/T0836/T0855)
- Added get_param, set_param (Parameter object class 0x0F — T0836)
- Added send_rr_data (generic unconnected — T0869)
- Unregister_session for T0826

**PROFINET DCP** (`profinet_dcp.py`): 1 → 8 styles
- Real DCP PDU structure with block encoding
- Added identify_unicast (targeted device query — T0888)
- Added get_name (DCP Get NameOfStation — T0882)
- Added get_ip (DCP Get IP parameter — T0882)
- Added set_name (DCP Set NameOfStation — T0849 device masquerade)
- Added set_ip (DCP Set IP — T0849)
- Added hello (DCP Hello PDU — T0840 passive enumeration)
- Added factory_reset (DCP Set Control — T0816)

### Scenarios — complete rebuild

- **67 scenarios** across 7 protocols and **36 ATT&CK for ICS techniques**
- All scenarios are wire-level distinct (no copy-paste traffic patterns)
- 6 named attack chains based on real incidents:
  - `industroyer2` — Ukraine 2022 power grid (IEC-104 + S7comm)
  - `triton` — Triton/TRISIS safety system attack
  - `stuxnet` — Stuxnet-style Siemens PLC attack
  - `water_treatment` — Oldsmar-style water treatment attack
  - `opcua_espionage` — OPC UA silent data exfiltration
  - `enip_manufacturing` — Allen-Bradley manufacturing line attack
- Techniques newly covered: T0806, T0813, T0816, T0820, T0821, T0822, T0827, T0829,
  T0836, T0841, T0842, T0843, T0845, T0846, T0849, T0859, T0861, T0868, T0871,
  T0875, T0876, T0878, T0879, T0881, T0882, T0883
- 67 short aliases for CLI/UI use

### Fixes
- `sender.py`: profinet_dcp now passes `style` parameter correctly

## v0.2 (initial)
- Initial release with 7 protocols, 120+ scenarios (largely repetitive)

## v0.22 (2025 — Black Hat / DEF CON build — Sender UX + Bug Fixes)

### Bug Fixes (silent, affected all live sends)
- **`sender.py`**: Live TCP sends were ignoring the scenario `style` field — all protocols always used their default style. Fixed: style is now read per-step and passed through to every protocol builder.
- **`engine.py`**: PCAP builder for `profinet_dcp` also ignored `style`. Fixed.

### New API Endpoints
- **`/api/preview_payload`** — Returns an annotated hex dump of the actual PDU bytes built by the real protocol implementation for any scenario step. Accepts `name` and `step` (0-indexed). Supports step navigation through multi-step scenarios. Returns proto, style, port, byte count, and coloured hex+ASCII dump.
- **`/api/scenarios_grouped`** — Returns all 67 scenarios grouped by ATT&CK tactic (11 groups), with per-scenario metadata: techniques, protocols, step count, title. Powers the new filterable scenario list.
- **`/api/preview`** (improved) — Now returns `title`, `description`, `is_chain`, and per-step `style` and `interval` fields.

### Sender UI Rewrite (`sender.html`)
- **Attack Chain Quick-Launch** — 6 named chains (Industroyer2, Triton, Stuxnet, Water Treatment, OPC UA Espionage, EtherNet/IP MFG) displayed as one-click cards at the top of the page with technique tags and protocol list.
- **Searchable grouped scenario list** — 67 scenarios now displayed in an 11-group tactic-grouped list with live filter. Protocol presence shown as colour-coded dots per scenario row.
- **Hex dump panel** — Real-time hex dump of actual PDU bytes for every scenario step, with step navigation (Prev/Next). Colour-coded: addresses in purple, bytes in cyan, ASCII in green. Updates instantly on scenario selection.
- **Animated step plan** — Steps rendered as a plan view (pending → sending → ok/err) with protocol colour badges and ATT&CK technique IDs. Animates in sequence during a run.
- **Scenario description** — Shows the full scenario description text on selection.
- **PCAP-only mode** — "Generate PCAP Only" button for offline generation without live send.

## v0.23 (2025 — Black Hat / DEF CON build — UI Redesign + v0.23 Features)

### Design System Rewrite (main.css + base.html + main.js)
- **Fonts**: JetBrains Mono (code/hex) + Barlow Condensed (headings) via Google Fonts. Distinctive, technical, readable.
- **Dark-first**: Dark theme is now the default (was light). localStorage persists preference.
- **Colour system**: Amber (#f59e0b) primary accent — matches industrial HMI palette. Cyan (#22d3ee) for live/active state. Protocol colours unified throughout.
- **Topbar**: Grid texture background, amber bottom-line accent, proper tab navigation (not button row), version chip always visible.
- **Cards**: Tighter border radius, amber top-border on key cards, refined shadows.
- **ATT&CK Matrix tiles**: Runnable tiles have amber left border + amber glow on hover. Precursor tiles have cyan left border. Compact badge (RUN/PRE) instead of verbose text.
- **Buttons**: Amber primary, cyan variant, ghost secondary. Hover lifts with amber border.
- **Badges, KPIs, tables**: All updated to new colour system.

### v0.23 Feature: Live Receiver Feed (Sender page)
- New "Live Receiver Feed" panel on the Sender page, always-on.
- Polls `/api/receiver/overview` every 2 seconds.
- Shows: total packets received, run count, technique count, protocol count.
- Top techniques shown as amber badges. Packet counter flashes green on new arrivals.
- Live pulse dot indicates receiver connectivity.
- Closes the send→receive loop visually without a second browser tab.

### v0.23 Feature: Matrix Auto-Overlay
- After `sendTech()` resolves with a `run_id`, the fired technique tile immediately highlights green (executed).
- Then fetches `/api/matrix_status?run_id=…` to apply full overlay (executed/detected/gap) in one step.
- Automatically populates the run selector with the latest run.
- No more manual "Load Runs → Apply Overlay" sequence.

### v0.23 Feature: Run History Sidebar (Sender page)
- "Recent Runs" panel shows last 8 runs from `/api/runs`.
- Refreshes after every run automatically.
- Click a row: shows run_id in toast + copies to clipboard.
- Manual refresh button.

### Other improvements
- `index.html` redesigned: hero layout, numbered quick-start steps, amber KPI strip.
- `receiver.html` redesigned: cyan KPI strip, protocol colour badges in receipt table, live dot indicator.
- `matrix.html`: Compact tech tiles (fit more per column), amber/cyan colour coding per support level.

## v0.24 (2025 — Maximum ATT&CK Coverage Release)

### Scenario coverage expansion: 36 → 72 techniques
- **+73 new scenarios** covering 36 previously-missing techniques
- **72 unique techniques** now covered across 140 scenarios (was 36 / 67)
- **62 runnable** (full network simulation), **7 precursor** (network-observable approximations)
- **15 host-only techniques** correctly documented in technique_support.json (no false claims)

### New techniques covered (28 fully runnable):
T0800, T0803, T0804, T0809, T0811, T0812, T0819, T0826, T0828, T0830,
T0835, T0837, T0838, T0839, T0856, T0857, T0858, T0866, T0867, T0869,
T0877, T0880, T0884, T0885, T0886, T0889, T0891, T0892, T0895

### New techniques covered (7 precursor/approximation):
T0805, T0807, T0834, T0853, T0864, T0872, T0890

### New attack chains (+5):
- CHAIN__firmware_persistence__s7comm — T0889+T0839+T0857+T0858 full firmware persistence
- CHAIN__aitm_sensor_spoof__opcua_dnp3 — T0830+T0856+T0832 AitM + sensor spoofing
- CHAIN__loss_of_availability__multi — T0826+T0814+T0813 multi-protocol concurrent DoS
- CHAIN__default_creds_to_ics_impact__multi — T0812→T0886→T0889→T0831 full kill chain
- CHAIN__full_ics_kill_chain__s7comm — 10-step complete recon-to-impact chain

### Protocol mapping for new scenarios:
- **Modbus**: T0800, T0803, T0804, T0805, T0809, T0812, T0819, T0826, T0828, T0835, T0837, T0838, T0869, T0877, T0880, T0885, T0892
- **DNP3**: T0803, T0804, T0807, T0830, T0853, T0856, T0858, T0872
- **S7comm**: T0800, T0808, T0809, T0811, T0812, T0819, T0826, T0834, T0835, T0839, T0857, T0858, T0866, T0867, T0877, T0880, T0886, T0889, T0891, T0895
- **IEC-104**: T0826, T0828, T0838, T0856
- **OPC UA**: T0811, T0812, T0819, T0830, T0838, T0856, T0869, T0884, T0886, T0890, T0891, T0892
- **EtherNet/IP**: T0800, T0812, T0819, T0839, T0857, T0866, T0867, T0869, T0877, T0885
- **PROFINET DCP**: T0864

### Bug fixes:
- Fixed profinet_dcp marker type in /api/preview_payload endpoint (str→bytes)
- Fixed api_matrix_status precursor/runnable classification to use technique_support.json
  as authoritative source (previously all covered techniques showed as runnable)

## v0.25 — UX polish & SOC removal

### SOC Mode removed
- Removed SOC Mode tab from nav on all pages
- `/soc` route now redirects → `/sender` (backwards compat)
- Removed SOC references from index quick-start and matrix header
- Backend SOC route retained as redirect; SOC-only API endpoints untouched (non-breaking)

### Sender: confirm button redesign
- Replaced plain checkbox with a full-width amber safety toggle button
- Shows ○ (muted) when unchecked → ✓ green when confirmed
- Clear visual state: green border + green background when active

### Stuxnet chain preview fix
- CHAIN__stuxnet__siemens_plc step 0 is PROFINET DCP; bytes/str marker mismatch fixed
- `/api/preview_payload` now correctly encodes marker as bytes for profinet_dcp proto

### ATT&CK Matrix — compact single-row redesign
- All 12 tactics now render as a horizontal grid across the full viewport width
- Micro-tile design: 38px min-height, 9.5px technique name, 8.5px ID badge
- Each tactic column scrolls independently (max-height: calc(100vh - 280px))
- Amber left-border for runnable, cyan for precursor, dimmed for host-only
- Hover tooltip shows technique ID + name + status without opening modal
- Filter buttons: All / Runnable / Precursor / Gap — hide empty columns
- Matrix route now uses technique_support.json for correct precursor vs runnable classification

## v0.26 — PROFINET DCP live delivery fix (scapy removed)

### Root cause
PROFINET DCP live traffic was silently failing end-to-end due to three stacked problems:
1. `live/sender.py` called `from scapy.all import sendp` — scapy was never a dependency, so it crashed with ModuleNotFoundError before a single byte was sent.
2. `receiver/receiver.py` was a pure TCP accept() loop (SOCK_STREAM on ports 502/102/etc). PROFINET DCP is ethertype 0x8892 — a raw Layer-2 frame, not a TCP connection. The receiver would never have seen it even with scapy installed.
3. `protocols/common.py` and `core.py` also used scapy for tcp_packet(), ether_frame(), and write_pcap(), so even PCAP generation would fail if scapy was absent.

### Fix — scapy fully removed, pure Python throughout

**protocols/common.py** (rewritten)
- `tcp_packet()`: builds Ethernet II + IPv4 + TCP frame as raw bytes with correct IP and TCP checksums (RFC 793/791, Wireshark-valid)
- `ether_frame()`: builds raw Ethernet II frame as bytes
- No external dependencies

**core.py** (rewritten)
- `write_pcap()`: pure-Python struct-based pcap writer (LINKTYPE_ETHERNET, magic 0xa1b2c3d4)
- `replay_pcap()`: parses pcap frames directly, extracts TCP payload, sends via SOCK_STREAM; handles non-TCP frames gracefully

**live/sender.py** (rewritten)
- `_send_profinet_dcp(iface, payload)`: sends Ethernet II frame (ethertype 0x8892) via AF_PACKET raw socket — Linux only, root/CAP_NET_RAW required
- Clear RuntimeError if AF_PACKET unavailable (non-Linux) or iface missing
- All TCP protocols use socket.create_connection() as before

**receiver/receiver.py** (rewritten)
- `_l2_profinet_listener(iface, receipts_path, max_payload)`: new thread
  - Opens AF_PACKET/SOCK_RAW + ETH_P_ALL socket on the specified interface
  - Filters incoming frames for ethertype 0x8892
  - Parses DCP payload for ICSForge marker, writes receipt with src_mac/dst_mac/bytes/sha256
  - Graceful degradation: logs warning if AF_PACKET unavailable or permission denied
- TCP listeners unchanged

**receiver/config.yml** (updated)
- Added `l2_listen:` section with `profinet_dcp: ""` (disabled by default)
- Set via config or CLI: `icsforge-receiver --l2-iface eth0`

**web/app.py** (updated)
- Health endpoint now reports `af_packet: true/false` and `profinet_live: true/false` instead of `scapy: true/false`

### Usage
To capture PROFINET DCP on the receiver:
```
icsforge-receiver --l2-iface eth0        # recommended: CLI flag
# or: set l2_listen.profinet_dcp: eth0 in receiver/config.yml
```
Both sender and receiver require root/CAP_NET_RAW on Linux for L2 sockets.

## v0.27 — Matrix variant sync (technique_variants.json + matrix.yml fix)

### Bug
Matrix technique modal showed wrong/stale variants from pre-v0.24, e.g. T0800 showed
iec104/dnp3/modbus variants when the actual implemented scenarios are s7comm + enip.

### Root cause
`technique_variants.json` and `matrix.yml` were separate auto-generated files that were
never updated when 73 new scenarios were added in v0.24. `api_technique_variants` read
from `technique_variants.json` (stale) and `api_technique_send` looked up scenarios in
`matrix.yml` (also stale), both completely disconnected from `scenarios.yml`.

### Fix
1. `technique_variants.json` regenerated from `scenarios.yml` as single source of truth
   - 71 techniques / 129 variants (was 83 techniques / stale data)
   - variant `id` = scenario suffix after `{technique}__`, matching `api_technique_send` lookup
   - variant `label` = real scenario title from scenarios.yml
   - variant `proto` = actual protocols used in that scenario's steps
   - variant `notes` = first 150 chars of scenario description
2. `MATRIX_SINGLETON_PACK` constant changed from `matrix.yml` → `scenarios.yml`
   - `api_technique_send` now looks up scenarios in the same file as everything else
   - `matrix.yml` is now dead code (can be deleted; kept for reference)

## v0.27.1 — Technique count reconciliation

### What the discrepancy was
The "72 techniques / 129 variants" contradiction in v0.27 release notes had two distinct causes:

**Cause 1 — technique_variants.json only counts standalone scenarios (not chains)**
T0879 (Damage to Property) only appears inside CHAIN__industrial_espionage__opcua, never
as a standalone scenario. Variants are generated from standalone scenarios, so T0879 has
no entry in technique_variants.json. This is correct behaviour — you can't fire a bare
T0879 from the matrix modal, only as part of the chain. Count: 71 standalone techniques
+ 1 chain-only = 72 total, consistent.

**Cause 2 — T0841 / T0875 / T0876 absent from ics_attack_matrix.json**
These three techniques exist in our scenarios.yml and technique_variants.json, but were
missing from the ATT&CK matrix JSON (which was slightly behind the full ICS matrix):
- T0841 Network Service Scanning (Discovery)
- T0875 Change Program State (Execution)
- T0876 Loss of Safety (Impact)

Without them in the JSON the matrix page didn't render their tiles at all, and
api_matrix_status never reported them, so they appeared invisible even though traffic
generation for them was fully implemented.

### Fix
- Added T0841, T0875, T0876 to ics_attack_matrix.json in their correct tactic columns
- Matrix now shows 86 unique technique entries (83 original + 3 added)
- api_matrix_status: 65 runnable + 7 precursor = **72 covered** ✓
- Scenarios: 140 ✓
- Variants: 71 standalone techniques (T0879 chain-only, correctly excluded)

## v0.28 — PROFINET DCP live delivery: three socket bugs fixed

### Bug 1 — Sender: wrong socket pattern (silent frame loss)
**Old:** `socket(AF_PACKET, SOCK_RAW)` with no proto + `bind((iface, 0x8892))` + `send(frame)`
- `0x8892` passed to bind without `htons()` — on little-endian the kernel saw ethertype filter `0x9288` (byte-swapped), meaning the socket was misconfigured from the start.
- `send()` after a bind may silently drop on some kernels if the socket has no valid protocol set.

**Fix:** `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` + `sendto(frame, (iface, 0))`
- ETH_P_ALL in the constructor, correctly `htons()`'d — socket can send any ethertype.
- `sendto(frame, (iface, 0))` is the correct AF_PACKET send pattern; `iface` selects the egress interface, `proto=0` means "read ethertype from frame header."

### Bug 2 — Receiver: no promiscuous mode (NIC hardware filter drops frames)
**Old:** AF_PACKET socket opened with ETH_P_ALL but interface left in default mode.
- PROFINET DCP uses dst MAC `01:0e:cf:00:00:00` (multicast). The NIC hardware filter drops multicast frames unless the host has joined that group or the interface is in promiscuous mode.
- Result: frames arrive at the switch port but the NIC silently discards them before AF_PACKET sees them.

**Fix:** `setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, packet_mreq{PACKET_MR_PROMISC})`
- Per-socket promiscuous mode via `PACKET_ADD_MEMBERSHIP` / `PACKET_MR_PROMISC`.
- Automatically released when the socket closes — no manual cleanup needed.
- Requires root/CAP_NET_RAW (same requirement as opening AF_PACKET socket).

### Bug 3 — Receiver: recv() instead of recvfrom(), no PACKET_OUTGOING filter
**Old:** `sock.recv(max_payload)` — no packet type information.
- On a single host (sender+receiver same machine), AF_PACKET with ETH_P_ALL also receives OUTGOING frames (pkttype=4) — the frames you just sent. This would cause false receipt records.

**Fix:** `sock.recvfrom(max_payload)` returns `(data, (ifname, proto, pkttype, hatype, addr))`.
- Frames with `pkttype == 4` (PACKET_OUTGOING) are skipped.
- pkttype is also written to the receipt record for diagnostics.
