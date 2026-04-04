## v0.57.5 (2026-04 — receipt consistency across all run endpoints + lint clean)

### Fix 1: /api/run and /api/run_detail were still callback-blind

The v0.57.4 fix applied the live-receipts merge only to `/api/run_full` and
`/api/export`. `/api/run` and `/api/run_detail` in `bp_receiver.py` were
still reading exclusively from `out/receipts.jsonl`, which is populated by
the standalone receiver process but not by the sender callback path.

For a live run using the callback path: `/api/receiver/live` showed 29 receipts,
`/api/run_full` showed 29 receipts (fixed in v0.57.4), but `/api/run` and
`/api/run_detail` still returned `{}` (empty).

All four run-detail endpoints now merge both sources:
- JSONL file (standalone receiver process)
- `_live_receipts` deque (sender callback path)

Verified: 10 live receipts → all four endpoints return `packets: 10`.

### Fix 2: Stable receipt deduplication key

The v0.57.4 dedup used `id(r)` — object identity — which is not stable across
JSONL-parsed dicts and in-memory deque entries (different objects, same data).
Replaced with a content-based tuple key:
`(run_id, @timestamp, technique, proto, src_ip, src_port)`

Dedup verified: adding 10 duplicate receipts keeps count at 10, not 20.

### Fix 3: Import ordering in bp_runs.py (Ruff I001)

The `_live_receipts` import was inserted in the wrong alphabetical position in
v0.57.4, causing a Ruff I001 lint error. Import block is now correctly sorted.
`bp_receiver.py` import block also sorted correctly.

## v0.57.4 (2026-04 — bug fixes from external review of v0.57.3)

### Fix 1: /api/run_full receipts always empty for live runs

Root cause: live receipts arrive via the sender callback path
(`POST /api/receiver/callback`) which stores them in `_live_receipts` — an
in-memory deque in `helpers_sse.py`. The JSONL receipts file at
`out/receipts.jsonl` is written only by the standalone receiver process.

`/api/run_full` read only from the JSONL file. `_live_receipts` was checked
by `/api/receiver/live` but not by `run_full`. So for a live run: packets=29,
receiver/live=29, but run_full receipts=[].

Fix: `api_run_full` and `api_export_run` now merge both sources:
1. JSONL file (receipts from standalone receiver process)
2. `_live_receipts` deque (receipts from sender callback path)

Duplicates excluded via `id()` comparison. Result: run_full receipts_preview
now correctly reflects all live receipts for the run.

### Fix 2: Ruff lint — two unused imports in bp_scenarios.py

- `import json` — unused since the variants endpoint was rewritten to derive
  from scenarios.yml (no longer reads JSON from technique_variants.json)
- `TECH_VARIANTS` — unused for the same reason

Additionally, `import random as _rnd_off` was declared inside the
`api_generate_offline` function body. Moved to module level as `import random
as _rnd`. All references updated. No behaviour change.

## v0.57.3 (2026-04 — bug fixes: matrix tiles, dst_ip propagation, campaign chains)

### Bug 1: Matrix tile height — long names clipped (regression from v0.57.2)
The v0.57.2 fix set a fixed `height: 52px` which clipped technique names like
"Device Restart/Shutdown" and "Block Reporting Message". Reverted to `height: auto`
with `min-height: 46px`. All technique names are now fully visible. The `-webkit-line-clamp`
was also removed — it was the cause of the visible text truncation in the screenshot.

### Bug 2: Destination IP not propagating from Network Settings
Two changes to make the dst_ip field reliably reflect the Network Settings IP:

1. `cfg_receiver_ip` now has an `oninput` handler that mirrors its value to `dst_ip`
   in real time as the user types — before any Save button is clicked.
2. `saveNetworkConfig()` now mirrors `receiver_ip → dst_ip` and `sender_ip → src_ip`
   at the very top of the function before any `await`, so the field is updated
   immediately rather than after a network roundtrip that could fail or delay.

Previously the mirror happened after `await API("/api/config/network")` which is
correct in theory but could be delayed or skipped if the network call path threw.
Now it is unconditional and synchronous.

### Bug 3: Campaign page — attack chains do not work
Root cause: `/api/scenarios_grouped` did not include the `steps` array in chain
scenario cards — only `step_count` (an integer). The campaign page `_runChain()`
function reads `sc.steps` to render the step-by-step progress view. With `steps`
absent, it got an empty array, rendered no rows, and the chain appeared to do nothing
even though `/api/send` would have executed it.

Fix: `/api/scenarios_grouped` now includes the full `steps` array for chain scenarios
(non-chain scenarios still omit steps to keep the response small). All 11 chains
verified: 5–10 steps each, correct proto/technique fields, send path returns 200.

## v0.57.2 (2026-04 — UI fixes: sender, matrix, home page)

### 7 UI fixes from review

**1. Home page tagline**
"ICSForge validates cybersecurity..." -> "ICSForge helps you to validate cybersecurity..."

**2. Tactic group ordering (sender)**
Privilege Escalation was last in the list. Corrected to ATT&CK for ICS position 4:
Chains → Initial Access → Execution → Persistence → **Privilege Escalation** → Evasion
→ Discovery → Lateral Movement → Collection → Command and Control
→ Inhibit Response Function → Impair Process Control → Impact

**3. Attack chains layout (sender)**
Named chains (Industroyer2, Triton/TRISIS, Stuxnet-style, Water Treatment, OPC UA
Espionage, EtherNet/IP MFG) now render as a prominent first row. Generic multi-protocol
chains appear below with a "MULTI-PROTOCOL CHAINS" section label.

**4. Confirm button text (sender)**
"Confirm: synthetic traffic only — destination is a safe host in your OT environment"
→ "Confirm: Destination is a safe host (receiver) in your environment"

**5. Matrix column header duplicate removed**
Each tactic column showed the name ("Initial Access") and the shortname
("initial-access") below it. The shortname line is now removed — one clean label only.

**6. Matrix tile text overlap fixed**
- .mc-col: overflow changed from `visible` to `hidden` — tiles no longer bleed outside
  their column bounds
- .mt: added overflow:hidden to contain content within tile bounds
- .mt-name: added -webkit-line-clamp:3 so long technique names truncate cleanly
  instead of overflowing into adjacent tiles

**7. Home page top techniques table**
- Was: top 20 by scenario count, showing "Refs" column
- Now: top 10 by protocol coverage breadth (most protocols covered), showing
  "Protocols" (x/10 in green) and "Scenarios" columns
- All top 10 currently show 10/10 protocol coverage — the table correctly
  reflects the expansion work done across all batch releases

## v0.57.2 (2026-04 — UI fixes across home, sender, and matrix pages)

### 7 UI fixes

**Fix 1: Home page tagline**
"ICSForge validates cybersecurity..." →
"ICSForge helps you to validate cybersecurity detection coverage..."

**Fix 2: Sender tactic group order — Privilege Escalation position**
Privilege Escalation was last in the sender scenario list. Corrected to match
ATT&CK for ICS tactic order: Persistence → Privilege Escalation → Evasion.

**Fix 3: Attack chains — named chains first, generic chains below**
Named chains (Industroyer2, Triton, Stuxnet, Water Treatment, OPC UA Espionage,
EtherNet/IP MFG) now render in the first row with their icons and labels.
Generic multi-protocol chains (CHAIN__loss_of_availability, etc.) appear below
with a "MULTI-PROTOCOL CHAINS" separator.

**Fix 4: Confirm button text**
"Confirm: synthetic traffic only — destination is a safe host in your OT environment"
→ "Confirm: Destination is a safe host (receiver) in your environment"

**Fix 5: Matrix column header — duplicate shortname removed**
Each tactic column header showed the tactic name (e.g. "Initial Access") AND
the kebab-case shortname (e.g. "initial-access") below it, making it appear
duplicated. The shortname line is removed; column headers now show just the name.

**Fix 6: Matrix tile text overflow**
Technique tiles now have a fixed height (52px) with CSS -webkit-line-clamp: 3
on the technique name. Long names (e.g. "Exploitation for Privilege Escalation")
no longer overflow and overlap adjacent tiles.

**Fix 7: Home page top techniques — correct data, top 10 only**
Previously showed top 20 sorted by scenario count (a proxy for coverage).
Now shows top 10 sorted by protocol coverage breadth (most protocols covered),
with a "Protocols" column showing X/10 and a "Scenarios" column showing count.
All 18 techniques at 10/10 coverage are sorted secondarily by scenario count.

## v0.57.1 (2026-04 — matrix overlay and sender scenario visibility fixed)

### Bug: technique variants were stale (matrix click-through broken)

The `/api/technique/variants` endpoint read from `icsforge/data/technique_variants.json`,
a static file maintained separately from `scenarios.yml`. This file was last updated
many versions ago and only contained 2–3 variants per technique regardless of how
many scenarios were actually added. When a user clicked a technique tile on the matrix
page to see available scenarios, they saw only the old entries — all new scenarios
from every expansion batch (v0.52–v0.57) were invisible.

Fix: the endpoint now derives variants live from `scenarios.yml`:
- Queries all scenarios matching the requested technique ID
- Skips CHAIN__ scenarios (they cover multiple techniques)  
- Returns `{id, label, proto, protocols, notes}` built from actual scenario metadata
- Variant IDs are the scenario name with the `T0XXX__` prefix stripped, so the
  send endpoint constructs the correct scenario name on lookup

Result:
- T0858 Change Operating Mode: was 2 variants, now 11 (all protocols)
- T0892 Change Credential: was 0 variants, now 6
- T0880 Loss of Safety: was 2 variants, now 11
- T0855 Unauthorized Command: was 4 variants, now 14 (all 10 protocols)
- All 68 techniques: 100% of scenario variants visible, all IDs resolve correctly

`technique_variants.json` is now unused by the variants endpoint and will be
removed in a future cleanup. The send path (`api/technique/send`) was already
correctly looking up scenarios in `scenarios.yml`.

### Verified
- All 68 techniques: variants endpoint returns correct count
- All variant IDs round-trip correctly through generate_offline
- Matrix tile click -> variant select -> generate_offline: end-to-end PASS
- Smoke test: 35/35
- Syntax: clean

## v0.57.0 (2026-04 — scenario expansion: 394 -> 434, 53.4% -> 59.3% coverage)

### Batch 5 expansion: +40 scenarios across 10 techniques

Techniques explicitly NOT expanded (domain filter applied):
  T0842 Network Sniffing — passive, no packets generated. 1/10 ceiling.
  T0820 Exploitation for Evasion — malformed-frame scenarios already exist for
    modbus/enip/opcua/s7comm. No new protocols have equivalent malformed styles.
  T0871 Execution through API — OPC UA call_method is the only OT network path.
  T0807 CLI, T0853 Scripting — DNP3 file_open is the only OT network path.
  T0834 Native API — S7comm native_cotp is the only OT network path.
  T0837 Loss of Protection — modbus:protection_relay is the only equivalent.
  T0864 Transient Cyber Asset — physical access. 1/10 ceiling.
  T0872 Indicator Removal — endpoint. DNP3 clear_events is the only OT equiv.
  T0884 Connection Proxy, T0890 Privilege Escalation — OPC UA specific. 1/10 ceiling.
  T0895 Autorun Image — S7comm SDB0 is the only OT network equivalent.

New scenarios added:
  T0858 Change Operating Mode (+5: bacnet, iec61850, modbus, mqtt, profinet_dcp) -> 10/10
  T0829 Loss of View (+5: bacnet, enip, iec61850, mqtt, profinet_dcp) -> 10/10
  T0889 Modify Program (+5: dnp3, iec104, iec61850, modbus, profinet_dcp) -> 10/10
  T0880 Loss of Safety (+4: bacnet, iec61850, opcua, profinet_dcp) -> 9/10
  T0800 Firmware Update Mode (+4: dnp3, iec104, modbus, mqtt) -> 6/10
  T0892 Change Credential (+4: dnp3, enip, iec104, s7comm) -> 6/10
  T0891 Hardcoded Credentials (+4: bacnet, dnp3, enip, iec104) -> 6/10
  T0828 Loss of Productivity (+4: bacnet, enip, mqtt, s7comm) -> 6/10
  T0859 Valid Accounts (+3: enip, iec104, s7comm) -> 5/10
  T0822 External Remote Services (+2: enip, s7comm) -> 4/10

### New techniques at 10/10 protocol coverage
T0858, T0829, T0889 — 18 techniques now at full coverage.

### Coverage: 53.4% -> 59.3% (403/680 combinations)
### Standalone scenarios: 423 + 11 chains = 434 total
### All 423 standalone: 0 bad styles, 0 tactic mismatches, 0 mangled IDs

## v0.56.3 (2026-04 — metadata alignment and alerts ingest policy)

### Developer review findings from v0.56.2 — addressed

Three substantive fixes based on a second extensive external review.

**Fix 1: Local ATT&CK for ICS matrix file aligned with current MITRE list**

The bundled `ics_attack_matrix.json` contained 97 total entries / 86 unique technique IDs
from an older version of the framework. MITRE ATT&CK for ICS currently lists 83 techniques.
The three extra IDs (T0841, T0875, T0876) were deprecated/invalid — removed.

Matrix is now: 94 total entries (11 techniques appear in >1 tactic = intentional ATT&CK
design), 83 unique technique IDs. Matches `technique_support.json` exactly — gap is zero.

**Fix 2: /api/matrix_status now exposes matrix_info block**

The response previously returned only `{run_id, status}`. Callers seeing 94 entries in
the matrix file but 83 unique IDs were confused. New `matrix_info` field in the response:

```json
"matrix_info": {
  "total_entries": 94,
  "unique_technique_ids": 83,
  "note": "total_entries > unique_technique_ids because some techniques appear under multiple tactics"
}
```

The 11 techniques that appear in >1 tactic (e.g. T0856 Spoof Reporting under both
Evasion and Impair Process Control; T0839 Module Firmware under both Persistence and
Impair Process Control) are correct ATT&CK for ICS design, not a data error.

**Fix 3: /api/alerts/ingest returns 400 for malformed `alert` field**

After v0.56.1 fixed the 500 crash, the endpoint was accepting malformed `alert` values
(string instead of object) and silently importing them with fallback placeholders.
Policy decision: malformed alert structure is a caller bug and should be rejected clearly.

Before: string alert field -> imported with `signature: "alert"` placeholder (200 OK)
After:  string alert field -> `400 {"ok": false, "error": "Row N: 'alert' field must be
         an object, got str"}`

Valid alert objects continue to import normally (200 OK).

### Findings not acted on

**Webhook field name (`webhook_url`)**: intentional API design, documented in API surface.
**Auth setup requires username**: intentional hardening, not a regression.
**Developer note on T0841/T0875/T0876**: resolved by Fix 1 — removing the deprecated IDs
  from the local matrix rather than adding them back to support.json.

### Metadata state after v0.56.3
| Source | Count | Notes |
|--------|-------|-------|
| MITRE ATT&CK for ICS (live) | 83 techniques | authoritative |
| ics_attack_matrix.json unique IDs | 83 | now aligned |
| ics_attack_matrix.json total entries | 94 | 11 multi-tactic techniques |
| technique_support.json | 83 entries | aligned |
| scenario step-level techniques | 72 | 11 host-only have no OT network scenarios |

## v0.56.2 (2026-04 — correct invalid ATT&CK for ICS technique IDs)

### Correction: T0841, T0875, T0876 are not valid ATT&CK for ICS technique IDs

The external developer's Bug 3 report claimed these three IDs were missing from
`technique_support.json`. The report compared against our bundled `ics_attack_matrix.json`,
which is from an older version of the framework (97 techniques vs the current 83).

The current MITRE ATT&CK for ICS (attack.mitre.org/techniques/ics/) lists exactly 83
techniques. T0841, T0875, and T0876 do not appear in this list:
- T0841 "Network Service Scanning" was from the pre-2021 collaborate.mitre.org era
- T0875 "Change Program State" does not exist in the current framework
- T0876 "Loss of Safety" is a duplicate of T0880 which is the current valid ID

The v0.56.1 "fix" of adding these to technique_support.json was wrong and is reverted.

### What was actually fixed

17 scenario top-level technique fields and 39 step-level technique fields pointing to
invalid IDs have been remapped to the correct current ATT&CK for ICS equivalents:

- T0841 "Network Service Scanning" -> T0846 "Remote System Discovery"
  (all network scanning scenarios now correctly filed under T0846)
- T0875 "Change Program State" -> T0858 "Change Operating Mode"
  (all PLC stop/start/mode scenarios now correctly filed under T0858)
- T0876 "Loss of Safety" -> T0880 "Loss of Safety"
  (same concept, T0880 is the current valid ID)

Scenario keys renamed accordingly (e.g. T0841__network_scan__* -> T0846__network_scan__*).

technique_support.json: 83 entries, exactly matching the current MITRE ATT&CK for ICS
technique count. No fabricated IDs.

### Coverage after remapping (unchanged total, IDs corrected)
- T0846 Remote System Discovery: 10/10 protocols
- T0858 Change Operating Mode:    5/10 protocols
- T0880 Loss of Safety:           5/10 protocols

## v0.56.1 (2026-04 — bug fixes from external developer review of v0.53.0)

### Developer review findings — all addressed

External developer performed a full end-to-end review from a clean tarball install:
real web launcher, real receiver, live CLI sends, artifact verification, SQLite state,
auth flow, webhook, alerts ingest, and scenario pack inspection.

**Fix 1: `/api/alerts/ingest` 500 on malformed `alert` field (real runtime crash)**
When a Suricata EVE JSONL row had `"alert": "some_string"` instead of
`"alert": {...}`, the endpoint crashed with `AttributeError: 'str' object has
no attribute 'get'`. Fixed: `isinstance(alert, dict)` guard applied before
any `.get()` calls. Malformed rows now produce a clean empty-alert normalised
record rather than a 500.

**Fix 2: Remaining mangled top-level `technique` field**
One chain scenario (`CHAIN__loss_of_availability__multi`) still had its technique
field set to `'T0813 followed by S7comm CPU stop commands...'` from the yaml.dump
width-wrapping bug fixed in v0.55.0. Repaired to `T0813`.

**Fix 3: `technique_support.json` not aligned with ATT&CK ICS matrix**
Three techniques covered by scenarios (T0841, T0875, T0876) were missing entries
in `technique_support.json`. The file had 83 entries vs the matrix's 86. All three
added with correct runnable classification and evidence descriptions. Files now
align exactly: 86 entries each.

**Fix 4: `/api/campaigns` returned 404**
The campaigns list endpoint was only registered at `/api/campaigns/list`. Added
`/api/campaigns` as a second route decorator on the same handler. Both paths now
return 200.

**Fix 5: Stealth mode events JSONL still contained `icsforge.marker: "ICSFORGE_SYNTH"`**
In stealth mode (`--no-marker`), the generated PCAP correctly contained no
ICSForge correlation tags. However, the events JSONL ground-truth file still
wrote `icsforge.marker: "ICSFORGE_SYNTH"` — inconsistent with the wire traffic.
Fixed: `event_base()` now accepts a `no_marker` parameter; when True,
`icsforge.marker` is set to `None`. The `icsforge.synthetic: True` field is
intentionally preserved (the events ARE synthetic regardless of marker mode).

**Developer-noted items that are intentional / acknowledged:**
- Auth setup requires `username` + `password` (hardening, not a bug; documented)
- Alerts ingest is path-based and repo-constrained (power-user UX, acceptable)
- `icsforge.synthetic: True` remains in stealth events (accurate metadata)

## v0.56.0 (2026-04 — Scenario expansion: 355 -> 394, 46.9% -> 52.1% coverage)

### No-nonsense expansion: 39 new scenarios across 13 techniques

Every scenario was evaluated against a strict domain filter before being written:
- Does the protocol genuinely reach the relevant device class?
- Does the specific style produce traffic that represents the technique?
- Is it meaningfully different from existing scenarios for the same technique?
- Was it excluded only because it genuinely cannot be simulated via network traffic?

Techniques explicitly NOT expanded (rationale documented):
  T0842 Network Sniffing — passive activity; no packets emitted. 1/10 ceiling.
  T0872 Indicator Removal — primarily endpoint. DNP3 clear_events is the only OT equivalent.
  T0864 Transient Cyber Asset — physical access. PROFINET DCP hello is the only equivalent.
  T0884 Connection Proxy, T0890 Privilege Escalation — OPC UA specific, no generic equivalents.
  T0895 Autorun Image — S7comm SDB0 is the only protocol-native equivalent.
  T0807 CLI, T0853 Scripting — DNP3 file transfer is the only OT network equivalent.
  T0820 Exploitation for Evasion — requires deep protocol stack implementation; correct
    as malformed/exception-probe (existing modbus/enip/opcua/s7comm scenarios cover this).

New scenarios added:
  T0816 Device Restart/Shutdown (+4: dnp3, iec104, modbus, mqtt) -> 8/10
  T0815 Denial of View (+4: iec61850, modbus, s7comm, profinet_dcp) -> 8/10
  T0801 Monitor Process State (+3: dnp3, enip, s7comm) -> 8/10
  T0821 Modify Controller Tasking (+3: enip, opcua, dnp3) -> 4/10
  T0806 Brute Force I/O (+3: dnp3, enip, s7comm) -> 4/10
  T0838 Modify Alarm Settings (+4: bacnet, enip, iec61850, profinet_dcp) -> 10/10
  T0839 Module Firmware (+3: enip, dnp3, iec104) -> 5/10
  T0845 Program Upload (+3: enip, opcua, dnp3) -> 4/10
  T0846 Remote System Discovery (+3: enip, modbus, opcua) -> 4/10
  T0849 Masquerading (+3: dnp3, enip, s7comm) -> 8/10
  T0875 Change Program State (+3: enip, iec104, opcua) -> 4/10
  T0889 Modify Program (+3: enip, opcua, s7comm) -> 6/10
  T0835 Manipulate I/O Image — already covered from previous batch

New technique at 10/10: T0838 Modify Alarm Settings

### Protocol gains
EtherNet/IP: +9 (38->47), DNP3: +7 (38->45), OPC UA: +5 (37->42), S7comm: +4 (48->52)

### Totals
Standalone scenarios: 383 (+ 11 chains = 394)
Techniques covered: 71/72
Coverage: 46.9% -> 52.1% (370/710 combinations)
Techniques at 10/10: 15
Techniques at 8+/10: 25

## v0.55.0 (2026-04 — Quality audit + genuine scenario expansion: 334 -> 355)

### Quality audit: major correctness pass across all 314 standalone scenarios

**Issue 1: 37 invalid style/protocol combinations (FIXED)**
Scenarios written in earlier development sessions used style names that were
invented or renamed: mqtt:connect (-> auto), mqtt:publish (-> publish_telemetry),
mqtt:subscribe (-> subscribe_all), dnp3:app_read (-> read_class1),
dnp3:data_link (-> delay_measure), dnp3:unsolicited (-> enable_unsolicited
corrected further to spoof_response), s7comm:negotiate (-> szl_read),
iec104:command (-> setpoint_float / double_command), modbus:device_id (-> report_block).
All 37 were corrected to valid styles that the protocol builders actually implement.

**Issue 2: enumerate_ied missing from iec61850.py (FIXED)**
The enumerate_ied style was referenced in 9 IEC 61850 scenarios but the actual
elif branch was never written into the protocol builder. All 9 scenarios used
the fallback path (benign keep-alive GOOSE) instead of the intended test-mode
probe. The style is now properly implemented.

**Issue 3: 86 tactic mismatches against ATT&CK for ICS matrix (FIXED)**
Many scenarios had tactically incorrect labels — some inherited from early
development, others introduced by batch additions. Full ATT&CK for ICS matrix
alignment enforced across all techniques:
- T0813 Denial of Control -> Impact (not Inhibit Response Function)
- T0832 Manipulation of View -> Impact (not Evasion / Inhibit Response Function)
- T0856 Spoof Reporting -> Impair Process Control (not Inhibit Response Function)
- T0848 Rogue Master -> Initial Access (not Lateral Movement)
- T0812 Default Credentials -> Lateral Movement (not Initial Access)
- T0877 I/O Image -> Collection (not Discovery)
- T0868 Detect Operating Mode -> Collection (not Discovery)
- T0882 Theft of Operational Information -> Impact (not Collection)
- T0830 AitM -> Collection (not Lateral Movement)
- All 86 fixed; 0 mismatches remain.

**Issue 4: 65 mangled technique fields (FIXED)**
yaml.dump(width=120) wrapped long description text into the technique field for
65 scenarios, turning the technique from 'T0803' into 'T0803 PLC and starving
legitimate master access.' Re-parsed all affected scenarios; technique fields
are now strictly the 5-character IEC code. Switched to width=2000 to prevent
recurrence.

**Issue 5: 9 T0820 scenarios with wrong technique ID (DELETED)**
T0820 in ATT&CK for ICS is "Exploitation for Evasion", not network connection
enumeration. Nine 'T0820 network discovery' scenarios were mislabeled T0840
duplicates. Deleted. T0840 Network Connection Enumeration remains at 10/10.

**Issue 6: T0829 safety scenario misattributed (FIXED)**
T0829__loss_of_protection__modbus_safety contained safety_write steps targeting
SIS registers — that is T0876 Loss of Safety, not T0829 Loss of View. Renamed
to T0876__loss_of_safety__modbus_sis and corrected description.

**Issue 7: T0832 dnp3 used enable_unsolicited (FIXED)**
enable_unsolicited turns ON change reporting — it does not inject false data.
T0832 Manipulation of View requires actually spoofing values. Corrected to
spoof_response which injects forged analog responses.

### New genuine scenarios (+30 across 8 techniques)

Added only where the protocol-technique combination is operationally meaningful:

T0829 Loss of View (0->5/10): modbus flood, dnp3 disable_unsolicited, iec104 STOPDT,
  opcua subscription delete, s7comm diagnostic flood
T0827 Loss of Control (+3: bacnet, dnp3, enip): 3->6/10
T0876 Loss of Safety (+3: dnp3, enip, iec104): 2->5/10
T0881 Service Stop (+4: bacnet, dnp3, iec104, opcua): 2->6/10
T0809 Data Destruction (+3: modbus, dnp3, enip): 3->6/10
T0843 Program Download (+3: dnp3, enip, opcua): 3->6/10
T0835 Manipulate I/O Image (+3: dnp3, enip, iec104): 2->5/10
T0861 Point & Tag Identification (+3: dnp3, enip, iec104): 3->6/10
T0802 Automated Collection (+3: dnp3, enip, iec104): 3->6/10

### Scenario totals: 355 (344 standalone + 11 chains)
### Coverage: 44.1% -> 46.9% (333/710 combinations)
### All 344 standalone scenarios: 0 bad styles, 0 tactic mismatches, 0 mangled IDs

## v0.54.0 (2026-04 — Scenario expansion: 275 → 334 scenarios, 36% → 44% coverage)

### Coverage batch 3: +59 scenarios across 18 techniques

Systematic fill of the highest-value remaining gaps, with heavy focus on
BACnet, PROFINET, IEC 61850, and MQTT which were the least-covered protocols.

**Techniques reaching 10/10 protocol coverage this batch:**
T0813, T0820, T0826, T0831, T0832, T0836 (already), T0840, T0841, T0848,
T0855, T0856, T0877, T0878, T0882, T0888 -- 15 techniques now at full coverage.

**Techniques expanded:**
- T0803 Block Command (+5: bacnet, enip, iec104, iec61850, s7comm) 2 -> 7/10
- T0804 Block Reporting (+5: bacnet, enip, iec104, iec61850, s7comm) 2 -> 7/10
- T0830 AitM (+3: bacnet, mqtt, s7comm) 6 -> 9/10
- T0831 Manipulation of Control (+4: bacnet, enip, profinet_dcp, s7comm) -> 10/10
- T0848 Rogue Master (+4: bacnet, iec61850, mqtt, profinet_dcp) -> 10/10
- T0856 Spoof Reporting (+1: profinet_dcp) -> 10/10
- T0812 Default Credentials (+2: bacnet, dnp3) -> 9/10
- T0813 Denial of Control (+2: dnp3, iec104) -> 10/10
- T0814 Denial of View (+2: bacnet, enip) -> 8/10
- T0820 Network Discovery (+5: bacnet, enip, iec61850, mqtt, profinet_dcp) -> 10/10
- T0826 Loss of Availability (+2: bacnet, profinet_dcp) -> 10/10
- T0832 Manipulation of View (+2: bacnet, profinet_dcp) -> 10/10
- T0868 Detect Op Mode (+3: bacnet, iec61850, mqtt) -> 8/10
- T0869 Standard App Layer (+4: dnp3, iec104, iec61850, s7comm) -> 9/10
- T0877 I/O Module Discovery (+4: bacnet, iec61850, mqtt, profinet_dcp) -> 10/10
- T0878 Alarm Suppression (+4: bacnet, enip, mqtt, profinet_dcp) -> 10/10
- T0882 Theft of Op Info (+3: iec61850, mqtt, profinet_dcp) -> 10/10
- T0883 Internet Accessible (+4: bacnet, iec104, iec61850, s7comm) -> 8/10

### Protocol gains this batch
BACnet: +14 (17->31), IEC 61850: +9 (13->22), PROFINET: +9 (11->20),
MQTT: +7 (22->29), S7comm: +6 (42->48), EtherNet/IP: +6 (26->32)

### Scenario total: 334 (323 standalone + 11 attack chains)
### Coverage: 35.8% -> 44.1% (313/710 technique-protocol combinations)

## v0.53.0 (2026-04 — Scenario expansion: 179 → 275 scenarios, 25% → 36% coverage)

### Coverage gap analysis and targeted expansion

Systematic audit of all 72 ATT&CK for ICS techniques x 10 protocols:

- Feasibility conclusion: 720 (72x10) is the theoretical max; realistic ceiling
  is ~490-520 scenarios once host-only and protocol-specific techniques are excluded.
  15 techniques are endpoint-only (no OT network footprint). ~20 are protocol-specific.
  The remaining ~37 are protocol-independent and fully achievable across all 10 protocols.
- This release: 179 -> 275 scenarios (+96 net). Coverage: 25.2% -> 35.8%.

### New standalone scenarios (+45 across 14 techniques)

T0832 Manipulation of View (+4: dnp3, iec104, s7comm, enip) -- now 8/10
T0856 Spoof Reporting (+4: bacnet, modbus, s7comm, enip) -- now 9/10
T0888 Remote System Info (+5: dnp3, iec104, mqtt, profinet_dcp, iec61850) -- now 10/10
T0840 Network Connection Enum (+4: dnp3, iec104, s7comm, iec61850) -- now 10/10
T0841 Network Scanning (+3: bacnet, iec61850, profinet_dcp) -- now 10/10
T0830 AitM (+3: modbus, enip, iec104) -- now 6/10
T0813 Denial of Control (+3: enip, profinet_dcp, opcua) -- now 8/10
T0814 Denial of View (+2: opcua, s7comm)
T0836 Modify Parameter (+2: dnp3, iec61850) -- now 10/10
T0838 Modify Alarm Settings (+2: dnp3, s7comm)
T0855 Unauthorized Command (+3: enip, opcua, profinet_dcp) -- now 10/10
T0812 Default Credentials (+2: iec104, profinet_dcp) -- now 7/10
T0820 Network Discovery (+4: opcua, s7comm, dnp3, iec104) -- now 5/10
T0826 Loss of Availability (+2: opcua, iec61850)
T0849 Masquerading (+2: iec61850, mqtt)

### Techniques at full 10/10 protocol coverage
T0840 Network Connection Enumeration
T0841 Network Scanning
T0855 Unauthorized Command
T0836 Modify Parameter
T0888 Remote System Info Discovery

### New IEC 61850 style: enumerate_ied
GOOSE frames with test=True flag to generic multicast for IED discovery
without triggering protection actions. Used by T0840/T0841/T0888 scenarios.

### Roadmap to ~490 scenarios (next iterations)
T0803/T0804 Block Command/Reporting: 2/10, all protocols viable
T0831 Manipulation of Control: expand remaining 5 protocols
T0882 Theft of Operational Information: 7/10, needs mqtt/iec104/profinet
T0800 Activate Firmware Update Mode: 2/10, applicable to s7comm/opcua/iec104

## v0.52.0 (2026-04 — IEC 61850 GOOSE protocol and substation scenarios)

### New protocol: IEC 61850 GOOSE

IEC 61850 is the international standard for communication in electrical substations and
smart grids. Its GOOSE (Generic Object-Oriented Substation Events) protocol is the
time-critical Layer-2 multicast mechanism used for circuit breaker trip/close commands
and protection relay events. GOOSE has no built-in authentication — any frame on the
process bus VLAN with a higher stNum (state number) is accepted as authoritative by
all receiving IEDs. This is the primary attack surface for substation cyber-physical
attacks and was exploited in the 2015 Ukraine power grid attack.

**Why IEC 61850 belongs in ICSForge:**
- Deployed in power substations globally (Europe, North America, Asia-Pacific)
- Critical infrastructure: a single GOOSE trip injection can open a live circuit breaker
- Zero authentication in standard deployments (IEC 62351 rarely implemented in practice)
- Parsed natively by Zeek, Dragos, Nozomi, Claroty, and all OT-aware NSMs
- Distinctive EtherType 0x88B8 — immediately identifiable by Suricata and Wireshark
- Required for power sector ICS coverage validation

**Wire format (IEC 61850-8-1):**
- EtherType: 0x88B8 (GOOSE)
- DST MAC: 01:0C:CD:01:00:01 (protection multicast) or 01:0C:CD:01:00:00 (generic)
- Header: APPID(2) + Length(2) + Reserved1(2) + Reserved2(2)
- APDU: BER-encoded IECGoosePdu — all 12 required fields including gocbRef, datSet,
  goID, UTC timestamp, stNum, sqNum, confRev, allData

### New scenarios (4) — IEC 61850 techniques

**T0855__unauth_command__iec61850_goose_trip** — Unauthorized Command Message
Injects a forged GOOSE frame with stNum far above the legitimate IED's value. All
subscribers accept it as the most recent state change and execute the circuit-breaker
TRIP command. 5-step scenario replicates the real GOOSE retransmit burst pattern:
initial injection followed by exponentially spaced retransmits (4ms, 8ms, 16ms, 1s).

**T0856__spoof_reporting__iec61850_goose_meas** — Spoof Reporting Message
Injects GOOSE with falsified FLOAT32 voltage and current values (0.0V — simulating
a dead feeder). SCADA and receiving IEDs display incorrect grid state.

**T0813__denial_of_control__iec61850_goose_replay** — Denial of Control
Rapid GOOSE replay flood (100+ msg/s) with fixed stNum but incrementing sqNum.
Saturates IED message queues; real protection events are delayed or lost.

**T0830__aitm__iec61850_goose_relay** — Adversary-in-the-Middle
Simulates AitM relay injection: captures a legitimate GOOSE, modifies allData
(e.g., close→trip), re-injects with stNum = captured+1. Subscribers accept the
attacker's frame over the legitimate publisher's.

### Technical notes
- L2 protocol (like PROFINET DCP): requires `--iface eth0` for live send (AF_PACKET)
- GOOSE frames fully parseable by Wireshark (goose dissector), Zeek iec61850 analyzer,
  and all OT NSM tools that inspect EtherType 0x88B8
- Stealth mode works: no ICSFORGE tag in GOOSE frames when `--no-marker` is used
- IED reference, GCB suffix, APPID, stNum, and voltage all configurable via UI params
- T0855 and T0813 updated in technique_support.json: now classified as `runnable`

### Scenario count
175 → **179 scenarios** across 10 protocols

### UI fixes (post-initial implementation review)

- **Payload preview broken for IEC 61850**: `api_preview_payload` had a hardcoded
  builder list that omitted `iec61850`. All four scenarios returned `proto=None`.
  Fixed: added `iec61850` to builders, ports, L2 proto set, and marker encoding path.
  Now returns `proto=iec61850`, `transport=L2/Ethernet`, correct EtherType `0x88B8`.
- **Protocol badge**: `iec61850` was missing from the `PROTO_C` colour map in
  `sender.js` — scenarios showed grey dots in the scenario list. Fixed: added
  `iec61850: "#16a34a"` (power-sector green, distinct from the iec104 green).
- **Port display**: L2 protocols have `port=0` — rendered as "L2/Ethernet 0" in
  the hex dump meta. Fixed: port number only shown when non-zero.

### Verified
- All 179 scenarios generate without error
- All 4 GOOSE styles: correct EtherType 0x88B8, DST multicast MACs, BER-encoded PDU
- Smoke test: 35/35 PASS
- Syntax: 0 errors

## v0.51.0 (2026-04 — Stealth mode, Ruff cleanup, protocol authenticity)

### New: Stealth mode — 100% real protocol traffic

Every packet ICSForge generates normally embeds an `ICSFORGE_SYNTH|run-id|technique|step`
correlation tag in the payload (enabling receiver confirmation). This makes packets
detectably synthetic — a real Modbus FC03 read is 12 bytes; the tagged version is 57+.

Stealth mode removes all tags. Packets are byte-for-bit identical to what genuine
PLCs, RTUs, and engineering workstations generate. Validated:

- Normal PCAP: 4781B · Stealth PCAP: 2562B (marker overhead fully eliminated)
- `ICSFORGE` tag present in normal PCAP: True; in stealth PCAP: False
- All 9 protocols produce structurally valid frames in both modes

**Confirmation in stealth mode:** Instead of receiver marker detection, the sender
tracks TCP ACK delivery per step. Any technique whose TCP connection completed
without error is counted as network-confirmed and shown in the Live Attack Timeline.
This is at least as meaningful as marker-based confirmation and requires no ICSForge
receiver running.

**Where to enable:**

*Sender UI* — new `Stealth mode — real traffic, no synthetic tags` toggle in the
Configuration card. When active it turns red and a `STEALTH` badge appears in the
Live Attack Timeline header. Confirmation counts via TCP ACK automatically.

*CLI:*
```
icsforge send     --name T0855__unauth_command__modbus --dst-ip 10.0.0.50 \
                  --confirm-live-network --no-marker
icsforge generate --name CHAIN__industroyer2__power_grid --outdir out/ --no-marker
```

*API:* `no_marker: true` in the body of `POST /api/send`, `POST /api/generate_offline`,
`POST /api/technique/send`.

### Protocol authenticity (all 9 protocols)

All protocols produce structurally correct frames as verified by field parsing:
- Modbus/TCP: valid MBAP (protocol=0, correct length) + correct function codes
- DNP3: correct 0x0564 start bytes, CRC16 computed per 16-byte block per spec
- IEC 60870-5-104: correct 0x68 APCI start, valid APDU type IDs
- S7comm: correct TPKT version=3 + COTP + S7 protocol_id=0x32
- EtherNet/IP: correct encapsulation commands (0x0063/0x006F), CIP service codes
- BACnet/IP: correct BVLC 0x81, NPDU version=1, APDU type/service IDs
- MQTT: valid CONNECT with protocol "MQTT" and level 4 (v3.1.1)
- PROFINET DCP: FrameID 0xFEFE, service ID 0x05, AF_PACKET raw socket
- OPC-UA: correct message type codes (HEL/OPN/MSG), valid length fields

Live sends use real TCP/UDP OS sockets — the OS handles full TCP handshake.
Zeek, Suricata, and OT-aware NSMs parse these as real protocol traffic.

### Ruff cleanup (v0.50.8)

External developer pass: import ordering, unused import removal, context manager
fixes, `collections.abc.Callable` modernisation, `__all__` added to `helpers.py`.
One genuine bug fixed: `_parse_node_numeric()` in `opcua.py` used `rnd` (local
variable inside `build_payload`) instead of `random`.

### Bug fixes across v0.50.x

- `CampaignRunner` was never imported in `bp_campaigns.py` — campaigns never worked
- Timeline "0 confirmed" race: isTempId pattern now accepts technique-only matching
- Matrix overlay showed nothing for campaign/chain runs (events file has no
  `mitre.ics.technique`; meta.techniques fallback added)
- Coverage report `run_full` techniques from events file, not just receipts
- `api_generate_offline` always assigns meaningful run_id and registers in SQLite
- `toggleConfirm()` and `toggleStealth()` were called but never defined in HTML
- T0890 OPC-UA crash: `_parse_node_numeric()` handles `ns=2;i=1001` format
- `fire_webhook` missing import in `bp_config.py` (test_webhook always 500)
- Credentials now in `out/.credentials.json` — reset on reinstall (was `~/.icsforge/`)
- Matrix overlay light-theme: technique name no longer turns white

### Verified
- Syntax: 0 errors across all 58 Python files
- App startup: 67 routes (56 API)
- Smoke test: 35/35 PASS
- All 175 scenarios generate without error
- All 9 protocols: structurally valid frames confirmed by field parsing
- Auth: setup, login, rate limiting, reinstall all correct
- Stealth mode: PCAP clean, techniques tracked, TCP ACK confirmation working
- All web pages: /, /sender, /matrix, /campaigns, /report, /tools
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`

## v0.50.9 (2026-04 — Stealth mode: real protocol traffic without synthetic tags)

### New feature: Stealth mode / no-marker traffic generation

By default, every ICSForge packet embeds a correlation tag
(`ICSFORGE_SYNTH|run-id|technique|step`) in the payload so the receiver can
confirm delivery. This makes packets detectably synthetic — a real Modbus FC03
read is 12 bytes; the marked version is 57.

Stealth mode omits the tag entirely. Packets are bit-for-bit identical to what a
genuine PLC, RTU, or engineering workstation would generate. This is useful for:

- IDS/NGFW/SIEM validation without triggering synthetic-traffic signatures
- Red team exercises where traffic authenticity matters
- Testing detection rules on real protocol frames
- Generating reference PCAPs that match legitimate device captures

**Trade-off:** With no marker, the ICSForge receiver has nothing to detect.
Receiver confirmation will show 0. ATT&CK technique coverage is still tracked
through the events file (the engine knows which techniques were sent regardless).

#### Where to enable

**Sender web UI** — new toggle button in the Configuration card:
`○ Stealth mode — real traffic, no synthetic tags`
When active, it turns red and a `STEALTH` badge appears in the Live Attack
Timeline header.

**CLI** — `--no-marker` flag on both `send` and `generate`:
```
icsforge send --name T0855__unauth_command__modbus --dst-ip 10.0.0.50 \
    --confirm-live-network --no-marker

icsforge generate --name CHAIN__industroyer2__power_grid \
    --outdir out/stealth --no-marker
```

**API** — `no_marker: true` in the JSON body of:
- `POST /api/send`
- `POST /api/generate_offline`
- `POST /api/technique/send` (matrix page)

#### Implementation

- `no_marker` parameter added to `run_scenario()` in `engine.py` and
  `send_scenario_live()` in `sender.py` — all three protocol branches
  (TCP, UDP, Profinet/L2) pass `b''` as the marker when enabled
- All call sites in `bp_scenarios.py` forward the flag correctly
- ATT&CK technique events are still written to the JSONL events file;
  technique coverage reporting, matrix overlay, and the coverage report
  all work identically in stealth mode

#### Verified
- Normal PCAP: 4695B  Stealth PCAP: 2526B (2169B marker overhead removed per scenario)
- `ICSFORGE` tag present in normal PCAP: True; in stealth PCAP: False
- Technique coverage identical in both modes: T0855 tracked in both
- Chain runs (5 techniques, Industroyer2) — no tag, all techniques tracked
- Smoke test: 35/35 PASS
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`

## v0.50.8 (2026-04 — Ruff cleanup pass)

External developer Ruff cleanup applied across 22 files. No behavioural changes
except one genuine bug fix.

### Bug fix
`opcua.py` — `_parse_node_numeric()` used `rnd.randint()` in its default-value
fallback path. `rnd` is a local variable inside `build_payload()` and is not
visible to the helper function defined outside it. Corrected to `random.randint()`.
This was a latent F821 that would have caused a `NameError` if `_parse_node_numeric`
were called with `val=None` (no `node_id` kwarg provided).

### Additional fix (found during release testing)
`api_generate_offline` only assigned a meaningful run_id when `build_pcap=True`.
Without PCAP, runs silently fell back to `run_id="offline"` and were never
registered in SQLite — so they never appeared in `/api/runs`, the matrix overlay
dropdown, or the coverage report. Fixed: a run_id is now always generated and
the run is always registered in SQLite regardless of whether PCAP is requested.

### Code hygiene (no behaviour change)
- Import ordering (I001) normalised alphabetically across all changed files
- Deferred imports moved to module top (E402): `_rnd`, `_dt`, `_append_run_index`
  in `cli.py`; `Path`, `re` in `bp_scenarios.py`; `yaml`, `send_scenario_live` in
  `runner.py`
- Unused imports removed (F401): `os` from `network_validation.py`, `json` from
  `helpers_stats.py`, `os`/`log` from `bp_detections.py`, `json`/`tempfile` from
  `test_auth.py`, `json`/`queue`/`threading` from `test_sse_campaigns.py`
- Bare `open()` without context manager (SIM115) fixed in `cli.py`, `bp_campaigns.py`
- `with suppress(Exception):` replaces `try/except pass` in `bp_campaigns.py`
- `collections.abc.Callable` replaces deprecated `typing.Callable` in `eve/tap.py`
- Redundant `"r"` mode removed from `open()` in `eve/tap.py`
- `helpers.py` gains `__all__` declaring all intentional re-exports so Ruff treats
  them as public API rather than unused imports

### Verified
- All Python files pass `py_compile` — zero syntax errors
- App starts: 67 routes (56 API)
- Smoke test: 35/35 PASS
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`

## v0.50.6 (2026-04 — Sender layout, PCAP download, campaign registry, matrix, tools)

### Bugfix: credentials persisted across reinstalls

**Root cause:** `~/.icsforge/credentials.json` (user home directory)

The credential file was stored in `~/.icsforge/` — outside the project directory.
Deleting and unpacking a new version left `~/.icsforge/credentials.json` untouched,
so the old username and password from a previous installation were silently reused.
There were no hardcoded credentials; the file was just stored in the wrong place.

**Fix:** Credentials now live at `out/.credentials.json` inside the project directory.
Replacing or deleting the project folder resets the auth state and the setup screen
appears on next launch. The `ICSFORGE_CRED_FILE` environment variable still works as
an explicit override. The `out/` directory is already excluded from tarballs, so
credentials are never shipped. The setup page now shows the credential file location.



### Sender page

**Step Plan moved to right column**
Step Plan now appears in the right column between Scenario Summary and Live Attack
Timeline, keeping related execution context together. Live Receiver Feed moved back
to the left column above the EVE Tap card.

**PCAP Only triggers immediate browser download**
Clicking `⬇ PCAP Only` now generates the PCAP on the server and immediately triggers
a browser file download. Previously the PCAP path was shown in the run log but no
download occurred. The named file (`T0855__unauth_command__2026-04-01__BRAVO.pcap`)
is downloaded directly without any manual path lookup.

### Campaigns → matrix overlay

**Campaign runs now appear in matrix overlay run list**
The campaign runner thread did not write completed runs to either the SQLite registry
or the JSONL run index. After `runner.run()` completes, `bp_campaigns` now calls
`reg.upsert_run()` and `_append_run_index()`, so campaign runs appear in `/api/runs`
and the matrix overlay dropdown alongside chain and single-scenario runs.

### Matrix page

**Technique boxes no longer overlap or clip text**
`overflow: hidden` was removed from `.mc-col` (was clipping tile content). `.mt-name`
now uses `word-break: break-word` and `overflow-wrap: break-word` so long technique
names wrap inside their tiles instead of overflowing. Tile height is `auto` instead
of a fixed minimum.

### Tools page

**PCAP file upload in PCAP Replay**
Added a `Upload PCAP` file picker alongside the path input. Selecting a `.pcap` or
`.pcapng` file and clicking Upload sends it to the new `POST /api/pcap/upload`
endpoint, which saves it to `out/pcaps/uploads/` and fills the path field
automatically. The replay can then be run immediately.

**Selftest and Matrix Status removed from Health section**
`Selftest` requires a live network and running receiver (`--live` flag) — it always
returned an error in the UI tools panel. `Matrix Status` was a confusing diagnostic
output. Both buttons removed. Only `Health` remains, which works in all contexts.

### Dark theme readability

**Muted and dim text lightened throughout**
On the dark theme, `.small` / `.muted` text was too dark to read comfortably
against the dark panel backgrounds:
- `--muted`: `#566882` → `#8499b5` (readable mid-grey-blue)
- `--dim`:   `#2c3a4e` → `#506070` (visible but still subdued)
- `--text`:  `#d4dce8` → `#dce4ef` (slightly crisper primary text)

Applied globally via CSS variables — affects all pages: sender, receiver, matrix,
campaigns, report, tools, home.

### Verified
- All Python files pass `py_compile`
- `create_app()` loads 66 routes
- `/api/pcap/upload` returns `200 {ok, path, filename}` with file data
- Smoke test: 36/36 PASS
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`

 (2026-04 — UI and functional fixes)

### Bugfixes

**Campaigns: playbooks never executed (root cause fix)**
`CampaignRunner` was missing from the import in `bp_campaigns.py`. Every playbook
run hit a `NameError` server-side the moment it tried to instantiate the runner —
no SSE stream ever started, no steps progressed, no result appeared. Fixed: one
missing import added.

**Timeline "0 confirmed by receiver" despite live receipts**
Race condition: `tlStart()` set a temporary run ID (`selectedName + "_" + timestamp`)
before the API call returned the real server-assigned run ID. SSE receipts arrived
carrying the real ID and were silently dropped by `tlConfirmStep` because the IDs
didn't match. Fixed: temp IDs are detected by their format and the match falls back
to technique-only while the temp ID is still active.

**Matrix fired runs invisible in overlay dropdown**
`api/technique/send` wrote runs to the JSONL index only, not to SQLite. `api/runs`
reads SQLite first. Matrix-fired runs therefore never appeared in the run list or
overlay selector. Fixed: added the same SQLite `upsert_run` block used by `api/send`.

**Matrix overlay: name turns white in light theme**
`.mt.executed .mt-name` was hardcoded to `#ecfdf5` (near-white), invisible on the
light theme. Fixed: replaced with `var(--text)` so it adapts to the active theme.

### Improvements

**Sender: Attack Chains shown first in scenario list**
Chains already appeared first in the grouped API, but this confirms the correct
rendering order in the sender scenario picker.

**Sender: ATT&CK for ICS tactic ordering corrected**
Previous order: Discovery → Collection → Lateral Movement → Execution (arbitrary).
Correct order per MITRE ATT&CK for ICS: Initial Access → Execution → Persistence
→ Evasion → Discovery → Lateral Movement → Collection → Command and Control →
Inhibit Response Function → Impair Process Control → Impact → Privilege Escalation.

**Sender layout: Live Attack Timeline and Live Receiver Feed moved to right column**
Both cards now appear in the right column below Scenario Summary, keeping the
left column focused on scenario selection, configuration, step plan, and run controls.

**Coverage report: "All runs combined" option**
The run reference dropdown now includes a `★ All runs combined` entry at the top
(when more than one run exists). Selecting it fetches every run's techniques in
parallel and unions them into the Executed field, giving a single cumulative report
across all assessment activity.

**Pull mode: description corrected**
Removed the inaccurate OT firewall framing. Pull mode description now accurately
states the actual use case: sender polls the receiver when the sender has no
reachable callback address (NAT, no public IP, receiver cannot initiate outbound).

### Verified
- All Python files pass `py_compile` — zero syntax errors
- `create_app()` loads 66 routes
- Smoke test: 36/36 PASS
- Tactic order: Chains → Initial Access → Execution → Persistence → Evasion → Discovery → Lateral Movement → Collection → C2 → Inhibit → Impair → Impact
- Campaign playbook SSE stream confirmed functional (was never working before)
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`

 (2026-04 — UI reliability pass)

Every panel button that landed without browser testing was audited against the live API.
Three panels were broken in ways that were invisible from the backend but would have been
obvious the first time an operator clicked a button.

### Root cause: SQLite artifact paths invisible to UI endpoints

`RunRegistry.get_run()` returns artifacts as a structured list:
```json
{"artifacts": [{"kind": "events", "path": "…"}, {"kind": "pcap", "path": "…"}]}
```

Three UI-facing endpoints read `idx.get("events")` — a flat key that only exists on
the legacy JSONL index format, not on SQLite results. For any run registered via
`icsforge send` or the web sender (i.e. all runs since v0.49), those endpoints saw
`None` and either returned 400 or silently built an empty export bundle.

**`POST /api/validate` — Run Management panel "Validate" button**
- Read `idx.get("events")` → `None` for SQLite runs → `400 Ground-truth events path not found`
- Fixed: checks `artifacts` list first, falls back to flat key
- Also fixed: if `receiver_out/receipts.jsonl` doesn't exist yet (fresh install), now
  creates an empty file rather than raising `OSError`. Validate completes with a
  "receipts empty" warning in the report instead of crashing.

**`GET /api/run/export_bundle` — Run Management panel "Export" button**
- Read `idx.get("events")` and `idx.get("pcap")` → both `None` → zip created but empty
- Fixed: resolves artifact paths from `artifacts` list via a `_artifact_path(kind)`
  helper before falling back to flat keys

**`GET /api/run_full` — run detail view used by the history panel**
- Returned `events: null`, `pcap: null` for all SQLite runs
- Fixed: `events` and `pcap` fields now resolved from `artifacts` list

### Verification

All three previously broken actions confirmed working with real SQLite-registered runs:

| Panel button | Before | After |
|---|---|---|
| Validate | 400 for all real runs | 200 with report |
| Correlate | 400 for all real runs | works (was already correct in code) |
| Export | 200 but empty zip | 200 with events + pcap in zip |
| Run Full detail | events/pcap null | paths resolved correctly |
| Rename | working | still working |
| Tag | working | still working |
| EVE tap arm/disarm | working | still working |
| Webhook save/load | working | still working |

Full panel verification: **16/16 PASS** with real run data.

### Verified clean
- All Python files pass `py_compile`
- `create_app()` loads 66 routes
- Smoke test: 36/36 PASS
- 16/16 panel wiring checks PASS with real SQLite-registered run
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`

 (2026-04 — Live CLI send artifact pipeline fully fixed)

### Root cause found and fixed: empty events / no PCAP on live CLI send

The developer reproduced the failure with `T0801__monitor_process__modbus_poll`,
which has 3 steps × (20+15+15=50 steps) × 0.5 s interval = **25 seconds** of sleep
during ground-truth PCAP generation. This sleep happened *after* the live send
(which correctly paced its own traffic), making the ground-truth generation phase
unnecessarily slow and interruption-prone.

**Root cause in `engine.py`**: when `cmd_send` called `run_scenario` with
`build_pcap=True`, the PCAP building phase slept `interval × count` seconds per step
to match the live traffic pacing. A KeyboardInterrupt during those sleeps would:
1. Exit the step loop mid-way (partial or zero events, depending on timing)
2. Skip `write_pcap()` entirely (no PCAP file)
3. Propagate past `cmd_send`'s `except Exception` handler (which only catches
   `Exception`, not `BaseException`) leaving the run unregistered

**Three coordinated fixes**:

1. **`run_scenario()` gains `skip_intervals: bool = False` parameter**
   When `True`, all `time.sleep(interval)` calls in the PCAP-building loop are
   skipped. The live send already paced the traffic; the offline ground-truth PCAP
   is just a reference artifact and needs no pacing.

2. **`cmd_send` passes `skip_intervals=True`**
   Ground-truth generation for a live send now completes in milliseconds regardless
   of scenario step counts and intervals. T0801 (25 s → <1 s). All 50 events written.
   PCAP generated. Both registered in SQLite and JSONL index.

3. **`cmd_send` catches `KeyboardInterrupt` explicitly**
   A `KeyboardInterrupt` during ground-truth generation is now caught, logged as a
   warning, and the run is still registered in the registry. Previously, Ctrl+C would
   terminate the process before any registry code ran.

**Smoke test updated**: `check_engine_signature()` now verifies `run_scenario` has
the `skip_intervals` parameter as check #2, before any HTTP endpoint tests. This
prevents regressions to the pre-fix behaviour.

### Verified
- `run_scenario` with `skip_intervals=True` on T0801: **0.5 s** (was ~25 s)
- 50/50 events written, PCAP generated, run registered in both SQLite and JSONL index
- Smoke test: **36/36 PASS** (2 structural + 34 endpoint checks)
- All Python files pass `py_compile`
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`

# ICSForge Changelog

## v0.50.2 (2026-03 — CLI/web integration + tooling fixes)

Based on a full end-to-end review of v0.50.1 against a real running environment:
live sender→receiver→callback flow, real web app launch, full pytest suite.

### Additional fixes (second review pass)

**Empty events file on live CLI send — root cause and fix (`icsforge/scenarios/engine.py`)**
The confirmed root cause: `run_scenario()` wrote events **after** building pcap packets
in the step loop. If the pcap-building block raised (unknown proto) or was interrupted
(long interval sleeps on large scenarios like T0801 with 50 steps × 0.5 s = 25 s),
the file was left with 0 lines because `ef.write()` had not yet run.

Fix: events are now written **first** in each step iteration, followed by an `ef.flush()`,
before any pcap building. A pcap build failure can no longer produce an empty events file.
The `raise ValueError` for unknown proto is now a `log.warning` with graceful continuation.

**SQLite `ResourceWarning: unclosed database` in tests**
`RunRegistry._conn()` returned a bare `sqlite3.Connection`. Using it as a context manager
(`with self._conn() as c:`) commits/rolls back but does not close the connection — Python
defers closing until GC, emitting a `ResourceWarning`. Fixed: `_conn()` now returns a
proper `contextlib.contextmanager` that commits, rolls back on exception, and explicitly
closes the connection in a `finally` block. Verified: no `ResourceWarning` raised under
`warnings.simplefilter('error', ResourceWarning)`.

**CLI: explicit empty-events detection and warning**
After `run_scenario()` completes, `cmd_send` now counts lines in the events file and
logs a `WARNING` with a clear explanation if it is empty, rather than silently producing
a broken artifact.

### Additional fixes (post-review patch)

**Pull mode `urllib.request` crash (thread exception)**
`icsforge/web/helpers_sse.py` imported `urllib.parse` but used `urllib.request` in
the `_pull_worker()` background thread. Unlike the main process (which may have
`urllib.request` accessible as a side-effect of other imports), the thread hit an
`AttributeError: module 'urllib' has no attribute 'request'`, producing a
`PytestUnhandledThreadExceptionWarning` and silently breaking the pull-mode feature.
Fixed: `import urllib.request` added explicitly.

**CLI `icsforge send` artifact path reliability**
Three improvements to make `icsforge send` work correctly in all environments:

1. `--file` and `--outdir` are now resolved to absolute paths at the start of both
   `cmd_send` and `cmd_generate`. If the default relative path `icsforge/scenarios/
   scenarios.yml` does not exist from the working directory (e.g. when running from
   outside the repo), the installed package path is used as a fallback.

2. `run_scenario()` is now wrapped in `try/except Exception` with explicit
   `log.error(...)` output. Previously a failure here was silent; now it surfaces
   immediately with a clear message.

3. The SQLite registry exception catch was `(OSError, ValueError)` — too narrow.
   `sqlite3.OperationalError` inherits from `sqlite3.Error` → `Exception`, not from
   `OSError` or `ValueError`. Registry failures were still silently swallowed in some
   environments. Fixed: catch broadened to `(OSError, ValueError, sqlite3.Error)`.

### Fix: CLI live-send runs now appear in the web run registry

`icsforge send` was silently swallowing all registry errors with a bare
`except Exception: pass` block. Registry failures were invisible; if SQLite
was unavailable or the path differed, the run was registered nowhere.

Two changes:

1. The `except Exception: pass` is replaced with a typed `except (OSError, ValueError)`
   that logs a `WARNING` instead of discarding the error silently.
2. After attempting SQLite registration, `cmd_send` now **always** writes the run to
   the JSONL index (`_append_run_index`). The JSONL index is the web UI's fallback when
   SQLite is unavailable, so CLI runs now show up in `/api/runs` via either path.

### Fix: `net-validate` warns loudly on empty events or receipts

When `icsforge net-validate` was given an empty events file (as happens with a live run
where ground-truth was not generated), it silently produced a report with empty
`expected_techniques` lists. The problem was invisible unless you inspected the JSON
carefully.

Now `build_network_validation_report()` logs a `WARNING` and includes a `"warnings"`
list in the report JSON explaining what is missing and why, with a suggested remedy.
Empty receipts also trigger a warning.

### Fix: duplicate `import argparse` in `receiver.py`

A double import left by an earlier automated fix. Removed.

### Fix: `RuntimeWarning` on `python -m icsforge.web` (partial)

The warning fired when `icsforge/web/__main__.py` imported from `.app` at module
level. Fixed by deferring the import to inside `main()`.

`python -m icsforge.web` (the recommended and documented launch path) is now
clean. `python -m icsforge.web.app` still emits the warning — this is a Python
`runpy` limitation when a submodule is also a package member; it cannot be
eliminated without moving `app.py` outside the package. The `icsforge-web`
entry-point script and `./bin/icsforge web` are both clean.

### Fix: `pytest -q` hang when `pytest-cov` is installed

`pytest -q` without `--no-cov` would hang at the end in environments where
`pytest-cov` is installed but no coverage config is active. Added `-p no:cov` to
`[tool.pytest.ini_options] addopts` in `pyproject.toml`. The full suite now
completes cleanly with `273 passed`.

### Fix: alerts ingest path restriction not communicated in UI

The `POST /api/alerts/ingest` backend correctly restricts paths to inside the repo
or `/var/log/suricata`. Operators hitting the 400 error had no in-UI explanation.
Added a visible warning box to the Tools page alerts card explaining the restriction
and showing an example allowed path (`out/alerts/suricata_eve.json`).

### Fix: duplicate `import urllib` in `helpers.py` and `helpers_sse.py`

Both files had `urllib` imported twice from different earlier fix passes. Deduplicated.

### Fix: further unused imports removed

- `warnings` (added by automation, unused) from `network_validation.py`
- `collections` (unused) from `bp_receiver.py`
- `Response` (unused) from `bp_scenarios.py`
- `_correlate_run_impl` (unused re-export) from `helpers.py`

### Known limitations (documented, not fixed in this release)

**Live-send PCAP with intervals**: scenarios with large `count × interval` products
(e.g. T0801 with 50 steps × 0.5 s = 25 s) will make `run_scenario` take that long
to generate the ground-truth PCAP, because packet-building respects the defined
pacing. This is correct behaviour for offline replay fidelity but surprising for
live-send users who just want the PCAP quickly. A `--no-intervals` flag for
ground-truth generation is on the backlog.

**selftest without --live**: exits with `"Selftest currently supports --live only."`.
A dry-run mode that validates config without network is on the backlog.

**Browser automation**: no automated end-to-end browser tests. Manual click-through
of all UI flows on each release remains a manual step.

### Verified clean
- All Python files pass `py_compile`
- `create_app()` loads 66 routes — zero import errors
- Smoke test: 36/36 PASS
- Zero duplicate imports across codebase
- Zero non-intentional inline imports
- `pytest -q` (with `-p no:cov`): 273 passed
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`



## v0.50.1 (2026-03 — Launcher fix + full import cleanup + self-review fixes)

### Critical: launcher bug fixed (introduced in v0.50.0)
`main()` in `icsforge/web/app.py` was constructing a bare Flask app with only the `web`
page blueprint registered. Every API route returned 404 in production. Fixed: `main()`
now calls `create_app()`. All launch paths confirmed equivalent.

The smoke test's `check_launcher()` AST check now runs first and catches any future
reversion to the partial-app pattern before packaging.

### Bugs found and fixed by self-review

**Offline events missing `run_id` field (`icsforge/scenarios/engine.py`)**
`engine.py` only wrote `run_id` into generated events when a truthy `run_id` was passed.
The CLI `generate` command passes `None`, so all offline-generated events were missing
`run_id`. This would cause `net-validate` to find zero matches when correlating against
offline artifacts, because the correlation reads `run_id` to match events to receipts.
Fixed: the resolved `rid` value (`"offline"` when no `run_id` given, or the actual
run_id otherwise) is now always written into every event.

**Health endpoint missing `version` field (`icsforge/web/bp_config.py`)**
`GET /api/health` returned `ok`, `capabilities`, `timestamp`, and system metadata but
no version string. Any integration polling the health endpoint to check the deployed
version would get nothing. Fixed: `"version": __version__` added to the response.

**Inline `import socket as _s` inside `api_health()` function**
`socket` was imported inside the function body rather than at module scope, inconsistent
with the import hygiene work done in this release series. Fixed: `import socket` moved
to module top, `socket` used directly throughout.

### Import cleanup sprint
Every non-intentional function-scoped import moved to module scope. Zero non-intentional
inline imports remain. Smoke test covers 36 checks (35 endpoints + 1 launcher structural
check via AST).

### selftest --live improvements
`--no-web` passed to receiver subprocess; receipts path resolved to absolute path;
explicit `CAP_NET_RAW` warning emitted when running without root privileges.

### Verified clean (post-self-review)
- All Python files pass `py_compile` — zero syntax errors
- `create_app()` loads 66 routes (55 API + 9 page + static)
- Smoke test: 36/36 PASS including launcher structural check
- Non-intentional inline imports: **0**
- `GET /api/health`: returns `ok`, `version`, `capabilities`, `timestamp`
- `icsforge generate`: events always contain `run_id` and `mitre.ics.technique`
- Auth layer: public paths exempt, protected routes block unauthenticated access
- EVE tap, webhook, report download, detection download, campaigns: all confirmed working
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`, 145 files

### Known limitations (not bugs, documented)
- `selftest --live` requires root or `CAP_NET_RAW` to bind ICS protocol ports (502,
  20000, 44818, etc.). A warning is emitted but the test will still fail without
  the capability regardless.
- The smoke test verifies the factory path (`create_app()`) and the launcher
  structural correctness via AST, but does not spawn a real server process.
  An integration test that starts the actual server over a real port remains a
  backlog item.



## v0.50.1 (2026-03 — Launcher fix + full import cleanup)

### Critical: launcher bug fixed (introduced in v0.50.0)
`main()` in `icsforge/web/app.py` was constructing a bare Flask app with only the `web`
page blueprint registered. Every API route returned 404 when launching via `icsforge-web`,
`python -m icsforge.web`, `python -m icsforge.web.app`, or `./bin/icsforge web`. Tests
passed because they used `create_app()`. The fix: `main()` now calls `create_app()`.

The smoke test has been hardened with a structural AST check (`check_launcher()`) that
runs first and verifies `main()` calls `create_app()` and does not instantiate its own
`Flask()`. This check would have caught v0.50.0 before packaging.

### Import cleanup — zero non-intentional inline imports
Every non-intentional function-scoped import has been moved to module scope:

- `icsforge/web/app.py`: `argparse`, `configure_logging`, inline `json`/`yaml` in
  page routes moved to module top; `_canonical_scenarios_path`, `_registry` removed
  (unused). Blueprint imports inside `create_app()` remain inline — they are
  intentional circular-dependency guards.
- `icsforge/web/bp_campaigns.py`: `CampaignRunner`, `CampaignValidationError` moved
  to module top; duplicate inline instance removed.
- `icsforge/web/bp_config.py`: duplicate inline webhook helper imports removed
  (already at module top).
- `icsforge/web/bp_scenarios.py`: inline `yaml` in `api_profiles()` moved to module
  top; unused `Response` removed.
- `icsforge/web/helpers.py`: `urllib.request` moved to module top.
- `icsforge/web/helpers_sse.py`: `queue` moved to module top.
- `icsforge/campaigns/runner.py`: `send_scenario_live` moved to module top; spurious
  `Path` import removed.
- `icsforge/eve/tap.py`: remaining inline `re` removed (already at module top).
- `icsforge/receiver/receiver.py`: `argparse`, `sys`, `configure_logging` moved to
  module top; indentation regression from regex fix corrected.

### selftest --live fixes
Three issues made `icsforge selftest --live` unreliable without root:
1. Receiver subprocess was started without `--no-web`, causing it to try binding
   port 9090 and potentially failing before writing any receipts.
2. Receipts path was relative to the calling process CWD, not the receiver subprocess
   CWD — causing the existence check to look in the wrong place.
3. No warning when running without root/CAP_NET_RAW, leaving operators confused.

Fixed: `--no-web` now passed to receiver subprocess; receipts path resolved to
absolute using `os.path.abspath(args.cwd)`; explicit warning emitted if `os.geteuid() != 0`.

### Verified clean
- All Python files pass `py_compile` — zero syntax errors
- `create_app()` loads 66 routes (55 API + 9 page + static)
- Smoke test: 36/36 PASS (35 endpoints + 1 launcher structural check)
- Non-intentional inline imports: **0**
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`, 145 files



## v0.50.1 (2026-03 — Critical launcher fix)

### Critical fix: real web server was missing all API routes

**`main()` in `icsforge/web/app.py` was building a partial Flask app** that registered
only the `web` page blueprint, not the seven API blueprints. This meant:

- `python -m icsforge.web.app` — broken
- `python -m icsforge.web` — broken  
- `icsforge-web` entry point — broken
- `./bin/icsforge web` — broken

Every API-driven UI action returned 404 in production. Tests and the smoke test
passed because they used `create_app()` which was correct. The launcher did not.

**Fix**: `main()` now calls `create_app()` instead of constructing its own Flask app.
Three lines replaced a twelve-line manual construction block. All launch paths
(`python -m`, entry point script, shell launcher) now register all 55 API routes.

The bug was present in v0.50.0 despite the smoke test passing — because the smoke
test also used `create_app()`. The smoke test has been updated to explicitly verify
that `main()` delegates to `create_app()` as its first check, so this class of
regression will be caught before packaging in future.

### Smoke test hardened (`scripts/smoke_test.py`)

Added `check_launcher()` as the first check in the smoke test suite. It parses
`app.py` with the AST and verifies that `main()` calls `create_app()` and does not
instantiate its own `Flask()`. This check now runs before any HTTP endpoint test and
will catch any future regression to the partial-app pattern.

Smoke test now covers 36 checks total (35 endpoint + 1 launcher structural check).

### Verified clean
- All Python files pass `py_compile`
- `create_app()` and `main()` both register 55 API routes and 9 page routes (66 total)
- Smoke test: 36/36 PASS including launcher structural check
- `main()`: zero `Flask()` calls, zero `secrets` references — fully delegated to factory
- All launch paths confirmed equivalent: `icsforge-web`, `python -m icsforge.web`,
  `python -m icsforge.web.app`, `./bin/icsforge web`
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`



## v0.50.0 (2026-03 — Code Quality + Complete UI Coverage)

### Import hygiene sprint
Every blueprint now has its dependencies declared at module scope, eliminating the
function-scoped import pattern that caused five separate runtime NameErrors across
v0.49.x. Specific changes:

- `bp_reports.py`: `generate_report` moved to module scope; `datetime` moved to module scope
  replacing the inline `import datetime as _dt` alias inside `api_report_heatmap()`
- `bp_detections.py`: `generate_all` moved to module scope; `Response` removed (unused)
- `bp_reports.py`: removed `_supported_techniques`, `_tech_name`, `MATRIX_JSON_PATH`,
  `MATRIX_SINGLETON_PACK` — none referenced in the file body
- `bp_config.py`: removed `_canonical_scenarios_path`, `_is_safe_private_ip`,
  `_load_persisted_config`, `MATRIX_SINGLETON_PACK`, `__version__` — all unused
- `bp_receiver.py`: removed `_repo_root`, `_stats_from_receipts` — unused
- `bp_runs.py`: removed `_canonical_scenarios_path`, `_load_yaml`, `_run_index_path`,
  `_save_run_index`, `_stats_from_receipts`, `_supported_techniques` — unused
- `bp_scenarios.py`: removed `Response`, `stream_with_context`, unused `_h` alias
- `bp_campaigns.py`: removed unused `_h` alias and lingering `import yaml as _yaml`
  local alias inside `api_campaigns_list()`
- `core.py`: `import re` moved from inside `is_legacy_run_id()` to module top
- `helpers_sse.py`: `import urllib.request` moved from inside `_pull_worker()` to module top
- `eve/tap.py`: `import re` moved from inside `_process_alert()` to module top

### Pre-release smoke test (`scripts/smoke_test.py`)
New developer tool that exercises 35 endpoints in a test Flask app and fails loudly
on any HTTP 500. Covers all pages, all major APIs including the three that were broken
in v0.49.2 (marked ★ in output), EVE tap, campaigns, reports, and detections.

Run before every release:
```bash
python scripts/smoke_test.py          # dots for pass, detail on fail
python scripts/smoke_test.py --verbose # show every endpoint result
```

This is the gate that would have caught every runtime regression in the v0.49 series
before packaging.

### Alerts ingest UI (Tools page)
`POST /api/alerts/ingest` existed since v0.43 with no UI surface. Added to the Tools
page as a card with path input, optional run ID, and Suricata EVE / Generic profile
selector. Output path shown on completion. Closes the last CLI-only analysis workflow.

### Coverage heatmap direct link (Tools page)
`GET /api/report/heatmap` was accessible only by URL. Added a direct download button
to the Tools page alongside a link to the Custom Report Builder, making it
discoverable without reading the docs.

### Verified clean
- All 47 Python files pass `py_compile` — zero syntax errors
- `create_app()` loads 66 routes, zero import errors
- Smoke test: 35/35 PASS — zero 500s
- 10/10 UI feature checks PASS
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`

### Backlog (next cycle)
- Ruff full cleanup to zero warnings (import ordering, remaining style items)
- Coverage trend tracking over time (`GET /api/coverage/trend`, line chart on report page)
- Scenario scheduling — cron-style campaigns, background thread, drift detection
- STIX 2.1 bundle export (`GET /api/run/{id}/stix`)
- Zeek script output alongside Suricata/Sigma
- Multi-user auth with roles (viewer/operator/admin)



## v0.49.3 (2026-03 — Detection/Report fixes + Run Management UI)

### Runtime bug fixes (were returning 500 on every call)

**`GET /api/detections/download` — NameError: `generate_all` not defined**
`generate_all` was imported inside `api_detections_preview()` only. The sibling route
`api_detections_download()` called it without importing it, crashing on every request.
Fixed by moving the import to module scope in `bp_detections.py`.

**`POST /api/report/download` and `GET /api/report/heatmap` — NameError: `generate_report` not defined**
Same pattern: `generate_report` was imported inside `api_report_generate()` only. Both
`api_report_download()` and `api_report_heatmap()` called it without importing it.
Fixed by moving the import to module scope in `bp_reports.py`.

All three of these are operator-facing buttons — the Detection Rules download button on the
Tools page, the Download Report button on the Coverage page, and the one-click Heatmap export.
All confirmed returning 200 after the fix.

### New UI: Industry profile filter on Campaigns page

The Sender dashboard has had a profile selector (Oil & Gas, Power, Manufacturing, Food & Beverage)
since v0.47, filtering the scenario list to sector-relevant techniques and protocols. The Campaigns
page had no equivalent — you could not filter chains by industry context before running them.

Added to campaigns page left column:
- `camp_profile_select` dropdown, populated dynamically from `GET /api/profiles`
- `filterByProfile()` filters the Attack Chains list to chains that match the profile's protocol
  and technique sets — same logic as the sender's `activeProfile` filter
- Sector description shown below the selector when a profile is active
- Chains that don't match the profile are hidden; a "no matches" message shows if all are filtered

### New UI: Run Management panel on Sender page

Clicking any run in Recent Runs now opens a management panel (previously only copied the run_id
to the clipboard with a toast). The panel surfaces four API endpoints that existed but had no UI:

- **Rename** — `POST /api/run/rename` with a title input field
- **Validate** — `POST /api/validate`; shows delivery percentage on completion
- **Correlate** — `POST /api/correlate_run`; shows detection coverage ratio and gap count
- **Export bundle** — `GET /api/run/export_bundle`; triggers browser download of the ZIP
- **Tags** — `POST /api/run/tag` with a comma-separated input; saves and confirms

The panel slides in below Recent Runs when a run is selected and shows the run_id in monospace
for reference.

### Verified clean
- All 47 Python files pass `py_compile`
- `create_app()` loads 66 routes — zero import errors
- 9 endpoint checks: all PASS including the 3 previously-broken report/detection routes
- 16 UI feature checks: all PASS
- 0 `__pycache__`, 0 `*.egg-info`, 0 `out/` in tarball



## v0.49.2 (2026-03 — Runtime Bug Fix Release)

This is a targeted fix release addressing every defect identified in the v0.49.1 review.
No new features. The goal was a clean, honest pass on all developer-reported findings.

### Runtime NameError fixes (were crashing endpoints)

**`_active_eve_tap_lock` undefined in `bp_config.py`** — The module-level state block
(`_active_eve_tap`, `_active_eve_tap_lock`) was lost during a cleanup pass in v0.49.1.
All three EVE endpoints (`/api/eve/start`, `/api/eve/stop`, `/api/eve/matches`) returned
HTTP 500 on every call. Fixed by restoring the state declarations before the route functions.

**`_append_run_index` undefined in `bp_scenarios.py`** — The import-fix pass in v0.49.1
removed it from the helpers import line but left three call sites in `api_send()` and related
routes. Fixed by adding `_append_run_index` back to the blueprint's helpers import.

**`_yaml` scoping error in `bp_campaigns.py`** — `api_campaigns_run()` referenced `_yaml`
which was only defined inside `api_campaigns_list()` via a local `import yaml as _yaml`.
Every unknown-campaign lookup raised `NameError: name '_yaml' is not defined`. Fixed by
using the module-level `yaml` import (already present) instead of the locally-scoped alias.

### Test fixes

**Rate limiter global state leak** — `_LOGIN_ATTEMPTS` is a module-level dict that persisted
across Flask test instances in the same process. The `test_correct_login_clears_rate_limit`
test was being hit by leftover state from `test_rate_limit_triggers_after_5_failures`, causing
a spurious 429. Fixed by adding `_reset_rate_limit()` to `auth.py` and an `autouse` pytest
fixture in `test_auth.py` that clears the dict before and after every auth test.

**Campaign field name mismatch** — `test_campaign_run_rejects_unknown_name` sent
`{"name": "..."}` but the API reads `campaign_id`. The route was returning 400
(missing required field) rather than 404 (campaign not found). Fixed the test to use
`campaign_id` and include the required `dst_ip`, aligning with the actual API contract.

### Import cleanup

Removed dead imports introduced by earlier fix passes:
- `import yaml` from `bp_config.py`, `bp_reports.py`, `bp_runs.py` — none referenced
- `import time` from `bp_scenarios.py` — not used
- `import threading`, `from contextlib import suppress`, `import yaml` from `helpers.py`
  — all three had zero non-import uses in the shim module itself
- `yaml` from `bp_config`'s helpers import line — used nowhere in that file

### Verified clean
- `python3 -m py_compile` passes on all 47 Python files — zero syntax errors
- `create_app()` loads 66 routes with zero import errors
- All 6 previously-failing endpoints confirmed working:
  `eve/stop`, `eve/matches`, `eve/start`, campaign 404, `api/send` step_options
- Rate limiter: correct lockout after 5 failures, correct reset on success
- No `__pycache__`, no `*.egg-info` in the release tarball



## v0.49.1 (2026-03 — Integration Fix Release)

### Breaking regression fixed
- **App startup was broken in v0.49.0.** Six blueprints (`bp_scenarios`, `bp_campaigns`, `bp_receiver`, `bp_reports`, `bp_detections`, `bp_runs`) imported `os`, `json`, `yaml`, `time` etc. through `icsforge.web.helpers` — a pattern the helpers split made fragile. `time` was never re-exported from the new shim, causing `ImportError` at `create_app()` before any route could load. Fixed by giving every blueprint its own direct stdlib imports. `helpers.py` no longer acts as a stdlib distribution hub.

### Additional fixes
- **Duplicate EVE routes**: `bp_config.py` had `/api/eve/start`, `/api/eve/stop`, `/api/eve/matches` registered twice due to a double-append in v0.49.0. Removed duplicate block; one definition per route.
- **Duplicate import statements**: the blueprint fix pass introduced duplicate `import` lines in several files. Cleaned; each stdlib module now imported exactly once per file.
- **Campaign validation test**: `test_invalid_delay_produces_warning` expected a warning list but `validate_campaign()` correctly raises `CampaignValidationError` for invalid delays. Test renamed to `test_invalid_delay_raises` and updated to match actual (correct) behaviour.
- **Missing webhook routes**: `POST /api/config/webhook` and `POST /api/config/test_webhook` were present in v0.49.0 only intermittently due to append ordering. Now reliably registered; verified in `create_app()` startup check.

### Security
- **Rate limiting on `/api/auth/login`**: in-memory fixed-window counter per IP address. 5 failures within 60 s triggers a 300 s lockout returning HTTP 429. Remaining-attempts hint included in 401 responses when 1–2 attempts left. Successful login clears the counter. No external dependency — 30 lines of Python in `auth.py`.

### Performance
- **SQLite indexes**: `CREATE INDEX IF NOT EXISTS idx_runs_ts ON runs(created_ts DESC)` and `idx_artifacts_run ON artifacts(run_id)` added to `RunRegistry` schema. `ANALYZE` called after schema init. Eliminates full-table scan on `list_runs()` at scale.

### UI completeness — new features now have Web UI surface
- **EVE tap panel** added to sender left column: path input, Arm/Stop buttons. `armEveTap()` calls `POST /api/eve/start`; `disarmEveTap()` calls `POST /api/eve/stop` and toasts the match count.
- **Webhook panel** added to sender left column: URL input, Save and Test buttons. `loadWebhookConfig()` called on page load to restore persisted URL.
- **Scenario step_options wired**: `doSend()` now calls `_collectStepOptions()` which reads all `param_*` input fields rendered by the params form and includes `step_options: {proto: {key: val}}` in the `/api/send` payload. The params form now actually affects the generated traffic.
- **EVE confirmation loop**: `startEveTapPoll()` polls `/api/eve/matches` every 1.5 s after a run fires. Each new technique match calls `tlConfirmStep()`, updating the live attack timeline with real IDS detection confirmations rather than just delivery receipts.

### Test additions
- `test_auth.py`: `TestAuthRateLimit` — 2 tests covering 429 after 5 failures and counter reset on successful login.
- `test_sse_campaigns.py`: `test_invalid_delay_raises` replaces the incorrect `test_invalid_delay_produces_warning`.

### Verified clean
- `python3 -m py_compile` passes on all 47 Python files
- `create_app()` loads 66 routes with zero import errors
- All blueprint stdlib dependencies are direct imports — no stdlib flows through `helpers.py`
- Rate limiting: PASS; SQLite indexes: PASS; UI panel checks: 10/10 PASS



## v0.49.0 (2026-03 — Quality, Trust, and Closing the Detection Loop)

### Exception handling cleanup
- Replaced all 87 bare `except Exception:` blocks across `bp_runs.py`, `bp_config.py`, `bp_reports.py`, and `helpers.py` with specific exception types (`OSError`, `ValueError`, `json.JSONDecodeError`, `ImportError`, etc.)
- All silently-swallowed errors now log at `debug` or `error` level with context, making field debugging tractable
- Registry fallback paths (SQLite → JSON index) retain their broad catch for resilience, but now log at `debug` level

### Protocol map unified
- `TCP_PROTOS`, `UDP_PROTOS`, and `L2_PROTOS` moved to `icsforge/protocols/__init__.py` as the single source of truth
- `icsforge/scenarios/engine.py` and `icsforge/live/sender.py` now import from there — adding a new protocol requires editing one file, not two

### Helpers split into focused sub-modules
- `helpers_io.py` — file I/O: JSONL, YAML, run index read/write
- `helpers_stats.py` — receipt statistics and timeline binning
- `helpers_sse.py` — SSE push, subscriber lifecycle, pull-mode polling thread
- `helpers.py` is now a thin re-export shim; all existing imports remain unchanged

### JS extraction
- `sender.html` reduced from 787 to 200 lines; 586-line JS block moved to `static/js/sender.js`
- `receiver.html` reduced from 319 to 98 lines; 220-line JS block moved to `static/js/receiver.js`
- Templates now use `<script src="/static/js/...">` — JS is cacheable and diff-readable

### Live Suricata EVE tap (`icsforge/eve/`)
- New `EveTap` class: tails an EVE JSON log file in a background thread, stat-polling with rotation detection
- Correlates alert signatures/SIDs against a technique map (built from ICSForge Suricata rules or provided inline)
- Extracts `T0XXX` technique IDs directly from signature strings as a fallback
- `build_technique_map_from_rules()`: parses ICSForge Suricata rules and produces `{sid: technique}` map
- Three new API endpoints: `POST /api/eve/start`, `POST /api/eve/stop`, `GET /api/eve/matches`
- EVE match events are pushed to the SSE bus with `type: "eve_match"` — the live attack timeline in the sender UI receives them automatically
- Path validation: only allows paths inside the repo `out/` dir, `/var/log/suricata`, `/var/log`, or `/tmp`

### Webhook notifications
- `fire_webhook(event_type, payload)` in helpers — async-free, fire-and-forget POST to configured URL
- `POST /api/config/webhook` — set/get webhook URL
- `POST /api/config/test_webhook` — verify the URL is reachable with a synthetic event
- Supports event types: `run_complete`, `gap_detected`, `campaign_complete`

### Scenario parameter wiring
- `send_scenario_live()` now accepts `step_options: dict | None` — per-protocol overrides passed as kwargs to payload builders
- `POST /api/send` now accepts `step_options` field: `{"modbus": {"address": 100, "quantity": 5}}`
- The params form that previously rendered but had no effect now passes values through to the live send

### Test suite additions
- `tests/test_auth.py` (16 tests): setup flow, login/logout, 401 protection, public path exemptions, regression test for `/api/config/set_callback` being auth-exempt, static file access
- `tests/test_sse_campaigns.py` (21 tests): SSE subscribe/notify/unsubscribe lifecycle, full-queue resilience, pull mode start/stop, campaign validation (valid, missing name, empty steps, bad delay, unknown scenario), campaign API endpoints, webhook config endpoints, EVE tap API, step options field acceptance



## v0.48.1 (2026-03 — Dead Import Cleanup)

### Fixed
- `bp_runs.py`: removed unused imports `io`, `Response`, `RunRegistry`, `default_db_path` — none were referenced in the file body; `_registry()` in helpers already handles registry instantiation
- `app.py`: removed unused imports `json`, `yaml`, `jsonify`, `MATRIX_JSON_PATH`, `MATRIX_SINGLETON_PACK`, `TECH_VARIANTS` — all were imported but never referenced in the module body
- These were the real defects surfaced by the developer's ruff run; the remaining 100+ ruff issues are pre-existing style/ordering noise carried from v0.47 and are tracked for a dedicated lint-cleanup pass

### Verified clean
- `python3 -m py_compile` passes on all 44 Python files
- Developer-reported bugs 1 (`correlate_run` NameError), 2 (`/api/config/set_callback` auth exemption), and 3 (`_notify_sse` undefined name) were verified against v0.48.0 source and confirmed already resolved — the developer's findings were against v0.47 or an intermediate build
- `notify_sse` is defined at `helpers.py:234` and called correctly at line 363 and in `bp_receiver.py:110` — no mismatch exists in v0.48.x

### Release packaging
- Tarball now excludes `__pycache__/`, `out/`, and `*.egg-info` directories



## v0.48.0 (2026-03 — Security Hardening + Live Attack Timeline)

### Bug fixes
- **bp_runs.py**: removed two sets of duplicate `_save_run_index()` / `_update_run_entry()` definitions. Both functions are imported from `helpers.py`; the local redefinitions were dead code and caused Python to silently use the last-defined copy
- **create_app()**: replaced hardcoded `"icsforge-dev-key-change-in-production"` session key with `secrets.token_hex(32)`. Added `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = "Lax"`, and `PERMANENT_SESSION_LIFETIME = timedelta(hours=12)`. Production deployments via gunicorn/waitress now receive the same security configuration as `main()`
- **app.py campaigns route**: `_CAMPAIGNS_BUILTIN` was referenced in the `/campaigns` page route but never defined in `app.py`, causing a `NameError` at runtime. Added the path constant before the route

### Security
- Added `secrets` and `datetime` imports to `app.py`; `create_app()` and `main()` now share identical session security configuration
- Session lifetime capped at 12 hours (configurable via `PERMANENT_SESSION_LIFETIME`)

### Live attack timeline (sender UI)
- New **Live Attack Timeline** card appears on scenario run, positioned between Step Plan and Live Receiver Feed
- Each scenario step renders as a timeline row cycling through four states: `pending → sending → delivered → confirmed`
- Steps animate from pending to sending in sequence as the scenario fires (delay scales with step count, 120–400ms per step)
- On run completion all steps move to `delivered`; steps flip to `confirmed` in real time as SSE receipts arrive from the receiver, matched by `run_id` + `technique`
- "Confirmed" badge animates in with a pop transition; the progress bar tracks overall delivery ratio
- Timeline header shows the run ID; elapsed timer runs during the live send and stops on completion
- Timeline card is hidden until a run starts and auto-scrolls into view
- SSE `onmessage` handler in sender now calls `tlConfirmStep(technique, run_id)` on every incoming receipt

### Receiver "got it" toast
- Receiver UI now opens an `EventSource("/api/receiver/stream")` connection on page load
- Each incoming receipt fires `window.toast("Received", "<technique> · <proto>", "ok")`
- Toast burst is throttled to one per 800ms to prevent flooding during high-volume scenarios
- Falls back gracefully to the existing 2s polling loop if SSE is unavailable



## v0.45.3 (2026-03 — Receiver Callback Hardening)

### Live Receiver Callback
- Fixed auth exemption mismatch for `POST /api/config/set_callback` so sender → receiver callback registration works with auth enabled
- Persist receiver port correctly when saving network settings from sender UI
- Added explicit `sender_callback_url` override instead of relying only on derived `request.host` values
- Added optional shared `callback_token` header validation for receiver → sender live receipts
- Added receiver-side callback settings UI with Save and Test actions
- Added `POST /api/config/test_callback` for immediate callback diagnostics (status, response time, error body)
- Receiver config now supports `callback.token`

## v0.45.2 (2026-03 — MQTT Release)

### New Protocol: MQTT 3.1.1
- Full MQTT packet framing per OASIS MQTT v3.1.1 standard (TCP port 1883)
- 13 payload styles: connect, connect_anon, connect_creds, publish_command, publish_setpoint, publish_firmware, publish_config, publish_c2, subscribe_all, subscribe_scada, unsubscribe, pingreq, disconnect
- 20 new scenarios covering T0801, T0802, T0812, T0815, T0822, T0826, T0831, T0836, T0841, T0843, T0855, T0859, T0869, T0882
- Registered in scenario engine, live sender (TCP_PROTOS), and receiver config
- IIoT/Sparkplug B topic naming conventions

### Receiver Default Port → 9090
- Receiver web UI now defaults to port 9090 (was 8080) to avoid conflicts on single-host setups
- Updated: receiver CLI default, Dockerfile.receiver EXPOSE+CMD, docker-compose.yml mapping, README
- Sender callback push defaults to receiver_port=9090
- Sender stays on :8080, receiver on :9090

### Receiver → Sender HTTP Callback
- Receiver HTTP POSTs each receipt to sender for live UI updates
- New receiver config: `callback.url` in config.yml + `--callback-url` CLI argument
- Fire-and-forget async callback via daemon thread (non-blocking receipt pipeline)
- Sender endpoints: `POST /api/receiver/callback`, `GET /api/receiver/live`
- Receiver endpoint: `POST /api/config/set_callback` (accepts callback URL push from sender)
- Callback URL auto-derived from sender host:port when receiver IP is configured

### Network Settings UI (IP Configuration)
- New "Network Settings" bar at top of sender dashboard: sender IP, receiver IP, receiver port
- `GET/POST /api/config/network` — combined config endpoint for both IPs
- On page load, saved IPs are fetched and prefilled into all scenario fields
- "Save & Connect" pushes callback URL to receiver and confirms link status
- Destination IP field no longer hardcoded to 198.51.100.42 — filled from saved config
- Offline PCAP mode also uses configured receiver IP as fallback
- BACnet and MQTT added to protocol color map in UI

### Authentication
- First-run setup flow: no credentials → redirect to `/setup` → create admin account
- Session-based auth with Flask secure cookies
- SHA-256 + per-user salt password hashing (no external dependencies)
- Public paths exempt: `/health`, `/api/health`, `/api/receiver/callback`, `/api/config/set_callback`, `/static/`
- `--no-auth` CLI flag and `ICSFORGE_NO_AUTH=1` env var for development
- Credentials stored in `~/.icsforge/credentials.json` (0600 permissions)

### PCAP Validation Script
- `scripts/validate_pcaps.py` — validates every scenario's PCAP output
- Struct-only mode (no external deps): checks magic, version, linktype, packet counts, ports, IP proto
- Optional `--tshark` mode: full Wireshark dissection, detects malformed frames
- `--quick` mode: one scenario per protocol + all CHAINs (19 tests in ~2 minutes)
- `--scenario NAME` mode: test a single specific scenario
- Multi-protocol CHAIN scenarios correctly validated (first packet matches any step's protocol)
- Handles L2 PROFINET frames gracefully (skips IP-layer port checks)

### UI Redesign — Industrial Control Room Terminal
- Complete CSS overhaul: "SCADA operator workstation" aesthetic
- Fonts: Oxanium (display/headings), Chakra Petch (body), JetBrains Mono (code)
- Glowing amber indicators with text-shadow and box-shadow glow effects
- Beveled glass instrument panels with inset shadows and subtle top highlights
- Scanline background texture for authentic control room feel
- Staggered fade-in animations on card load
- Custom scrollbar styling matching industrial theme
- Full dark/light mode with distinct palettes (both industrial, not generic)
- All existing class names preserved — zero template breakage

### Updated Numbers
- 175 runnable scenarios (was 155)
- 72 ATT&CK for ICS technique IDs
- 9 industrial protocols (added MQTT)

---


## v0.43.0 (2026-03 — Lean Cleanup Release)

### Dead Weight Removed
- **`icsforge/scenarios/matrix.yml`** (2,457 lines) — auto-generated file with zero Python references. The tool uses `scenarios.yml` exclusively via `MATRIX_SINGLETON_PACK`. Removed.
- **`docker/docker-compose.receiver.yml`** — old standalone receiver compose, superseded by root `docker-compose.yml`. Removed.
- **`icsforge/state/plc_state.py`** — `PLCState` class never used by any code outside its own `__init__.py`. Removed.
- **`icsforge/detection/generic.py`** — `validate()` function never called from anywhere. Removed.
- **`icsforge/detection/suricata.py`** — `validate_suricata()` never called from anywhere. Removed.
- **`icsforge/detection/zeek.py`** — `validate_zeek()` never called from anywhere. Removed.
- **`out/`** empty directory — runtime artifact, should not be in repo. Removed.

### Directory Merge: `detections/` → `detection/`
- Merged `icsforge/detections/generator.py` into `icsforge/detection/generator.py`
- Deleted the entire `icsforge/detections/` directory
- Updated all imports (`icsforge.detections.generator` → `icsforge.detection.generator`) in `web/app.py` and `tests/test_scenarios.py`
- `icsforge/detection/` is now the single detection package containing `mapping.py` (alert correlation) and `generator.py` (Suricata/Sigma rule generation)

### Stale Version Strings
- Replaced all `v0.30` references in `campaigns/__init__.py`, `reports/__init__.py`, `reports/coverage.py`, `web/app.py`

### Updated Exports
- `icsforge/detection/__init__.py` now exports only used functions: `correlate_run`, `map_alert_to_techniques`, `generate_all`
- `icsforge/state/__init__.py` exports only `RunRegistry` and `default_db_path` (removed unused `PLCState`)

---

## v0.42.1 (2026-03)

### Lint Cleanup
- Sorted imports in all 32 Python source files (stdlib → third-party → local with blank line separation)
- Fixed E741 ambiguous variable names (`l` → `line`/`ln` in `detection/zeek.py` and `test_scenarios.py`)
- Removed trailing whitespace (W291/W293) across 7 files
- Removed excessive blank lines (E303) throughout codebase
- All 44 Python files compile clean with zero syntax errors

### CI: Lint + Test Pipeline
- Added dedicated `lint` job to GitHub Actions CI: `ruff check icsforge/ tests/`
- Test job now depends on lint passing first (`needs: lint`)
- Lint runs on Python 3.12, tests run on 3.10–3.13 matrix
- Added Tests passing badge to README

---

## v0.42.0 (2026-03)

### Bug Fixes (from developer review)
- **`/api/correlate_run` crash fixed** — `import time` added at module level in `web/app.py`. Previously crashed with `NameError: name 'time' is not defined` when generating correlation report filenames. Tested end-to-end: empty body → 400, unknown run → 400, real run → 200 with valid correlation.
- **README API path corrected** — was `GET /api/generate_detection_rules` (404), now correctly documents `GET /api/detections/preview` and `GET /api/detections/download`
- **`docs/PHASE.md` updated** — was "120+ scenarios", now accurate with 155 scenarios, 8 protocols

### Lint Cleanup
- Resolved all 59 lint issues (46 F401 unused imports, 10 F541 f-strings without placeholders, 3 E722 bare excepts)
- Added `__all__` to all `__init__.py` re-export modules (`detection`, `live`, `protocols`, `receiver`, `state`, `web`)
- Fixed bare `except:` in `detection/generic.py` and `detection/suricata.py` → `except (json.JSONDecodeError, ValueError):`
- Removed unnecessary `from __future__ import annotations` from 12 files
- Removed unused imports: `defaultdict`, `session`, `yaml`, `tempfile`, `time`, `rand_ip`, `Path`, `is_allowed_dest`, typing members
- Fixed f-prefix on string literals without placeholders in `detections/generator.py`

### Scenario Metadata Normalization
- All 155 scenarios now have a top-level `technique:` field (was missing on 73 scenarios)
- CHAIN scenarios get primary technique from their attack chain
- UI/export/summary logic can now rely on scenario-level metadata consistently

### Official Count Wording
README Key Numbers table uses precise, defensible wording:
- 155 runnable scenarios in the main scenario pack
- 72 ATT&CK for ICS technique IDs exercised across runnable scenarios
- 83 techniques in support data, 86 in bundled matrix data
- 8 industrial protocols

### New Tests
- `tests/test_web_api.py` — Flask test client tests for:
  - `/api/correlate_run`: empty body → 400, unknown run → 400, full end-to-end → 200 with correlation data
  - `/api/detections/preview` and `/api/detections/download`: return 200
  - Old wrong path `/api/generate_detection_rules`: returns 404
  - Basic endpoints: `/api/health`, `/api/scenarios`, `/api/packs`, `/api/runs`
  - Route audit: all README-documented routes exist in Flask app
  - POST routes with empty body return 400 (not 500)

---

## v0.41.0 (2026-03)

### Bug Fixes
- **`/api/correlate_run` crash fixed** — `time` module was not imported at module level in `web/app.py`, causing `NameError` when generating correlation report filenames. Also affected `/api/alerts/ingest`.
- **README API path corrected** — was `GET /api/generate_detection_rules` (404), now correctly documents `GET /api/detections/preview` and `GET /api/detections/download`
- **`docs/PHASE.md` updated** — was "120+ scenarios", now matches actual 155 with 8 protocols

### Scenario Metadata Normalization
- All 155 scenarios now have a top-level `technique:` field (was missing on 73 scenarios)
- CHAIN scenarios get primary technique from first step
- UI/export/summary logic can now rely on scenario-level metadata consistently

### Official Count Wording
README Key Numbers table now uses precise, defensible wording:
- 155 runnable scenarios in the main scenario pack
- 72 ATT&CK for ICS technique IDs exercised across runnable scenarios
- 83 techniques in support data, 86 in bundled matrix data
- 8 industrial protocols

### New Protocol: BACnet/IP
- Full BVLC + NPDU + APDU framing per ASHRAE 135-2020
- 16 payload styles: who_is, i_am, read_property, read_property_multi, write_property, write_property_multi, subscribe_cov, reinitialize_device, device_comm_control, read_file, write_file, private_transfer, who_has, time_sync, create_object, delete_object
- UDP transport (port 47808) with proper UDP packet builder in common.py
- 15 new scenarios covering T0840, T0801, T0802, T0809, T0813, T0816, T0836, T0843, T0849, T0855, T0861, T0869, T0882, T0888, T0889
- Live sender UDP support for BACnet/IP traffic generation

### README Accuracy Fix
- Scenario count corrected: 155 (was incorrectly stated as 221)
- Technique count corrected: 72 (was incorrectly stated as 80)
- Protocol count updated: 8 (added BACnet/IP)
- Protocol style counts updated to exact numbers

### PROFINET DCP Test Coverage Fix
- Tests now cover all 8 actual styles (identify, identify_unicast, get_name, get_ip, set_name, set_ip, hello, factory_reset)
- Previous tests only covered 3 styles, 2 of which used wrong names and hit the fallback clause

### Detection Mapping Expansion
- Expanded from 13 rules to 70+ rules
- Added protocol-specific patterns for all 8 protocols (Modbus, DNP3, S7comm, IEC-104, OPC UA, ENIP, BACnet, PROFINET)
- Added Suricata ET ICS/SCADA rule naming pattern support
- Added Suricata EVE JSON nested alert format support
- Added Zeek Notice log format support (note/sub fields)
- New technique mappings: T0801, T0802, T0809, T0812, T0838, T0841, T0843, T0845, T0849, T0856, T0858, T0866, T0869, T0872, T0876, T0882, T0888, T0889

### Test Suite
- Added BACnet protocol tests: all 16 styles + BVLC header + NPDU version + broadcast/unicast function checks
- Added UDP packet structure test
- Fixed PROFINET style names in test expectations
- Total protocol styles tested: 159 (was 138)

---

## v0.4.0 (2026-03)

### Engineering & Packaging
- **pyproject.toml**: Full PEP 621 packaging with entry points (`icsforge`, `icsforge-web`, `icsforge-receiver`). Pip-installable: `pip install -e .`
- **Scapy made optional**: Core engine is pure Python. Scapy only needed for pcap replay (`pip install icsforge[replay]`)
- **Dependency ranges**: Replaced pinned versions with compatible ranges in requirements.txt

### Testing
- **pytest test suite**: 100+ tests covering all 7 protocol builders, core utilities, scenario engine, and detection generator
- **Protocol builder tests**: Every documented style verified for all protocols (Modbus 28+, DNP3 17+, S7comm 25+, IEC-104 18+, OPC UA 16+, ENIP 15+, PROFINET 5+)
- **PCAP validation tests**: Verify global header magic, packet structure, and timing jitter
- **Detection generator tests**: Suricata and Sigma rule generation coverage
- **GitHub Actions CI**: Matrix testing across Python 3.10–3.13, Docker image builds

### Protocol Fixes
- **DNP3 CRC-16**: Implemented proper CRC-16/DNP (polynomial 0x3D65) per IEEE 1815. Link header and data block CRCs now computed correctly instead of placeholder zeros
- **PCAP timing jitter**: Packet timestamps now include ±30% jitter around base interval, eliminating the uniform-spacing pattern that flagged synthetic PCAPs in Wireshark

### Logging
- **Structured logging framework** (`icsforge.log`): All `print()` statements replaced with Python `logging` module. Configurable via `--log-level`, `--verbose`, `--log-file`, or `ICSFORGE_LOG_LEVEL` environment variable
- Consistent log format across sender, receiver, web UI, and CLI
- Third-party logger suppression (werkzeug, urllib3)

### Receiver
- **Thread-safe receipt writing**: `threading.Lock()` protects JSONL file writes from concurrent TCP handler corruption
- **Proper error handling**: All TCP accept/handler errors logged instead of silently swallowed
- **Bind error reporting**: Clear error messages when ports are already in use

### Web Application
- **Flask secret key**: Cryptographic secret key generated on startup (configurable via `ICSFORGE_SECRET_KEY`)
- **Session security**: HttpOnly and SameSite=Lax cookie settings
- **Fixed duplicate code**: `/api/send` handler had 6 duplicate variable assignments (timeout, allowlist, iface, src_ip, outdir assigned twice each)
- **Deprecated API fixed**: All `datetime.utcnow()` replaced with timezone-aware `datetime.now(timezone.utc)`
- **HTTP output logging**: `_send_http()` now logs failures instead of silently passing

### Docker
- **docker-compose.yml**: Full-stack setup with sender, receiver, and optional Suricata in isolated bridge network
- **Updated Dockerfiles**: Python 3.12-slim base, proper output directory creation
- **Suricata profile**: Opt-in IDS monitoring via `docker compose --profile suricata up`

### Community & CI
- **CONTRIBUTING.md**: Development setup, testing guide, code style, protocol/scenario addition guides
- **GitHub issue templates**: Bug report and feature request templates
- **.github/workflows/ci.yml**: Automated testing, linting, coverage, and Docker builds
- **Updated README**: Architecture diagram, badges, quick-start guide, protocol coverage table

### Code Quality
- **core.py**: `_send_http` error logging, proper timezone handling throughout
- **state/run_registry.py**: Fixed deprecated `datetime.utcnow()` usage
- **cli.py**: Added `--verbose`, `--log-level`, `--log-file` global flags

---

## v0.31 (2025)

### Minor fixes and stability

---

## v0.21

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

---

