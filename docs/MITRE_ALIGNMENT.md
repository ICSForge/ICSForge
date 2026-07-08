# MITRE ATT&CK for ICS — Alignment Reference (v0.77.5)

## Source of truth

All technique IDs in ICSForge map to the **canonical MITRE ATT&CK for
ICS catalog** at `https://attack.mitre.org/techniques/ics/`. Scenarios
are authored against **v18.1** technique IDs (12 tactics, 83 distinct
technique IDs), which remain the stable identifiers.

**v18.1 vs v19.** With the April 2026 v19 release, ATT&CK for ICS gained
**sub-techniques for the first time** (79 standalone techniques + 18
sub-techniques). Nine v18 techniques were revoked and reissued as
sub-techniques (e.g. T0855 Unauthorized Command Message → T1692.001).
ICSForge keeps scenarios on stable v18 IDs and maps forward to v19 via
the official crosswalk (`docs/MITRE_V19_CROSSWALK.md`,
`icsforge/data/mitre_v18_v19_crosswalk.json`); the Matrix view offers a
v18/v19 toggle. The bundled v19 matrix
(`icsforge/data/ics_attack_matrix_v19.json`) is generated from MITRE's
official `ics-attack-19.1` STIX bundle.

## Common pitfall — fan-made technique lists

Several blogs, slide decks, and quick-reference cards online use
TECHNIQUE NAMES with WRONG IDs. Examples that triggered the v0.62.3
correction:

| Wrong (fan-made list) | Real (MITRE official) |
|---|---|
| T0801 "Alarm Suppression" | T0801 is **"Monitor Process State"** (Alarm Suppression is **T0878**) |
| T0805 "Change Credential" | T0805 is **"Block Serial COM"** (Change Credential is **T0892**) |
| T0817 "User Execution" | T0817 is **"Drive-by Compromise"** (User Execution is **T0863**) |
| T0879 "Data Historian Compromise" | T0879 is **"Damage to Property"** ("Data Historian Compromise" doesn't exist in MITRE; OPC UA HistoryRead is covered by **T0882 Theft of Operational Information**) |

**Always verify against `attack.mitre.org/techniques/ics/` directly,
never against derived references.**

## Technique IDs that do NOT exist in current MITRE matrix

These were used historically but were **deprecated or never assigned**.
v0.62.3 removes/re-tags them:

| Non-existent ID | Old ICSForge claim | What it actually became |
|---|---|---|
| T0841 | "Network Service Scanning" | Re-tagged to **T0840** (Network Connection Enumeration) |
| T0875 | "Change Program State" | Re-tagged to **T0858** (Change Operating Mode) |
| T0876 | "Loss of Safety" | Re-tagged to **T0880** (Loss of Safety, the real ID) |

## ICSForge v0.77.5 mapping

### Coverage summary

- **MITRE catalog (v18.1)**: 83 techniques
- **ICSForge scenarios**: 77 techniques covered (76 standalone + T0879
  "Damage to Property" as a chain objective) = **77 of 83 (92.8%)**
- **v19 mapping**: 73 of 79 standalone + 17 of 18 sub-techniques = 90/97 (92.8%) combined
- **33 techniques** at full 10/10 protocol coverage
- **Detection rules**: 210 lab + 239 heuristic + 357 semantic = 806 total
- **Drift**: 0 orphan rules, 0 missing rules

### Per-protocol breakdown

| Protocol | Techniques covered (of 68) |
|---|---|
| OPC UA | 58/68 |
| DNP3 | 57/68 |
| S7comm | 56/68 |
| EtherNet/IP | 55/68 |
| Modbus/TCP | 54/68 |
| BACnet/IP | 54/68 |
| MQTT | 52/68 |
| IEC-104 | 51/68 |
| PROFINET DCP | 45/68 |
| IEC 61850 GOOSE | 42/68 |

### MITRE techniques NOT covered in ICSForge (15)

Out-of-scope by design (host-level, physical-access, or wireless that
ICSForge does not target):

| ID | MITRE name | Why not covered |
|---|---|---|
| T0817 | Drive-by Compromise | Browser exploit; not OT-protocol-observable |
| T0823 | Graphical User Interface | Operator UI interaction; host-level |
| T0847 | Replication Through Removable Media | Physical USB/disk delivery |
| T0851 | Rootkit | Host-level malware persistence |
| T0852 | Screen Capture | Host-level data theft |
| T0860 | Wireless Compromise | Wireless OT not in our 10 protocols |
| T0862 | Supply Chain Compromise | Pre-deployment exposure |
| T0863 | User Execution | Operator action; host-level |
| T0865 | Spearphishing Attachment | Email delivery vector |
| T0873 | Project File Infection | Engineering workstation file format |
| T0874 | Hooking | API hooking on engineering workstation |
| T0883 | Internet Accessible Device | Exposure precursor; no protocol traffic |
| T0887 | Wireless Sniffing | Wireless OT |
| T0893 | Data from Local System | Host-level |
| T0894 | System Binary Proxy Execution | Host-level binary execution |

These are correctly classified as "not runnable" in
`icsforge/data/technique_support.json`. The remaining 68 are runnable
and have at least one scenario + matching detection spec.

## How to verify alignment

```bash
# Show the per-source consistency report
python3 -c "
import yaml, json
MITRE = {  # 83 IDs
    'T0800', 'T0801', 'T0802', 'T0803', 'T0804', 'T0805', 'T0806', 'T0807',
    'T0809', 'T0811', 'T0812', 'T0813', 'T0814', 'T0815', 'T0816', 'T0817',
    'T0819', 'T0820', 'T0821', 'T0822', 'T0823', 'T0826', 'T0827', 'T0828',
    'T0829', 'T0830', 'T0831', 'T0832', 'T0834', 'T0835', 'T0836', 'T0837',
    'T0838', 'T0839', 'T0840', 'T0842', 'T0843', 'T0845', 'T0846', 'T0847',
    'T0848', 'T0849', 'T0851', 'T0852', 'T0853', 'T0855', 'T0856', 'T0857',
    'T0858', 'T0859', 'T0860', 'T0861', 'T0862', 'T0863', 'T0864', 'T0865',
    'T0866', 'T0867', 'T0868', 'T0869', 'T0871', 'T0872', 'T0873', 'T0874',
    'T0877', 'T0878', 'T0879', 'T0880', 'T0881', 'T0882', 'T0883', 'T0884',
    'T0885', 'T0886', 'T0887', 'T0888', 'T0889', 'T0890', 'T0891', 'T0892',
    'T0893', 'T0894', 'T0895',
}
with open('icsforge/scenarios/scenarios.yml') as f: sc = yaml.safe_load(f)['scenarios']
techs = set(s['technique'] for b in sc.values() for s in b.get('steps', []) if 'technique' in s)
extra = techs - MITRE
assert not extra, f'Found non-MITRE techniques in scenarios: {extra}'
print(f'OK: all {len(techs)} scenario techniques are valid MITRE IDs')
"
```

## When MITRE updates the catalog

If MITRE adds/removes techniques (e.g., new ICS-specific techniques in
a future release), update:

1. The set in `tests/test_coverage_consistency.py` if a baseline check
   exists
2. `icsforge/data/technique_support.json` — add/remove canonical entries
3. This file (`MITRE_ALIGNMENT.md`) with the new retrieval date
4. README counts under "Key Numbers"

Do **not** add new technique IDs to scenarios or detection specs without
first verifying they exist in the current MITRE catalog.
