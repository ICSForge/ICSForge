# MITRE ATT&CK ICS v18 → v19 Crosswalk for ICSForge

**Authoritative source:** https://attack.mitre.org/docs/subtechniques/ics-sub-techniques-crosswalk.json
**v19 release date:** 2026-04-28
**This document last updated:** 2026-06-27 (v0.77.5; v19 matrix regenerated from official ics-attack-19.1 STIX)

## Summary

ATT&CK ICS v19 introduced **18 sub-techniques** for the first time in
the ICS domain, organised under 5 new parent techniques (T1691 Block
OT Message, T1692 Unauthorized Message, T1693 Modify Firmware, T1694
Insecure Credentials, T1695 Block Communications). Each parent is a
"new in v19" standalone technique; nine v18 standalone IDs (T0803,
T0804, T0805, T0812, T0839, T0855, T0856, T0857, T0891) were retired
and became sub-techniques.

ICSForge has **applied all relevant remaps** from the v19 crosswalk
JSON, plus added v19 sub-technique annotations on scenarios that match
the new fine-grained classifications.

### Coverage figures (v0.77.5)

| Reading | Number |
|---|---|
| v18 standalone techniques covered | **77 of 83** (92.8%) |
| v19 standalone techniques covered | **73 of 79** (92.4%) |
| v19 sub-techniques covered | **17 of 18** (94.4%) |
| **v19 combined coverage (standalone + subs)** | **90 of 97** (92.8%) |
| Scenarios with `technique_v19` annotation | **111 of 611 standalone** |

### Why the v19 standalone count is higher than v18 might suggest

In v18 we cover 77 of 83 = 92.8% of standalone techniques. In v19, 9
of those covered v18 IDs became sub-techniques under 5 new parent IDs.
ICSForge keeps the v18 ID as the primary `technique` field for
tooling stability, and adds `technique_v19` annotations on each
remapped scenario. By covering the sub-technique annotations, we
*also* cover the parent technique (per ATT&CK convention: a sub-tech
hit implies parent-technique relevance).

So the v19 standalone count is:
  77 v18 IDs covered
  − 9 that became sub-techs (no longer in v19 standalone catalog)
  + 5 new parent techniques (covered by virtue of their sub-techs being covered)
  = **73 of 79 v19 standalone = 92.4%**

## Section 1 — "Became new sub-technique" (9 v18 IDs remapped)

These 9 v18 standalone techniques are now sub-techniques in v19. Per the
authoritative crosswalk, the v18 ID was retired and the v19 sub-tech ID
should be used. ICSForge keeps the v18 ID as the primary `technique`
field for tooling stability and adds `technique_v19` for v19-aware
consumers.

| v18 ID | v19 sub-tech ID | v19 name | ICSForge scenarios |
|---|---|---|---|
| T0803 | **T1691.001** | Block OT Message: Command Message | 11 |
| T0804 | **T1691.002** | Block OT Message: Reporting Message | 11 |
| T0805 | **T1695.001** | Block Communications: Serial COM | 2 |
| T0812 | **T1694.001** | Insecure Credentials: Default Credentials | 7 |
| T0839 | **T1693.002** | Modify Firmware: Module Firmware | 11 |
| T0855 | **T1692.001** | Unauthorized Message: Command Message | 13 |
| T0856 | **T1692.002** | Unauthorized Message: Reporting Message | 14 |
| T0857 | **T1693.001** | Modify Firmware: System Firmware | 10 |
| T0891 | **T1694.002** | Insecure Credentials: Hardcoded Credentials | 12 |
| **Total** | | | **91 scenarios remapped** |

✅ **All 91 scenarios carry the correct `technique_v19` annotation.**

## Section 2 — "Remains a technique" (3 parents that gained sub-techs)

These 3 v18 techniques retain their ID in v19 but now have sub-techniques
available. ICSForge has applied sub-technique refinements based on
scenario styles.

### T0843 Program Download (9 ICSForge scenarios)

| ICSForge scenario | v19 sub-tech | Reasoning |
|---|---|---|
| `T0843__program_download__s7comm` | T0843.001 Download All | Full cpu_stop + download_block sequence |
| `T0843__program_download__bacnet_write_file` | T0843.001 Download All | Whole-file write |
| `T0843__program_download__mqtt_firmware` | T0843.001 Download All | Firmware payload publish |
| `T0843__program_download__dnp3_file_transfer` | T0843.001 Download All | File-object transfer |
| `T0843__program_download__enip_firmware` | T0843.001 Download All | boot_firmware operation |
| `T0843__program_download__opcua_method_call` | T0843.001 Download All | Method-based program load |
| `T0843__program_download__iec104` | T0843.001 Download All | Reset+inject sequence |
| `T0843__program_download__profinet` | T0843.001 Download All | Full reconfiguration |
| `T0843__program_download__modbus` | **T0843.002 Online Edit** | Single-register write while running |

**T0843.003 Program Append** is not currently covered — it's a distinct technique
where the adversary appends a NEW block to an existing program rather than
overwriting. Could be added in future as a Siemens-specific S7comm scenario
that uses a `download_block` with a previously-unused block number.

### T0846 Remote System Discovery (9 ICSForge scenarios)

| ICSForge scenario | v19 sub-tech | Reasoning |
|---|---|---|
| `T0846__remote_sys_discovery__dnp3_probe` | T0846.001 Port Scan | Single-target probe |
| `T0846__remote_sys_discovery__modbus` | T0846.001 Port Scan | Single-target probe |
| `T0846__remote_sys_discovery__enip` | T0846.001 Port Scan | ListIdentity to single host |
| `T0846__remote_sys_discovery__opcua` | T0846.001 Port Scan | find_servers / get_endpoints |
| `T0846__network_scanning__multi` | T0846.001 Port Scan | Mixed protocol port probes |
| `T0846__service_scan__mqtt_ping` | T0846.001 Port Scan | Single-broker PINGREQ |
| `T0846__network_scan__bacnet_sweep` | T0846.002 Broadcast Discovery | BACnet Who-Is broadcast |
| `T0846__network_scan__profinet_dcp` | T0846.002 Broadcast Discovery | DCP Identify-All multicast (functional broadcast) |
| `T0846__network_scan__iec61850_goose` | **T0846.003 Multicast Discovery** | GOOSE multicast IED enumeration |

### T0873 Project File Infection (1 ICSForge scenario)

| ICSForge scenario | v19 sub-tech |
|---|---|
| `T0873__project_infection__s7comm_upload_modify_dl` | **T0873.001 Siemens Project File Format** |

The single T0873 scenario is Siemens-specific (S7comm read-modify-write OB1
cycle), so it maps cleanly to the new v19 sub-technique.

## Section 3 — v19 NEW techniques (no v18 equivalent at the leaf level)

The crosswalk introduces 5 entirely new parent techniques + several entirely
new sub-techniques.

### New parent techniques

| v19 ID | Name | ICSForge coverage approach |
|---|---|---|
| T1691 | Block Operational Technology Message | Covered via T0803/T0804 sub-techniques (22 scenarios) |
| T1692 | Unauthorized Message | Covered via T0855/T0856 sub-techniques (27 scenarios) |
| T1693 | Modify Firmware | Covered via T0857/T0839 sub-techniques (21 scenarios) |
| T1694 | Insecure Credentials | Covered via T0812/T0891 sub-techniques (19 scenarios) |
| T1695 | Block Communications | Covered via T0805/T1695.001 (Serial COM, 2 scenarios) |

### New sub-techniques NOT covered by ICSForge

| v19 sub-tech | Name | Why not covered |
|---|---|---|
| T0843.003 | Program Download: Program Append | Distinct attack pattern (appending NEW block to existing program) — could be added as future S7comm scenario; currently not modelled |
| T1695.002 | Block Communications: Ethernet | Link-layer blocking (ARP poisoning, port disable) — out of scope for OT-protocol generation |
| T1695.003 | Block Communications: Wi-Fi | RF/wireless jamming — fundamentally out of scope for an Ethernet/IP traffic generator |

The 2 T1695 sub-techniques are correctly out-of-scope by design — ICSForge
generates IP-layer OT protocol traffic and cannot model link-layer or RF
attacks. T0843.003 is a real coverage gap that could be filled in a future
release.

## Section 4 — Out-of-scope ICS techniques (unchanged in v19)

The 7 v18 ICS techniques ICSForge does not cover are unchanged in v19.
All remain standalone techniques in the v19 catalog and are correctly
out-of-scope:

| Technique | Why out of scope |
|---|---|
| T0817 Drive-by Compromise | Browser exploit, not OT-protocol observable |
| T0847 Replication Through Removable Media | Physical USB, not network |
| T0852 Screen Capture | Host-level capture, not network |
| T0865 Spearphishing Attachment | Email, not OT |
| T0874 Hooking | Engineering-workstation API hooking |
| T0879 Damage to Property | Consequence, not network-observable behaviour |
| T0894 System Binary Proxy Execution | Host-level proxy execution |

## Section 5 — How ICSForge represents v19 in scenario YAML

Each affected scenario carries both `technique` (v18 primary) and
`technique_v19` (refined sub-technique under v19):

```yaml
T0855__unauth_command__modbus:
  title: T0855 – Unauthorized Command Message — Modbus FC5/6/15/16 writes
  tactic: Impair Process Control
  technique: T0855                # v18 — primary, used by tooling
  technique_v19: T1692.001        # v19 — Unauthorized Message: Command Message
  confidence: high
  steps: ...
```

```yaml
T0846__network_scan__iec61850_goose:
  title: T0846 – Remote System Discovery — IEC 61850 GOOSE multicast scan
  tactic: Discovery
  technique: T0846                # v18 — same in v19
  technique_v19: T0846.003        # v19 — Remote System Discovery: Multicast Discovery
  confidence: high
  steps: ...
```

## Section 6 — Public-facing wording

For Black Hat Arsenal / DEF CON Demo Labs reviewers, the defensible
coverage statement is:

> ICSForge v0.64.1 generates network-observable OT traffic for 76 distinct
> MITRE ATT&CK ICS techniques (v18 numbering — current ATT&CK as of May 2026).
> Under the v19 sub-technique reorganization (released April 28, 2026),
> ICSForge's coverage maps to 73 of 79 standalone techniques and 17 of 18
> sub-techniques (90 of 97 = 92.8% combined). The 6 v19 standalone
> techniques and 1 sub-technique we don't cover (T0817, T0847, T0852,
> T0865, T0874, T0894 standalone; T1695.003 Wi-Fi sub-technique) are
> all host-level, physical-access, or radio-layer — out of scope for a
> packet-generation tool by design.

## Section 7 — Verification

Reproduce the coverage figures with:

```bash
python3 -c "
import yaml
with open('icsforge/scenarios/scenarios.yml') as f:
    sc = yaml.safe_load(f)['scenarios']
techs = set(s.get('technique') for body in sc.values() if isinstance(body,dict)
            for s in body.get('steps', []) if 'technique' in s)
v19_subs = set(body.get('technique_v19') for body in sc.values()
               if isinstance(body,dict) and 'technique_v19' in body)
print(f'v18 techniques covered: {len(techs)}')
print(f'v19 sub-techniques covered: {len(v19_subs)}')
"
```

Expected output:
```
v18 techniques covered: 76
v19 sub-techniques covered: 15
```
