# SIEM Integration with ICSForge Detection Content

ICSForge ships detection content in three formats, each suited to
different SIEM/IDS deployments. This document explains how to convert
or deploy each format.

| Format | File(s) | Engines that consume natively | Engines via converter |
|---|---|---|---|
| Suricata rules | `icsforge_lab.rules`, `icsforge_heuristic.rules`, `icsforge_semantic.rules` | Suricata, Snort 3 | — |
| Sigma rules | `sigma/<scenario_id>.yml` | none directly | Splunk SPL, Elastic EQL/KQL, Microsoft Sentinel KQL, ArcSight, QRadar |
| Zeek signatures | `icsforge.sig` | Zeek 5.x+ | — |

Generate all three at once:

```bash
icsforge detections export --outdir /tmp/rules
ls /tmp/rules
# icsforge_lab.rules  icsforge_heuristic.rules  icsforge_semantic.rules
# icsforge.sig  sigma/  README.txt
```

## Suricata / Snort 3

Drop the `.rules` files into your Suricata rule directory and load via
`suricata.yaml`:

```yaml
rule-files:
  - icsforge_semantic.rules        # recommended for production
  - icsforge_heuristic.rules       # protocol-presence (high FP)
  - icsforge_lab.rules             # ICSForge runs only — zero FP
```

Snort 3 consumes the same rule format. For Snort 2.x compatibility you
may need to drop `metadata:` fields the older parser doesn't recognize.

See `docs/REFERENCE_DETECTION_COVERAGE.md` for per-protocol detection
rates and tier deployment guidance.

## Zeek

L2-only protocols (IEC 61850 GOOSE, PROFINET DCP) are covered by
`icsforge.sig` using Zeek's signature framework. Suricata 7.x cannot
match these protocols (no IP layer).

Deployment:

```bash
# One-off PCAP analysis
zeek -r capture.pcap /path/to/icsforge.sig

# Persistent in site policy:
echo '@load-sigs /path/to/icsforge.sig' >> /usr/local/zeek/share/zeek/site/local.zeek
zeekctl deploy
```

Notices appear in `notice.log` with the standard ICSForge tier prefix
(`LAB-MARKER`, `HEURISTIC`, `SEMANTIC`).

## Sigma → Splunk SPL

The `pySigma` toolchain converts Sigma rules to many target backends.

```bash
pip install sigma-cli pysigma-backend-splunk
sigma convert -t splunk -p sigmac \
  /tmp/rules/sigma/*.yml > icsforge.spl
```

Output is a SPL search per scenario. Wrap in a saved search:

```spl
| from icsforge.spl
| stats count by sourcetype, technique
```

Caveats: Sigma's `network_traffic` logsource maps to Splunk Stream or
Zeek inputs; the field names (`dst_port`, `network.transport`,
`payload`) must match your data source. ICSForge Sigma rules emit field
names compatible with Zeek default outputs and Splunk Stream's TCP
events.

## Sigma → Elastic EQL/KQL

```bash
pip install sigma-cli pysigma-backend-elasticsearch
sigma convert -t lucene -p ecs_zeek \
  /tmp/rules/sigma/*.yml > icsforge.eql
```

ECS field mapping: ICSForge Sigma rules pre-translate to ECS
(`destination.port`, `network.transport`, `network.protocol`) when the
`ecs_zeek` pipeline is applied.

## Sigma → Microsoft Sentinel KQL

```bash
pip install sigma-cli pysigma-backend-kusto
sigma convert -t kusto \
  /tmp/rules/sigma/*.yml > icsforge.kql
```

Output is one KQL query per scenario, ready for Sentinel's analytics
rules.

## Field name compatibility table

The Sigma rules use these field names; here's how they map to common
SIEM data sources:

| Sigma field | Zeek log field | Splunk Stream | Elastic ECS |
|---|---|---|---|
| `dst_port` | `id.resp_p` | `dest_port` | `destination.port` |
| `src_port` | `id.orig_p` | `src_port` | `source.port` |
| `network.transport` | `proto` | `transport` | `network.transport` |
| `network.protocol` | `service` | `app` | `network.protocol` |
| `payload` | (custom logging) | `payload` | `network.bytes` (truncated) |

For accurate matching, ensure your network sensor logs include payload
bytes. For Zeek users, ICSForge's per-protocol parsers (Modbus, DNP3,
S7comm built-in; OPC UA via `icsnpp`; BACnet via community packages)
are the easiest path.

## Limitations and honest caveats

- **L2 protocols (GOOSE, PROFINET DCP) require Zeek.** Sigma rules
  exist but their `payload` clauses depend on a Zeek front-end that can
  see L2 frames. Suricata cannot. SIEM-only deployments without Zeek
  cannot detect these protocols.
- **Sigma rules carry the same per-tier semantics as Suricata.** Tier 1
  is lab-only (zero FP, requires ICSForge marker). Tier 2 is
  protocol-presence (high FP). Tier 3 is function-code-level
  (recommended for production). This guidance applies regardless of
  the target SIEM.
- **Per-protocol detection rates** measured in
  `docs/REFERENCE_DETECTION_COVERAGE.md` are Suricata-specific. Sigma
  rules carry the same logic, but the actual hit rate depends on how
  faithfully the target SIEM's data source captures the relevant
  fields. Lab-marker (Tier 1) detection is reliable across all SIEMs
  if the data source captures payload. Tier 2/3 effectiveness depends
  on protocol-specific parsing in the upstream sensor.

## Reproducing detection-rate measurement on your SIEM

The `scripts/measure_detection_coverage.py` harness is Suricata-only.
For your target SIEM, the equivalent workflow is:

1. Generate ICSForge PCAPs: `icsforge campaign --offline --outdir pcaps/`
2. Replay or ingest PCAPs into your sensor pipeline (e.g.,
   `tcpreplay --intf=eth1 pcaps/*.pcap` against a Zeek tap)
3. Convert Sigma rules to your SIEM's format (above)
4. Run rules over the ingested data
5. Count alerts per scenario, compare to the Suricata baseline

If you do this, please share the results — we'd value the
cross-SIEM measurement data for the next REFERENCE_DETECTION_COVERAGE
update.
