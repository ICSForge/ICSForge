---
name: False positive — Suricata / Sigma rule
about: An ICSForge-generated detection rule fires on legitimate (non-attack) OT traffic
title: '[rule-name] FP on <protocol>'
labels: false-positive
assignees: ''
---

## Rule identifier
<!-- Suricata SID or Sigma rule UUID. The lab/heuristic/semantic tier
     matters — say which:
       - lab_marker      (requires ICSFORGE_SYNTH; should NEVER fire on real traffic)
       - protocol_heuristic (matches protocol magic bytes; some real-traffic FP is expected)
       - semantic        (matches at function-code level; FP here is the bug we want to know about)
-->

- SID/UUID:
- Tier: `lab_marker` / `protocol_heuristic` / `semantic`

## What real traffic triggered it
<!-- Anonymise IPs/MACs/ports if needed. Wireshark's "Export Specified
     Packets" with the offending frame range gives us the smallest
     reproducer. -->

- Protocol:
- Direction (from PLC / from HMI / E-W / N-S):
- Operational context (production / test bench / lab):
- Sample size (one frame? ongoing? burst?):

## Suricata `eve.json` alert (or Sigma match)

```json
{ ... paste the alert event here ... }
```

## What you think is going wrong
<!-- e.g. "rule matches on byte 6 = 0x06 but vendor X uses 0x06 for a
     legitimate poll request, not the attack pattern" — this is the
     most useful field if you have the time. -->

## Could you share a PCAP?
<!-- A 5-frame PCAP of the false-positive traffic is gold. If you can
     share it (anonymised), please attach. If not, we'll try to
     reproduce from the description. -->

## Environment
- ICSForge version:
- Suricata version:
- Wireshark/tshark version:
- Operating system:
