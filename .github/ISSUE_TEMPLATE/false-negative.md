---
name: False negative — detection rule missed an attack
about: An ICSForge attack scenario or external attack PCAP did not trigger the rule it should have
title: '[scenario / SID] FN — short summary'
labels: false-negative
assignees: ''
---

## What did NOT fire
- Suricata SID / Sigma UUID (if you know which rule was supposed to fire):
- Tier (lab / heuristic / semantic):

## What attack was running

### If it was an ICSForge scenario:
- Scenario name (e.g. `T0855__unauth_command__modbus`):
- Was the scenario run with `--no-marker` / stealth mode? (lab-tier won't fire in stealth):
- Command used to fire it:

### If it was an external attack PCAP:
- Source (red team exercise, public PCAP, vendor sample):
- Brief description of the attack pattern:

## What was running detection
- Suricata version:
- Did the lab-tier marker fire? (helps isolate detection vs traffic generation issue):
- Other rules from other tiers that DID fire (or no rules at all):

## eve.json snippet (if any rules fired)
```json
{ ... paste alerts that did fire, even if not the right ones ... }
```

## Why you think this should have fired
<!-- e.g. "the scenario writes to Modbus FC06 with value 0xDEAD which
     is the attack signature in our local rule_005, but Suricata didn't
     emit any alert for that frame" -->

## Steps to reproduce
1.
2.
3.

## Environment
- ICSForge version:
- Suricata config (default ICSForge-generated, custom-tuned):
- Operating system:
