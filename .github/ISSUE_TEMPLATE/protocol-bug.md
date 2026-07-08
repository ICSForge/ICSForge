---
name: Protocol bug report
about: A protocol implementation produces incorrect bytes, fails dissection, or violates a published spec
title: '[protocol] short summary'
labels: protocol-bug
assignees: ''
---

## Affected protocol
<!-- Tick one -->
- [ ] Modbus/TCP
- [ ] DNP3
- [ ] IEC-104
- [ ] S7comm
- [ ] OPC UA
- [ ] EtherNet/IP / CIP
- [ ] BACnet/IP
- [ ] MQTT
- [ ] IEC 61850 GOOSE
- [ ] PROFINET DCP

## Style / scenario where it appears
<!-- e.g. T0855__unauth_command__modbus, style=write_register -->

## ICSForge version
<!-- output of: icsforge --version -->

## Expected per protocol spec
<!-- Quote the relevant section: "IEEE 1815-2012 §11.3.5.2 says CROB
     status byte must be one of the codes in §A.21.3" -->

## What the generator actually produces
<!-- A few hex bytes will help us see exactly where it diverges.
     Use:  icsforge generate <scenario> --outdir /tmp/x; xxd /tmp/x/*.pcap | head
     Or open the PCAP in Wireshark and screenshot the offending field. -->

```
<paste hex / dissector tree here>
```

## Repro steps
1.
2.
3.

## Anything else?
<!-- Wireshark version (some dissector bugs are upstream — e.g. #19580
     for GOOSE on tshark 4.0.10–4.0.12 / 4.2.0–4.2.2). Other parsers
     you tried. Whether this is regression vs an earlier ICSForge
     version. -->
