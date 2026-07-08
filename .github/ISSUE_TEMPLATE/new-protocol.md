---
name: New protocol request
about: Request support for an industrial protocol not yet covered by ICSForge
title: '[new-protocol] short summary'
labels: enhancement, new-protocol
assignees: ''
---

## Protocol name
<!-- e.g. CC-Link, MELSOFT, Foundation Fieldbus HSE, Allen-Bradley CSP,
     PROFINET IO (cyclic — we cover DCP only), HART-IP, Genisys,
     EtherCAT EoE, etc. -->

## Why it matters
<!-- Vendor footprint, geographic prevalence, sectors using it.
     Examples that have been compelling in the past:
       - "MELSOFT is in 60% of Japanese auto manufacturing"
       - "HART-IP is the modern wrapper for Foundation Fieldbus
          devices and many sites are migrating to it"
-->

## Specification source(s)
<!-- Link to the open spec, an IEC/IEEE/ANSI document number, or vendor
     PDFs. We can only implement protocols whose framing is publicly
     documented or reverse-engineered. -->

## Suggested initial scope
<!-- Which 3-5 styles would be most valuable to implement first?
     Looking for the smallest set that covers reconnaissance + a few
     impact-class techniques. -->

- [ ] Discovery / device identification
- [ ] Read (e.g. tag/register/object read)
- [ ] Write (control-class — would map to T0855)
- [ ] Configuration / parameter change (T0836)
- [ ] Operating-mode change / restart (T0858 / T0816)
- [ ] Other: ____________________

## ATT&CK for ICS techniques this would unlock
<!-- See https://attack.mitre.org/techniques/ics/ — list any
     techniques that ICSForge currently doesn't cover but would with
     this protocol added. -->

## Existing PCAPs / parser support
<!-- Does Wireshark already have a dissector for this protocol? Zeek?
     Any vendor or research PCAPs you can point us to (publicly
     accessible — please don't share anything sensitive)? -->

## Are you able to help?
- [ ] I can review PRs against this protocol for spec correctness
- [ ] I can provide / point to PCAPs of legitimate traffic for testing
- [ ] I'm willing to draft the initial implementation (we'll review)
- [ ] I can help test against real / lab equipment
