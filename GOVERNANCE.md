# ICSForge Governance

ICSForge is a small open-source project. This document describes, briefly
and honestly, how decisions are made.

## Maintainers

ICSForge currently has a single primary maintainer. As the project grows,
additional maintainers will be invited based on demonstrated contribution
and alignment with project goals.

A maintainer can:

- Merge pull requests
- Cut releases
- Grant triage permissions to contributors
- Enforce the Code of Conduct

Current maintainers are listed in [MAINTAINERS.md](MAINTAINERS.md) (coming
soon as the project grows).

## Decision Making

### Day-to-day (PRs, issue triage, bug fixes)
Maintainers merge at their discretion. Non-trivial changes should accumulate
at least one review from another contributor when available.

### Bigger changes (new protocols, new API endpoints, architectural changes)
Opened as a GitHub Issue with the `proposal` label first. Two weeks of
community feedback before implementation starts. Final call made by the
maintainer after weighing inputs.

### Very bigger changes (licence, project direction, safety model)
Discussed publicly in a Discussion thread. Maintainer presents the reasoning
in writing. Decisions are documented in `docs/decisions/NNNN-title.md`.

## Scope

ICSForge's scope is **defender-first OT/ICS coverage validation**. This
boundary is deliberate and restrictive:

**In scope:**
- Network-observable ATT&CK for ICS technique traffic generation
- PCAP generation, campaign orchestration, detection content
- Coverage validation workflows and reporting
- Correlation tooling between ground truth, delivery, and detection

**Out of scope:**
- Exploitation payloads or vulnerability research against real devices
- Tools primarily designed for offensive operations
- Traffic that causes unsafe process impact on real OT systems
- Host-based techniques that generate no network traffic

Maintainers reserve the right to close PRs that extend ICSForge beyond
this scope, with a clear explanation and suggestion of an alternate
project that might be a better fit.

## Contributions

See [CONTRIBUTING.md](CONTRIBUTING.md) for the mechanics. Contributions
are licensed under GPLv3 as per the project licence.

## Security

See [SECURITY.md](SECURITY.md). Security issues are handled privately
via GitHub Security Advisories, not public issues.

## Changes to This Document

Changes require a PR, review by at least one maintainer, and a 7-day
comment window before merge.
