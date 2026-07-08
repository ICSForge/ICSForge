# ICSForge Scenario Schema

This document explains the YAML schema in `icsforge/scenarios/scenarios.yml`,
with particular focus on the parts that have surprised external reviewers.

## Two scenario types

ICSForge has **two structurally distinct kinds of entries** in
`scenarios.yml`. Tooling that audits the file must handle both correctly.

### 1. Standalone scenarios (611 of 627)

A single MITRE ATT&CK ICS technique exercised on a single protocol via
one or more steps using related styles.

```yaml
T0855__unauth_command__modbus_force_coil:
  title: 'T0855 – Unauthorized Command Message: Modbus Force Coil'
  tactic: Impair Process Control
  technique: T0855                         # primary
  technique_v19: T1692.001                 # optional v19 sub-tech mapping
  confidence: high
  steps:
    - type: pcap
      proto: modbus
      technique: T0855                     # MUST match scenario primary
      style: force_coil
      count: 5
      interval: 0.4s
```

For standalone scenarios:
- **Every step's `technique` field equals the scenario's `technique` field.**
  This is enforced by `tests/test_coverage_consistency.py` and audit
  tooling can rely on it.
- The scenario name uses the convention `T<id>__<short_label>__<proto>_<style>`.

### 2. Chain scenarios (16 of 627)

A multi-stage attack reproducing a known TTP sequence (e.g.
Industroyer2, TRITON, Stuxnet). The chain's `technique:` field is the
**chain's tactical-objective primary** — typically the
*Impact* / *Lateral Movement* technique that summarizes the attacker's
goal — while individual steps use their own observable techniques.

```yaml
CHAIN__industroyer2__power_grid:
  title: CHAIN – Industroyer2 / Ukraine 2022 power grid (IEC-104 + S7comm)
  description: 'Reproduces the Industroyer2 attack sequence...'
  tactic: Multi-Stage                       # always 'Multi-Stage' for chains
  technique: T0855                          # CHAIN PRIMARY (tactical objective)
  confidence: medium                        # always medium-or-low for chains
  confidence_rationale: 'Multi-stage chain spanning 5 techniques...'
  steps:
    - type: pcap
      proto: iec104
      technique: T0888                      # STEP technique (observable),
      style: startdt                        # may differ from chain primary
      count: 2
      interval: 0.2s
    - type: pcap
      proto: iec104
      technique: T0848
      style: single_command
      count: 5
    # ... more steps with their own technique IDs
```

For chain scenarios:
- **Step-level `technique` may differ from scenario-level `technique`.**
  This is intentional, not drift.
- The scenario name MUST start with `CHAIN__`.
- The `tactic` field is always `Multi-Stage`.
- The `confidence` is always `medium` or `low`, with a
  `confidence_rationale` explaining the chain framing.
- **ATT&CK mapping is derived, not duplicated.** Standalone scenarios carry
  a structured `attack_mapping:` object; chains intentionally do **not**.
  A chain's ATT&CK coverage is the union of its steps' techniques, with the
  top-level `technique:` field naming the chain's primary objective. Tools
  that need a chain's mapping should read the primary from `technique:` and
  the secondary set from the per-step `technique:` fields rather than expecting
  a top-level `attack_mapping` block. This keeps a single source of truth (the
  steps) and avoids a duplicated mapping drifting out of sync with them.

### Why chains exist

Chains capture observable attack *sequences* (TTP chains) that:
1. Map to a single tactical objective (the chain primary)
2. Decompose into multiple individual techniques (the steps)

Examples:
- **Industroyer2 chain** — primary T0855 Unauthorized Command, steps
  span T0888 Discovery, T0848 Coordinated Cmd, T0813 DoS, T0815 DoV.
- **Damage to Property chain** — primary T0879 (an *effect*, not
  directly observable), steps span T0846, T0888, T0878, T0855, T0856
  (all observable on the wire).

The chain framing connects the observable steps into a known threat
model that defenders recognise. Without chains, T0879 (Damage to
Property) couldn't be primary-mapped at all because it's a physical
effect, not a network signature.

## Audit guidance

Tooling that audits `scenarios.yml` for "step technique matches
scenario technique" MUST treat chains specially:

```python
for name, body in scenarios.items():
    if name.startswith("CHAIN__"):
        # Chains: step techniques INTENTIONALLY may differ from chain primary.
        # Do not flag as drift. Treat each step as its own observable technique.
        continue
    # Standalone: step technique must match scenario technique.
    primary = body.get("technique")
    for step in body.get("steps", []):
        assert step.get("technique") == primary, (
            f"{name}: step technique != scenario technique"
        )
```

This pattern is already implemented in
`tests/test_coverage_consistency.py` and in the rule generator at
`icsforge/detection/generator.py`. External audits should adopt it
to avoid the 82 false-positive "mismatches" that chain scenarios
otherwise produce.

## Coverage counting

The canonical script `scripts/v19_coverage.py` counts coverage in a
chain-aware way:

- A technique is **covered** if it appears as either:
  - The `technique` field of any standalone scenario, OR
  - The `technique` field of any chain (chain primary), OR
  - The `technique` of any step within any scenario (incl. chain steps)

This is why T0879 (chain-primary-only) shows up in coverage even
though no standalone scenario exercises it.

## Other fields

- `technique_v19`: optional. Set when the v18 ID became a v19
  sub-technique (e.g. T0855 → T1692.001). Validated against the
  MITRE v19 catalog by `tests/test_v062_additions.py`.
- `confidence`: required. `high` / `medium` / `low`. Anything below
  high requires `confidence_rationale`.
- `tactic`: required. One of the 12 canonical MITRE ATT&CK ICS
  tactics, OR `Multi-Stage` for chains.
- `attack_mapping`: optional. Structured ATT&CK metadata block (used
  by some scenarios).
