# ICSForge — CLI Reference

Complete reference for the `icsforge` command-line interface and the
`icsforge-receiver` command. The web app (see `USER_MANUAL.md`) is the primary
interface for most users; the CLI exposes the same capabilities for scripting,
CI, and headless use.

All examples assume ICSForge is installed (see `INSTALLATION.md`) and, if you used
a virtual environment, that it is activated.

---

## Global usage

```
icsforge [-h] [-V] [-v] [--log-level LEVEL] [--log-file FILE] <command> ...
```

| Option | Meaning |
|---|---|
| `-V`, `--version` | Print the ICSForge version and exit |
| `-v`, `--verbose` | Enable debug logging (same as `--log-level DEBUG`) |
| `--log-level LEVEL` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `--log-file FILE` | Write logs to a file in addition to stderr |

**Commands:** `generate`, `send`, `net-validate`, `selftest`, `scenarios`,
`campaign`, `detections`, `viewer`, `demo`.

---

## `generate` — build offline artifacts (events + PCAP)

Produces a ground-truth event log and an optional PCAP from a scenario, **without
sending anything on the network**. This is the zero-risk path: nothing leaves the
machine.

```
icsforge generate --name <scenario> [options]
```

| Flag | Default | Meaning |
|---|---|---|
| `--name NAME` | *(required)* | Scenario name (see `scenarios list`) |
| `--file FILE` | bundled pack | Scenario YAML pack to load from |
| `--outdir OUTDIR` | `out` | Where to write events/PCAP |
| `--dst-ip DST_IP` | `127.0.0.1` | Destination IP written into the packets |
| `--src-ip SRC_IP` | `127.0.0.1` | Source IP written into the packets |
| `--no-marker` | off | **Stealth** mode — no correlation marker (bit-for-bit real traffic) |
| `--explicit-marker` | off | **Explicit** mode — literal 13-byte `ICSF` tag in payloads (matchable offline without a receiver) |
| `--stateful` | off | Emit a full TCP conversation (SYN/SYN-ACK/ACK + per-segment ACKs + FIN/ACK teardown) so the PCAP survives stream reassembly |
| `--profile {firewall,nsm}` | `firewall` | Test profile. `nsm` defaults `--stateful` on; an explicit `--stateful` always wins. Never fabricates device responses. |

**Marker modes** are mutually exclusive in effect: default is covert,
`--explicit-marker` selects explicit, `--no-marker` selects stealth.

```bash
# Covert (default), offline PCAP
icsforge generate --name T0855__unauth_command__modbus --dst-ip 10.20.30.40

# Stealth + stateful for a stream-IDS test capture
icsforge generate --name T0855__unauth_command__modbus --dst-ip 10.20.30.40 \
  --no-marker --stateful

# NSM profile (handshake on by default)
icsforge generate --name T0855__unauth_command__modbus --dst-ip 10.20.30.40 --profile nsm
```

**Output:** a JSON summary with the `run_id`, the events JSONL path, and the PCAP
path (or `null` if no packets were built). Artifacts land under `--outdir`
(`events/` and `pcaps/`).

---

## `send` — emit traffic live to a Receiver

Sends real protocol traffic over the network to an ICSForge Receiver. This opens
real OS sockets (a genuine TCP handshake). It is **gated**: you must pass
`--confirm-live-network`, and the destination must be in the allowlist.

```
icsforge send --name <scenario> --dst-ip <ip> --confirm-live-network [options]
```

| Flag | Default | Meaning |
|---|---|---|
| `--name NAME` | *(required)* | Scenario name |
| `--dst-ip DST_IP` | *(required)* | Receiver IP to send to |
| `--confirm-live-network` | off | **Required** — explicit opt-in to put traffic on the wire |
| `--file FILE` | bundled pack | Scenario YAML pack |
| `--outdir OUTDIR` | `out` | Where to write ground-truth artifacts |
| `--iface IFACE` | auto | Egress interface (required for L2 protocols: GOOSE, PROFINET-DCP) |
| `--src-ip SRC_IP` | auto | Source IP |
| `--timeout TIMEOUT` | `2.0` | Per-connection timeout (seconds) |
| `--allowlist ALLOWLIST` | `dst-ip` | Comma-separated allowlisted receiver IPs |
| `--also-build-pcap` | off | Also write an offline PCAP of the same run |
| `--no-marker` | off | Stealth mode (no correlation marker) |
| `--explicit-marker` | off | Explicit `ICSF` marker mode |

```bash
icsforge send --name T0855__unauth_command__modbus \
  --dst-ip 10.20.30.40 --confirm-live-network --also-build-pcap
```

> Live send and live L2 capture need raw-socket privilege — run with `sudo` or
> grant the interpreter `cap_net_raw` (see `INSTALLATION.md` §6). The per-protocol
> sequence fields and marker modes behave identically to `generate`, so the live
> traffic matches the offline PCAP byte-for-byte (plus a real handshake).

---

## `net-validate` — correlate events, receipts, and alerts

Builds the witnessed-vs-expected report by correlating ground-truth events with
the receiver's receipts and (optionally) your sensor's alerts.

```
icsforge net-validate --events <events.jsonl> --receipts <receipts.jsonl> [options]
```

| Flag | Default | Meaning |
|---|---|---|
| `--events EVENTS` | *(required)* | Ground-truth events JSONL (from `generate`/`send`) |
| `--receipts RECEIPTS` | *(required)* | Receiver receipts JSONL |
| `--alerts ALERTS` | none | Your sensor's alerts (e.g. Suricata EVE JSON) — enables the NSM detection-gap diff |
| `--out OUT` | stdout | Write the JSON report to a file |

The report is framed by test profile: Firewall/ACL runs read as boundary-traversal
findings; NSM runs pair witnessed traffic with the expected technique and flag a
**detection gap** when traffic arrived but no matching alert fired.

---

## `selftest` — end-to-end sanity check

Stands up a receiver, sends to it, and validates the receipts — proving the core
pipeline works.

```
icsforge selftest [--live] [--web-port PORT] [options]
```

| Flag | Default | Meaning |
|---|---|---|
| `--live` | off | Exercise the live send path (not just offline) |
| `--web-port WEB_PORT` | `8765` | Port for the temporary receiver web console |
| `--dst-ip DST_IP` | loopback | Target for the self-test |
| `--bind BIND` | — | Receiver bind address |
| `--cwd CWD` | — | Working directory |
| `--receipts RECEIPTS` | — | Receipts path override |
| `--receiver-config CONFIG` | — | Receiver config override |

```bash
icsforge selftest --live          # expect a series of [PASS] lines
```

---

## `scenarios` — inspect the library

```
icsforge scenarios list [options]
```

| Flag | Meaning |
|---|---|
| `--proto PROTO` | Filter by protocol (modbus, dnp3, s7comm, iec104, opcua, enip, bacnet, mqtt, iec61850, profinet_dcp) |
| `--technique TECHNIQUE` | Filter by MITRE technique ID (e.g. T0855) |
| `--search SEARCH` | Free-text search across names/descriptions |
| `--limit LIMIT` | Cap the number of results |
| `--json` | Machine-readable JSON output |
| `--file FILE` | Scenario pack to inspect |

```bash
icsforge scenarios list --proto modbus
icsforge scenarios list --technique T0855
icsforge scenarios list --search "stop cpu" --json
```

---

## `detections` — generate Suricata + Sigma rules

```
icsforge detections preview                 # tier counts, writes nothing
icsforge detections export [options]        # write the rules
```

**`export` options:**

| Flag | Default | Meaning |
|---|---|---|
| `--outdir OUTDIR` | — | Write rule files to this directory |
| `--zip ZIP` | — | Write a zip archive instead of a folder |
| `--technique TECHNIQUE` | all | Restrict to one technique |
| `--no-marker` | off | Omit the Tier-1 lab_marker rules |

Produces three Suricata rule files plus per-scenario Sigma YAML:

- `icsforge_lab.rules` — **Tier 1**, matches the ICSForge marker (zero false positives)
- `icsforge_heuristic.rules` — **Tier 2**, protocol magic bytes
- `icsforge_semantic.rules` — **Tier 3**, function-code/command level (recommended)
- `sigma/<scenario>.yml` — Sigma rules covering all three tiers

```bash
icsforge detections preview
icsforge detections export --zip icsforge_rules.zip
suricata -r capture.pcap -S icsforge_semantic.rules -l /tmp/
```

See `USER_MANUAL.md` §7 for the full detection workflow.

---

## `viewer` — live Suricata alert viewer

A colour-coded (by tier) live view of Suricata EVE JSON alerts.

```
icsforge viewer serve [--host HOST] [--port PORT] [--eve-path EVE]    # tail an eve.json (default subcommand)
icsforge viewer replay <pcap> [<pcap> ...]                            # run pcaps through suricata first, then view
```

`viewer serve` is the default — tailing an `eve.json` live; `viewer replay` runs
one or more PCAPs through Suricata first and then opens the live view.

| Flag | Meaning |
|---|---|
| `--host HOST` | Bind host for the viewer web UI |
| `--port PORT` | Bind port |
| `--eve-path EVE_PATH` | Path to the `eve.json` to tail (`serve`) |

```bash
# Replay a generated capture through Suricata and watch alerts live
icsforge viewer replay out/pcaps/myrun.pcap
```

---

## `campaign` — run curated multi-scenario playbooks

Campaigns are named bundles of scenarios (e.g. sector-specific playbooks). Mirrors
the `/campaigns` web page.

```
icsforge campaign list [--json]
icsforge campaign validate
icsforge campaign run --id <campaign-id> --dst-ip <ip> --confirm-live-network [options]
```

**`run` options:**

| Flag | Default | Meaning |
|---|---|---|
| `--id ID` | *(required)* | Campaign identifier (from `campaign list`) |
| `--dst-ip DST_IP` | *(required)* | Receiver IP |
| `--confirm-live-network` | off | Required to send live |
| `--iface IFACE` | auto | Egress interface |
| `--timeout TIMEOUT` | `2.0` | Per-connection timeout |
| `--outdir OUTDIR` | `out` | Artifacts directory |
| `--campaigns-file FILE` | bundled | Campaign definitions file |
| `--json` | off | JSON output |

```bash
icsforge campaign list
icsforge campaign run --id water_treatment --dst-ip 10.20.30.40 --confirm-live-network
```

---

## `demo` — end-to-end demo stack

Brings up a containerised demo environment (Docker Compose).

```
icsforge demo up        # start the demo stack
icsforge demo fire      # run a curated attack through it
icsforge demo down      # tear it down
```

> The demo stack uses Docker; the rest of ICSForge does not require it (see
> `INSTALLATION.md`, which covers the traditional non-Docker install).

**Docker compose profiles (advanced).** The demo compose file supports profiles
to start subsets of the stack:

```bash
docker compose -f docker-compose.demo.yml --profile full up           # sender + receiver + suricata + viewer
docker compose -f docker-compose.demo.yml --profile sender up          # sender only
docker compose -f docker-compose.demo.yml --profile receiver-only up   # receiver only (split-host setups)
```

The `receiver-only` profile runs the receiver stand-alone (no sender required) —
useful when the receiver lives on a separate host across the boundary under test.

---

## `icsforge-receiver` — the safe sinkhole

Runs the receiver that witnesses arriving traffic and reports it back. Place it at
the target location of your test.

```
icsforge-receiver [--web] [--web-host HOST] [--web-port PORT] [options]
```

| Flag | Default | Meaning |
|---|---|---|
| `--web` | off | Run with the web console |
| `--web-host HOST` | `127.0.0.1` | Web console bind host (alias `--host`) |
| `--web-port PORT` | `9090` | Web console port (alias `--port`) |
| `--no-web` | — | Headless (no web console) |
| `--config CONFIG` | — | Receiver config file |
| `--bind BIND` | — | Listener bind address for incoming traffic |
| `--l2-iface L2_IFACE` | — | Interface for PROFINET-DCP / GOOSE L2 capture |
| `--callback-url URL` | — | Sender callback URL for live receipt forwarding |
| `--callback-token TOKEN` | — | Shared token for callback auth (must match the sender) |
| `--log-level LEVEL` | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR` |
| `--log-file FILE` | — | Also log to a file |

```bash
icsforge-receiver --web --web-host 0.0.0.0 --web-port 9090
```

> The callback is a fire-and-forget HTTP POST on a path **separate** from the ICS
> traffic under test — best run over a management network. If the callback path is
> blocked, the receiver still records the receipt locally; that log is the ground
> truth.

---

## Exit codes & scripting

- Commands return `0` on success, non-zero on error.
- Use `--json` (where available) for machine-readable output in CI.
- `generate` and `detections export` are the headless building blocks for a CI
  detection-regression pipeline: generate a capture, export the rules, run
  Suricata, assert the expected alerts fired.
