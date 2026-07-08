# ICSForge — User Manual (Web App)

This manual covers day-to-day use of ICSForge through its **web application** —
the primary interface. It assumes ICSForge is already installed (see
`INSTALLATION.md`). The command-line tool can do everything the web app does, but
this manual focuses on the UI.

**What ICSForge does:** it generates realistic ICS protocol traffic mapped to
MITRE ATT&CK for ICS and sends it from a **Sender** to a **Receiver** (a safe
sinkhole), so you can test whether your security controls behave as expected:
firewalls/ACLs (did the traffic get through?) and network security monitoring
sensors (did the sensor alarm?).

---

## 1. The two roles: Sender and Receiver

ICSForge runs as two cooperating pieces:

- **Sender** — generates and emits the attack traffic. This is the main web UI.
- **Receiver** — a safe sinkhole placed at the target location. It witnesses what
  arrives and reports it back. It is **not** a simulated PLC and never sends
  device responses, so it is safe to point traffic at.

A typical test: put the Sender in your IT zone (or another OT zone) and the
Receiver in the target OT zone, with the firewall/sensor you want to test in
between. ICSForge then tells you what crossed the boundary and/or whether the
sensor fired.

```
[ Sender (web UI) ] --- firewall / NSM under test --- [ Receiver (sinkhole) ]
        |                                                      |
        '--------------- callback / report (HTTP) -------------'
```

---

## 2. Starting the apps

**Start the receiver** (on the target/sinkhole host) with its own web console:

```bash
icsforge-receiver --web --web-host 0.0.0.0 --web-port 9090
```

**Start the sender web app** (on your operator host):

```bash
icsforge-web --host 0.0.0.0 --port 8080
```

Open `http://<sender-host>:8080/`. On first run you'll create an admin account
(**Setup**) and then **Log in**.

> Keep the Sender on localhost (`127.0.0.1`) unless you specifically need remote
> access on a trusted network. The callback/management channel between receiver
> and sender is HTTP and is best run over a management network, separate from the
> path you're testing.

---

## 3. The Sender page — a tour

The Sender page is where you'll spend most of your time. Its main areas:

- **Scenario list** (left) — the 600+ scenarios and named attack chains, grouped
  by technique. Click one to select it.
- **Payload preview** (center) — a live hex dump of the exact bytes for the
  selected scenario/step. It updates instantly as you change options.
- **Network config** — Receiver IP/Port, your Sender IP (SRC), the egress
  interface, and a timeout.
- **Run options** — Test profile, Marker mode, Stateful TCP, Build PCAP, and the
  safety confirmation.
- **Action buttons** — **▶ Run Live** and **⬇ PCAP Only**.
- **Run log / timeline** — live progress and per-step confirmation as traffic is
  witnessed by the receiver.

Other pages (top navigation): **Matrix** (ATT&CK coverage view), **Report**
(witnessed-vs-expected validation results), **Receiver** (the receiver console),
and **Campaigns** (batched runs).

---

## 4. Run options explained

These four controls determine *what* traffic is produced and *how* results are
interpreted. Each has a hover `?` in the UI.

### 4.1 Test profile — Firewall/ACL ⟷ NSM

Sets safe defaults and how results are framed. **The receiver is always a passive
sink; no device responses are ever fabricated.**

| | **Firewall / ACL** (default) | **NSM** |
|---|---|---|
| Question | Did the traffic *arrive*? | Did the sensor *alarm*? |
| Transport | Unidirectional — no handshake assumed | Completes the TCP handshake so stream sensors engage |
| The finding | Arrival = a rule allowed it; investigate the policy | Witnessed traffic is paired with the expected technique to spot detection gaps |

Why this matters: in a firewall test you must **not** assume return traffic — a
rule that permits the forward flow may still block the reverse, so treating the
run as bidirectional would hide real misconfigurations. Selecting **NSM**
automatically turns **Stateful TCP** on.

### 4.2 Marker mode — Covert / Explicit / Stealth

How (and whether) ICSForge tags traffic so the receiver can correlate it back to
the run.

- **Covert** (default) — correlation marker woven into an existing protocol field
  (e.g. Modbus transaction ID). **Zero added bytes, no visible signature** — your
  IDS can't "cheat" on a watermark, yet the receiver still correlates the run.
- **Explicit** — a literal `ICSF` tag in the payload. Matchable by a single
  content rule; useful for offline PCAP detection **without a receiver**. Visibly
  synthetic.
- **Stealth** — no marker at all; bit-for-bit like real device traffic.
  Correlation falls back to the receiver's expectation registry / TCP ACK.

The payload preview re-renders immediately when you switch modes, so you can see
exactly what each produces.

### 4.3 Stateful TCP

Emits a full TCP conversation (SYN/SYN-ACK/ACK handshake, per-segment ACKs,
FIN/ACK teardown) in the PCAP, so it survives stream reassembly and exercises
stateful IDS engines. Off by default; **on** by default when the Test profile is
NSM. You can toggle it independently.

### 4.4 Build PCAP

When enabled, a `.pcap` of the run is written alongside the event log, downloadable
afterward. For **PCAP Only** runs this is implied.

---

## 5. Workflow A — Firewall / ACL test (offline or live)

**Goal:** find out whether any of the 10 ICS protocols can cross a boundary they
shouldn't.

1. On the **Receiver** host, start `icsforge-receiver --web ...` in the target
   zone.
2. In the Sender UI, set **Test profile → Firewall / ACL** (default).
3. Set **Receiver IP/Port** to the sinkhole, and **Source IP (SRC)** to your
   sender's address.
4. Select a scenario (or a whole chain) from the list. Check the payload preview.
5. Choose how to run:
   - **⬇ PCAP Only** — produces a capture without sending anything on the wire
     (zero risk; good for rehearsal or feeding an offline analyzer).
   - **▶ Run Live** — actually emits the traffic toward the receiver. This is
     gated: you must tick the **safety confirmation** checkbox first, and live
     send is restricted to your allowlist.
6. Read the result:
   - **Traffic witnessed at the receiver** → a firewall rule allowed it. That's
     your finding — investigate the policy that permitted that protocol.
   - **Nothing witnessed** → the boundary blocked it (expected for a correctly
     segmented path).

> Note on the callback: confirmation travels back to the Sender over HTTP, which
> is a *separate* path from the ICS traffic under test. If that HTTP path is also
> blocked you may not see the live callback even though the receiver logged the
> arrival — check the receiver console / report, which is the ground truth.

---

## 6. Workflow B — NSM / sensor test

**Goal:** confirm your monitoring sensor raises the expected alert for a given
technique.

1. Place Sender and Receiver where the path between them is **known to be open**
   (so you're testing detection, not connectivity).
2. Set **Test profile → NSM**. Stateful TCP turns on automatically so your
   stream-tracking sensor engages.
3. Optionally set **Marker mode → Stealth** if you want to be sure the sensor is
   detecting the *behavior*, not an ICSForge tag.
4. Select the scenario and **▶ Run Live**.
5. The receiver witnesses the traffic and records the **expected technique** for
   that scenario.
6. Open the **Report** page. For NSM runs it shows, per run:
   - traffic **witnessed at the sink** + the **expected technique**, and
   - when you supply your sensor's alert feed, whether the sensor **fired** — or a
     **"possible detection gap"** when traffic arrived but no matching alert did.

That detection-gap line is the actionable result: it's the question *"if someone
did this in my plant, would my sensor see it?"* answered concretely.

---

## 7. Detection content — Suricata & Sigma rules

ICSForge doesn't just generate attack traffic; it ships **matching detection
content** so you can prove your sensor would catch each technique — and close the
loop with the witnessed-vs-expected report. The rules are auto-generated from the
same scenario library that produces the traffic, so they stay in lockstep with it.

### 7.1 The three detection tiers

Every scenario produces rules at three tiers, each a deliberate trade-off between
false-positive rate and how much it depends on ICSForge's own markers:

| Tier | File | What it matches | False positives | Use it when |
|---|---|---|---|---|
| **Tier 1 — lab_marker** | `icsforge_lab.rules` | The ICSForge correlation marker (covert field value or explicit `ICSF` tag) | **Zero** — only ICSForge traffic carries it | Confirming *your pipeline works* — "did my sensor see the test at all?" |
| **Tier 2 — protocol_heuristic** | `icsforge_heuristic.rules` | Protocol magic bytes at fixed offsets (e.g. an S7comm header) | Some — real protocol traffic can match | Broad "is this protocol present where it shouldn't be?" detection |
| **Tier 3 — semantic** | `icsforge_semantic.rules` | Function-code / command semantics (e.g. Modbus FC 0x06 write, S7 STOP-CPU) | Low | **Recommended** — detects the malicious *action*, not a watermark |

Tier 3 is what you'd actually deploy: it keys on the dangerous behavior itself, so
it fires on a real attacker, not just on ICSForge. Tier 1 is the honest "did the
plumbing work" check (it can't false-positive, but it also only catches ICSForge's
own traffic). Sigma YAML is emitted per scenario covering all three tiers, so you
can convert to your SIEM's language (`sigma convert -t splunk …`).

### 7.2 Getting the rules from the web app

On the **Report** page, click **⬇ Detection Rules (Suricata + Sigma)**. This
downloads a zip containing:

```
icsforge_lab.rules         ← Tier 1
icsforge_heuristic.rules   ← Tier 2
icsforge_semantic.rules    ← Tier 3 (recommended)
sigma/<scenario>.yml       ← Sigma rules per scenario, all tiers
```

(The same content is available on the CLI via `icsforge detections export --outdir
rules/` or `--zip rules.zip`, and `icsforge detections preview` prints the tier
counts without writing anything.)

### 7.3 Running the rules against ICSForge traffic

Point Suricata at a capture (e.g. a **Build PCAP** / **PCAP Only** artifact, or a
live capture on your sensor's span port):

```bash
suricata -r capture.pcap -S icsforge_semantic.rules -l /tmp/
cat /tmp/fast.log     # one line per alert
```

These rules fire on the **bytes on the wire** — so they alert identically whether
the traffic came from an offline PCAP or a live send. A live send puts the same
spec-correct bytes on the network (with a real TCP handshake), so the same rules
that pass offline fire on live traffic too. When testing a stream-based sensor,
use the **NSM** profile (or turn on **Stateful TCP**) so the capture includes a
full handshake for the engine to track.

> Tip: for an honest end-to-end test, send in **Stealth** marker mode and run the
> **Tier 3 (semantic)** rules. That proves your detection catches the *attack
> behavior* with no ICSForge watermark to lean on — the closest thing to a real
> adversary.

### 7.4 Closing the loop — feeding alerts back into the report

The point of the rules is to confirm your sensor fires. Two ways to bring that
result back into ICSForge's witnessed-vs-expected report:

- **Live EVE tap (Sender page).** Set the **Suricata EVE JSON** path in the sender
  config (the `eve.json` your sensor writes). ICSForge tails it live and
  **confirmed detections update the run timeline automatically** as they fire —
  you watch detections light up step-by-step during the run.
- **Alerts Ingest (Tools page).** After a run, point ICSForge at your sensor's
  alert output — **Suricata EVE JSON**, or **Generic** pass-through for other
  sources. ICSForge correlates the alerts with the run's expected techniques and
  feeds the NSM **detection-gap** analysis in the Report.

  > The EVE path must be **relative to the ICSForge project root** (e.g.
  > `out/alerts/suricata_eve.json`); absolute paths like `/var/log/suricata/eve.json`
  > are rejected for safety. Copy or symlink your sensor's output under the project
  > if needed.

With either path, the Report's NSM view turns into the answer you came for: for
each technique, **traffic witnessed at the sink** + **sensor fired / did NOT fire**
— a concrete map of your detection gaps.

---

## 8. Reviewing results

- **Run log / timeline** (Sender page) — live, per-step progress and confirmation
  as each step is witnessed.
- **Report page** — the witnessed-vs-expected validation report, framed by test
  profile (boundary-traversal findings for Firewall/ACL; detection-gap analysis
  for NSM). Supply an alerts feed to complete the NSM diff. Also hosts the
  **Detection Rules** download (Suricata + Sigma).
- **Detection rules** — download from the Report page and run against your captures
  or sensor; feed the resulting alerts back via the live EVE tap or Alerts Ingest
  (see §7).
- **Downloaded PCAP** — open in Wireshark to inspect the exact bytes; the traffic
  is built to survive independent dissection.
- **Matrix page** — see which ATT&CK for ICS techniques your run/campaign covered.
  Toggle between **v18.1** and **v19** at the top: v19 shows the sub-techniques
  introduced in the April 2026 release (e.g. Program Download → Download All /
  Online Edit / Program Append), with your covered scenarios mapped forward
  automatically. Click any runnable tile to fire it.

---

## 9. Tips and good practice

- **Rehearse with PCAP Only first.** It produces the exact artifact with zero wire
  traffic — ideal for verifying a scenario before a live run.
- **Put the callback/management traffic on a separate management network** from
  the path you're testing, so a blocked data path never hides the receiver's
  confirmation.
- **Use Covert (default) or Stealth for IDS/NGFW tests** so detections can't rely
  on a visible watermark. Use Explicit only when you deliberately want an
  offline, receiver-less detection check.
- **Trust HIGH-confidence ATT&CK mappings; sanity-check MEDIUM; treat LOW as a
  hint.** Scenarios carry honest confidence labels.
- **Live send is intentionally gated** behind the confirmation checkbox and an
  allowlist. Keep it that way; point traffic at the cooperative receiver, never at
  production controllers.

---

## 10. Quick reference

| Task | Where |
|---|---|
| Start receiver | `icsforge-receiver --web --web-port 9090` |
| Start sender UI | `icsforge-web --port 8080` → `http://localhost:8080/` |
| Generate a capture, no wire traffic | Sender page → **⬇ PCAP Only** |
| Send live to the receiver | Sender page → tick confirmation → **▶ Run Live** |
| Firewall test | Test profile → **Firewall / ACL** |
| Sensor test | Test profile → **NSM** |
| Hide the marker from an IDS | Marker mode → **Stealth** |
| Exercise a stream IDS | **Stateful TCP** on (auto in NSM) |
| See witnessed-vs-expected | **Report** page |
| Download detection rules | **Report** page → **⬇ Detection Rules (Suricata + Sigma)** |
| Run rules on a capture | `suricata -r capture.pcap -S icsforge_semantic.rules -l /tmp/` |
| Feed sensor alerts back | Sender page **EVE tap** (live) or Tools page **Alerts Ingest** |
| Replay a saved PCAP | Tools page → **PCAP Replay** (Destination IP auto-fills from the PCAP; edit to redirect) |
| See ATT&CK coverage | **Matrix** page (toggle v18.1 / v19) |

For anything not covered here, every run option has a hover `?` in the UI, and the
CLI mirrors all of this (`icsforge --help`).
