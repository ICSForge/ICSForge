# ICSForge HOWTO
Installation, Usage, Receiver Validation, PCAP Workflows, and SOC Demo Guidance.

---

## 1) Install

```bash
chmod +x icsforge.sh bin/icsforge
./icsforge.sh install
```

### Run with sudo?
For realistic ICS ports and raw packet send, run web/receiver with sudo:

```bash
sudo ./icsforge.sh web
sudo ./icsforge.sh receiver
```

---

## 2) Start Sender (Web UI)

```bash
sudo ./icsforge.sh web --host 0.0.0.0 --port 8080
```

Open: `http://localhost:8080/`

Sender mode navigation includes:
- Sender
- SOC Mode
- ATT&CK Matrix
- Tools

### Run a scenario (live send)
1. Pick a scenario
2. Set destination IP (your receiver / safe target)
3. Choose interface (if required)
4. Click **Send**

### “Also build offline PCAP”
If enabled, ICSForge creates a `.pcap` artifact for the run (in addition to live traffic).
After the run finishes, the Sender UI shows **Download PCAP** (when a PCAP was created).

> Note: This PCAP is a generated artifact of the scenario steps, not an OS capture.
> (If you need a true capture, run tcpdump/wireshark separately.)

---

## 3) Start Receiver (Appliance UI)

```bash
sudo ./icsforge.sh receiver --host 0.0.0.0 --port 8080
```

Receiver mode navigation is intentionally minimal:
- Receiver
- ATT&CK Matrix
- Tools

Receiver is used to:
- confirm delivery (“did traffic reach the destination?”)
- record validations for reporting

---

## 4) ATT&CK Matrix Page
Open Matrix and click **runnable** techniques to:
- pick a scenario variant (protocol alternatives)
- send traffic to the configured destination

Techniques that are not network-runnable are marked accordingly.

---

## 5) Tools Page (offline)
Tools can:
- build offline PCAP bundles for replay
- run coverage reports
- run self-test / diagnostics

---

## 6) SOC Mode (Executed vs Detected)
SOC Mode compares:

- **Executed**: what ICSForge ran (ground truth)
- **Detected**: what your NSM/IDS produced

To evaluate detections, you must provide exports from your tooling, e.g.:
- Suricata EVE JSON
- Zeek logs
- vendor sensor JSON/CSV exports

SOC Mode then correlates time window + protocol/port + technique mapping.

---

## 7) Live SOC demo flow
See `docs/LIVE_SOC_DEMO_FLOW.md`.

---

## 8) Troubleshooting
- If web returns 500: run from terminal and copy the traceback.
- If ports fail: use sudo or change ports.
- If live send doesn’t traverse the network: verify interface and routing; use Receiver to confirm delivery.

---

## 9) Latest phase notes
See `docs/PHASE.md`.
