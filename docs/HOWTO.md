# ICSForge HOWTO

Installation, first-time setup, sender/receiver workflow, and validation guidance.

---

## 1) Install

```bash
git clone https://github.com/ICSforge/ICSforge.git
cd ICSforge
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .
chmod +x icsforge.sh
```

Installs into `.venv`. Run with `sudo` for live packet sends and raw socket access.

---

## 2) First-Time Setup

On first launch ICSForge prompts you to create an admin account:

```bash
sudo ./icsforge.sh web
# Open http://localhost:8080 — setup page appears automatically
```

**After creating your account, the setup page shows a generated callback token:**

```
Callback Token: abcXYZ123...
Receiver command: ./icsforge.sh receiver --callback-token abcXYZ123...
```

Copy this token. It protects receipt integrity — receipts without the correct
token are rejected. You will need it every time you start the receiver.

---

## 3) Start Sender

```bash
sudo ./icsforge.sh web --host 0.0.0.0 --port 8080
```

Navigate to `http://localhost:8080`. The Sender page lets you:

- Browse and search all 547 scenarios by tactic
- Set destination IP, source IP, and interface
- Preview live hex dump of protocol bytes before sending
- Toggle stealth mode (no correlation markers — realistic traffic only)
- Run scenarios live or generate offline PCAPs
- View the ATT&CK matrix with run overlay

---

## 4) Start Receiver

```bash
sudo ./icsforge.sh receiver --callback-token <your-token> --host 0.0.0.0 --port 9090
```

For Layer-2 protocols (PROFINET DCP, IEC 61850 GOOSE) on the same network segment:

```bash
sudo ./icsforge.sh receiver --callback-token <your-token> --l2-iface eth0
```

Navigate to `http://receiver-ip:9090`. The Receiver page shows:

- Live receipt feed as traffic arrives
- Unique technique and protocol counts
- ATT&CK matrix overlay of received techniques

---

## 5) Two-Machine Setup

**Sender machine (8080):**

```bash
sudo ./icsforge.sh web --host 0.0.0.0
# Network Settings → set Receiver IP to receiver machine's IP
# Click Save & Connect — sender registers callback URL with receiver
```

**Receiver machine (9090):**

```bash
sudo ./icsforge.sh receiver --callback-token <token> --host 0.0.0.0
```

The callback token must match on both sides. The sender's Network Settings
panel shows the configured token. Set the same value via `--callback-token`
on the receiver (or in `receiver/config.yml` under `callback.token`).

---

## 6) Run a Scenario

1. Open Sender → select a scenario from the list
2. Live payload preview appears immediately in the hex dump panel
3. Set **Destination IP** (your receiver's IP or the target device)
4. Click **Run Live** — traffic is sent and receipts appear in the receiver UI
5. Or click **Offline PCAP** to generate a PCAP without sending

**Stealth mode:** Toggle the stealth button before running to strip all
ICSForge correlation markers from the payload. Traffic is then bit-for-bit
identical to real device traffic. Delivery is confirmed via TCP ACK instead
of marker detection.

---

## 7) ATT&CK Matrix

Open `/matrix` on either sender or receiver:

- **Runnable** tiles (bright) — click to fire that technique variant
- **Precursor** tiles (dim) — network approximation only, not full technique
- **Overlay** — select a run or "★ All runs" to see which techniques executed

---

## 8) Campaigns

Open `/campaigns` to run multi-step attack chains:

- Industroyer2, TRITON-inspired, Stuxnet-style, and others
- Live SSE progress feed shows each step as it completes
- Full run stored in registry for matrix overlay

---

## 9) Non-RFC1918 Internal Networks

If your OT network uses publicly-routed IPs internally (e.g. `130.75.0.0/24`):

Go to **Tools → ⚙ Allowed Networks**, enter your CIDRs one per line, and click Save.
Takes effect immediately, survives restarts. No environment variables needed.

---

## 10) Send Policy

**Tools → 🔒 Send Policy** controls two opt-in capabilities that are disabled by default:

**Allow public webhook URLs** — off by default. Enable to deliver webhook events to
public services like Slack, PagerDuty, or Teams. When off, webhooks are restricted
to private/loopback addresses.

**Allow public PCAP replay targets** — off by default. Enable only when you have
explicit permission to send traffic to a device on a public IP. When off, replay
is restricted to private/loopback ranges.

The UI toggle is the sole authority. Settings persist across restarts.

## 11) Tools Page

- **Offline PCAP generator** — build PCAPs for any scenario without sending
- **PCAP upload & replay** — upload a PCAP and replay it to any destination IP
- **Coverage heatmap** — download a standalone HTML ATT&CK heatmap
- **Allowed Networks** — configure non-RFC1918 internal ranges
- **Detection rules** — download Suricata + Sigma rules for all scenarios

---

## 12) Validation: Executed → Delivered → Detected

The full validation loop:

1. **Executed** — ICSForge ground-truth events JSONL, one entry per packet
2. **Delivered** — receiver receipts confirm traffic traversed the network
3. **Detected** — ingest your NSM/IDS EVE JSON via Tools → Alerts Ingest

Report page generates a gap analysis: which techniques were executed, which
were delivered (by marker or TCP ACK), and which triggered a detection alert.

Delivery ratio is computed as `delivered_techniques / expected_techniques`
per run — not a binary pass/fail.

---

## 13) Troubleshooting

| Symptom | Fix |
|---|---|
| Receipt not appearing in sender | Check callback token matches on both sides; check firewall allows :8080 |
| `sent: 0` on live run | Nothing listening on target port; check receiver is running |
| PROFINET/GOOSE not received | Use `--l2-iface`; sender and receiver must be on same L2 segment |
| `dst_ip blocked` error | IP not in allowed ranges; add via Allowed Networks UI |
| Port bind fails | Use `sudo` or change ports in Network Settings |
