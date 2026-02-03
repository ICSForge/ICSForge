# Live SOC Demo Flow (PCAP → Alert → Coverage + Proof-of-Delivery)

## Receiver (B) – Raspberry Pi
```bash
python -m icsforge.receiver --config icsforge/receiver/config.yml --bind 0.0.0.0
```
Receipts: `receiver_out/receipts.jsonl`

## Sender (A) – Run live scenario to Receiver
```bash
python -m icsforge.cli send --name unauthorized-command-chain --dst-ip <RECEIVER_IP> --outdir out --confirm-live-network
```

## Compare with NSM alerts + generate report
Normalize alerts to JSONL (optional) and run:
```bash
python -m icsforge.cli net-validate --events out/unauthorized-command-chain.jsonl --receipts receiver_out/receipts.jsonl --alerts alerts.jsonl --out out/network_validation.json
```


## Web UI
Receiver includes a read-only dashboard:
```bash
python -m icsforge.web --host 0.0.0.0 --port 8080
```


## Tip: PCAP artifacts
If you enable **Also build offline PCAP** when sending live traffic, you can download the generated PCAP directly from the Sender UI via **Download PCAP**.
