#!/usr/bin/env python3
"""
ICSForge PCAP Validation Script

Generates a PCAP for every scenario and validates:
1. PCAPs have valid structure (magic, version, linktype)
2. Correct destination ports per protocol
3. Frame count matches expected scenario step counts
4. No truncated packets
5. (Optional) tshark can dissect every packet with no malformed frames

Usage:
  python scripts/validate_pcaps.py                    # struct-only (no tshark needed)
  python scripts/validate_pcaps.py --tshark           # full tshark dissection
  python scripts/validate_pcaps.py --tshark --verbose # show per-packet details
  python scripts/validate_pcaps.py --scenario T0855__unauth_command__modbus
"""
import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

EXPECTED_PORTS = {
    "modbus": 502, "dnp3": 20000, "s7comm": 102, "iec104": 2404,
    "opcua": 4840, "enip": 44818, "mqtt": 1883,
    "bacnet": 47808, "profinet_dcp": None,
}

EXPECTED_IP_PROTO = {
    "modbus": 6, "dnp3": 6, "s7comm": 6, "iec104": 6,
    "opcua": 6, "enip": 6, "mqtt": 6,
    "bacnet": 17, "profinet_dcp": None,
}


def validate_pcap_struct(pcap_path):
    """Validate PCAP binary structure without tshark."""
    errors = []
    with open(pcap_path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return ["PCAP too short for global header"], 0, []
        magic = struct.unpack("<I", gh[0:4])[0]
        if magic != 0xA1B2C3D4:
            errors.append(f"Bad magic: {magic:#x}")
        major, minor = struct.unpack("<HH", gh[4:8])
        if major != 2 or minor != 4:
            errors.append(f"Bad version: {major}.{minor}")
        network = struct.unpack("<I", gh[20:24])[0]
        if network != 1:
            errors.append(f"Bad linktype: {network}")

        pkt_count = 0
        timestamps = []
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", ph)
            timestamps.append(ts_sec + ts_usec / 1_000_000)
            frame = f.read(incl_len)
            if len(frame) < incl_len:
                errors.append(f"Packet {pkt_count}: truncated ({len(frame)}/{incl_len})")
                break
            if len(frame) < 14:
                errors.append(f"Packet {pkt_count}: too short for Ethernet ({len(frame)}B)")
            pkt_count += 1

    return errors, pkt_count, timestamps


def validate_pcap_tshark(pcap_path, verbose=False):
    """Run tshark to validate PCAP dissection."""
    errors = []
    try:
        result = subprocess.run(
            ["tshark", "-r", pcap_path, "-T", "fields",
             "-e", "frame.number", "-e", "frame.len",
             "-e", "ip.proto", "-e", "tcp.dstport", "-e", "udp.dstport",
             "-e", "_ws.malformed"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            errors.append(f"tshark error: {result.stderr.strip()[:200]}")
            return errors, []

        packets = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            fields = line.split("\t")
            pkt = {
                "frame": fields[0] if len(fields) > 0 else "",
                "len": fields[1] if len(fields) > 1 else "",
                "ip_proto": fields[2] if len(fields) > 2 else "",
                "tcp_dst": fields[3] if len(fields) > 3 else "",
                "udp_dst": fields[4] if len(fields) > 4 else "",
                "malformed": fields[5] if len(fields) > 5 else "",
            }
            if pkt["malformed"]:
                errors.append(f"Packet {pkt['frame']}: MALFORMED")
            packets.append(pkt)

        if verbose:
            for p in packets[:5]:
                proto = "TCP" if p["ip_proto"] == "6" else "UDP" if p["ip_proto"] == "17" else p["ip_proto"]
                port = p["tcp_dst"] or p["udp_dst"] or "?"
                print(f"    pkt#{p['frame']} {p['len']}B {proto}:{port}")

        return errors, packets
    except FileNotFoundError:
        return ["tshark not found"], []
    except subprocess.TimeoutExpired:
        return ["tshark timed out"], []


def main():
    ap = argparse.ArgumentParser(description="ICSForge PCAP Validation")
    ap.add_argument("--tshark", action="store_true", help="Also validate with tshark")
    ap.add_argument("--verbose", "-v", action="store_true", help="Show per-packet details")
    ap.add_argument("--scenario", default=None, help="Test only this scenario name")
    ap.add_argument("--quick", action="store_true",
                    help="Test one scenario per protocol + all CHAINs (fast representative check)")
    args = ap.parse_args()

    from icsforge.scenarios.engine import load_scenarios, run_scenario

    pack = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "icsforge", "scenarios", "scenarios.yml"))
    doc = load_scenarios(pack)
    scenarios = doc.get("scenarios", {})

    if args.scenario:
        scenarios = {k: v for k, v in scenarios.items() if k == args.scenario}
        if not scenarios:
            print(f"Scenario '{args.scenario}' not found")
            sys.exit(1)
    elif args.quick:
        # Pick one scenario per protocol + all CHAINs
        seen_protos = set()
        quick = {}
        for k, v in sorted(scenarios.items()):
            if k.startswith("CHAIN"):
                quick[k] = v
                continue
            proto = next((s.get("proto") for s in v.get("steps", []) if s.get("proto")), None)
            if proto and proto not in seen_protos:
                seen_protos.add(proto)
                quick[k] = v
        scenarios = quick

    # Skip PROFINET (L2 only) and chains with mixed L2+TCP
    skip_l2 = {k for k, v in scenarios.items()
               if all(s.get("proto") == "profinet_dcp" for s in v.get("steps", []))}
    has_l2 = {k for k, v in scenarios.items()
              if any(s.get("proto") == "profinet_dcp" for s in v.get("steps", []))}

    total = len(scenarios) - len(skip_l2)
    passed = 0
    failed = 0
    fail_details = []

    has_tshark = shutil.which("tshark") is not None
    use_tshark = args.tshark and has_tshark
    if args.tshark and not has_tshark:
        print("WARNING: --tshark requested but tshark not found. Struct-only mode.\n")

    label = f"+ tshark" if use_tshark else "struct-only"
    print(f"ICSForge PCAP Validation — {total} scenarios ({label})\n")

    for name, sc in sorted(scenarios.items()):
        if name in skip_l2:
            continue

        protos = set(s.get("proto", "") for s in sc.get("steps", []) if s.get("proto"))
        step_count = sum(s.get("count", 1) for s in sc.get("steps", []))
        proto = next(iter(protos), "?")

        with tempfile.TemporaryDirectory() as td:
            try:
                r = run_scenario(pack, name, outdir=td,
                                 dst_ip="198.51.100.42", src_ip="127.0.0.1",
                                 run_id="validate", build_pcap=True)
            except Exception as e:
                failed += 1
                fail_details.append(f"{name}: execution error: {e}")
                print(f"  ✗ {name} — {e}")
                continue

            pcap = r.get("pcap")
            if not pcap or not os.path.exists(pcap):
                failed += 1
                fail_details.append(f"{name}: no PCAP generated")
                print(f"  ✗ {name} — no PCAP")
                continue

            errs, pkt_count, timestamps = validate_pcap_struct(pcap)

            if pkt_count != step_count:
                errs.append(f"count {pkt_count} != expected {step_count}")

            # Validate first packet port and IP proto
            # Skip port check for scenarios with L2 (profinet) — first frame may be L2
            if name not in has_l2:
                all_expected_ports = set()
                all_expected_protos = set()
                for p in protos:
                    ep = EXPECTED_PORTS.get(p)
                    if ep:
                        all_expected_ports.add(ep)
                    eip = EXPECTED_IP_PROTO.get(p)
                    if eip:
                        all_expected_protos.add(eip)

                with open(pcap, "rb") as f:
                    f.read(24)
                    ph = f.read(16)
                    if len(ph) == 16:
                        _, _, il, _ = struct.unpack("<IIII", ph)
                        frame = f.read(il)
                        if len(frame) >= 42:
                            ip_proto = frame[23]
                            ihl = (frame[14] & 0x0F) * 4
                            dport = struct.unpack(">H", frame[14 + ihl + 2:14 + ihl + 4])[0]
                            if all_expected_ports and dport not in all_expected_ports:
                                errs.append(f"port {dport} not in {sorted(all_expected_ports)}")
                            if all_expected_protos and ip_proto not in all_expected_protos:
                                errs.append(f"ip_proto {ip_proto} not in {sorted(all_expected_protos)}")

            if use_tshark:
                tshark_errs, _ = validate_pcap_tshark(pcap, verbose=args.verbose)
                errs.extend(tshark_errs)

            if errs:
                failed += 1
                detail = "; ".join(errs[:3])
                fail_details.append(f"{name}: {detail}")
                print(f"  ✗ {name} ({proto}, {pkt_count}pkts) — {detail}")
            else:
                passed += 1
                if args.verbose:
                    print(f"  ✓ {name} ({proto}, {pkt_count}pkts)")

    if not args.verbose and passed > 0:
        print(f"  ... {passed} scenarios validated")

    print(f"\n{'=' * 60}")
    print(f"  {passed} passed, {failed} failed out of {total}")
    if fail_details:
        print(f"\n  Failures:")
        for d in fail_details:
            print(f"    ✗ {d}")
    if failed == 0:
        print(f"\n  ★ ALL {total} PCAPs VALIDATED ★")
    print(f"{'=' * 60}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
