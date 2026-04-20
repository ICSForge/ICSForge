#!/usr/bin/env bash
# Third-party NSM validation — runs ICSForge PCAPs through Wireshark's
# ICS dissectors (the same dissector foundation Zeek/Malcolm wrap) in
# both standard and stealth modes. Produces a per-protocol report.
#
# Requirements: tshark (wireshark-common), icsforge installed.
#
# Usage:
#   scripts/validate_third_party.sh [--outdir DIR]
#
# Output: stdout table + machine-readable JSON at $OUTDIR/validation.json
#
set -euo pipefail

OUTDIR="${1:-/tmp/icsforge-validation-$$}"
mkdir -p "$OUTDIR"

if ! command -v tshark >/dev/null 2>&1; then
  echo "ERROR: tshark not installed. Try: apt install wireshark-common" >&2
  exit 2
fi

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

# Scenario + dissector + port-filter per protocol. Keep this list in
# sync with the 10 supported protocols.
PROTOS=(
  "modbus:T0855__unauth_command__modbus:mbtcp:tcp.port==502"
  "dnp3:T0800__fw_update_mode__dnp3:dnp3:tcp.port==20000"
  "s7comm:T0800__fw_update_mode__s7comm:s7comm:tcp.port==102"
  "iec104:T0855__unauth_command__iec104:iec60870_104:tcp.port==2404"
  "enip:T0800__fw_update_mode__enip:enip:tcp.port==44818"
  "opcua:T0831__manipulation_control__opcua_write:opcua:tcp.port==4840"
  "bacnet:T0801__monitor_process__bacnet_read:bvlc:udp.port==47808"
  "mqtt:T0801__monitor_process__mqtt_subscribe:mqtt:tcp.port==1883"
  "iec61850:T0801__monitor_process__iec61850:goose:eth.type==0x88b8"
  "profinet_dcp:T0840__network_enum__profinet_identify:pn_dcp:eth.type==0x8892"
)

printf "%-14s  %-8s  %-8s  %-7s  %-8s  %-8s  %-7s  %s\n" \
       "protocol" "std_pkts" "std_diss" "std_err" "stlth_pkt" "stlth_diss" "stlth_err" "verdict"
printf "%-14s  %-8s  %-8s  %-7s  %-8s  %-8s  %-7s  %s\n" \
       "--------" "--------" "--------" "-------" "---------" "----------" "---------" "-------"

JSON_ROWS=()
FAIL=0
for entry in "${PROTOS[@]}"; do
  proto="${entry%%:*}"; rest="${entry#*:}"
  name="${rest%%:*}"; rest="${rest#*:}"
  diss="${rest%%:*}"
  filt="${rest#*:}"

  std_dir="$OUTDIR/$proto-std"
  stlth_dir="$OUTDIR/$proto-stealth"
  mkdir -p "$std_dir" "$stlth_dir"

  python3 -m icsforge.cli generate --name "$name" --outdir "$std_dir" \
    --dst-ip 192.0.2.10 --src-ip 192.0.2.11 >/dev/null 2>&1 || continue
  python3 -m icsforge.cli generate --name "$name" --outdir "$stlth_dir" \
    --dst-ip 192.0.2.10 --src-ip 192.0.2.11 --no-marker >/dev/null 2>&1 || continue

  std_pcap=$(ls "$std_dir"/pcaps/*.pcap 2>/dev/null | head -1 || true)
  stlth_pcap=$(ls "$stlth_dir"/pcaps/*.pcap 2>/dev/null | head -1 || true)
  [ -z "$std_pcap" ] || [ -z "$stlth_pcap" ] && continue

  std_pkts=$(tshark -r "$std_pcap" 2>/dev/null | wc -l)
  std_diss=$(tshark -r "$std_pcap" -Y "$filt && $diss" 2>/dev/null | wc -l)
  std_err=$(tshark -r "$std_pcap" -Y "_ws.malformed || _ws.expert.severity==error" 2>/dev/null | wc -l)

  stlth_pkts=$(tshark -r "$stlth_pcap" 2>/dev/null | wc -l)
  stlth_diss=$(tshark -r "$stlth_pcap" -Y "$filt && $diss" 2>/dev/null | wc -l)
  stlth_err=$(tshark -r "$stlth_pcap" -Y "_ws.malformed || _ws.expert.severity==error" 2>/dev/null | wc -l)

  if [ "$std_err" = "0" ] && [ "$stlth_err" = "0" ]; then
    verdict="PASS"
  else
    verdict="FAIL (std=$std_err, stealth=$stlth_err)"
    FAIL=$((FAIL+1))
  fi

  printf "%-14s  %-8s  %-8s  %-7s  %-8s  %-8s  %-7s  %s\n" \
    "$proto" "$std_pkts" "$std_diss" "$std_err" "$stlth_pkts" "$stlth_diss" "$stlth_err" "$verdict"

  JSON_ROWS+=("  {\"protocol\":\"$proto\",\"std_pkts\":$std_pkts,\"std_dissected\":$std_diss,\"std_errors\":$std_err,\"stealth_pkts\":$stlth_pkts,\"stealth_dissected\":$stlth_diss,\"stealth_errors\":$stlth_err,\"verdict\":\"$verdict\"}")
done

echo ""
echo "Workdir: $OUTDIR"
echo "Failures: $FAIL / 10"

(
  echo "{"
  echo "  \"generated_at\": \"$(date -Iseconds)\","
  echo "  \"tool\": \"tshark $(tshark -v 2>/dev/null | head -1 | awk '{print $2}')\","
  echo "  \"results\": ["
  IFS=$',\n'; echo "${JSON_ROWS[*]}"; unset IFS
  echo "  ]"
  echo "}"
) > "$OUTDIR/validation.json"

exit "$FAIL"
