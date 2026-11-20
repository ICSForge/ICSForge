import json
import os
import random as _rnd_eng
import time
from typing import Any

import yaml

from icsforge.core import build_marker, event_base, parse_interval, write_pcap
from icsforge.log import get_logger
from icsforge.protocols import TCP_PROTOS as PROTO_PAYLOADS
from icsforge.protocols import UDP_PROTOS as UDP_PAYLOADS
from icsforge.protocols import iec61850, profinet_dcp
from icsforge.protocols.common import (
    TCPFlow,
    _resolve_dst_mac,
    _src_mac_from_ip,
    ether_frame,
    tcp_packet,
    udp_packet,
)

_SCENARIO_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}


# ── Session prologue (stateful realism) ──────────────────────────────────────
# Session-based ICS protocols require an opener exchange before any data/command
# frames: a real device rejects data sent before the session is established, and
# session-aware NSMs (Dragos, Nozomi, Zeek session tracking) baseline the opener.
# When a stateful scenario does NOT already begin with its opener, the engine
# prepends the opener frame(s) once, on the first flow, so the trace reflects a
# real conversation. Gated to stateful mode only — firewall/ACL (unidirectional)
# testing deliberately keeps single-frame behaviour.
#
# Each entry: proto -> (ordered list of opener build styles, set of styles that
# ALREADY constitute the opener so we don't double it up).
_SESSION_PROLOGUE: dict[str, tuple[list[str], frozenset[str]]] = {
    # IEC-104: U-format STARTDT act must enable data transfer (IEC 60870-5-104 §5.3).
    "iec104": (["startdt"], frozenset({"startdt", "available", "testfr", "stopdt"})),
    # S7comm: COTP Connection Request (TPDU 0xE0) then S7 setup-communication.
    # Note: the S7 'setup' style rides COTP DT and does NOT itself open the COTP
    # connection, so it must NOT count as already-opened — only a COTP CR does.
    "s7comm": (["native_cotp", "setup"],
               frozenset({"native_cotp", "cotp_connect", "connect"})),
    # OPC UA: HEL (Hello) then OpenSecureChannel (OPN) before any MSG service call.
    # If the scenario already starts by opening the channel (open_session=OPN,
    # get_endpoints/find_servers which include their own OPN), don't double it;
    # otherwise prepend the full HEL+OPN opener.
    "opcua": (["hello", "open_session"],
              frozenset({"hello", "open_session", "get_endpoints",
                         "find_servers", "create_sub"})),
    # EtherNet/IP: RegisterSession before SendRRData/UnitData explicit messaging.
    "enip": (["register_session"],
             frozenset({"register_session", "list_identity", "list_services"})),
    # MQTT: CONNECT before any PUBLISH/SUBSCRIBE (broker drops otherwise).
    "mqtt": (["connect"],
             frozenset({"connect", "connect_anonymous", "connect_creds"})),
}


def _session_prologue_payloads(proto: str, first_style: str) -> list[bytes]:
    """Return the opener payload frames for a stateful session of ``proto``.

    Empty when the protocol needs no prologue, or when the scenario already
    opens with its session opener (``first_style`` is one of the opener styles).

    Special case OPC UA: HEL (transport Hello) must precede *everything*,
    including a scenario that opens with OpenSecureChannel/GetEndpoints. So for
    OPC UA, if the scenario starts by opening a channel (but not with HEL), we
    still prepend HEL alone; if it starts data-first we prepend the full HEL+OPN.
    """
    spec = _SESSION_PROLOGUE.get(proto)
    if not spec:
        return []
    styles, already = spec
    from icsforge.protocols import TCP_PROTOS as _tp
    entry = _tp.get(proto)
    if not entry:
        return []
    builder = entry[1]

    def _build(style_list: list[str]) -> list[bytes]:
        out: list[bytes] = []
        for st in style_list:
            try:
                out.append(builder(b"", style=st, marker_mode="none"))
            except Exception:
                log.debug("session prologue: %s has no '%s' opener style", proto, st)
        return out

    # OPC UA transport rule: HEL precedes everything. A channel-opening scenario
    # (open_session / get_endpoints / find_servers / create_sub) supplies its own
    # OPN, so it only needs HEL prepended — not a second OPN.
    if proto == "opcua":
        if first_style == "hello":
            return []
        if first_style in {"open_session", "get_endpoints", "find_servers", "create_sub"}:
            return _build(["hello"])
        return _build(["hello", "open_session"])

    if first_style in already:
        return []
    return _build(styles)





def load_scenarios(scenario_path: str) -> dict[str, Any]:
    # Use libyaml's C loader when available — it parses the ~700 KB scenarios
    # file roughly 8x faster than the pure-Python SafeLoader (≈0.2s vs ≈1.5s),
    # which matters because every generate/send invocation loads it. Falls back
    # to the pure-Python loader if libyaml isn't built in.
    #
    # In-process cache keyed on (path, mtime): the catalog is parsed at most once
    # per process for a given file, and automatically re-parsed if the file
    # changes on disk. This removes repeated full-catalog parsing when many
    # operations run in one process (test suites, batch generation, the web app),
    # while staying correct for live edits.
    try:
        mtime = os.path.getmtime(scenario_path)
        cached = _SCENARIO_CACHE.get(scenario_path)
        if cached is not None and cached[0] == mtime:
            return cached[1]
    except OSError:
        mtime = None

    _Loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    with open(scenario_path, encoding="utf-8") as f:
        data = yaml.load(f, Loader=_Loader) or {}

    if mtime is not None:
        _SCENARIO_CACHE[scenario_path] = (mtime, data)
    return data

log = get_logger(__name__)


def profile_defaults(profile: str) -> dict[str, Any]:
    """Map a test profile to its generation/transport defaults.

    Profiles encode operator *intent*; they set safe defaults and how results
    are framed — they never fabricate device responses (the receiver is a safe
    sinkhole, not a simulated device).

      firewall (default) — boundary/ACL test. Sender sits in IT or another OT
          zone; the receiver is a safe sinkhole. The question is purely whether
          sender->receiver traffic *arrives* (a misconfigured rule let it
          through). Unidirectional by design: no handshake assumption, because a
          firewall that permits the forward flow may still block the return.
      nsm — sensor test. The path is known-open; the question is whether the NSM
          *alarms* on the behaviour. Completing the TCP handshake helps stream-
          tracking sensors engage, so the offline pcap defaults to stateful, and
          the witnessed receipt is paired with the expected technique/alert for
          diffing against what the NSM fired.

    Returns a dict of defaults; callers apply them only where the user has not
    set an explicit override.
    """
    p = (profile or "firewall").strip().lower()
    if p == "nsm":
        return {"stateful": True}
    # firewall (and any unknown value) -> conservative, unidirectional
    return {"stateful": False}


def run_scenario(
    scenario_path: str,
    name: str,
    outdir: str = "out",
    dst_ip: str = "127.0.0.1",
    src_ip: str = "127.0.0.1",
    run_id: str | None = None,
    build_pcap: bool = True,
    skip_intervals: bool = False,
    no_marker: bool = False,
    explicit_marker: bool = False,
    resolve_mac: bool = False,
    stateful: bool = False,
) -> dict[str, Any]:
    """Offline scenario runner.

    Produces:
    - Ground-truth events JSONL (always)
    - PCAP (optional) with per-step correlation markers embedded in payloads

    Marker modes:
    - default (covert/stego): the run marker is woven into genuinely-arbitrary
      protocol fields (Modbus transaction ID, ENIP sender context, S7 PDU ref,
      etc.) for zero added bytes and realistic traffic. Detection uses a
      Layer-1 band pre-filter plus Layer-2 receiver HMAC verification.
    - explicit_marker=True: embed the compact 13-byte 'ICSF<code><hash>'
      string in the payload so Layer-1 detection works without a receiver.
    - no_marker=True: stealth, no marker at all (registry-only attribution).

    NOTE: Live sending is handled by icsforge.live.sender; this runner is for
    offline generation and evidence artifacts.
    """
    doc = load_scenarios(scenario_path)
    scenarios = doc.get("scenarios") or {}
    aliases = doc.get("aliases") or {}
    if name not in scenarios and name in aliases:
        name = aliases[name]
    sc = scenarios.get(name)
    if not sc:
        raise ValueError(f"Scenario '{name}' not found in {scenario_path}")

    os.makedirs(outdir, exist_ok=True)
    run_id = run_id or os.environ.get("ICSFORGE_RUN_ID")  # optional, can be None

    # Resolve dst MAC once per scenario run.
    # resolve_mac=True (live context): ARP cache lookup → deterministic unicast fallback.
    # resolve_mac=False (offline PCAP builder): ff:ff:ff:ff:ff:ff kept for clarity.
    _dst_mac_bytes: bytes | None = _resolve_dst_mac(dst_ip) if resolve_mac else None

    # Stable TCP source port per scenario run — mimics a persistent client connection.
    # Real ICS clients open one TCP session per master-RTU pair; all frames share the
    # same 4-tuple (src_ip, src_port, dst_ip, dst_port). Random-per-frame src ports
    # make NSMs model each frame as a separate session, which is unrealistic.
    import hashlib as _hl
    _sport_seed = int(_hl.md5(f'{src_ip}{dst_ip}{run_id or name}'.encode()).hexdigest()[:4], 16)
    _tcp_sport: int = 49152 + (_sport_seed % 16383)  # ephemeral range 49152-65534

    events_dir = os.path.join(outdir, "events")
    pcaps_dir = os.path.join(outdir, "pcaps")
    os.makedirs(events_dir, exist_ok=True)
    os.makedirs(pcaps_dir, exist_ok=True)
    rid = (run_id or "offline")
    events_path = os.path.join(events_dir, f"{rid}.jsonl")
    pcap_path = os.path.join(pcaps_dir, f"{rid}.pcap")

    packets: list[Any] = []

    # Session-level protocol contexts — keep sequence numbers coherent
    # across all steps within this scenario run
    _opcua_ctx = {
        "secure_channel_id": _rnd_eng.randint(1, 0xFFFFFF),
        "security_token":    _rnd_eng.randint(1, 0xFFFFFF),
        "sequence_number":   _rnd_eng.randint(1, 0xFFFFFF),
        "request_id":        _rnd_eng.randint(1, 0xFFFF),
        "dst_ip":            dst_ip,
    }
    _dnp3_seq:    int = _rnd_eng.randint(0, 15)           # DNP3 app seq (0-15)
    _tcp_seq:     int = _rnd_eng.randint(0, 0xFFFFFFFF)    # TCP ISN
    _iec104_seq:  int = _rnd_eng.randint(0, 0x7FFF)        # IEC-104 send seq (15-bit)
    _s7_pdu_ref:  int = _rnd_eng.randint(1, 0xFFFF)        # S7comm PDU reference
    _modbus_tid:  int = _rnd_eng.randint(0, 0xFFFF)        # Modbus transaction ID
    _bacnet_inv:  int = _rnd_eng.randint(0, 255)           # BACnet invoke ID
    _pkt_index:   int = 0                                  # global packet index (covert marker HMAC input)
    _session_prologue_done: bool = False                   # inject opener once per scenario (stateful)
    # Per-step timing schedule: (n_packets_added, interval_seconds, proto). Lets
    # write_pcap reproduce realistic per-protocol/per-step inter-packet timing in
    # the offline PCAP instead of a flat global cadence — what anomaly NSMs
    # (Dragos, Nozomi) baseline on. Captured as each step appends its packets.
    _pkt_schedule: list[tuple[int, float, str]] = []

    with open(events_path, "w", encoding="utf-8") as ef:
        for idx, step in enumerate((sc.get("steps") or []), start=1):
            stype = (step.get("type") or "event").strip().lower()
            proto = step.get("proto")
            tech = step.get("technique")
            count = int(step.get("count", 1))
            interval = parse_interval(step.get("interval", "0s"))
            style = step.get("style", "auto")
            options = step.get("options") or {}
            # Inject session-level OPC UA context (per-packet increment in TCP loop)
            if proto == "opcua":
                options = {**_opcua_ctx, **options}
            # Inject dst_ip for protocols that encode the target address in payload
            if proto in ("opcua", "s7comm"):
                options = {"dst_ip": dst_ip, **options}

            step_id = f"{name}:{idx}:{proto or ''}"

            # Write ground-truth events FIRST — before pcap building.
            # This ensures events are always recorded even if pcap building
            # fails, raises, or is interrupted (e.g. KeyboardInterrupt).
            for _ in range(count):
                ev = event_base(
                    tech,
                    source=stype,
                    no_marker=no_marker,
                    scenario=name,
                    proto=proto,
                    message=step.get("message", ""),
                )
                ev["run_id"] = rid          # always present; "offline" when no run_id given
                ev["icsforge.run_id"] = rid
                ef.write(json.dumps(ev, ensure_ascii=False) + "\n")
            ef.flush()  # flush after each step so partial runs are readable

            # Build PCAP packets (optional) — after events are safely written
            pcap_step = (stype == "pcap") or (stype == "packet" and bool(step.get("pcap")))
            _pkt_count_before = len(packets)
            if build_pcap and pcap_step:
                if proto == "profinet_dcp":
                    for _ in range(count):
                        marker = b'' if no_marker else build_marker(run_id, tech, step_id)
                        payload = profinet_dcp.build_payload(marker, style=style)
                        # Default multicast dst for DCP Identify
                        pkt = ether_frame(
                            src_mac=_src_mac_from_ip(src_ip, proto="profinet_dcp").hex(":"),
                            dst_mac="01:0e:cf:00:00:00",
                            ethertype=0x8892,
                            payload=payload,
                        )
                        packets.append(pkt)
                        if interval and not skip_intervals:
                            time.sleep(interval)
                elif proto == "iec61850":
                    # GOOSE retransmission cadence: after a state change a publisher
                    # bursts fast then backs off — sqNum increments 0,1,2,… within a
                    # state while the inter-frame gap doubles 1→2→4→8ms up to a
                    # steady heartbeat (~1s). stNum stays fixed within the state.
                    # This is the distinctive rhythm anomaly NSMs baseline; a flat
                    # interval would look nothing like real GOOSE. Each frame gets
                    # its own schedule entry so write_pcap reproduces the curve.
                    _steady_ms = 1000.0
                    if interval and interval > 0:
                        _steady_ms = interval * 1000.0
                    _base_st = int(options.get("st_num", _rnd_eng.randint(1, 50)))
                    for _k in range(count):
                        marker = b'' if no_marker else build_marker(run_id, tech, step_id)
                        _g_opts = {**options}
                        # sqNum increments within the state; stNum fixed for this step.
                        _g_opts.setdefault("st_num", _base_st)
                        _g_opts["sq_num"] = _k
                        # iec61850.build_payload returns a complete Ethernet frame
                        # (GOOSE: EtherType 0x88B8, GOOSE multicast DST)
                        pkt = iec61850.build_payload(marker, style=style, **_g_opts)
                        packets.append(pkt)
                        # doubling backoff 1,2,4,8,… ms capped at the steady heartbeat
                        _gap_ms = min(1.0 * (2 ** _k), _steady_ms)
                        _pkt_schedule.append((1, _gap_ms / 1000.0, "iec61850"))
                        if not skip_intervals:
                            time.sleep(_gap_ms / 1000.0)
                    # already recorded per-frame schedule entries above; prevent the
                    # step-level recorder below from double-counting these packets.
                    _pkt_count_before = len(packets)
                else:
                    pb = PROTO_PAYLOADS.get(proto)
                    upb = UDP_PAYLOADS.get(proto)
                    if not pb and not upb:
                        log.warning("PCAP skipped for step %d: unknown proto '%s' (events already written)", idx, proto)
                    elif pb:
                        dport, payload_builder = pb
                        # Stateful mode: wrap this step's segments in a real TCP
                        # conversation (handshake → data+ACK → teardown). Default
                        # stays the stateless single-PSH/ACK model.
                        _flow = None
                        if stateful:
                            # Fresh ephemeral source port per connection (a real
                            # client would not reuse the same port for a new
                            # session); keeps each flow a clean, independent
                            # conversation in the trace.
                            _flow = TCPFlow(src_ip, dst_ip, _tcp_sport, dport,
                                            client_isn=_tcp_seq,
                                            dst_mac=_dst_mac_bytes, proto=proto)
                            packets.extend(_flow.handshake())
                            # Session prologue: prepend the protocol's opener
                            # (STARTDT / COTP-CR+setup / HEL+OPN / RegisterSession
                            # / CONNECT) once, on the first flow, when the scenario
                            # doesn't already start with it — so stateful traces
                            # reflect a real, device-acceptable session.
                            if not _session_prologue_done:
                                for _op in _session_prologue_payloads(proto, style):
                                    packets.extend(_flow.client_data(_op))
                                _session_prologue_done = True
                            _tcp_sport = 49152 + ((_tcp_sport - 49152 + 1) % 16383)
                        for _ in range(count):
                            marker = b'' if no_marker else build_marker(run_id, tech, step_id)
                            _pkt_opts = {**options}
                            # Marker mode + run identity + per-packet index let the
                            # builder weave a covert marker into protocol fields.
                            _pkt_opts["marker_mode"] = (
                                "none" if no_marker else ("explicit" if explicit_marker else "covert")
                            )
                            _pkt_opts["run_marker"] = run_id or "offline"
                            _pkt_opts["pkt_index"] = _pkt_index
                            if proto == "opcua":
                                _pkt_opts["sequence_number"] = _opcua_ctx["sequence_number"]
                                _pkt_opts["request_id"]      = _opcua_ctx["request_id"]
                                _opcua_ctx["sequence_number"] = (_opcua_ctx["sequence_number"] + 1) & 0xFFFFFF
                                _opcua_ctx["request_id"]      = (_opcua_ctx["request_id"]      + 1) & 0xFFFF
                            elif proto == "dnp3":
                                _pkt_opts["dnp3_seq"] = _dnp3_seq
                                _dnp3_seq = (_dnp3_seq + 1) & 0x0F
                            elif proto == "iec104":
                                _pkt_opts["iec104_seq"] = _iec104_seq
                                _iec104_seq = (_iec104_seq + 1) & 0x7FFF
                            elif proto == "s7comm":
                                _pkt_opts["s7_pdu_ref"] = _s7_pdu_ref
                                _s7_pdu_ref = (_s7_pdu_ref + 1) & 0xFFFF
                            elif proto == "modbus":
                                _pkt_opts["modbus_tid"] = _modbus_tid
                                _modbus_tid = (_modbus_tid + 1) & 0xFFFF
                            _payload = payload_builder(marker, style=style, **_pkt_opts)
                            if _flow is not None:
                                packets.extend(_flow.client_data(_payload))
                            else:
                                packets.append(tcp_packet(src_ip, dst_ip, dport,
                                    _payload, tcp_seq=_tcp_seq,
                                    dst_mac=_dst_mac_bytes, proto=proto,
                                    sport=_tcp_sport))
                                _tcp_seq = (_tcp_seq + max(len(_payload), 1)) & 0xFFFF_FFFF
                            _pkt_index += 1
                            if interval and not skip_intervals:
                                time.sleep(interval)
                        if _flow is not None:
                            packets.extend(_flow.teardown())
                            # Advance the scenario ISN past this whole flow so a
                            # subsequent same-tuple step doesn't reuse sequence space.
                            _tcp_seq = (_flow.cseq + 1) & 0xFFFF_FFFF
                    elif upb:
                        dport, payload_builder = upb
                        for _ in range(count):
                            marker = b'' if no_marker else build_marker(run_id, tech, step_id)
                            _udp_opts = {**options}
                            _udp_opts["marker_mode"] = (
                                "none" if no_marker else ("explicit" if explicit_marker else "covert")
                            )
                            _udp_opts["run_marker"] = run_id or "offline"
                            _udp_opts["pkt_index"] = _pkt_index
                            if proto == "bacnet":
                                _udp_opts["bacnet_invoke_id"] = _bacnet_inv
                                _bacnet_inv = (_bacnet_inv + 1) & 0xFF
                            packets.append(udp_packet(src_ip, dst_ip, dport,
                                payload_builder(marker, style=style, **_udp_opts),
                                dst_mac=_dst_mac_bytes, proto=proto))
                            _pkt_index += 1
                            if interval and not skip_intervals:
                                time.sleep(interval)

            # Record this step's contribution to the timing schedule.
            _added = len(packets) - _pkt_count_before
            if _added > 0:
                _pkt_schedule.append((_added, interval, proto or ""))

    if build_pcap and packets:
        write_pcap(packets, pcap_path, schedule=_pkt_schedule)

    return {"run_id": (run_id or "offline"), "events": events_path, "pcap": pcap_path if (build_pcap and packets) else None}
